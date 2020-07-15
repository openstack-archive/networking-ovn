# Copyright 2016 Red Hat, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import abc
import datetime

from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log import log
from oslo_utils import timeutils
from ovs.stream import Stream
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import event as row_event
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp import event

from networking_ovn.common import config as ovn_config
from networking_ovn.common import constants as ovn_const
from networking_ovn.common import exceptions
from networking_ovn.common import hash_ring_manager
from networking_ovn.common import utils
from networking_ovn.db import hash_ring as db_hash_ring

CONF = cfg.CONF
LOG = log.getLogger(__name__)


class BaseEvent(row_event.RowEvent):
    table = None
    events = tuple()

    def __init__(self):
        self.event_name = self.__class__.__name__
        super(BaseEvent, self).__init__(self.events, self.table, None)

    @abc.abstractmethod
    def match_fn(self, event, row, old=None):
        """Define match criteria other than table/event"""

    def matches(self, event, row, old=None):
        if row._table.name != self.table or event not in self.events:
            return False
        if not self.match_fn(event, row, old):
            return False
        LOG.debug("%s : Matched %s, %s, %s %s", self.event_name, self.table,
                  event, self.conditions, self.old_conditions)
        return True


class ChassisEvent(row_event.RowEvent):
    """Chassis create update delete event."""

    def __init__(self, driver):
        self.driver = driver
        self.l3_plugin = directory.get_plugin(constants.L3)
        table = 'Chassis'
        events = (self.ROW_CREATE, self.ROW_UPDATE, self.ROW_DELETE)
        super(ChassisEvent, self).__init__(events, table, None)
        self.event_name = 'ChassisEvent'

    def handle_ha_chassis_group_changes(self, event, row, old):
        """Handle HA Chassis Group changes.

        This method handles the inclusion and removal of Chassis to/from
        the default HA Chassis Group.
        """
        if not self.driver._ovn_client.is_external_ports_supported():
            return

        # NOTE(lucasgomes): If the external_ids column wasn't updated
        # (meaning, Chassis "gateway" status didn't change) just returns
        if not hasattr(old, 'external_ids') and event == self.ROW_UPDATE:
            return

        is_gw_chassis = utils.is_gateway_chassis(row)
        # If the Chassis being created is not a gateway, ignore it
        if not is_gw_chassis and event == self.ROW_CREATE:
            return

        if event == self.ROW_UPDATE:
            is_old_gw = utils.is_gateway_chassis(old)
            if is_gw_chassis and is_old_gw:
                return
            elif not is_gw_chassis and is_old_gw:
                # Chassis is not a gateway anymore, treat it as deletion
                event = self.ROW_DELETE
            elif is_gw_chassis and not is_old_gw:
                # Chassis is now a gateway, treat it as creation
                event = self.ROW_CREATE

        if event == self.ROW_CREATE:
            default_group = self.driver._nb_ovn.ha_chassis_group_get(
                ovn_const.HA_CHASSIS_GROUP_DEFAULT_NAME).execute(
                check_error=True)

            # Find what's the lowest priority number current in the group
            # and add the new chassis as the new lowest
            try:
                min_priority = min(
                    [ch.priority for ch in default_group.ha_chassis])
            except ValueError:
                min_priority = ovn_const.HA_CHASSIS_GROUP_HIGHEST_PRIORITY

            self.driver._nb_ovn.ha_chassis_group_add_chassis(
                ovn_const.HA_CHASSIS_GROUP_DEFAULT_NAME, row.name,
                priority=min_priority - 1).execute(check_error=True)

        elif event == self.ROW_DELETE:
            self.driver._nb_ovn.ha_chassis_group_del_chassis(
                ovn_const.HA_CHASSIS_GROUP_DEFAULT_NAME,
                row.name, if_exists=True).execute(check_error=True)

    def match_fn(self, event, row, old):
        if event != self.ROW_UPDATE:
            return True
        # NOTE(lucasgomes): If the external_ids column wasn't updated
        # (meaning, Chassis "gateway" status didn't change) just returns
        if not hasattr(old, 'external_ids'):
            return
        if (old.external_ids.get('ovn-bridge-mappings') !=
                row.external_ids.get('ovn-bridge-mappings')):
            return True
        f = utils.is_gateway_chassis
        return f(old) != f(row)

    def run(self, event, row, old):
        host = row.hostname
        phy_nets = []
        if event != self.ROW_DELETE:
            bridge_mappings = row.external_ids.get('ovn-bridge-mappings', '')
            mapping_dict = helpers.parse_mappings(bridge_mappings.split(','),
                                                  unique_values=False)
            phy_nets = list(mapping_dict)

        self.driver.update_segment_host_mapping(host, phy_nets)

        if utils.is_ovn_l3(self.l3_plugin):
            # If chassis lost physnet or has been
            # deleted we can limit the scope and
            # reschedule only ports from this chassis.
            # In other cases we need to reschedule all gw ports.
            kwargs = {'event_from_chassis': None}
            if event == self.ROW_DELETE:
                kwargs['event_from_chassis'] = row.name
            elif event == self.ROW_UPDATE:
                old_mappings = old.external_ids.get('ovn-bridge-mappings',
                                                    set()) or set()
                new_mappings = row.external_ids.get('ovn-bridge-mappings',
                                                    set()) or set()
                if old_mappings:
                    old_mappings = set(old_mappings.split(','))
                if new_mappings:
                    new_mappings = set(new_mappings.split(','))

                mappings_removed = old_mappings - new_mappings
                mappings_added = new_mappings - old_mappings
                if mappings_removed and not mappings_added:
                    # Mapping has been only removed. So we can
                    # limit scope of rescheduling only to impacted
                    # gateway chassis.
                    kwargs['event_from_chassis'] = row.name
            self.l3_plugin.schedule_unhosted_gateways(**kwargs)

        self.handle_ha_chassis_group_changes(event, row, old)


class PortBindingChassisUpdateEvent(row_event.RowEvent):
    """Event for matching a port moving chassis

    If the LSP is up and the Port_Binding chassis has just changed,
    there is a good chance the host died without cleaning up the chassis
    column on the Port_Binding. The port never goes down, so we won't
    see update the driver with the LogicalSwitchPortUpdateUpEvent which
    only monitors for transitions from DOWN to UP.
    """

    def __init__(self, driver):
        self.driver = driver
        table = 'Port_Binding'
        events = (self.ROW_UPDATE,)
        super(PortBindingChassisUpdateEvent, self).__init__(
            events, table, None)
        self.event_name = self.__class__.__name__

    def match_fn(self, event, row, old=None):
        # NOTE(twilson) ROW_UPDATE events always pass old, but chassis will
        # only be set if chassis has changed
        old_chassis = getattr(old, 'chassis', None)
        if not (row.chassis and old_chassis) or row.chassis == old_chassis:
            return False
        if row.type == ovn_const.OVN_CHASSIS_REDIRECT:
            return False
        try:
            lsp = self.driver._nb_ovn.lookup('Logical_Switch_Port',
                                             row.logical_port)
        except idlutils.RowNotFound:
            LOG.warning("Logical Switch Port %(port)s not found for "
                        "Port_Binding %(binding)s",
                        {'port': row.logical_port, 'binding': row.uuid})
            return False

        return bool(lsp.up)

    def run(self, event, row, old=None):
        self.driver.set_port_status_up(row.logical_port)


class PortBindingChassisEvent(row_event.RowEvent):
    """Port_Binding update event - set chassis for chassisredirect port.

    When a chassisredirect port is updated with chassis, this event get
    generated. We will update corresponding router's gateway port with
    the chassis's host_id. Later, users can check router's gateway port
    host_id to find the location of master HA router.
    """

    def __init__(self, driver):
        self.driver = driver
        self.l3_plugin = directory.get_plugin(constants.L3)
        table = 'Port_Binding'
        events = (self.ROW_UPDATE,)
        super(PortBindingChassisEvent, self).__init__(
            events, table, (('type', '=', ovn_const.OVN_CHASSIS_REDIRECT),))
        self.event_name = 'PortBindingChassisEvent'

    def run(self, event, row, old):
        if not utils.is_ovn_l3(self.l3_plugin):
            return
        router = host = None
        chassis = getattr(row, 'chassis', None)
        if chassis:
            router = row.datapath.external_ids.get('name', '').replace(
                'neutron-', '')
            host = chassis[0].hostname
            LOG.info("Router %(router)s is bound to host %(host)s",
                     {'router': router, 'host': host})
        self.l3_plugin.update_router_gateway_port_bindings(
            router, host)


class LogicalSwitchPortCreateUpEvent(row_event.RowEvent):
    """Row create event - Logical_Switch_Port 'up' = True.

    On connection, we get a dump of all ports, so if there is a neutron
    port that is down that has since been activated, we'll catch it here.
    This event will not be generated for new ports getting created.
    """

    def __init__(self, driver):
        self.driver = driver
        table = 'Logical_Switch_Port'
        events = (self.ROW_CREATE,)
        super(LogicalSwitchPortCreateUpEvent, self).__init__(
            events, table, (('up', '=', True),))
        self.event_name = 'LogicalSwitchPortCreateUpEvent'

    def run(self, event, row, old):
        self.driver.set_port_status_up(row.name)


class LogicalSwitchPortCreateDownEvent(row_event.RowEvent):
    """Row create event - Logical_Switch_Port 'up' = False

    On connection, we get a dump of all ports, so if there is a neutron
    port that is up that has since been deactivated, we'll catch it here.
    This event will not be generated for new ports getting created.
    """
    def __init__(self, driver):
        self.driver = driver
        table = 'Logical_Switch_Port'
        events = (self.ROW_CREATE,)
        super(LogicalSwitchPortCreateDownEvent, self).__init__(
            events, table, (('up', '=', False),))
        self.event_name = 'LogicalSwitchPortCreateDownEvent'

    def run(self, event, row, old):
        self.driver.set_port_status_down(row.name)


class LogicalSwitchPortUpdateUpEvent(row_event.RowEvent):
    """Row update event - Logical_Switch_Port 'up' going from False to True

    This happens when the VM goes up.
    New value of Logical_Switch_Port 'up' will be True and the old value will
    be False.
    """
    def __init__(self, driver):
        self.driver = driver
        table = 'Logical_Switch_Port'
        events = (self.ROW_UPDATE,)
        super(LogicalSwitchPortUpdateUpEvent, self).__init__(
            events, table, (('up', '=', True),),
            old_conditions=(('up', '=', False),))
        self.event_name = 'LogicalSwitchPortUpdateUpEvent'

    def run(self, event, row, old):
        self.driver.set_port_status_up(row.name)


class LogicalSwitchPortUpdateDownEvent(row_event.RowEvent):
    """Row update event - Logical_Switch_Port 'up' going from True to False

    This happens when the VM goes down.
    New value of Logical_Switch_Port 'up' will be False and the old value will
    be True.
    """
    def __init__(self, driver):
        self.driver = driver
        table = 'Logical_Switch_Port'
        events = (self.ROW_UPDATE,)
        super(LogicalSwitchPortUpdateDownEvent, self).__init__(
            events, table, (('up', '=', False),),
            old_conditions=(('up', '=', True),))
        self.event_name = 'LogicalSwitchPortUpdateDownEvent'

    def run(self, event, row, old):
        self.driver.set_port_status_down(row.name)


class FIPAddDeleteEvent(row_event.RowEvent):
    """Row event - NAT 'dnat_and_snat' entry added or deleted

    This happens when a FIP is created or removed.
    """
    def __init__(self, driver):
        self.driver = driver
        table = 'NAT'
        events = (self.ROW_CREATE, self.ROW_DELETE)
        super(FIPAddDeleteEvent, self).__init__(
            events, table, (('type', '=', 'dnat_and_snat'),))
        self.event_name = 'FIPAddDeleteEvent'

    def run(self, event, row, old):
        # When a FIP is added or deleted, we will delete all entries in the
        # MAC_Binding table of SB OVSDB corresponding to that IP Address.
        # TODO(dalvarez): Remove this workaround once fixed in core OVN:
        # https://mail.openvswitch.org/pipermail/ovs-discuss/2018-October/047604.html
        self.driver.delete_mac_binding_entries(row.external_ip)


class OvnDbNotifyHandler(event.RowEventHandler):
    def __init__(self, driver):
        super(OvnDbNotifyHandler, self).__init__()
        self.driver = driver


class BaseOvnIdl(connection.OvsdbIdl):

    def __init__(self, remote, schema):
        self.notify_handler = event.RowEventHandler()
        super(BaseOvnIdl, self).__init__(remote, schema)

    @classmethod
    def from_server(cls, connection_string, schema_name):
        _check_and_set_ssl_files(schema_name)
        helper = idlutils.get_schema_helper(connection_string, schema_name)
        helper.register_all()
        return cls(connection_string, helper)

    def notify(self, event, row, updates=None):
        self.notify_handler.notify(event, row, updates)


class BaseOvnSbIdl(connection.OvsdbIdl):
    @classmethod
    def from_server(cls, connection_string, schema_name):
        _check_and_set_ssl_files(schema_name)
        helper = idlutils.get_schema_helper(connection_string, schema_name)
        helper.register_table('Chassis')
        helper.register_table('Encap')
        helper.register_table('Port_Binding')
        helper.register_table('Datapath_Binding')
        return cls(connection_string, helper)


class OvnIdl(BaseOvnIdl):

    def __init__(self, driver, remote, schema):
        super(OvnIdl, self).__init__(remote, schema)
        self.driver = driver
        self.notify_handler = OvnDbNotifyHandler(driver)
        # ovsdb lock name to acquire.
        # This event lock is used to handle the notify events sent by idl.Idl
        # idl.Idl will call notify function for the "update" rpc method it
        # receives from the ovsdb-server.
        # This event lock is required for the following reasons
        #  - If there are multiple neutron servers running, OvnWorkers of
        #    these neutron servers would receive the notify events from
        #    idl.Idl
        #
        #  - we do not want all the neutron servers to handle these events
        #
        #  - only the neutron server which has the lock will handle the
        #    notify events.
        #
        #  - In case the neutron server which owns this lock goes down,
        #    ovsdb server would assign the lock to one of the other neutron
        #    servers.
        self.event_lock_name = "neutron_ovn_event_lock"

    def notify(self, event, row, updates=None):
        # Do not handle the notification if the event lock is requested,
        # but not granted by the ovsdb-server.
        if self.is_lock_contended:
            return
        self.notify_handler.notify(event, row, updates)

    @abc.abstractmethod
    def post_connect(self):
        """Should be called after the idl has been initialized"""


class OvnIdlDistributedLock(BaseOvnIdl):

    def __init__(self, driver, remote, schema):
        super(OvnIdlDistributedLock, self).__init__(remote, schema)
        self.driver = driver
        self.notify_handler = OvnDbNotifyHandler(driver)
        self._node_uuid = self.driver.node_uuid
        self._hash_ring = hash_ring_manager.HashRingManager(
            self.driver.hash_ring_group)
        self._last_touch = None

    def notify(self, event, row, updates=None):
        try:
            target_node = self._hash_ring.get_node(str(row.uuid))
        except exceptions.HashRingIsEmpty as e:
            LOG.error('HashRing is empty, error: %s', e)
            return

        if target_node != self._node_uuid:
            return

        # If the worker hasn't been health checked by the maintenance
        # thread (see bug #1834498), indicate that it's alive here
        time_now = timeutils.utcnow()
        touch_timeout = time_now - datetime.timedelta(
            seconds=ovn_const.HASH_RING_TOUCH_INTERVAL)
        if not self._last_touch or touch_timeout >= self._last_touch:
            # NOTE(lucasagomes): Guard the db operation with an exception
            # handler. If heartbeating fails for whatever reason, log
            # the error and continue with processing the event
            try:
                db_hash_ring.touch_node(self._node_uuid)
                self._last_touch = time_now
            except Exception:
                LOG.exception('Hash Ring node %s failed to heartbeat',
                              self._node_uuid)

        LOG.debug('Hash Ring: Node %(node)s (host: %(hostname)s) '
                  'handling event "%(event)s" for row %(row)s '
                  '(table: %(table)s)',
                  {'node': self._node_uuid, 'hostname': CONF.host,
                   'event': event, 'row': row.uuid, 'table': row._table.name})
        self.notify_handler.notify(event, row, updates)

    @abc.abstractmethod
    def post_connect(self):
        """Should be called after the idl has been initialized"""


class OvnNbIdl(OvnIdlDistributedLock):

    def __init__(self, driver, remote, schema):
        super(OvnNbIdl, self).__init__(driver, remote, schema)
        self._lsp_update_up_event = LogicalSwitchPortUpdateUpEvent(driver)
        self._lsp_update_down_event = LogicalSwitchPortUpdateDownEvent(driver)
        self._lsp_create_up_event = LogicalSwitchPortCreateUpEvent(driver)
        self._lsp_create_down_event = LogicalSwitchPortCreateDownEvent(driver)
        self._fip_create_delete_event = FIPAddDeleteEvent(driver)

        self.notify_handler.watch_events([self._lsp_create_up_event,
                                          self._lsp_create_down_event,
                                          self._lsp_update_up_event,
                                          self._lsp_update_down_event,
                                          self._fip_create_delete_event])

    @classmethod
    def from_server(cls, connection_string, schema_name, driver):

        _check_and_set_ssl_files(schema_name)
        helper = idlutils.get_schema_helper(connection_string, schema_name)
        helper.register_all()
        return cls(driver, connection_string, helper)

    def unwatch_logical_switch_port_create_events(self):
        """Unwatch the logical switch port create events.

        When the ovs idl client connects to the ovsdb-server, it gets
        a dump of all logical switch ports as events and we need to process
        them at start up.
        After the startup, there is no need to watch these events.
        So unwatch these events.
        """
        self.notify_handler.unwatch_events([self._lsp_create_up_event,
                                            self._lsp_create_down_event])
        self._lsp_create_up_event = None
        self._lsp_create_down_event = None

    def post_connect(self):
        self.unwatch_logical_switch_port_create_events()


class OvnSbIdl(OvnIdlDistributedLock):

    @classmethod
    def from_server(cls, connection_string, schema_name, driver):
        _check_and_set_ssl_files(schema_name)
        helper = idlutils.get_schema_helper(connection_string, schema_name)
        helper.register_table('Chassis')
        helper.register_table('Encap')
        helper.register_table('Port_Binding')
        helper.register_table('Datapath_Binding')
        helper.register_table('MAC_Binding')
        return cls(driver, connection_string, helper)

    def post_connect(self):
        """Watch Chassis events.

        When the ovs idl client connects to the ovsdb-server, it gets
        a dump of all Chassis create event. We don't need to process them
        because there will be sync up at startup. After that, we will watch
        the events to make notify work.
        """
        self._chassis_event = ChassisEvent(self.driver)
        self._portbinding_event = PortBindingChassisEvent(self.driver)
        self.notify_handler.watch_events(
            [self._chassis_event, self._portbinding_event,
             PortBindingChassisUpdateEvent(self.driver)])


def _check_and_set_ssl_files(schema_name):
    if schema_name == 'OVN_Southbound':
        priv_key_file = ovn_config.get_ovn_sb_private_key()
        cert_file = ovn_config.get_ovn_sb_certificate()
        ca_cert_file = ovn_config.get_ovn_sb_ca_cert()
    else:
        priv_key_file = ovn_config.get_ovn_nb_private_key()
        cert_file = ovn_config.get_ovn_nb_certificate()
        ca_cert_file = ovn_config.get_ovn_nb_ca_cert()

    if priv_key_file:
        Stream.ssl_set_private_key_file(priv_key_file)

    if cert_file:
        Stream.ssl_set_certificate_file(cert_file)

    if ca_cert_file:
        Stream.ssl_set_ca_cert_file(ca_cert_file)

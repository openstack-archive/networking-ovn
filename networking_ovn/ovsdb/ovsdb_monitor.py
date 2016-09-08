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

import atexit
from eventlet import greenthread
import retrying
from six.moves import queue
import threading

from oslo_log import log
from ovs.db import idl
from ovs import poller

from networking_ovn._i18n import _LE
from networking_ovn.common import config as ovn_config
from networking_ovn.ovsdb import row_event
from neutron.agent.ovsdb.native import connection
from neutron.agent.ovsdb.native import idlutils
from neutron.common import config
from neutron.common import utils as n_utils
from neutron import manager
from neutron.plugins.common import constants as plugin_constants
from neutron import worker

LOG = log.getLogger(__name__)


class ChassisEvent(row_event.RowEvent):
    """Chassis create update delete event."""

    def __init__(self, driver):
        self.driver = driver
        self.l3_plugin = manager.NeutronManager.get_service_plugins().get(
            plugin_constants.L3_ROUTER_NAT)
        table = 'Chassis'
        events = (self.ROW_CREATE, self.ROW_UPDATE, self.ROW_DELETE)
        super(ChassisEvent, self).__init__(events, table, None)
        self.event_name = 'ChassisEvent'

    def run(self, event, row, old):
        host = row.hostname
        phy_nets = []
        if event != self.ROW_DELETE:
            bridge_mappings = row.external_ids.get('ovn-bridge-mappings', '')
            mapping_dict = n_utils.parse_mappings(bridge_mappings.split(','))
            phy_nets = list(mapping_dict)

        self.driver.update_segment_host_mapping(host, phy_nets)
        if ovn_config.is_ovn_l3():
            self.l3_plugin.schedule_unhosted_routers()


class LogicalSwitchPortCreateUpEvent(row_event.RowEvent):
    """Row create event - Logical_Switch_Port 'up' = True.

    On connection, we get a dump of all ports, so if there is a neutron
    port that is down that has since been activated, we'll catch it here.
    This event will not be generated for new ports getting created.
    """

    def __init__(self, driver):
        self.driver = driver
        table = 'Logical_Switch_Port'
        events = (self.ROW_CREATE)
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
        events = (self.ROW_CREATE)
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
        events = (self.ROW_UPDATE)
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
        events = (self.ROW_UPDATE)
        super(LogicalSwitchPortUpdateDownEvent, self).__init__(
            events, table, (('up', '=', False),),
            old_conditions=(('up', '=', True),))
        self.event_name = 'LogicalSwitchPortUpdateDownEvent'

    def run(self, event, row, old):
        self.driver.set_port_status_down(row.name)


class OvnDbNotifyHandler(object):

    STOP_EVENT = ("STOP", None, None, None)

    def __init__(self, driver):
        self.driver = driver
        self.__watched_events = set()
        self.__lock = threading.Lock()
        self.notifications = queue.Queue()
        self.notify_thread = greenthread.spawn_n(self.notify_loop)
        atexit.register(self.shutdown)

    def matching_events(self, event, row, updates):
        with self.__lock:
            return tuple(t for t in self.__watched_events
                         if t.matches(event, row, updates))

    def watch_event(self, event):
        with self.__lock:
            self.__watched_events.add(event)

    def watch_events(self, events):
        with self.__lock:
            for event in events:
                self.__watched_events.add(event)

    def unwatch_event(self, event):
        with self.__lock:
            try:
                self.__watched_events.remove(event)
            except KeyError:
                # For ONETIME events, they should normally clear on their own
                pass

    def unwatch_events(self, events):
        with self.__lock:
            for event in events:
                try:
                    self.__watched_events.remove(event)
                except KeyError:
                    # For ONETIME events, they should normally clear on
                    # their own
                    pass

    def shutdown(self):
        self.notifications.put(OvnDbNotifyHandler.STOP_EVENT)

    def notify_loop(self):
        while True:
            try:
                match, event, row, updates = self.notifications.get()
                if (not isinstance(match, row_event.RowEvent) and
                        (match, event, row, updates) == (
                            OvnDbNotifyHandler.STOP_EVENT)):
                    self.notifications.task_done()
                    break
                match.run(event, row, updates)
                if match.ONETIME:
                    self.unwatch_event(match)
                self.notifications.task_done()
            except Exception:
                # If any unexpected exception happens we don't want the
                # notify_loop to exit.
                LOG.exception(_LE('Unexpected exception in notify_loop'))

    def notify(self, event, row, updates=None):
        matching = self.matching_events(
            event, row, updates)
        for match in matching:
            self.notifications.put((match, event, row, updates))


class OvnIdl(idl.Idl):

    def __init__(self, driver, remote, schema):
        super(OvnIdl, self).__init__(remote, schema)

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
        if (self.is_lock_contended and not self.has_lock):
            LOG.debug("Don't have the event lock to handle the notify"
                      " events. Ignoring the event : %s", event)
            return
        LOG.debug("Have the event lock to handle the notify events")
        self.notify_handler.notify(event, row, updates)

    def post_initialize(self, driver):
        """Should be called after the idl has been initialized"""
        pass


class OvnNbIdl(OvnIdl):

    def __init__(self, driver, remote, schema):
        super(OvnNbIdl, self).__init__(driver, remote, schema)
        self._lsp_update_up_event = LogicalSwitchPortUpdateUpEvent(driver)
        self._lsp_update_down_event = LogicalSwitchPortUpdateDownEvent(driver)
        self._lsp_create_up_event = LogicalSwitchPortCreateUpEvent(driver)
        self._lsp_create_down_event = LogicalSwitchPortCreateDownEvent(driver)

        self.notify_handler.watch_events([self._lsp_create_up_event,
                                          self._lsp_create_down_event,
                                          self._lsp_update_up_event,
                                          self._lsp_update_down_event])

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

    def post_initialize(self, driver):
        self.unwatch_logical_switch_port_create_events()


class OvnSbIdl(OvnIdl):

    def post_initialize(self, driver):
        """Watch Chassis events.

        When the ovs idl client connects to the ovsdb-server, it gets
        a dump of all Chassis create event. We don't need to process them
        because there will be sync up at startup. After that, we will watch
        the events to make notify work.
        """
        self._chassis_event = ChassisEvent(driver)
        self.notify_handler.watch_events([self._chassis_event])


class OvnConnection(connection.Connection):

    def get_ovn_idl_cls(self):
        """Get the ovn idl class

        The connection might be for OVN_Southbound or OVN_Northbound. Return
        different idl class according to the schema_name of connection.
        """
        if self.schema_name == 'OVN_Southbound':
            return OvnSbIdl

        # Return the ovn nb idl for the backward compatibility
        return OvnNbIdl

    def start(self, driver, table_name_list=None):
        # The implementation of this function is same as the base class start()
        # except that OvnIdl object is created instead of idl.Idl and the
        # enable_connection_uri() helper isn't called (since ovs-vsctl won't
        # exist on the controller node when using the reference architecture).
        with self.lock:
            if self.idl is not None:
                return

            try:
                helper = idlutils.get_schema_helper(self.connection,
                                                    self.schema_name)
            except Exception:
                # There is a small window for a race, so retry up to a second
                @retrying.retry(wait_exponential_multiplier=10,
                                stop_max_delay=1000)
                def do_get_schema_helper():
                    return idlutils.get_schema_helper(self.connection,
                                                      self.schema_name)
                helper = do_get_schema_helper()

            if table_name_list is None:
                helper.register_all()
            else:
                for table_name in table_name_list:
                    helper.register_table(table_name)

            idl_cls = self.get_ovn_idl_cls()
            self.idl = idl_cls(driver, self.connection, helper)
            self.idl.set_lock(self.idl.event_lock_name)
            idlutils.wait_for_change(self.idl, self.timeout)
            self.idl.post_initialize(driver)
            self.poller = poller.Poller()
            self.thread = threading.Thread(target=self.run)
            self.thread.setDaemon(True)
            self.thread.start()


class OvnWorker(worker.NeutronWorker):
    def start(self):
        super(OvnWorker, self).start()
        # NOTE(twilson) The super class will trigger the post_fork_initialize
        # in the driver, which starts the connection/IDL notify loop which
        # keeps the process from exiting

    def stop(self):
        """Stop service."""
        # TODO(numans)

    def wait(self):
        """Wait for service to complete."""
        # TODO(numans)

    @staticmethod
    def reset():
        config.reset_service()

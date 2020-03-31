#    Copyright 2018 Red Hat, Inc. All rights reserved.
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
import copy
import re
import threading

import netaddr
from neutronclient.common import exceptions as n_exc
from octavia_lib.api.drivers import data_models as o_datamodels
from octavia_lib.api.drivers import driver_lib as o_driver_lib
from octavia_lib.api.drivers import exceptions as driver_exceptions
from octavia_lib.api.drivers import provider_base as driver_base
from octavia_lib.common import constants
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
from ovs.stream import Stream
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import event as row_event
from ovsdbapp.backend.ovs_idl import idlutils
from six.moves import queue as Queue
from stevedore import driver
import tenacity

from networking_ovn._i18n import _
from networking_ovn.common import config as ovn_cfg
from networking_ovn.common import constants as ovn_const
from networking_ovn.common import utils as ovn_utils
from networking_ovn.ovsdb import impl_idl_ovn
from networking_ovn.ovsdb import ovsdb_monitor

CONF = cfg.CONF  # Gets Octavia Conf as it runs under o-api domain

LOG = logging.getLogger(__name__)

REQ_TYPE_LB_CREATE = 'lb_create'
REQ_TYPE_LB_DELETE = 'lb_delete'
REQ_TYPE_LB_FAILOVER = 'lb_failover'
REQ_TYPE_LB_UPDATE = 'lb_update'
REQ_TYPE_LISTENER_CREATE = 'listener_create'
REQ_TYPE_LISTENER_DELETE = 'listener_delete'
REQ_TYPE_LISTENER_UPDATE = 'listener_update'
REQ_TYPE_POOL_CREATE = 'pool_create'
REQ_TYPE_POOL_DELETE = 'pool_delete'
REQ_TYPE_POOL_UPDATE = 'pool_update'
REQ_TYPE_MEMBER_CREATE = 'member_create'
REQ_TYPE_MEMBER_DELETE = 'member_delete'
REQ_TYPE_MEMBER_UPDATE = 'member_update'
REQ_TYPE_LB_CREATE_LRP_ASSOC = 'lb_create_lrp_assoc'
REQ_TYPE_LB_DELETE_LRP_ASSOC = 'lb_delete_lrp_assoc'
REQ_TYPE_HANDLE_VIP_FIP = 'handle_vip_fip'
REQ_TYPE_HANDLE_MEMBER_DVR = 'handle_member_dvr'

REQ_TYPE_EXIT = 'exit'

REQ_INFO_ACTION_ASSOCIATE = 'associate'
REQ_INFO_ACTION_DISASSOCIATE = 'disassociate'
REQ_INFO_MEMBER_ADDED = 'member_added'
REQ_INFO_MEMBER_DELETED = 'member_deleted'

DISABLED_RESOURCE_SUFFIX = 'D'

OVN_NATIVE_LB_PROTOCOLS = [constants.PROTOCOL_TCP,
                           constants.PROTOCOL_UDP, ]
OVN_NATIVE_LB_ALGORITHMS = [constants.LB_ALGORITHM_SOURCE_IP_PORT, ]
EXCEPTION_MSG = "Exception occurred during %s"
OVN_EVENT_LOCK_NAME = "neutron_ovn_octavia_event_lock"


class IPVersionsMixingNotSupportedError(
        driver_exceptions.UnsupportedOptionError):
    user_fault_string = _('OVN provider does not support mixing IPv4/IPv6 '
                          'configuration within the same Load Balancer.')
    operator_fault_string = user_fault_string


def get_network_driver():
    try:
        CONF.import_group('controller_worker', 'octavia.common.config')
        name = CONF.controller_worker.network_driver
    except ImportError:
        # TODO(mjozefcz): Remove this when the config option will
        # land in octavia-lib.
        name = 'network_noop_driver'
    return driver.DriverManager(
        namespace='octavia.network.drivers',
        name=name,
        invoke_on_load=True
    ).driver


class LogicalRouterPortEvent(row_event.RowEvent):

    driver = None

    def __init__(self, driver):
        table = 'Logical_Router_Port'
        events = (self.ROW_CREATE, self.ROW_DELETE)
        super(LogicalRouterPortEvent, self).__init__(
            events, table, None)
        self.event_name = 'LogicalRouterPortEvent'
        self.driver = driver

    def run(self, event, row, old):
        LOG.debug('LogicalRouterPortEvent logged, '
                  '%(event)s, %(row)s',
                  {'event': event,
                   'row': row})
        if not self.driver or row.gateway_chassis:
            return
        if event == self.ROW_CREATE:
            self.driver.lb_create_lrp_assoc_handler(row)
        elif event == self.ROW_DELETE:
            self.driver.lb_delete_lrp_assoc_handler(row)


class LogicalSwitchPortUpdateEvent(row_event.RowEvent):

    driver = None

    def __init__(self, driver):
        table = 'Logical_Switch_Port'
        events = (self.ROW_UPDATE,)
        super(LogicalSwitchPortUpdateEvent, self).__init__(
            events, table, None)
        self.event_name = 'LogicalSwitchPortUpdateEvent'
        self.driver = driver

    def run(self, event, row, old):
        # Get the neutron:port_name from external_ids and check if
        # it's a vip port or not.
        port_name = row.external_ids.get(
            ovn_const.OVN_PORT_NAME_EXT_ID_KEY, '')
        if self.driver and port_name.startswith(ovn_const.LB_VIP_PORT_PREFIX):
            # Handle port update only for vip ports created by
            # this driver.
            self.driver.vip_port_update_handler(row)


class OvnNbIdlForLb(ovsdb_monitor.OvnIdl):
    SCHEMA = "OVN_Northbound"
    TABLES = ('Logical_Switch', 'Load_Balancer', 'Logical_Router',
              'Logical_Switch_Port', 'Logical_Router_Port',
              'Gateway_Chassis', 'NAT')

    def __init__(self, event_lock_name=None):
        self.conn_string = ovn_cfg.get_ovn_nb_connection()
        ovsdb_monitor._check_and_set_ssl_files(self.SCHEMA)
        helper = self._get_ovsdb_helper(self.conn_string)
        for table in OvnNbIdlForLb.TABLES:
            helper.register_table(table)
        super(OvnNbIdlForLb, self).__init__(
            driver=None, remote=self.conn_string, schema=helper)
        self.event_lock_name = event_lock_name
        if self.event_lock_name:
            self.set_lock(self.event_lock_name)
        atexit.register(self.stop)

    @tenacity.retry(
        wait=tenacity.wait_exponential(max=180),
        reraise=True)
    def _get_ovsdb_helper(self, connection_string):
        return idlutils.get_schema_helper(connection_string, self.SCHEMA)

    def start(self):
        self.conn = connection.Connection(
            self, timeout=ovn_cfg.get_ovn_ovsdb_timeout())
        return impl_idl_ovn.OvsdbNbOvnIdl(self.conn)

    def stop(self):
        # Close the running connection if it has been initalized
        if ((hasattr(self, 'conn') and not
             self.conn.stop(timeout=ovn_cfg.get_ovn_ovsdb_timeout()))):
            LOG.debug("Connection terminated to OvnNb "
                      "but a thread is still alive")
        # complete the shutdown for the event handler
        self.notify_handler.shutdown()
        # Close the idl session
        self.close()


class OvnProviderHelper(object):

    ovn_nbdb_api_for_events = None
    ovn_nb_idl_for_events = None
    ovn_nbdb_api = None

    def __init__(self):
        self.requests = Queue.Queue()
        self.helper_thread = threading.Thread(target=self.request_handler)
        self.helper_thread.daemon = True
        atexit.register(self.shutdown)
        self._octavia_driver_lib = o_driver_lib.DriverLibrary()
        self._check_and_set_ssl_files()
        self._init_lb_actions()
        self.events = [LogicalRouterPortEvent(self),
                       LogicalSwitchPortUpdateEvent(self)]
        self.start()

    def _init_lb_actions(self):
        self._lb_request_func_maps = {
            REQ_TYPE_LB_CREATE: self.lb_create,
            REQ_TYPE_LB_DELETE: self.lb_delete,
            REQ_TYPE_LB_UPDATE: self.lb_update,
            REQ_TYPE_LB_FAILOVER: self.lb_failover,
            REQ_TYPE_LISTENER_CREATE: self.listener_create,
            REQ_TYPE_LISTENER_DELETE: self.listener_delete,
            REQ_TYPE_LISTENER_UPDATE: self.listener_update,
            REQ_TYPE_POOL_CREATE: self.pool_create,
            REQ_TYPE_POOL_DELETE: self.pool_delete,
            REQ_TYPE_POOL_UPDATE: self.pool_update,
            REQ_TYPE_MEMBER_CREATE: self.member_create,
            REQ_TYPE_MEMBER_DELETE: self.member_delete,
            REQ_TYPE_MEMBER_UPDATE: self.member_update,
            REQ_TYPE_LB_CREATE_LRP_ASSOC: self.lb_create_lrp_assoc,
            REQ_TYPE_LB_DELETE_LRP_ASSOC: self.lb_delete_lrp_assoc,
            REQ_TYPE_HANDLE_VIP_FIP: self.handle_vip_fip,
            REQ_TYPE_HANDLE_MEMBER_DVR: self.handle_member_dvr,
        }

    @staticmethod
    def _is_lb_empty(external_ids):
        """Check if there is no pool or listener defined."""
        return not any([k.startswith('listener') or k.startswith('pool')
                        for k in external_ids])

    @staticmethod
    def _delete_disabled_from_status(status):
        d_regex = ':%s$' % DISABLED_RESOURCE_SUFFIX
        return {
            k: [{c: re.sub(d_regex, '', d) for c, d in i.items()}
                for i in v]
            for k, v in status.items()}

    def _check_and_set_ssl_files(self):
        # TODO(reedip): Make ovsdb_monitor's _check_and_set_ssl_files() public
        # This is a copy of ovsdb_monitor._check_and_set_ssl_files
        if OvnProviderHelper.ovn_nbdb_api:
            return
        priv_key_file = ovn_cfg.get_ovn_nb_private_key()
        cert_file = ovn_cfg.get_ovn_nb_certificate()
        ca_cert_file = ovn_cfg.get_ovn_nb_ca_cert()
        if priv_key_file:
            Stream.ssl_set_private_key_file(priv_key_file)

        if cert_file:
            Stream.ssl_set_certificate_file(cert_file)

        if ca_cert_file:
            Stream.ssl_set_ca_cert_file(ca_cert_file)

    def start(self):
        # NOTE(mjozefcz): This API is only for handling octavia API requests.
        if not OvnProviderHelper.ovn_nbdb_api:
            OvnProviderHelper.ovn_nbdb_api = OvnNbIdlForLb().start()

        # NOTE(mjozefcz): This API is only for handling OVSDB events!
        if not OvnProviderHelper.ovn_nbdb_api_for_events:
            OvnProviderHelper.ovn_nb_idl_for_events = OvnNbIdlForLb(
                event_lock_name=OVN_EVENT_LOCK_NAME)
            (OvnProviderHelper.ovn_nb_idl_for_events.notify_handler.
             watch_events(self.events))
            OvnProviderHelper.ovn_nbdb_api_for_events = (
                OvnProviderHelper.ovn_nb_idl_for_events.start())
        self.helper_thread.start()

    def shutdown(self):
        self.requests.put({'type': REQ_TYPE_EXIT})
        self.helper_thread.join()
        self.ovn_nb_idl_for_events.notify_handler.unwatch_events(self.events)

    @staticmethod
    def _map_val(row, col, key):
        # If the row doesnt exist, RowNotFound is raised by the _map_val
        # and is expected to be caught by the caller.
        try:
            return getattr(row, col)[key]
        except KeyError:
            raise idlutils.RowNotFound(table=row._table.name,
                                       col=col, match=key)

    def _get_nw_router_info_on_interface_event(self, lrp):
        """Get the Router and Network information on an interface event

        This function is called when a new interface between a router and
        a network is added or deleted.
        Input: Logical Router Port row which is coming from
               LogicalRouterPortEvent.
        Output: A row from router table and network table matching the router
                and network for which the event was generated.
        Exception: RowNotFound exception can be generated.
        """
        router = self.ovn_nbdb_api.lookup(
            'Logical_Router', ovn_utils.ovn_name(self._map_val(
                lrp, 'external_ids', ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY)))
        network = self.ovn_nbdb_api.lookup(
            'Logical_Switch',
            self._map_val(lrp, 'external_ids',
                          ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY))
        return router, network

    def _clean_lb_if_empty(self, ovn_lb, lb_id, external_ids):
        commands = []
        lb_to_delete = False
        if OvnProviderHelper._is_lb_empty(external_ids):
            # Verify if its only OVN LB defined. If so - leave with
            # undefined protocol. If there is different for other protocol
            # remove this one.
            try:
                defined_ovn_lbs = self._find_ovn_lbs(lb_id)
            except idlutils.RowNotFound:
                defined_ovn_lbs = []
            if len(defined_ovn_lbs) == 1:
                commands.append(
                    self.ovn_nbdb_api.db_set(
                        'Load_Balancer', ovn_lb.uuid, ('protocol', [])))
            elif len(defined_ovn_lbs) > 1:
                # Delete the lb.
                commands.append(self.ovn_nbdb_api.lb_del(ovn_lb.uuid))
                lb_to_delete = True
        return (commands, lb_to_delete)

    def lb_delete_lrp_assoc_handler(self, row):
        try:
            router, network = self._get_nw_router_info_on_interface_event(row)
        except idlutils.RowNotFound:
            LOG.debug("Router or network information not found")
            return
        request_info = {'network': network,
                        'router': router}
        self.add_request({'type': REQ_TYPE_LB_DELETE_LRP_ASSOC,
                          'info': request_info})

    def lb_delete_lrp_assoc(self, info):
        # TODO(reedip): When OVS>=2.12, LB can be deleted without removing
        # Network and Router references as pushed in the patch
        # https://github.com/openvswitch/ovs/commit
        # /612f80fa8ebf88dad2e204364c6c02b451dca36c
        commands = []
        network = info['network']
        router = info['router']

        # Find all loadbalancers which have a reference with the network
        nw_lb = self._find_lb_in_ls(network=network)
        # Find all loadbalancers which have a reference with the router
        r_lb = set(router.load_balancer) - nw_lb
        # Delete all LB on N/W from Router
        for nlb in nw_lb:
            commands.extend(self._update_lb_to_lr_association(nlb, router,
                                                              delete=True))
        # Delete all LB on Router from N/W
        for rlb in r_lb:
            commands.append(self.ovn_nbdb_api.ls_lb_del(
                network.uuid, rlb.uuid))
        if commands:
            self._execute_commands(commands)

    def lb_create_lrp_assoc_handler(self, row):
        try:
            router, network = self._get_nw_router_info_on_interface_event(row)
        except idlutils.RowNotFound:
            LOG.debug("Router or network information not found")
            return
        request_info = {'network': network,
                        'router': router}
        self.add_request({'type': REQ_TYPE_LB_CREATE_LRP_ASSOC,
                          'info': request_info})

    def lb_create_lrp_assoc(self, info):
        commands = []

        router_lb = set(info['router'].load_balancer)
        network_lb = set(info['network'].load_balancer)
        # Add only those lb to routers which are unique to the network
        for lb in (network_lb - router_lb):
            commands.extend(self._update_lb_to_lr_association(
                lb, info['router']))

        # Add those lb to the network which are unique to the router
        for lb in (router_lb - network_lb):
            commands.append(self.ovn_nbdb_api.ls_lb_add(
                            info['network'].uuid, lb.uuid, may_exist=True))
        if commands:
            self._execute_commands(commands)

    def vip_port_update_handler(self, vip_lp):
        """Handler for VirtualIP port updates.

        If a floating ip is associated to a vip port, then networking-ovn sets
        the fip in the external_ids column of the logical port as:
        Logical_Switch_Port.external_ids:port_fip = <FIP>.
        Then, in the Load_Balancer table for the vip, networking-ovn creates
        another vip entry for the FIP.
        If a floating ip is disassociated from the vip, then it deletes
        the vip entry for the FIP.
        """

        port_name = vip_lp.external_ids.get(ovn_const.OVN_PORT_NAME_EXT_ID_KEY)
        lb_id = port_name[len(ovn_const.LB_VIP_PORT_PREFIX):]
        try:
            ovn_lbs = self._find_ovn_lbs(lb_id)
        except idlutils.RowNotFound:
            LOG.debug("Loadbalancer %s not found!", lb_id)
            return

        # Loop over all defined LBs with given ID, because it is possible
        # than there is more than one (for more than 1 L4 protocol).
        for lb in ovn_lbs:
            fip = vip_lp.external_ids.get(ovn_const.OVN_PORT_FIP_EXT_ID_KEY)
            lb_vip_fip = lb.external_ids.get(ovn_const.LB_EXT_IDS_VIP_FIP_KEY)
            request_info = {'ovn_lb': lb,
                            'vip_fip': fip}
            if fip and fip != lb_vip_fip:
                request_info['action'] = REQ_INFO_ACTION_ASSOCIATE
            elif fip is None and fip != lb_vip_fip:
                request_info['action'] = REQ_INFO_ACTION_DISASSOCIATE
            else:
                continue
            self.add_request({'type': REQ_TYPE_HANDLE_VIP_FIP,
                              'info': request_info})

    def _find_lb_in_ls(self, network):
        """Find LB associated to a Network using Network information

        This function retrieves those loadbalancers whose ls_ref
        column in the OVN northbound database's load_balancer table
        has the network's name. Though different networks can be
        associated with a loadbalancer, but ls_ref of a loadbalancer
        points to the network where it was actually created, and this
        function tries to retrieve all those loadbalancers created on this
        network.
        Input : row of type Logical_Switch
        Output: set of rows of type Load_Balancer or empty set
        """
        return {lb for lb in network.load_balancer
                if network.name in lb.external_ids.get(
                    ovn_const.LB_EXT_IDS_LS_REFS_KEY,
                    [])}

    def _find_lb_in_table(self, lb, table):
        return [item for item in self.ovn_nbdb_api.tables[table].rows.values()
                if lb in item.load_balancer]

    def request_handler(self):
        while True:
            try:
                request = self.requests.get()
                request_type = request['type']
                if request_type == REQ_TYPE_EXIT:
                    break

                request_handler = self._lb_request_func_maps.get(request_type)
                if request_handler:
                    status = request_handler(request['info'])
                    if status:
                        self._update_status_to_octavia(status)
                self.requests.task_done()
            except Exception:
                # If any unexpected exception happens we don't want the
                # notify_loop to exit.
                LOG.exception('Unexpected exception in request_handler')

    def add_request(self, req):
        self.requests.put(req)

    def _update_status_to_octavia(self, status):
        try:
            status = OvnProviderHelper._delete_disabled_from_status(status)
            LOG.debug('Updating status to octavia: %s', status)
            self._octavia_driver_lib.update_loadbalancer_status(status)
        except driver_exceptions.UpdateStatusError as e:
            msg = ("Error while updating the load balancer "
                   "status: %s") % e.fault_string
            LOG.error(msg)
            raise driver_exceptions.UpdateStatusError(msg)

    def _find_ovn_lbs(self, lb_id, protocol=None):
        """Find the Loadbalancers in OVN with the given lb_id as its name

        This function searches for the LoadBalancers whose Name has the pattern
        passed in lb_id.
        @param lb_id: LoadBalancer ID provided by Octavia in its API
               request. Note that OVN saves the above ID in the 'name' column.
        @type lb_id: str
        @param protocol: Loadbalancer protocol.
        @type protocol: str or None if not defined.

        :returns: LoadBalancer row if protocol specified
                  or list of rows matching the lb_id.
        :raises:  RowNotFound can be generated if the LoadBalancer is not
                  found.
        """
        lbs = self.ovn_nbdb_api.db_find_rows(
            'Load_Balancer', ('name', '=', lb_id)).execute()
        if not protocol:
            if lbs:
                return lbs
            raise idlutils.RowNotFound(table='Load_Balancer',
                                       col='name', match=lb_id)
        # If there is only one LB without protocol defined, so
        # it is 'clean' LB record without any listener.
        if len(lbs) == 1 and not lbs[0].protocol:
            return lbs[0]
        # Search for other lbs.
        for lb in lbs:
            if lb.protocol[0].upper() == protocol.upper():
                return lb
        raise idlutils.RowNotFound(table='Load_Balancer',
                                   col='name', match=lb_id)

    def _get_or_create_ovn_lb(self, lb_id, protocol, admin_state_up):
        """Find or create ovn lb with given protocol

           Find the loadbalancer configured with given protocol or
           create required if not found
        """
        # Make sure that its lowercase - OVN NBDB stores lowercases
        # for this field.
        protocol = protocol.lower()
        ovn_lbs = self._find_ovn_lbs(lb_id)
        lbs_with_required_protocol = [
            ovn_lb for ovn_lb in ovn_lbs
            if protocol in ovn_lb.protocol]
        lbs_with_no_protocol = [ovn_lb for ovn_lb in ovn_lbs
                                if not ovn_lb.protocol]
        if lbs_with_required_protocol:
            # We found existing LB with required
            # protocol, just return it.
            return lbs_with_required_protocol[0]
        elif lbs_with_no_protocol:
            ovn_lb = lbs_with_no_protocol[0]
            # Set required protocol here.
            self.ovn_nbdb_api.db_set(
                'Load_Balancer', ovn_lb.uuid,
                ('protocol', protocol)).execute(check_error=True)
        else:
            # NOTE(mjozefcz): Looks like loadbalancer with given protocol
            # doesn't exist. Try to add it with required protocol
            # by copy the existing one data.
            lb_info = {
                'id': lb_id,
                'protocol': protocol,
                'vip_address': ovn_lbs[0].external_ids.get(
                    ovn_const.LB_EXT_IDS_VIP_KEY),
                'vip_port_id':
                    ovn_lbs[0].external_ids.get(
                        ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY),
                ovn_const.LB_EXT_IDS_LR_REF_KEY:
                    ovn_lbs[0].external_ids.get(
                        ovn_const.LB_EXT_IDS_LR_REF_KEY),
                ovn_const.LB_EXT_IDS_LS_REFS_KEY:
                    ovn_lbs[0].external_ids.get(
                        ovn_const.LB_EXT_IDS_LS_REFS_KEY),
                'admin_state_up': admin_state_up}
            # NOTE(mjozefcz): Handle vip_fip info if exists.
            vip_fip = ovn_lbs[0].external_ids.get(
                ovn_const.LB_EXT_IDS_VIP_FIP_KEY)
            if vip_fip:
                lb_info.update({ovn_const.LB_EXT_IDS_VIP_FIP_KEY: vip_fip})
            self.lb_create(lb_info, protocol=protocol)
        # Looks like we've just added new LB
        # or updated exising, empty one.
        return self._find_ovn_lbs(
            lb_id,
            protocol=protocol)

    def _find_ovn_lb_with_pool_key(self, pool_key):
        lbs = self.ovn_nbdb_api.db_list_rows(
            'Load_Balancer').execute(check_error=True)
        for lb in lbs:
            if pool_key in lb.external_ids:
                return lb

    def _find_ovn_lb_by_pool_id(self, pool_id):
        pool_key = self._get_pool_key(pool_id)
        ovn_lb = self._find_ovn_lb_with_pool_key(pool_key)
        if not ovn_lb:
            pool_key = self._get_pool_key(pool_id, is_enabled=False)
            ovn_lb = self._find_ovn_lb_with_pool_key(pool_key)
        return pool_key, ovn_lb

    def _execute_commands(self, commands):
        with self.ovn_nbdb_api.transaction(check_error=True) as txn:
            for command in commands:
                txn.add(command)

    def _update_lb_to_ls_association(self, ovn_lb, network_id=None,
                                     subnet_id=None, associate=True):
        """Update LB association with Logical Switch

           This function deals with updating the References of Logical Switch
           in LB and addition of LB to LS.
        """
        commands = []
        if not network_id and not subnet_id:
            return commands

        if network_id:
            ls_name = ovn_utils.ovn_name(network_id)
        else:
            network_driver = get_network_driver()
            try:
                subnet = network_driver.get_subnet(subnet_id)
                ls_name = ovn_utils.ovn_name(subnet.network_id)
            except n_exc.NotFound:
                LOG.warning('Subnet %s not found while trying to '
                            'fetch its data.', subnet_id)
                ls_name = None
                ovn_ls = None

        if ls_name:
            try:
                ovn_ls = self.ovn_nbdb_api.ls_get(ls_name).execute(
                    check_error=True)
            except idlutils.RowNotFound:
                LOG.warning("LogicalSwitch %s could not be found.",
                            ls_name)
                if associate:
                    LOG.warning('Cannot associate LB %(lb)s to '
                                'LS %(ls)s because LS row '
                                'not found in OVN NBDB. Exiting.',
                                {'ls': ls_name, 'lb': ovn_lb.name})
                    return commands
                ovn_ls = None

        ls_refs = ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_LS_REFS_KEY)
        if ls_refs:
            try:
                ls_refs = jsonutils.loads(ls_refs)
            except ValueError:
                ls_refs = {}
        else:
            ls_refs = {}

        if associate and ls_name:
            if ls_name in ls_refs:
                ref_ct = ls_refs[ls_name]
                ls_refs[ls_name] = ref_ct + 1
            else:
                ls_refs[ls_name] = 1
                if ovn_ls:
                    commands.append(self.ovn_nbdb_api.ls_lb_add(
                        ovn_ls.uuid, ovn_lb.uuid, may_exist=True))
        else:
            if ls_name not in ls_refs:
                # Nothing to be done.
                return commands

            ref_ct = ls_refs[ls_name]
            if ref_ct == 1:
                del ls_refs[ls_name]
                if ovn_ls:
                    commands.append(self.ovn_nbdb_api.ls_lb_del(
                        ovn_ls.uuid, ovn_lb.uuid, if_exists=True))
            else:
                ls_refs[ls_name] = ref_ct - 1

        ls_refs = {ovn_const.LB_EXT_IDS_LS_REFS_KEY: jsonutils.dumps(ls_refs)}
        commands.append(self.ovn_nbdb_api.db_set(
            'Load_Balancer', ovn_lb.uuid,
            ('external_ids', ls_refs)))

        return commands

    def _del_lb_to_lr_association(self, ovn_lb, ovn_lr, lr_ref):
        commands = []
        if lr_ref:
            try:
                lr_ref = [r for r in
                          [lr.strip() for lr in lr_ref.split(',')]
                          if r != ovn_lr.name]
            except ValueError:
                msg = ('The loadbalancer %(lb)s is not associated with '
                       'the router %(router)s' %
                       {'lb': ovn_lb.name,
                        'router': ovn_lr.name})
                LOG.warning(msg)
            if lr_ref:
                commands.append(
                    self.ovn_nbdb_api.db_set(
                        'Load_Balancer', ovn_lb.uuid,
                        ('external_ids',
                         {ovn_const.LB_EXT_IDS_LR_REF_KEY: ','.join(lr_ref)})))
            else:
                commands.append(
                    self.ovn_nbdb_api.db_remove(
                        'Load_Balancer', ovn_lb.uuid, 'external_ids',
                        (ovn_const.LB_EXT_IDS_LR_REF_KEY))
                )
            commands.append(
                self.ovn_nbdb_api.lr_lb_del(ovn_lr.uuid, ovn_lb.uuid,
                                            if_exists=True)
            )
        for net in self._find_ls_for_lr(ovn_lr):
            commands.append(self.ovn_nbdb_api.ls_lb_del(
                net, ovn_lb.uuid, if_exists=True))
        return commands

    def _add_lb_to_lr_association(self, ovn_lb, ovn_lr, lr_rf):
        commands = []
        commands.append(
            self.ovn_nbdb_api.lr_lb_add(ovn_lr.uuid, ovn_lb.uuid,
                                        may_exist=True)
        )
        for net in self._find_ls_for_lr(ovn_lr):
            commands.append(self.ovn_nbdb_api.ls_lb_add(
                net, ovn_lb.uuid, may_exist=True))

        if ovn_lr.name not in str(lr_rf):
            # Multiple routers in lr_rf are separated with ','
            if lr_rf:
                lr_rf = {ovn_const.LB_EXT_IDS_LR_REF_KEY:
                         "%s,%s" % (lr_rf, ovn_lr.name)}
            else:
                lr_rf = {ovn_const.LB_EXT_IDS_LR_REF_KEY: ovn_lr.name}
            commands.append(
                self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                         ('external_ids', lr_rf)))
        return commands

    def _update_lb_to_lr_association(self, ovn_lb, ovn_lr, delete=False):
        lr_ref = ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_LR_REF_KEY)
        if delete:
            return self._del_lb_to_lr_association(ovn_lb, ovn_lr, lr_ref)
        else:
            return self._add_lb_to_lr_association(ovn_lb, ovn_lr, lr_ref)

    def _find_ls_for_lr(self, router):
        netdriver = get_network_driver()
        ls = []
        for port in router.ports:
            if port.gateway_chassis:
                continue
            sids = port.external_ids.get(
                ovn_const.OVN_SUBNET_EXT_IDS_KEY, '').split(' ')
            for sid in sids:
                try:
                    ls.append(ovn_utils.ovn_name(
                        netdriver.get_subnet(sid).network_id))
                except n_exc.NotFound:
                    LOG.exception('Subnet %s not found while trying to '
                                  'fetch its data.', sid)
        return ls

    def _find_lr_of_ls(self, ovn_ls):
        lsp_router_port = None
        for port in ovn_ls.ports or []:
            if port.type == 'router':
                lsp_router_port = port
                break
        else:
            return

        lrp_name = lsp_router_port.options.get('router-port')
        if not lrp_name:
            return

        for lr in self.ovn_nbdb_api.tables['Logical_Router'].rows.values():
            for lrp in lr.ports:
                if lrp.name == lrp_name:
                    return lr
            # Handles networks with only gateway port in the router
            if ovn_utils.ovn_lrouter_port_name(
                    lr.external_ids.get("neutron:gw_port_id")) == lrp_name:
                return lr

    def _get_listener_key(self, listener_id, is_enabled=True):
        listener_key = ovn_const.LB_EXT_IDS_LISTENER_PREFIX + str(listener_id)
        if not is_enabled:
            listener_key += ':' + DISABLED_RESOURCE_SUFFIX
        return listener_key

    def _get_pool_key(self, pool_id, is_enabled=True):
        pool_key = ovn_const.LB_EXT_IDS_POOL_PREFIX + str(pool_id)
        if not is_enabled:
            pool_key += ':' + DISABLED_RESOURCE_SUFFIX
        return pool_key

    def _extract_member_info(self, member):
        mem_info = []
        if member:
            for mem in member.split(','):
                mem_ip_port = mem.split('_')[2]
                mem_info.append(tuple(mem_ip_port.rsplit(':', 1)))
        return mem_info

    def _get_member_key(self, member, old_convention=False):
        member_info = ''
        if isinstance(member, dict):
            member_info = '%s%s_%s:%s' % (
                ovn_const.LB_EXT_IDS_MEMBER_PREFIX,
                member['id'],
                member['address'],
                member['protocol_port'])
            if not old_convention and member.get('subnet_id'):
                member_info += "_" + member['subnet_id']
        elif isinstance(member, o_datamodels.Member):
            member_info = '%s%s_%s:%s' % (
                ovn_const.LB_EXT_IDS_MEMBER_PREFIX,
                member.member_id,
                member.address,
                member.protocol_port)
            if not old_convention and member.subnet_id:
                member_info += "_" + member.subnet_id
        return member_info

    def _make_listener_key_value(self, listener_port, pool_id):
        return str(listener_port) + ':' + pool_id

    def _extract_listener_key_value(self, listener_value):
        v = listener_value.split(':')
        if len(v) == 2:
            return (v[0], v[1])
        else:
            return (None, None)

    def _is_listener_disabled(self, listener_key):
        v = listener_key.split(':')
        if len(v) == 2 and v[1] == DISABLED_RESOURCE_SUFFIX:
            return True

        return False

    def _get_pool_listeners(self, ovn_lb, pool_key):
        pool_listeners = []
        for k, v in ovn_lb.external_ids.items():
            if ovn_const.LB_EXT_IDS_LISTENER_PREFIX not in k:
                continue
            vip_port, p_key = self._extract_listener_key_value(v)
            if pool_key == p_key:
                pool_listeners.append(
                    k[len(ovn_const.LB_EXT_IDS_LISTENER_PREFIX):])
        return pool_listeners

    def _frame_vip_ips(self, lb_external_ids):
        vip_ips = {}
        # If load balancer is disabled, return
        if lb_external_ids.get('enabled') == 'False':
            return vip_ips

        lb_vip = lb_external_ids[ovn_const.LB_EXT_IDS_VIP_KEY]
        vip_fip = lb_external_ids.get(ovn_const.LB_EXT_IDS_VIP_FIP_KEY)

        for k, v in lb_external_ids.items():
            if (ovn_const.LB_EXT_IDS_LISTENER_PREFIX not in k or
                    self._is_listener_disabled(k)):
                continue

            vip_port, pool_id = self._extract_listener_key_value(v)
            if not vip_port or not pool_id:
                continue

            if pool_id not in lb_external_ids or not lb_external_ids[pool_id]:
                continue

            ips = []
            for member_ip, member_port in self._extract_member_info(
                    lb_external_ids[pool_id]):
                if netaddr.IPNetwork(member_ip).version == 6:
                    ips.append('[%s]:%s' % (member_ip, member_port))
                else:
                    ips.append('%s:%s' % (member_ip, member_port))

            if netaddr.IPNetwork(lb_vip).version == 6:
                lb_vip = '[%s]' % lb_vip
            vip_ips[lb_vip + ':' + vip_port] = ','.join(ips)

            if vip_fip:
                if netaddr.IPNetwork(vip_fip).version == 6:
                    vip_fip = '[%s]' % vip_fip
                vip_ips[vip_fip + ':' + vip_port] = ','.join(ips)

        return vip_ips

    def _refresh_lb_vips(self, ovn_lb_uuid, lb_external_ids):
        vip_ips = self._frame_vip_ips(lb_external_ids)
        return [self.ovn_nbdb_api.db_clear('Load_Balancer', ovn_lb_uuid,
                                           'vips'),
                self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb_uuid,
                                         ('vips', vip_ips))]

    def _is_listener_in_lb(self, lb):
        for key in list(lb.external_ids):
            if key.startswith(ovn_const.LB_EXT_IDS_LISTENER_PREFIX):
                return True
        return False

    def check_lb_protocol(self, lb_id, listener_protocol):
        ovn_lb = self._find_ovn_lbs(lb_id, protocol=listener_protocol)
        if not ovn_lb:
            return False
        elif not self._is_listener_in_lb(ovn_lb):
            return True
        else:
            return str(listener_protocol).lower() in ovn_lb.protocol

    def lb_create(self, loadbalancer, protocol=None):
        port = None
        network_driver = get_network_driver()
        if loadbalancer.get('vip_port_id'):
            # In case we don't have vip_network_id
            port = network_driver.neutron_client.show_port(
                loadbalancer['vip_port_id'])['port']
        elif (loadbalancer.get('vip_network_id') and
              loadbalancer.get('vip_address')):
            ports = network_driver.neutron_client.list_ports(
                network_id=loadbalancer['vip_network_id'])
            for p in ports['ports']:
                for ip in p['fixed_ips']:
                    if ip['ip_address'] == loadbalancer['vip_address']:
                        port = p
                        break

        # If protocol set make sure its lowercase
        protocol = protocol.lower() if protocol else None
        # In case port is not found for the vip_address we will see an
        # exception when port['id'] is accessed.
        external_ids = {
            ovn_const.LB_EXT_IDS_VIP_KEY: loadbalancer['vip_address'],
            ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY:
                loadbalancer.get('vip_port_id') or port['id'],
            'enabled': str(loadbalancer['admin_state_up'])}
        # In case vip_fip was passed - use it.
        vip_fip = loadbalancer.get(ovn_const.LB_EXT_IDS_VIP_FIP_KEY)
        if vip_fip:
            external_ids[ovn_const.LB_EXT_IDS_VIP_FIP_KEY] = vip_fip
        # In case of lr_ref passed - use it.
        lr_ref = loadbalancer.get(ovn_const.LB_EXT_IDS_LR_REF_KEY)
        if lr_ref:
            external_ids[ovn_const.LB_EXT_IDS_LR_REF_KEY] = lr_ref

        try:
            self.ovn_nbdb_api.db_create(
                'Load_Balancer', name=loadbalancer['id'],
                protocol=protocol,
                external_ids=external_ids
                ).execute(check_error=True)
            ovn_lb = self._find_ovn_lbs(
                loadbalancer['id'],
                protocol=protocol)
            ovn_lb = ovn_lb if protocol else ovn_lb[0]
            commands = self._update_lb_to_ls_association(
                ovn_lb, network_id=port['network_id'],
                associate=True)
            ls_name = ovn_utils.ovn_name(port['network_id'])
            ovn_ls = self.ovn_nbdb_api.ls_get(ls_name).execute(
                check_error=True)
            ovn_lr = self._find_lr_of_ls(ovn_ls)
            if ovn_lr:
                commands.extend(self._update_lb_to_lr_association(
                    ovn_lb, ovn_lr))

            # NOTE(mjozefcz): In case of LS references where passed -
            # apply LS to the new LB. That could happend in case we
            # need another loadbalancer for other L4 protocol.
            ls_refs = loadbalancer.get(ovn_const.LB_EXT_IDS_LS_REFS_KEY)
            if ls_refs:
                try:
                    ls_refs = jsonutils.loads(ls_refs)
                except ValueError:
                    ls_refs = {}
                for ls in ls_refs:
                    # Skip previously added LS because we don't want
                    # to duplicate.
                    if ls == ovn_ls.name:
                        continue
                    commands.extend(self._update_lb_to_ls_association(
                        ovn_lb, network_id=ls.replace('neutron-', ''),
                        associate=True))

            self._execute_commands(commands)
            operating_status = constants.ONLINE
            # The issue is that since OVN doesnt support any HMs,
            # we ideally should never put the status as 'ONLINE'
            if not loadbalancer.get('admin_state_up', True):
                operating_status = constants.OFFLINE
            status = {
                'loadbalancers': [{"id": loadbalancer['id'],
                                   "provisioning_status": constants.ACTIVE,
                                   "operating_status": operating_status}]}
        # If the connection with the OVN NB db server is broken, then
        # ovsdbapp will throw either TimeOutException or RunTimeError.
        # May be we can catch these specific exceptions.
        # It is important to report the status to octavia. We can report
        # immediately or reschedule the lb_create request later.
        # For now lets report immediately.
        except Exception:
            LOG.exception(EXCEPTION_MSG, "creation of loadbalancer")
            # Any Exception set the status to ERROR
            if isinstance(port, dict):
                self.delete_vip_port(port.get('id'))
                LOG.warning("Deleting the VIP port %s since LB went into "
                            "ERROR state", str(port.get('id')))
            status = {
                'loadbalancers': [{"id": loadbalancer['id'],
                                   "provisioning_status": constants.ERROR,
                                   "operating_status": constants.ERROR}]}
        return status

    def lb_delete(self, loadbalancer):
        port_id = None
        status = {'loadbalancers': [{"id": loadbalancer['id'],
                                     "provisioning_status": "DELETED",
                                     "operating_status": "OFFLINE"}],
                  'listeners': [],
                  'pools': [],
                  'members': []}

        ovn_lbs = None
        try:
            ovn_lbs = self._find_ovn_lbs(loadbalancer['id'])
        except idlutils.RowNotFound:
            LOG.warning("Loadbalancer %s not found in OVN Northbound DB. "
                        "Setting the Loadbalancer status to DELETED "
                        "in Octavia", str(loadbalancer['id']))
            return status

        try:
            port_id = ovn_lbs[0].external_ids[
                ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY]
            for ovn_lb in ovn_lbs:
                status = self._lb_delete(loadbalancer, ovn_lb, status)
            # Clear the status dict of any key having [] value
            # Python 3.6 doesnt allow deleting an element in a
            # dict while iterating over it. So first get a list of keys.
            # https://cito.github.io/blog/never-iterate-a-changing-dict/
            status = {key: value for key, value in status.items() if value}
        except Exception:
            LOG.exception(EXCEPTION_MSG, "deletion of loadbalancer")
            status = {
                'loadbalancers': [{"id": loadbalancer['id'],
                                   "provisioning_status": constants.ERROR,
                                   "operating_status": constants.ERROR}]}
        # Delete VIP port from neutron.
        self.delete_vip_port(port_id)
        return status

    def _lb_delete(self, loadbalancer, ovn_lb, status):
        commands = []
        if loadbalancer['cascade']:
            # Delete all pools
            for key, value in ovn_lb.external_ids.items():
                if key.startswith(ovn_const.LB_EXT_IDS_POOL_PREFIX):
                    pool_id = key.split('_')[1]
                    # Delete all members in the pool
                    if value and len(value.split(',')) > 0:
                        for mem_info in value.split(','):
                            status['members'].append({
                                'id': mem_info.split('_')[1],
                                'provisioning_status': constants.DELETED})
                    status['pools'].append(
                        {"id": pool_id,
                         "provisioning_status": constants.DELETED})

                if key.startswith(ovn_const.LB_EXT_IDS_LISTENER_PREFIX):
                    status['listeners'].append({
                        'id': key.split('_')[1],
                        'provisioning_status': constants.DELETED,
                        'operating_status': constants.OFFLINE})
        ls_refs = ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_LS_REFS_KEY, {})
        if ls_refs:
            try:
                ls_refs = jsonutils.loads(ls_refs)
            except ValueError:
                ls_refs = {}
        for ls_name in ls_refs.keys():
            try:
                ovn_ls = self.ovn_nbdb_api.ls_get(ls_name).execute(
                    check_error=True)
                commands.append(
                    self.ovn_nbdb_api.ls_lb_del(ovn_ls.uuid, ovn_lb.uuid)
                )
            except idlutils.RowNotFound:
                LOG.warning("LogicalSwitch %s could not be found. Cannot "
                            "delete Load Balancer from it", ls_name)
        # Delete LB from all Networks the LB is indirectly associated
        for ls in self._find_lb_in_table(ovn_lb, 'Logical_Switch'):
            commands.append(
                self.ovn_nbdb_api.ls_lb_del(ls.uuid, ovn_lb.uuid,
                                            if_exists=True))
        lr_ref = ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_LR_REF_KEY, {})
        if lr_ref:
            for lr in self.ovn_nbdb_api.tables[
                    'Logical_Router'].rows.values():
                if lr.name == lr_ref:
                    commands.append(self.ovn_nbdb_api.lr_lb_del(
                        lr.uuid, ovn_lb.uuid))
                    break
        # Delete LB from all Routers the LB is indirectly associated
        for lr in self._find_lb_in_table(ovn_lb, 'Logical_Router'):
            commands.append(
                self.ovn_nbdb_api.lr_lb_del(lr.uuid, ovn_lb.uuid,
                                            if_exists=True))
        commands.append(self.ovn_nbdb_api.lb_del(ovn_lb.uuid))
        self._execute_commands(commands)
        return status

    def lb_failover(self, loadbalancer):
        status = {
            'loadbalancers': [{'id': loadbalancer['id'],
                               'provisioning_status': constants.ACTIVE}]}
        return status

    def lb_update(self, loadbalancer):
        lb_status = {'id': loadbalancer['id'],
                     'provisioning_status': constants.ACTIVE}
        status = {'loadbalancers': [lb_status]}
        if 'admin_state_up' not in loadbalancer:
            return status
        lb_enabled = loadbalancer['admin_state_up']

        try:
            ovn_lbs = self._find_ovn_lbs(loadbalancer['id'])
            # It should be unique for all the LBS for all protocols,
            # so we could just easly loop over all defined for given
            # Octavia LB.
            for ovn_lb in ovn_lbs:
                if str(ovn_lb.external_ids['enabled']) != str(lb_enabled):
                    commands = []
                    enable_info = {'enabled': str(lb_enabled)}
                    ovn_lb.external_ids['enabled'] = str(lb_enabled)
                    commands.append(
                        self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                                 ('external_ids', enable_info))
                    )
                    commands.extend(
                        self._refresh_lb_vips(ovn_lb.uuid,
                                              ovn_lb.external_ids))
                    self._execute_commands(commands)
                if lb_enabled:
                    operating_status = constants.ONLINE
                else:
                    operating_status = constants.OFFLINE
                lb_status['operating_status'] = operating_status
        except Exception:
            LOG.exception(EXCEPTION_MSG, "update of loadbalancer")
            lb_status['provisioning_status'] = constants.ERROR
            lb_status['operating_status'] = constants.ERROR
        return status

    def listener_create(self, listener):
        ovn_lb = self._get_or_create_ovn_lb(
            listener['loadbalancer_id'],
            listener['protocol'],
            listener['admin_state_up'])

        external_ids = copy.deepcopy(ovn_lb.external_ids)
        listener_key = self._get_listener_key(
            listener['id'], is_enabled=listener['admin_state_up'])

        if listener.get('default_pool_id'):
            pool_key = self._get_pool_key(listener['default_pool_id'])
        else:
            pool_key = ''
        external_ids[listener_key] = self._make_listener_key_value(
            listener['protocol_port'], pool_key)

        listener_info = {listener_key: external_ids[listener_key]}
        try:
            commands = []
            commands.append(
                self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                         ('external_ids', listener_info))
            )
            if not self._is_listener_in_lb(ovn_lb):
                commands.append(
                    self.ovn_nbdb_api.db_set(
                        'Load_Balancer', ovn_lb.uuid,
                        ('protocol', str(listener['protocol']).lower()))
                )
            commands.extend(
                self._refresh_lb_vips(ovn_lb.uuid, external_ids)
            )
            self._execute_commands(commands)

            operating_status = constants.ONLINE
            if not listener.get('admin_state_up', True):
                operating_status = constants.OFFLINE
            status = {
                'listeners': [{"id": listener['id'],
                               "provisioning_status": constants.ACTIVE,
                               "operating_status": operating_status}],
                'loadbalancers': [{"id": listener['loadbalancer_id'],
                                   "provisioning_status": constants.ACTIVE}]}
        except Exception:
            LOG.exception(EXCEPTION_MSG, "creation of listener")
            status = {
                'listeners': [{"id": listener['id'],
                               "provisioning_status": constants.ERROR,
                               "operating_status": constants.ERROR}],
                'loadbalancers': [{"id": listener['loadbalancer_id'],
                                   "provisioning_status": constants.ACTIVE}]}
        return status

    def listener_delete(self, listener):
        status = {
            'listeners': [{"id": listener['id'],
                           "provisioning_status": constants.DELETED,
                           "operating_status": constants.OFFLINE}],
            'loadbalancers': [{"id": listener['loadbalancer_id'],
                               "provisioning_status": constants.ACTIVE}]}
        try:
            ovn_lb = self._find_ovn_lbs(
                listener['loadbalancer_id'],
                protocol=listener['protocol'])
        except idlutils.RowNotFound:
            # Listener already deleted.
            return status

        external_ids = copy.deepcopy(ovn_lb.external_ids)
        listener_key = self._get_listener_key(listener['id'])
        if listener_key in external_ids:
            try:
                commands = []
                commands.append(
                    self.ovn_nbdb_api.db_remove(
                        'Load_Balancer', ovn_lb.uuid, 'external_ids',
                        (listener_key)))
                # Drop current listener from LB.
                del external_ids[listener_key]

                # Set LB protocol to undefined only if there are no more
                # listeners and pools defined in the LB.
                cmds, lb_to_delete = self._clean_lb_if_empty(
                    ovn_lb, listener['loadbalancer_id'], external_ids)
                commands.extend(cmds)
                # Do not refresh vips if OVN LB for given protocol
                # has pending delete operation.
                if not lb_to_delete:
                    commands.extend(
                        self._refresh_lb_vips(ovn_lb.uuid, external_ids))
                self._execute_commands(commands)
            except Exception:
                LOG.exception(EXCEPTION_MSG, "deletion of listener")
                status = {
                    'listeners': [{
                        "id": listener['id'],
                        "provisioning_status": constants.ERROR,
                        "operating_status": constants.ERROR}],
                    'loadbalancers': [{
                        "id": listener['loadbalancer_id'],
                        "provisioning_status": constants.ACTIVE}]}
        return status

    def listener_update(self, listener):
        # NOTE(mjozefcz): Based on
        # https://docs.openstack.org/api-ref/load-balancer/v2/?expanded=update-a-listener-detail
        # there is no possibility to update listener protocol or port.
        listener_status = {'id': listener['id'],
                           'provisioning_status': constants.ACTIVE}
        pool_status = []
        status = {
            'listeners': [listener_status],
            'loadbalancers': [{'id': listener['loadbalancer_id'],
                               'provisioning_status': constants.ACTIVE}],
            'pools': pool_status}

        try:
            ovn_lb = self._find_ovn_lbs(
                listener['loadbalancer_id'],
                protocol=listener['protocol'])
        except idlutils.RowNotFound:
            LOG.exception(EXCEPTION_MSG, "update of listener")
            # LB row not found during updating a listner. That is a problem.
            status['listeners'][0]['provisioning_status'] = constants.ERROR
            status['loadbalancers'][0]['provisioning_status'] = constants.ERROR
            return status

        l_key_when_enabled = self._get_listener_key(listener['id'])
        l_key_when_disabled = self._get_listener_key(
            listener['id'], is_enabled=False)

        external_ids = copy.deepcopy(ovn_lb.external_ids)
        if 'admin_state_up' not in listener and (
                'default_pool_id' not in listener):
            return status

        l_key_to_add = {}
        if l_key_when_enabled in external_ids:
            present_l_key = l_key_when_enabled
        elif l_key_when_disabled in external_ids:
            present_l_key = l_key_when_disabled
        else:
            # Something is terribly wrong. This cannot happen.
            return status

        try:
            commands = []
            new_l_key = None
            l_key_to_remove = None
            if 'admin_state_up' in listener:
                if listener['admin_state_up']:
                    # We need to enable the listener
                    new_l_key = l_key_when_enabled
                    listener_status['operating_status'] = constants.ONLINE
                else:
                    # We need to disable the listener
                    new_l_key = l_key_when_disabled
                    listener_status['operating_status'] = constants.OFFLINE

                if present_l_key != new_l_key:
                    external_ids[new_l_key] = external_ids[present_l_key]
                    l_key_to_add[new_l_key] = external_ids[present_l_key]
                    del external_ids[present_l_key]
                    l_key_to_remove = present_l_key

                if l_key_to_remove:
                    commands.append(
                        self.ovn_nbdb_api.db_remove(
                            'Load_Balancer', ovn_lb.uuid, 'external_ids',
                            (l_key_to_remove))
                    )
            else:
                new_l_key = present_l_key

            if 'default_pool_id' in listener:
                pool_key = self._get_pool_key(listener['default_pool_id'])
                l_key_value = self._make_listener_key_value(
                    listener['protocol_port'], pool_key)
                l_key_to_add[new_l_key] = l_key_value
                external_ids[new_l_key] = l_key_value
                pool_status.append({'id': listener['default_pool_id'],
                                    'provisioning_status': constants.ACTIVE})

            if l_key_to_add:
                commands.append(
                    self.ovn_nbdb_api.db_set(
                        'Load_Balancer', ovn_lb.uuid,
                        ('external_ids', l_key_to_add))
                )

            commands.extend(
                self._refresh_lb_vips(ovn_lb.uuid, external_ids))
            self._execute_commands(commands)
        except Exception:
            LOG.exception(EXCEPTION_MSG, "update of listener")
            status = {
                'listeners': [{'id': listener['id'],
                               'provisioning_status': constants.ERROR}],
                'loadbalancers': [{'id': listener['loadbalancer_id'],
                                   'provisioning_status': constants.ACTIVE}]}
        return status

    def pool_create(self, pool):
        ovn_lb = self._get_or_create_ovn_lb(
            pool['loadbalancer_id'],
            pool['protocol'],
            pool['admin_state_up'])
        external_ids = copy.deepcopy(ovn_lb.external_ids)
        pool_key = self._get_pool_key(pool['id'],
                                      is_enabled=pool['admin_state_up'])
        external_ids[pool_key] = ''
        if pool['listener_id']:
            listener_key = self._get_listener_key(pool['listener_id'])
            if listener_key in ovn_lb.external_ids:
                external_ids[listener_key] = str(
                    external_ids[listener_key]) + str(pool_key)
        try:
            self.ovn_nbdb_api.db_set(
                'Load_Balancer', ovn_lb.uuid,
                ('external_ids', external_ids)).execute(check_error=True)
            # Pool status will be set to Online after a member is added to it.
            operating_status = constants.OFFLINE

            status = {
                'pools': [{'id': pool['id'],
                           'provisioning_status': constants.ACTIVE,
                           'operating_status': operating_status}],
                'loadbalancers': [{"id": pool['loadbalancer_id'],
                                   "provisioning_status": constants.ACTIVE}]}
            if pool['listener_id']:
                listener_status = [{'id': pool['listener_id'],
                                    'provisioning_status': constants.ACTIVE}]
                status['listeners'] = listener_status
        except Exception:
            LOG.exception(EXCEPTION_MSG, "creation of pool")
            status = {
                'pools': [{"id": pool['id'],
                           "provisioning_status": constants.ERROR}],
                'loadbalancers': [{"id": pool['loadbalancer_id'],
                                   "provisioning_status": constants.ACTIVE}]}
            if pool['listener_id']:
                listener_status = [{'id': pool['listener_id'],
                                   'provisioning_status': constants.ACTIVE}]
                status['listeners'] = listener_status

        return status

    def pool_delete(self, pool):
        status = {
            'pools': [{"id": pool['id'],
                       "provisioning_status": constants.DELETED}],
            'loadbalancers': [{"id": pool['loadbalancer_id'],
                               "provisioning_status": constants.ACTIVE}]}
        try:
            ovn_lb = self._find_ovn_lbs(
                pool['loadbalancer_id'],
                pool['protocol'])
        except idlutils.RowNotFound:
            # LB row not found that means pool is deleted.
            return status

        pool_key = self._get_pool_key(pool['id'])
        commands = []
        external_ids = copy.deepcopy(ovn_lb.external_ids)
        try:
            if pool_key in ovn_lb.external_ids:
                commands.append(
                    self.ovn_nbdb_api.db_remove('Load_Balancer', ovn_lb.uuid,
                                                'external_ids', (pool_key))
                )
                del external_ids[pool_key]
                commands.extend(
                    self._refresh_lb_vips(ovn_lb.uuid, external_ids))
            # Remove Pool from Listener if it is associated
            listener_id = None
            for key, value in ovn_lb.external_ids.items():
                if (key.startswith(ovn_const.LB_EXT_IDS_LISTENER_PREFIX) and
                        pool_key in value):
                    external_ids[key] = value.split(':')[0] + ':'
                    commands.append(
                        self.ovn_nbdb_api.db_set(
                            'Load_Balancer', ovn_lb.uuid,
                            ('external_ids', external_ids)))
                    listener_id = key.split('_')[1]

            pool_key_when_disabled = self._get_pool_key(pool['id'],
                                                        is_enabled=False)
            if pool_key_when_disabled in ovn_lb.external_ids:
                commands.append(
                    self.ovn_nbdb_api.db_remove(
                        'Load_Balancer', ovn_lb.uuid,
                        'external_ids', (pool_key_when_disabled))
                )

            commands.extend(
                self._clean_lb_if_empty(
                    ovn_lb, pool['loadbalancer_id'], external_ids)[0])
            self._execute_commands(commands)

            if listener_id:
                status['listeners'] = [{
                    'id': listener_id,
                    'provisioning_status': constants.ACTIVE}]
        except Exception:
            LOG.exception(EXCEPTION_MSG, "deletion of pool")
            status = {
                'pools': [{"id": pool['id'],
                           "provisioning_status": constants.ERROR}],
                'loadbalancers': [{"id": pool['loadbalancer_id'],
                                   "provisioning_status": constants.ACTIVE}]}

        return status

    def pool_update(self, pool):
        pool_status = {'id': pool['id'],
                       'provisioning_status': constants.ACTIVE}
        status = {
            'pools': [pool_status],
            'loadbalancers': [{'id': pool['loadbalancer_id'],
                               'provisioning_status': constants.ACTIVE}]}
        if 'admin_state_up' not in pool:
            return status
        try:
            ovn_lb = self._find_ovn_lbs(
                pool['loadbalancer_id'], protocol=pool['protocol'])
        except idlutils.RowNotFound:
            LOG.exception(EXCEPTION_MSG, "update of pool")
            # LB row not found during updating a listner. That is a problem.
            status['pool'][0]['provisioning_status'] = constants.ERROR
            status['loadbalancers'][0]['provisioning_status'] = constants.ERROR
            return status

        pool_key = self._get_pool_key(pool['id'])
        p_key_when_disabled = self._get_pool_key(pool['id'],
                                                 is_enabled=False)
        external_ids = copy.deepcopy(ovn_lb.external_ids)
        p_key_to_remove = None
        p_key_to_add = {}

        try:
            if pool['admin_state_up']:
                if p_key_when_disabled in external_ids:
                    p_key_to_add[pool_key] = external_ids[p_key_when_disabled]
                    external_ids[pool_key] = external_ids[p_key_when_disabled]
                    del external_ids[p_key_when_disabled]
                    p_key_to_remove = p_key_when_disabled
            else:
                if pool_key in external_ids:
                    p_key_to_add[p_key_when_disabled] = external_ids[pool_key]
                    external_ids[p_key_when_disabled] = external_ids[pool_key]
                    del external_ids[pool_key]
                    p_key_to_remove = pool_key

            if p_key_to_remove:
                commands = []
                commands.append(
                    self.ovn_nbdb_api.db_remove(
                        'Load_Balancer', ovn_lb.uuid, 'external_ids',
                        (p_key_to_remove))
                )

                commands.append(
                    self.ovn_nbdb_api.db_set(
                        'Load_Balancer', ovn_lb.uuid,
                        ('external_ids', p_key_to_add))
                )

                commands.extend(
                    self._refresh_lb_vips(ovn_lb.uuid, external_ids))
                self._execute_commands(commands)
            if pool['admin_state_up']:
                operating_status = constants.ONLINE
            else:
                operating_status = constants.OFFLINE
            pool_status['operating_status'] = operating_status

            pool_listeners = self._get_pool_listeners(ovn_lb,
                                                      pool_key)
            listener_status = []
            for l in pool_listeners:
                listener_status.append(
                    {'id': l,
                     'provisioning_status': constants.ACTIVE})
            status['listeners'] = listener_status
        except Exception:
            LOG.exception(EXCEPTION_MSG, "update of pool")
            status = {
                'pools': [{"id": pool['id'],
                           'provisioning_status': constants.ERROR}],
                'loadbalancers': [{"id": pool['loadbalancer_id'],
                                   'provisioning_status': constants.ACTIVE}]}

        return status

    def _add_member(self, member, ovn_lb, pool_key):
        external_ids = copy.deepcopy(ovn_lb.external_ids)
        existing_members = external_ids[pool_key]
        if existing_members:
            existing_members = existing_members.split(",")
        member_info = self._get_member_key(member)
        # TODO(mjozefcz): Remove this workaround in W release.
        member_info_old = self._get_member_key(member, old_convention=True)
        member_found = [x for x in existing_members
                        if re.match(member_info_old, x)]
        if member_found:
            # Member already present
            return
        if existing_members:
            existing_members.append(member_info)
            pool_data = {pool_key: ",".join(existing_members)}
        else:
            pool_data = {pool_key: member_info}

        commands = []
        commands.append(
            self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                     ('external_ids', pool_data))
        )

        external_ids[pool_key] = pool_data[pool_key]
        commands.extend(
            self._refresh_lb_vips(ovn_lb.uuid, external_ids)
        )
        commands.extend(
            self._update_lb_to_ls_association(
                ovn_lb, subnet_id=member['subnet_id'], associate=True)
        )
        self._execute_commands(commands)

    def member_create(self, member):
        try:
            pool_key, ovn_lb = self._find_ovn_lb_by_pool_id(
                member['pool_id'])
            self._add_member(member, ovn_lb, pool_key)
            pool = {"id": member['pool_id'],
                    "provisioning_status": constants.ACTIVE,
                    "operating_status": constants.ONLINE}
            status = {
                'pools': [pool],
                'members': [{"id": member['id'],
                             "provisioning_status": constants.ACTIVE}],
                'loadbalancers': [{"id": ovn_lb.name,
                                   "provisioning_status": constants.ACTIVE}]}
            pool_listeners = self._get_pool_listeners(ovn_lb, pool_key)
            listener_status = []
            for l in pool_listeners:
                listener_status.append(
                    {'id': l,
                     'provisioning_status': constants.ACTIVE})
            status['listeners'] = listener_status
        except Exception:
            LOG.exception(EXCEPTION_MSG, "creation of member")
            status = {
                'pools': [{"id": member['pool_id'],
                           "provisioning_status": constants.ERROR}],
                'members': [{"id": member['id'],
                             "provisioning_status": constants.ACTIVE}],
                'loadbalancers': [{"id": ovn_lb.name,
                                   "provisioning_status": constants.ACTIVE}]}

        return status

    def _remove_member(self, member, ovn_lb, pool_key):
        external_ids = copy.deepcopy(ovn_lb.external_ids)
        existing_members = external_ids[pool_key].split(",")
        # TODO(mjozefcz): Delete this workaround in W release.
        # To support backward compatibility member
        # could be defined as `member`_`id`_`ip`:`port`_`subnet_id`
        # or defined as `member`_`id`_`ip`:`port
        member_info_old = self._get_member_key(member, old_convention=True)

        member_found = [x for x in existing_members
                        if re.match(member_info_old, x)]
        if member_found:
            commands = []
            existing_members.remove(member_found[0])

            if not existing_members:
                pool_status = constants.OFFLINE
            else:
                pool_status = constants.ONLINE
            pool_data = {pool_key: ",".join(existing_members)}
            commands.append(
                self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                         ('external_ids', pool_data)))
            external_ids[pool_key] = ",".join(existing_members)
            commands.extend(
                self._refresh_lb_vips(ovn_lb.uuid, external_ids))
            commands.extend(
                self._update_lb_to_ls_association(
                    ovn_lb, subnet_id=member.get('subnet_id'),
                    associate=False))
            self._execute_commands(commands)
            return pool_status
        else:
            msg = "Member %s not found in the pool" % member['id']
            raise driver_exceptions.DriverError(
                user_fault_string=msg,
                operator_fault_string=msg)

    def member_delete(self, member):
        try:
            pool_key, ovn_lb = self._find_ovn_lb_by_pool_id(
                member['pool_id'])
            pool_status = self._remove_member(member, ovn_lb, pool_key)
            pool = {"id": member['pool_id'],
                    "provisioning_status": constants.ACTIVE,
                    "operating_status": pool_status}
            status = {
                'pools': [pool],
                'members': [{"id": member['id'],
                             "provisioning_status": constants.DELETED}],
                'loadbalancers': [{"id": ovn_lb.name,
                                   "provisioning_status": constants.ACTIVE}]}
            pool_listeners = self._get_pool_listeners(ovn_lb, pool_key)
            listener_status = []
            for l in pool_listeners:
                listener_status.append(
                    {'id': l,
                     'provisioning_status': constants.ACTIVE})
            status['listeners'] = listener_status
        except Exception:
            LOG.exception(EXCEPTION_MSG, "deletion of member")
            status = {
                'pools': [{"id": member['pool_id'],
                           "provisioning_status": constants.ACTIVE}],
                'members': [{"id": member['id'],
                             "provisioning_status": constants.ERROR}],
                'loadbalancers': [{"id": ovn_lb.name,
                                   "provisioning_status": constants.ACTIVE}]}

        return status

    def _update_member(self, member, ovn_lb, pool_key):
        commands = []
        external_ids = copy.deepcopy(ovn_lb.external_ids)
        existing_members = external_ids[pool_key].split(",")
        member_info = self._get_member_key(member)
        for mem in existing_members:
            if (member_info.split('_')[1] == mem.split('_')[1] and
                    mem != member_info):
                existing_members.remove(mem)
                existing_members.append(member_info)
                pool_data = {pool_key: ",".join(existing_members)}
                commands.append(
                    self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                             ('external_ids', pool_data))
                )
                external_ids[pool_key] = ",".join(existing_members)
                commands.extend(
                    self._refresh_lb_vips(ovn_lb.uuid, external_ids)
                )
                self._execute_commands(commands)

    def member_update(self, member):
        try:
            pool_key, ovn_lb = self._find_ovn_lb_by_pool_id(
                member['pool_id'])
            status = {
                'pools': [{'id': member['pool_id'],
                           'provisioning_status': constants.ACTIVE}],
                'members': [{'id': member['id'],
                             'provisioning_status': constants.ACTIVE}],
                'loadbalancers': [{'id': ovn_lb.name,
                                   'provisioning_status': constants.ACTIVE}]}
            self._update_member(member, ovn_lb, pool_key)
            if 'admin_state_up' in member:
                if member['admin_state_up']:
                    status['members'][0]['operating_status'] = constants.ONLINE
                else:
                    status['members'][0][
                        'operating_status'] = constants.OFFLINE

            pool_listeners = self._get_pool_listeners(ovn_lb, pool_key)
            listener_status = []
            for l in pool_listeners:
                listener_status.append(
                    {'id': l,
                     'provisioning_status': constants.ACTIVE})
            status['listeners'] = listener_status
        except Exception:
            LOG.exception(EXCEPTION_MSG, "update of member")
            status = {
                'pools': [{'id': member['pool_id'],
                           'provisioning_status': constants.ACTIVE}],
                'members': [{'id': member['id'],
                             'provisioning_status': constants.ERROR}],
                'loadbalancers': [{'id': ovn_lb.name,
                                   'provisioning_status': constants.ACTIVE}]}
        return status

    def _get_existing_pool_members(self, pool_id):
        pool_key, ovn_lb = self._find_ovn_lb_by_pool_id(pool_id)
        if not ovn_lb:
            msg = _("Loadbalancer with pool %s does not exist") % pool_key
            raise driver_exceptions.DriverError(msg)
        external_ids = dict(ovn_lb.external_ids)
        return external_ids[pool_key]

    def get_pool_member_id(self, pool_id, mem_addr_port=None):
        '''Gets Member information

        :param pool_id: ID of the Pool whose member information is reqd.
        :param mem_addr_port: Combination of Member Address+Port. Default=None
        :returns: UUID -- ID of the Member if member exists in pool.
        :returns: None -- if no member exists in the pool
        :raises: Exception if Loadbalancer is not found for a Pool ID
        '''
        existing_members = self._get_existing_pool_members(pool_id)
        # Members are saved in OVN in the form of
        # member1_UUID_IP:Port, member2_UUID_IP:Port
        # Match the IP:Port for all members with the mem_addr_port
        # information and return the UUID.
        for meminf in existing_members.split(','):
            if mem_addr_port == meminf.split('_')[2]:
                return meminf.split('_')[1]

    def create_vip_port(self, project_id, lb_id, vip_d):
        port = {'port': {'name': ovn_const.LB_VIP_PORT_PREFIX + str(lb_id),
                         'network_id': vip_d['vip_network_id'],
                         'fixed_ips': [{'subnet_id': vip_d['vip_subnet_id']}],
                         'admin_state_up': True,
                         'project_id': project_id}}
        try:
            port['port']['fixed_ips'][0]['ip_address'] = vip_d['vip_address']
        except KeyError:
            pass
        network_driver = get_network_driver()
        try:
            return network_driver.neutron_client.create_port(port)
        except n_exc.IpAddressAlreadyAllocatedClient:
            # Sometimes the VIP is already created (race-conditions)
            # Lets get the it from Neutron API.
            ports = network_driver.neutron_client.list_ports(
                network_id=vip_d['vip_network_id'],
                name='%s%s' % (ovn_const.LB_VIP_PORT_PREFIX, lb_id))
            if not ports['ports']:
                LOG.error('Cannot create/get LoadBalancer VIP port with '
                          'fixed IP: %s', vip_d['vip_address'])
                status = {'loadbalancers': [{
                    "id": lb_id,
                    "provisioning_status": constants.ERROR,
                    "operating_status": constants.ERROR}]}
                self._update_status_to_octavia(status)
                return
            # there should only be one port returned
            port = ports['ports'][0]
            LOG.debug('VIP Port already exists, uuid: %s', port['id'])
            return {'port': port}

    def delete_vip_port(self, port_id):
        network_driver = get_network_driver()
        try:
            network_driver.neutron_client.delete_port(port_id)
        except n_exc.PortNotFoundClient:
            LOG.warning("Port %s could not be found. Please "
                        "check Neutron logs. Perhaps port "
                        "was already deleted.", port_id)

    def handle_vip_fip(self, fip_info):
        ovn_lb = fip_info['ovn_lb']
        external_ids = copy.deepcopy(ovn_lb.external_ids)
        commands = []

        if fip_info['action'] == REQ_INFO_ACTION_ASSOCIATE:
            external_ids[ovn_const.LB_EXT_IDS_VIP_FIP_KEY] = (
                fip_info['vip_fip'])
            vip_fip_info = {
                ovn_const.LB_EXT_IDS_VIP_FIP_KEY: fip_info['vip_fip']}
            commands.append(
                self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                         ('external_ids', vip_fip_info))
            )
        else:
            external_ids.pop(ovn_const.LB_EXT_IDS_VIP_FIP_KEY)
            commands.append(
                self.ovn_nbdb_api.db_remove(
                    'Load_Balancer', ovn_lb.uuid, 'external_ids',
                    (ovn_const.LB_EXT_IDS_VIP_FIP_KEY))
            )

        commands.extend(
            self._refresh_lb_vips(ovn_lb.uuid, external_ids)
        )
        self._execute_commands(commands)

    def handle_member_dvr(self, info):
        pool_key, ovn_lb = self._find_ovn_lb_by_pool_id(info['pool_id'])
        if not ovn_lb.external_ids.get(ovn_const.LB_EXT_IDS_VIP_FIP_KEY):
            LOG.debug("LB %(lb)s has no FIP on VIP configured. "
                      "There is no need to centralize member %(member)s "
                      "traffic.",
                      {'lb': ovn_lb.uuid, 'member': info['id']})
            return

        # Find out if member has FIP assigned.
        network_driver = get_network_driver()
        try:
            subnet = network_driver.get_subnet(info['subnet_id'])
            ls_name = ovn_utils.ovn_name(subnet.network_id)
        except n_exc.NotFound:
            LOG.exception('Subnet %s not found while trying to '
                          'fetch its data.', info['subnet_id'])
            return

        try:
            ls = self.ovn_nbdb_api.lookup('Logical_Switch', ls_name)
        except idlutils.RowNotFound:
            LOG.warning("Logical Switch %s not found."
                        "Can't verify member FIP configuration.",
                        ls_name)
            return

        fip = None
        f = ovn_utils.remove_macs_from_lsp_addresses
        for port in ls.ports:
            if info['address'] in f(port.addresses):
                # We found particular port
                fip = self.ovn_nbdb_api.db_find_rows(
                    'NAT', ('external_ids', '=', {
                        ovn_const.OVN_FIP_PORT_EXT_ID_KEY: port.name})
                ).execute(check_error=True)
                fip = fip[0] if fip else fip
                break

        if not fip:
            LOG.debug('Member %s has no FIP assigned.'
                      'There is no need to modify its NAT.',
                      info['id'])
            return

        if info['action'] == REQ_INFO_MEMBER_ADDED:
            LOG.info('Member %(member)s is added to Load Balancer %(lb)s '
                     'and both have FIP assigned. Member FIP %(fip)s '
                     'needs to be centralized in those conditions. '
                     'Deleting external_mac/logical_port from it.',
                     {'member': info['id'],
                      'lb': ovn_lb.uuid,
                      'fip': fip.external_ip})
            self.ovn_nbdb_api.db_clear(
                'NAT', fip.uuid, 'external_mac').execute(check_error=True)
            self.ovn_nbdb_api.db_clear(
                'NAT', fip.uuid, 'logical_port').execute(check_error=True)
        else:
            LOG.info('Member %(member)s is deleted from Load Balancer '
                     '%(lb)s. and both have FIP assigned. Member FIP %(fip)s '
                     'can be decentralized now if environment has DVR enabled.'
                     'Updating FIP object for recomputation.',
                     {'member': info['id'],
                      'lb': ovn_lb.uuid,
                      'fip': fip.external_ip})
            # NOTE(mjozefcz): We don't know if this env is DVR or not.
            # We should call neutron API to do 'empty' update of the FIP.
            # It will bump revision number and do recomputation of the FIP.
            try:
                fip_info = network_driver.neutron_client.show_floatingip(
                    fip.external_ids[ovn_const.OVN_FIP_EXT_ID_KEY])
                empty_update = {
                    "floatingip": {
                        'description': fip_info['floatingip']['description']}}
                network_driver.neutron_client.update_floatingip(
                    fip.external_ids[ovn_const.OVN_FIP_EXT_ID_KEY],
                    empty_update)
            except n_exc.NotFound:
                LOG.warning('Members %(member)s FIP %(fip)s not found in '
                            'Neutron. Can not update it.',
                            {'member': info['id'],
                             'fip': fip.external_ip})


class OvnProviderDriver(driver_base.ProviderDriver):
    _ovn_helper = None

    def __init__(self):
        super(OvnProviderDriver, self).__init__()
        if not OvnProviderDriver._ovn_helper:
            OvnProviderDriver._ovn_helper = OvnProviderHelper()

    def _check_for_supported_protocols(self, protocol):
        if protocol not in OVN_NATIVE_LB_PROTOCOLS:
            msg = _('OVN provider does not support %s protocol') % protocol
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)

    def _check_for_supported_algorithms(self, algorithm):
        if algorithm not in OVN_NATIVE_LB_ALGORITHMS:
            msg = _('OVN provider does not support %s algorithm') % algorithm
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)

    def loadbalancer_create(self, loadbalancer):
        admin_state_up = loadbalancer.admin_state_up
        if isinstance(admin_state_up, o_datamodels.UnsetType):
            admin_state_up = True
        request_info = {'id': loadbalancer.loadbalancer_id,
                        'vip_address': loadbalancer.vip_address,
                        'vip_network_id': loadbalancer.vip_network_id,
                        'admin_state_up': admin_state_up}

        request = {'type': REQ_TYPE_LB_CREATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def loadbalancer_delete(self, loadbalancer, cascade=False):
        request_info = {'id': loadbalancer.loadbalancer_id,
                        'cascade': cascade}
        request = {'type': REQ_TYPE_LB_DELETE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def loadbalancer_failover(self, loadbalancer_id):
        request_info = {'id': loadbalancer_id}
        request = {'type': REQ_TYPE_LB_FAILOVER,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def loadbalancer_update(self, old_loadbalancer, new_loadbalncer):
        request_info = {'id': new_loadbalncer.loadbalancer_id}
        if not isinstance(
                new_loadbalncer.admin_state_up, o_datamodels.UnsetType):
            request_info['admin_state_up'] = new_loadbalncer.admin_state_up
        request = {'type': REQ_TYPE_LB_UPDATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    # Pool
    def pool_create(self, pool):
        self._check_for_supported_protocols(pool.protocol)
        self._check_for_supported_algorithms(pool.lb_algorithm)
        admin_state_up = pool.admin_state_up
        if isinstance(admin_state_up, o_datamodels.UnsetType):
            admin_state_up = True
        request_info = {'id': pool.pool_id,
                        'loadbalancer_id': pool.loadbalancer_id,
                        'protocol': pool.protocol,
                        'listener_id': pool.listener_id,
                        'admin_state_up': admin_state_up}
        request = {'type': REQ_TYPE_POOL_CREATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def pool_delete(self, pool):
        for member in pool.members:
            self.member_delete(member)

        request_info = {'id': pool.pool_id,
                        'protocol': pool.protocol,
                        'loadbalancer_id': pool.loadbalancer_id}
        request = {'type': REQ_TYPE_POOL_DELETE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def pool_update(self, old_pool, new_pool):
        if not isinstance(new_pool.protocol, o_datamodels.UnsetType):
            self._check_for_supported_protocols(new_pool.protocol)
        if not isinstance(new_pool.lb_algorithm, o_datamodels.UnsetType):
            self._check_for_supported_algorithms(new_pool.lb_algorithm)
        request_info = {'id': old_pool.pool_id,
                        'protocol': old_pool.protocol,
                        'loadbalancer_id': old_pool.loadbalancer_id}

        if not isinstance(new_pool.admin_state_up, o_datamodels.UnsetType):
            request_info['admin_state_up'] = new_pool.admin_state_up
        request = {'type': REQ_TYPE_POOL_UPDATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def listener_create(self, listener):
        self._check_for_supported_protocols(listener.protocol)
        admin_state_up = listener.admin_state_up
        if isinstance(admin_state_up, o_datamodels.UnsetType):
            admin_state_up = True
        request_info = {'id': listener.listener_id,
                        'protocol': listener.protocol,
                        'loadbalancer_id': listener.loadbalancer_id,
                        'protocol_port': listener.protocol_port,
                        'default_pool_id': listener.default_pool_id,
                        'admin_state_up': admin_state_up}
        request = {'type': REQ_TYPE_LISTENER_CREATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def listener_delete(self, listener):
        request_info = {'id': listener.listener_id,
                        'loadbalancer_id': listener.loadbalancer_id,
                        'protocol_port': listener.protocol_port,
                        'protocol': listener.protocol}
        request = {'type': REQ_TYPE_LISTENER_DELETE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def listener_update(self, old_listener, new_listener):
        request_info = {'id': new_listener.listener_id,
                        'loadbalancer_id': old_listener.loadbalancer_id,
                        'protocol': old_listener.protocol,
                        'protocol_port': old_listener.protocol_port}

        if not isinstance(new_listener.admin_state_up, o_datamodels.UnsetType):
            request_info['admin_state_up'] = new_listener.admin_state_up

        if not isinstance(new_listener.default_pool_id,
                          o_datamodels.UnsetType):
            request_info['default_pool_id'] = new_listener.default_pool_id

        request = {'type': REQ_TYPE_LISTENER_UPDATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    # Member
    def _check_monitor_options(self, member):
        if (isinstance(member.monitor_address, o_datamodels.UnsetType) and
                isinstance(member.monitor_port, o_datamodels.UnsetType)):
            return False
        if member.monitor_address or member.monitor_port:
            return True
        return False

    def _ip_version_differs(self, member):
        _, ovn_lb = self._ovn_helper._find_ovn_lb_by_pool_id(member.pool_id)
        lb_vip = ovn_lb.external_ids[ovn_const.LB_EXT_IDS_VIP_KEY]
        return netaddr.IPNetwork(lb_vip).version != (
            netaddr.IPNetwork(member.address).version)

    def member_create(self, member):
        if self._check_monitor_options(member):
            msg = _('OVN provider does not support monitor options')
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)
        if self._ip_version_differs(member):
            raise IPVersionsMixingNotSupportedError()
        admin_state_up = member.admin_state_up
        if (isinstance(member.subnet_id, o_datamodels.UnsetType) or
                not member.subnet_id):
            msg = _('Subnet is required for Member creation'
                    ' with OVN Provider Driver')
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)

        if isinstance(admin_state_up, o_datamodels.UnsetType):
            admin_state_up = True
        request_info = {'id': member.member_id,
                        'address': member.address,
                        'protocol_port': member.protocol_port,
                        'pool_id': member.pool_id,
                        'subnet_id': member.subnet_id,
                        'admin_state_up': admin_state_up}
        request = {'type': REQ_TYPE_MEMBER_CREATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

        # NOTE(mjozefcz): If LB has FIP on VIP
        # and member has FIP we need to centralize
        # traffic for member.
        request_info = {'id': member.member_id,
                        'address': member.address,
                        'pool_id': member.pool_id,
                        'subnet_id': member.subnet_id,
                        'action': REQ_INFO_MEMBER_ADDED}
        request = {'type': REQ_TYPE_HANDLE_MEMBER_DVR,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def member_delete(self, member):
        request_info = {'id': member.member_id,
                        'address': member.address,
                        'protocol_port': member.protocol_port,
                        'pool_id': member.pool_id,
                        'subnet_id': member.subnet_id}
        request = {'type': REQ_TYPE_MEMBER_DELETE,
                   'info': request_info}
        self._ovn_helper.add_request(request)
        # NOTE(mjozefcz): If LB has FIP on VIP
        # and member had FIP we can decentralize
        # the traffic now.
        request_info = {'id': member.member_id,
                        'address': member.address,
                        'pool_id': member.pool_id,
                        'subnet_id': member.subnet_id,
                        'action': REQ_INFO_MEMBER_DELETED}
        request = {'type': REQ_TYPE_HANDLE_MEMBER_DVR,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def member_update(self, old_member, new_member):
        if self._check_monitor_options(new_member):
            msg = _('OVN provider does not support monitor options')
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)
        if new_member.address and self._ip_version_differs(new_member):
            raise IPVersionsMixingNotSupportedError()
        request_info = {'id': new_member.member_id,
                        'address': old_member.address,
                        'protocol_port': old_member.protocol_port,
                        'pool_id': old_member.pool_id,
                        'subnet_id': old_member.subnet_id}
        if not isinstance(new_member.admin_state_up, o_datamodels.UnsetType):
            request_info['admin_state_up'] = new_member.admin_state_up
        request = {'type': REQ_TYPE_MEMBER_UPDATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def member_batch_update(self, members):
        # Note(rbanerje): all members belong to the same pool.
        request_list = []
        skipped_members = []
        pool_id = None
        try:
            pool_id = members[0].pool_id
        except IndexError:
            msg = (_('No member information has been passed'))
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)
        except AttributeError:
            msg = (_('Member does not have proper pool information'))
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)
        pool_key, ovn_lb = self._ovn_helper._find_ovn_lb_by_pool_id(pool_id)
        external_ids = copy.deepcopy(ovn_lb.external_ids)
        existing_members = external_ids[pool_key].split(',')
        members_to_delete = copy.copy(existing_members)
        for member in members:
            if (self._check_monitor_options(member) or
                    member.address and self._ip_version_differs(member)):
                skipped_members.append(member.member_id)
                continue
            # NOTE(mjozefcz): We need to have subnet_id information.
            if (isinstance(member.subnet_id, o_datamodels.UnsetType) or
                    not member.subnet_id):
                msg = _('Subnet is required for Member creation'
                        ' with OVN Provider Driver')
                raise driver_exceptions.UnsupportedOptionError(
                    user_fault_string=msg,
                    operator_fault_string=msg)
            admin_state_up = member.admin_state_up
            if isinstance(admin_state_up, o_datamodels.UnsetType):
                admin_state_up = True

            member_info = self._ovn_helper._get_member_key(member)
            # TODO(mjozefcz): Remove this workaround in W release.
            member_info_old = self._ovn_helper._get_member_key(
                member, old_convention=True)
            member_found = [x for x in existing_members
                            if re.match(member_info_old, x)]
            if not member_found:
                req_type = REQ_TYPE_MEMBER_CREATE
            else:
                # If member exists in pool, then Update
                req_type = REQ_TYPE_MEMBER_UPDATE
                # Remove all updating members so only deleted ones are left
                # TODO(mjozefcz): Remove this workaround in W release.
                try:
                    members_to_delete.remove(member_info_old)
                except ValueError:
                    members_to_delete.remove(member_info)

            request_info = {'id': member.member_id,
                            'address': member.address,
                            'protocol_port': member.protocol_port,
                            'pool_id': member.pool_id,
                            'subnet_id': member.subnet_id,
                            'admin_state_up': admin_state_up}
            request = {'type': req_type,
                       'info': request_info}
            request_list.append(request)

        for member in members_to_delete:
            member_info = member.split('_')
            request_info = {'id': member_info[1],
                            'address': member_info[2].split(':')[0],
                            'protocol_port': member_info[2].split(':')[1],
                            'pool_id': pool_id}
            if len(member_info) == 4:
                request_info['subnet_id'] = member_info[3]
            request = {'type': REQ_TYPE_MEMBER_DELETE,
                       'info': request_info}
            request_list.append(request)

        for request in request_list:
            self._ovn_helper.add_request(request)
        if skipped_members:
            msg = (_('OVN provider does not support monitor options, '
                     'so following members skipped: %s') % skipped_members)
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)

    def create_vip_port(self, lb_id, project_id, vip_dict):
        try:
            port = self._ovn_helper.create_vip_port(
                project_id, lb_id, vip_dict)['port']
            vip_dict['vip_port_id'] = port['id']
            vip_dict['vip_address'] = port['fixed_ips'][0]['ip_address']
        except Exception as e:
            raise driver_exceptions.DriverError(e)
        return vip_dict

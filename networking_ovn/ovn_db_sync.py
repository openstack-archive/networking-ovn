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

from datetime import datetime
from eventlet import greenthread
import itertools
from neutron_lib import constants
from oslo_log import log

from neutron.common import utils as n_utils
from neutron import context
from neutron.extensions import providernet as pnet
from neutron import manager
from neutron.plugins.common import constants as service_constants

from networking_ovn._i18n import _LW
from networking_ovn.common import acl as acl_utils
from networking_ovn.common import config
from networking_ovn.common import utils
import six

LOG = log.getLogger(__name__)

SYNC_MODE_OFF = 'off'
SYNC_MODE_LOG = 'log'
SYNC_MODE_REPAIR = 'repair'


@six.add_metaclass(abc.ABCMeta)
class OvnDbSynchronizer(object):

    def __init__(self, core_plugin, ovn_api, ovn_driver):
        self.ovn_driver = ovn_driver
        self.ovn_api = ovn_api
        self.core_plugin = core_plugin

    def sync(self):
        greenthread.spawn_n(self._sync)

    @abc.abstractmethod
    def _sync(self):
        """Method to sync the OVN DB."""


class OvnNbSynchronizer(OvnDbSynchronizer):
    """Synchronizer class for NB."""

    def __init__(self, core_plugin, ovn_api, mode, ovn_driver):
        super(OvnNbSynchronizer, self).__init__(
            core_plugin, ovn_api, ovn_driver)
        self.mode = mode
        self.l3_plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)

    def _sync(self):
        if self.mode == SYNC_MODE_OFF:
            LOG.debug("Neutron sync mode is off")
            return

        # Initial delay until service is up
        greenthread.sleep(10)
        LOG.debug("Starting OVN-Northbound DB sync process")

        ctx = context.get_admin_context()
        self.sync_networks_and_ports(ctx)
        self.sync_acls(ctx)
        self.sync_routers_and_rports(ctx)

    @staticmethod
    def _get_attribute(obj, attribute):
        res = obj.get(attribute)
        if res is constants.ATTR_NOT_SPECIFIED:
            res = None
        return res

    def _create_network_in_ovn(self, net):
        physnet = self._get_attribute(net, pnet.PHYSICAL_NETWORK)
        segid = self._get_attribute(net, pnet.SEGMENTATION_ID)
        self.ovn_driver.create_network_in_ovn(net, {}, physnet, segid)

    def _create_port_in_ovn(self, ctx, port):
        ovn_port_info = self.ovn_driver.get_ovn_port_options(port)
        self.ovn_driver.create_port_in_ovn(port, ovn_port_info)

    def remove_common_acls(self, neutron_acls, nb_acls):
        """Take out common acls of the two acl dictionaries.

        @param   neutron_acls: neutron dictionary of port vs acls
        @type    neutron_acls: {}
        @param   nb_acls: nb dictionary of port vs acls
        @type    nb_acls: {}
        @return: Nothing, original dictionary modified
        """
        for port in neutron_acls.keys():
            for acl in list(neutron_acls[port]):
                if port in nb_acls and acl in nb_acls[port]:
                    neutron_acls[port].remove(acl)
                    nb_acls[port].remove(acl)

    def get_acls(self, context):
        """create the list of ACLS in OVN.

        @param context: neutron context
        @type  context: object of type neutron.context.Context
        @var   filters: to be used for filtering out group bindings, null here
        @var   lswitch_names: List of lswitch names
        @var   acl_list: List of NB acls
        @var   acl_list_dict: Dictionary of acl-lists based on lport as key
        @var   sg_ports: List of ports associated to SGs
        @return: acl_list-dict
        """
        filters = {}
        sg_ports = self.core_plugin._get_port_security_group_bindings(context,
                                                                      filters)
        lswitch_names = set([])
        for binding in sg_ports:
            port = self.core_plugin.get_port(context, binding['port_id'])
            lswitch_names.add(port['network_id'])
        acl_dict, ignore1, ignore2 = \
            self.ovn_api.get_acls_for_lswitches(lswitch_names)
        acl_list = list(itertools.chain(*six.itervalues(acl_dict)))
        acl_list_dict = {}
        for acl in acl_list:
            key = acl['lport']
            if key in acl_list_dict:
                acl_list_dict[key].append(acl)
            else:
                acl_list_dict[key] = list([acl])
        return acl_list_dict

    def sync_acls(self, ctx):
        """Sync ACLs between neutron and NB.

        @param ctx: neutron context
        @type  ctx: object of type neutron.context.Context
        @var   db_ports: List of ports from neutron DB
        @var   neutron_acls: neutron dictionary of port
               vs list-of-acls
        @var   nb_acls: NB dictionary of port
               vs list-of-acls
        @var   sg_ports_cache: cache for sg_ports
        @var   subnet_cache: cache for subnets
        @return: Nothing
        """
        LOG.debug('ACL-SYNC: started @ %s' %
                  str(datetime.now()))
        db_ports = {}
        for port in self.core_plugin.get_ports(ctx):
            db_ports[port['id']] = port

        sg_cache = {}
        sg_ports_cache = {}
        subnet_cache = {}
        neutron_acls = {}
        for port_id, port in db_ports.items():
            if port['security_groups']:
                if port_id in neutron_acls:
                    neutron_acls[port_id].extend(
                        acl_utils.add_acls(self.core_plugin,
                                           ctx,
                                           port,
                                           sg_cache,
                                           sg_ports_cache,
                                           subnet_cache))
                else:
                    neutron_acls[port_id] = \
                        acl_utils.add_acls(self.core_plugin,
                                           ctx,
                                           port,
                                           sg_cache,
                                           sg_ports_cache,
                                           subnet_cache)

        nb_acls = self.get_acls(ctx)

        self.remove_common_acls(neutron_acls, nb_acls)

        LOG.debug('ACLs-to-be-addded %d ACLs-to-be-removed %d' %
                  (len(list(itertools.chain(*six.itervalues(neutron_acls)))),
                   len(list(itertools.chain(*six.itervalues(nb_acls))))))

        if self.mode == SYNC_MODE_REPAIR:
            LOG.debug('ACL-SYNC: transaction started @ %s' %
                      str(datetime.now()))
            with self.ovn_api.transaction(check_error=True) as txn:
                for acla in list(itertools.chain(
                                 *six.itervalues(neutron_acls))):
                    txn.add(self.ovn_api.add_acl(**acla))
                for aclr in list(itertools.chain(*six.itervalues(nb_acls))):
                    # Both lswitch and lport aren't needed within the ACL.
                    lswitchr = aclr.pop('lswitch').replace('neutron-', '')
                    lportr = aclr.pop('lport')
                    aclr_dict = {lportr: aclr}
                    txn.add(self.ovn_api.update_acls([lswitchr],
                                                     [lportr],
                                                     aclr_dict,
                                                     need_compare=False,
                                                     is_add_acl=False))
            LOG.debug('ACL-SYNC: transaction finished @ %s' %
                      str(datetime.now()))

    def sync_routers_and_rports(self, ctx):
        """Sync Routers between neutron and NB.

        @param ctx: neutron context
        @type  ctx: object of type neutron.context.Context
        @var   db_routers: List of Routers from neutron DB
        @var   db_router_ports: List of Router ports from neutron DB
        @var   lrouters: NB dictionary of logical routers and
               the corresponding logical router ports.
               vs list-of-acls
        @var   del_lrouters_list: List of Routers that need to be
               deleted from NB
        @var   del_lrouter_ports_list: List of Router ports that need to be
               deleted from NB
        @return: Nothing
        """
        if not config.is_ovn_l3():
            LOG.debug("OVN L3 mode is disabled, skipping "
                      "sync routers and router ports")
            return

        LOG.debug('OVN-NB Sync Routers and Router ports started')
        db_routers = {}
        db_router_ports = {}
        for router in self.l3_plugin.get_routers(ctx):
            db_routers[router['id']] = router

        interfaces = self.l3_plugin._get_sync_interfaces(ctx,
                                                         db_routers.keys())
        for interface in interfaces:
            db_router_ports[interface['id']] = interface
        lrouters = self.ovn_api.get_all_logical_routers_with_rports()
        del_lrouters_list = []
        del_lrouter_ports_list = []
        update_sroutes_list = []
        for lrouter in lrouters:
            if lrouter['name'] in db_routers:
                for lrport in lrouter['ports']:
                    if lrport in db_router_ports:
                        del db_router_ports[lrport]
                    else:
                        del_lrouter_ports_list.append(
                            {'port': lrport, 'lrouter': lrouter['name']})
                if 'routes' in db_routers[lrouter['name']]:
                    db_routes = db_routers[lrouter['name']]['routes']
                else:
                    db_routes = []
                ovn_routes = lrouter['static_routes']
                add_routes, del_routes = n_utils.diff_list_of_dict(
                    ovn_routes, db_routes)
                update_sroutes_list.append({'id': lrouter['name'],
                                            'add': add_routes,
                                            'del': del_routes})
                del db_routers[lrouter['name']]
            else:
                del_lrouters_list.append(lrouter)

        for r_id, router in db_routers.items():
            LOG.warning(_LW("Router found in Neutron but not in "
                            "OVN DB, router id=%s"), router['id'])
            if self.mode == SYNC_MODE_REPAIR:
                try:
                    LOG.warning(_LW("Creating the router %s in OVN NB DB"),
                                router['id'])
                    self.l3_plugin.create_lrouter_in_ovn(router)
                    if 'routes' in router:
                        update_sroutes_list.append(
                            {'id': router['id'], 'add': router['routes'],
                             'del': []})
                except RuntimeError:
                    LOG.warning(_LW("Create router in OVN NB failed for"
                                    " router %s"), router['id'])

        for rp_id, rrport in db_router_ports.items():
            LOG.warning(_LW("Router Port found in Neutron but not in OVN "
                            "DB, router port_id=%s"), rrport['id'])
            if self.mode == SYNC_MODE_REPAIR:
                try:
                    LOG.warning(_LW("Creating the router port %s in "
                                    "OVN NB DB"), rrport['id'])
                    self.l3_plugin.create_lrouter_port_in_ovn(
                        ctx, rrport['device_id'], rrport)
                except RuntimeError:
                    LOG.warning(_LW("Create router port in OVN "
                                    "NB failed for"
                                    " router port %s"), rrport['id'])

        with self.ovn_api.transaction(check_error=True) as txn:
            for lrouter in del_lrouters_list:
                LOG.warning(_LW("Router found in OVN but not in "
                                "Neutron, router id=%s"), lrouter['name'])
                if self.mode == SYNC_MODE_REPAIR:
                    LOG.warning(_LW("Deleting the router %s from OVN NB DB"),
                                lrouter['name'])
                    txn.add(self.ovn_api.delete_lrouter(
                            utils.ovn_name(lrouter['name'])))

            for lrport_info in del_lrouter_ports_list:
                LOG.warning(_LW("Router Port found in OVN but not in "
                                "Neutron, port_id=%s"), lrport_info['port'])
                if self.mode == SYNC_MODE_REPAIR:
                    LOG.warning(_LW("Deleting the port %s from OVN NB DB"),
                                lrport_info['port'])
                    txn.add(self.ovn_api.delete_lrouter_port(
                            utils.ovn_lrouter_port_name(lrport_info['port']),
                            utils.ovn_name(lrport_info['lrouter']),
                            if_exists=False))
            for sroute in update_sroutes_list:
                if sroute['add']:
                    LOG.warning("Router %s static routes %s found in "
                                "Neutron but not in OVN", sroute['id'],
                                sroute['add'])
                    if self.mode == SYNC_MODE_REPAIR:
                        LOG.warning(_LW("Add static routes %s to OVN NB DB"),
                                    sroute['add'])
                        for route in sroute['add']:
                            txn.add(self.ovn_api.add_static_route(
                                utils.ovn_name(sroute['id']),
                                ip_prefix=route['destination'],
                                nexthop=route['nexthop']))
                if sroute['del']:
                    LOG.warning("Router %s static routes %s found in "
                                "OVN but not in Neutron", sroute['id'],
                                sroute['del'])
                    if self.mode == SYNC_MODE_REPAIR:
                        LOG.warning(_LW("Delete static routes %s from OVN "
                                        "NB DB"), sroute['del'])
                        for route in sroute['del']:
                            txn.add(self.ovn_api.delete_static_route(
                                utils.ovn_name(sroute['id']),
                                ip_prefix=route['destination'],
                                nexthop=route['nexthop']))
        LOG.debug('OVN-NB Sync routers and router ports finished')

    def sync_networks_and_ports(self, ctx):
        LOG.debug('OVN-NB Sync networks and ports started')
        db_networks = {}
        for net in self.core_plugin.get_networks(ctx):
            db_networks[utils.ovn_name(net['id'])] = net

        db_ports = {}
        for port in self.core_plugin.get_ports(ctx):
            db_ports[port['id']] = port

        lswitches = self.ovn_api.get_all_logical_switches_with_ports()
        del_lswitchs_list = []
        del_lports_list = []
        for lswitch in lswitches:
            if lswitch['name'] in db_networks:
                for lport in lswitch['ports']:
                    if lport in db_ports:
                        del db_ports[lport]
                    else:
                        del_lports_list.append({'port': lport,
                                                'lswitch': lswitch['name']})
                del db_networks[lswitch['name']]
            else:
                del_lswitchs_list.append(lswitch)

        for net_id, network in db_networks.items():
            LOG.warning(_LW("Network found in Neutron but not in "
                            "OVN DB, network_id=%s"), network['id'])
            if self.mode == SYNC_MODE_REPAIR:
                try:
                    LOG.debug('Creating the network %s in OVN NB DB',
                              network['id'])
                    self._create_network_in_ovn(network)
                except RuntimeError:
                    LOG.warning(_LW("Create network in OVN NB failed for"
                                    " network %s"), network['id'])

        for port_id, port in db_ports.items():
            LOG.warning(_LW("Port found in Neutron but not in OVN "
                            "DB, port_id=%s"), port['id'])
            if self.mode == SYNC_MODE_REPAIR:
                try:
                    LOG.debug('Creating the port %s in OVN NB DB',
                              port['id'])
                    self._create_port_in_ovn(ctx, port)
                except RuntimeError:
                    LOG.warning(_LW("Create port in OVN NB failed for"
                                    " port %s"), port['id'])

        with self.ovn_api.transaction(check_error=True) as txn:
            for lswitch in del_lswitchs_list:
                LOG.warning(_LW("Network found in OVN but not in "
                                "Neutron, network_id=%s"), lswitch['name'])
                if self.mode == SYNC_MODE_REPAIR:
                    LOG.debug('Deleting the network %s from OVN NB DB',
                              lswitch['name'])
                    txn.add(self.ovn_api.delete_lswitch(
                        lswitch_name=lswitch['name']))

            for lport_info in del_lports_list:
                LOG.warning(_LW("Port found in OVN but not in "
                                "Neutron, port_id=%s"), lport_info['port'])
                if self.mode == SYNC_MODE_REPAIR:
                    LOG.debug('Deleting the port %s from OVN NB DB',
                              lport_info['port'])
                    txn.add(self.ovn_api.delete_lswitch_port(
                        lport_name=lport_info['port'],
                        lswitch_name=lport_info['lswitch']))
        LOG.debug('OVN-NB Sync networks and ports finished')


class OvnSbSynchronizer(OvnDbSynchronizer):
    """Synchronizer class for SB."""

    def _sync(self):
        """Method to sync the OVN_Southbound DB with neutron DB.

        OvnSbSynchronizer will sync data from OVN_Southbound to neutron. And
        the synchronization will always be performed, no matter what mode it
        is.
        """
        # Initial delay until service is up
        greenthread.sleep(10)
        LOG.debug("Starting OVN-Southbound DB sync process")

        ctx = context.get_admin_context()
        self.sync_hostname_and_physical_networks(ctx)

    def sync_hostname_and_physical_networks(self, ctx):
        LOG.debug('OVN-SB Sync hostname and physical networks started')
        host_phynets_map = self.ovn_api.get_chassis_hostname_and_physnets()
        # TODO(xiaohhui): There is no function in neutron to check the existing
        # SegmentHostMapping. So update to neutron will always be triggered.
        # Neutron will update the DB if necessary.
        for host, phynets in six.iteritems(host_phynets_map):
            self.ovn_driver.update_segment_host_mapping(host, phynets)
        LOG.debug('OVN-SB Sync hostname and physical networks finished')

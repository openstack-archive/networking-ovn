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
#

import netaddr

from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.utils import helpers
from oslo_log import log
from oslo_utils import excutils

from neutron.db import common_db_mixin
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db
from neutron.extensions import l3
from neutron.services import service_base


from networking_ovn._i18n import _LE, _LI
from networking_ovn.common import config
from networking_ovn.common import constants as ovn_const
from networking_ovn.common import exceptions as exc
from networking_ovn.common import extensions
from networking_ovn.common import utils
from networking_ovn.l3 import l3_ovn_admin_net
from networking_ovn.l3 import l3_ovn_scheduler
from networking_ovn.ovsdb import impl_idl_ovn


LOG = log.getLogger(__name__)


class OVNL3RouterPlugin(service_base.ServicePluginBase,
                        common_db_mixin.CommonDbMixin,
                        extraroute_db.ExtraRoute_dbonly_mixin,
                        l3_gwmode_db.L3_NAT_db_mixin):
    """Implementation of the OVN L3 Router Service Plugin.

    This class implements a L3 service plugin that provides
    router and floatingip resources and manages associated
    request/response.
    """
    supported_extension_aliases = \
        extensions.ML2_SUPPORTED_API_EXTENSIONS_OVN_L3

    def __init__(self):
        LOG.info(_LI("Starting OVNL3RouterPlugin"))
        super(OVNL3RouterPlugin, self).__init__()
        self._nb_ovn_idl = None
        self._sb_ovn_idl = None
        self._plugin_property = None
        self.scheduler = l3_ovn_scheduler.get_scheduler()
        self._admin_net_mgr = None
        self._l3_admin_net_cidr = config.get_ovn_l3_admin_net_cidr()

    @property
    def _ovn(self):
        if self._nb_ovn_idl is None:
            LOG.info(_LI("Getting OvsdbNbOvnIdl"))
            self._nb_ovn_idl = impl_idl_ovn.OvsdbNbOvnIdl(self)
        return self._nb_ovn_idl

    @property
    def _sb_ovn(self):
        if self._sb_ovn_idl is None:
            LOG.info(_LI("Getting OvsdbSbOvnIdl"))
            self._sb_ovn_idl = impl_idl_ovn.OvsdbSbOvnIdl(self)
        return self._sb_ovn_idl

    @property
    def _plugin(self):
        if self._plugin_property is None:
            self._plugin_property = directory.get_plugin()
        return self._plugin_property

    @property
    def _admin_net(self):
        if self._admin_net_mgr is None:
            self._admin_net_mgr = l3_ovn_admin_net.OVNL3AdminNetwork(
                self._ovn, self._plugin, self._l3_admin_net_cidr)
        return self._admin_net_mgr

    def get_plugin_type(self):
        return n_const.L3

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("L3 Router Service Plugin for basic L3 forwarding"
                " using OVN")

    def _get_transit_network_ports(self, create=False):
        transit_net_ports = {}
        ports = self._admin_net.get_l3_admin_net_ports(
            ovn_const.OVN_L3_ADMIN_NET_PORT_NAMES,
            ovn_const.OVN_L3_ADMIN_NET_PORT_DEVICE_ID,
            ovn_const.OVN_L3_ADMIN_NET_PORT_DEVICE_OWNER, create)
        for port in ports:
            key = port['name'].lower()
            ip = port.get('fixed_ips')[0].get('ip_address')
            mac = port.get('mac_address')
            transit_net_ports[key] = {'ip': ip, 'mac_address': mac,
                                      'addresses': mac + ' ' + ip}

        return transit_net_ports

    def _check_and_delete_l3_admin_net(self, context):
        # Check if gateway ports are present, if not delete the l3 admin net
        filters = {'device_owner': [n_const.DEVICE_OWNER_ROUTER_GW]}
        gateway_ports = self._plugin.get_ports(context.elevated(),
                                               filters=filters)
        if gateway_ports:
            return

        # No gateway ports, delete the l3 admin net
        self._admin_net.delete_l3_admin_net_ports(
            context, ovn_const.OVN_L3_ADMIN_NET_PORT_NAMES,
            ovn_const.OVN_L3_ADMIN_NET_PORT_DEVICE_ID,
            ovn_const.OVN_L3_ADMIN_NET_PORT_DEVICE_OWNER)

    def _get_router_ports(self, context, router_id, get_gw_port=False):
        router_db = self._get_router(context.elevated(), router_id)
        if get_gw_port:
            return [p.port for p in router_db.attached_ports]
        else:
            return [p.port for p in router_db.attached_ports
                    if p.port_type == n_const.DEVICE_OWNER_ROUTER_INTF]

    def _get_v4_network_of_all_router_ports(self, context, router_id,
                                            ports=None):
        networks = []
        ports = ports or self._get_router_ports(context, router_id)
        for port in ports:
            network = self._get_v4_network_for_router_port(context, port)
            if network:
                networks.append(network)

        return networks

    def _get_router_ip(self, context, router):
        ext_gw_info = router.get('external_gateway_info', {})
        ext_fixed_ips = ext_gw_info.get('external_fixed_ips', [])
        for ext_fixed_ip in ext_fixed_ips:
            subnet_id = ext_fixed_ip['subnet_id']
            subnet = self._plugin.get_subnet(context.elevated(), subnet_id)
            if subnet['ip_version'] == 4:
                return ext_fixed_ip['ip_address']

    def _get_external_gateway_ip(self, context, router):
        ext_gw_info = router.get('external_gateway_info', {})
        ext_fixed_ips = ext_gw_info.get('external_fixed_ips', [])
        for ext_fixed_ip in ext_fixed_ips:
            subnet_id = ext_fixed_ip['subnet_id']
            subnet = self._plugin.get_subnet(context.elevated(), subnet_id)
            if subnet['ip_version'] == 4:
                return subnet.get('gateway_ip')

    def _is_snat_enabled(self, router):
        enable_snat = router.get(l3.EXTERNAL_GW_INFO, {}).get(
            'enable_snat', 'True')
        if enable_snat == 'False':
            return False
        else:
            return True

    def _get_v4_network_for_router_port(self, context, port):
        cidr = None
        for fixed_ip in port['fixed_ips']:
            subnet_id = fixed_ip['subnet_id']
            subnet = self._plugin.get_subnet(context, subnet_id)
            if subnet['ip_version'] != 4:
                continue
            cidr = subnet['cidr']
        return cidr

    def _get_lrouter_connected_to_nexthop(self, context, router_id,
                                          router_ports, nexthop):
        """Find lrouter connected to nexthop

        @param router_id: router id
        @param router_ports: router ports in router
        @param nexthop: nexthop
        @return: distributed logical router name or gateway router name or None
        """

        lrouter_name = None
        for port in router_ports:
            found_nexthop = False
            for fixed_ip in port.get('fixed_ips', []):
                subnet_id = fixed_ip['subnet_id']
                subnet = self._plugin.get_subnet(context.elevated(), subnet_id)
                network = netaddr.IPNetwork(subnet['cidr'])
                if netaddr.IPAddress(nexthop) in network:
                    if port['device_owner'] == n_const.DEVICE_OWNER_ROUTER_GW:
                        # Nexthop is in external network
                        lrouter_name = utils.ovn_gateway_router_name(router_id)
                    else:
                        # Next hop is in tenant network
                        lrouter_name = utils.ovn_name(router_id)
                    found_nexthop = True
                    break
            if found_nexthop:
                break
        if not lrouter_name:
            raise exc.L3RouterPluginStaticRouteError(nexthop=nexthop,
                                                     router=router_id)

        return lrouter_name

    def _add_router_ext_gw(self, context, router):
        # TODO(chandrav): Add sync support, bug #1629076 to track this.
        transit_net_ports = self._get_transit_network_ports(create=True)
        router_id = router['id']
        gw_lrouter_name = utils.ovn_gateway_router_name(router['id'])
        cleanup = []

        # 1. Create gateway router
        try:
            self.create_lrouter_in_ovn(router, is_gateway_router=True)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Unable to create gateway router %s'),
                          gw_lrouter_name)
        cleanup.append('gw_router')

        # 2. Add the external gateway router port to gateway router.
        ext_gw_ip = self._get_external_gateway_ip(context, router)
        gw_port_id = router['gw_port_id']
        port = self._plugin.get_port(context.elevated(), gw_port_id)
        try:
            self.create_lrouter_port_in_ovn(context.elevated(),
                                            router_id, port,
                                            is_lrouter_gateway_router=True)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._delete_router_ext_gw(context, router_id, router,
                                           transit_net_ports, cleanup)
                LOG.error(_LE('Unable to add external router port %(id)s to'
                              'gateway_router %(name)s'),
                          {'id': port['id'], 'name': gw_lrouter_name})
        cleanup.append('ext_gw_port')

        # 3. Add default route in gateway router with nexthop as ext_gw_ip
        route = [{'destination': '0.0.0.0/0', 'nexthop': ext_gw_ip}]
        try:
            self._update_lrouter_routes(context, router_id, route, [],
                                        gw_lrouter_name)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._delete_router_ext_gw(context, router_id, router,
                                           transit_net_ports, cleanup)
                LOG.error(_LE('Error updating routes %(route)s in lrouter '
                              '%(name)s'), {'route': route,
                                            'name': gw_lrouter_name})
        cleanup.append('ext_gw_ip_nexthop')

        # 4. Join the logical router and gateway router
        try:
            self._join_lrouter_and_gw_lrouter(router, transit_net_ports)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._delete_router_ext_gw(context, router_id, router,
                                           transit_net_ports, cleanup)
                LOG.error(_LE('Error in connecting lrouter and gateway router '
                              'for router %s'), router_id)
        cleanup.append('join')

        # 5. Check if tenant router ports are already configured.
        # If snat is enabled, add snat rules and static routes for tenant
        # networks in gateway router
        # If snat is disabled, add only static routes for tenant networks in
        # gateway router (For traffic destined to floating ips)
        # Static routes are added with a nexthop of gtsp port ip in logical
        # router.
        try:
            networks = self._get_v4_network_of_all_router_ports(context,
                                                                router_id)
            if not networks:
                return
            nexthop = transit_net_ports['dtsp']['ip']
            if self._is_snat_enabled(router):
                self._update_snat_and_static_routes_for_networks(
                    context, router, networks, nexthop, enable_snat=True,
                    update_static_routes=True)
            else:
                routes = []
                for network in networks:
                    routes.append({'destination': network, 'nexthop': nexthop})
                self._update_lrouter_routes(
                    context, router_id, routes, remove=[],
                    lrouter_name=gw_lrouter_name)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._delete_router_ext_gw(context, router_id, router,
                                           transit_net_ports, cleanup)
                LOG.error(_LE('Error in updating SNAT for router %s'),
                          router_id)

    def _delete_router_ext_gw(self, context, router_id, router,
                              transit_net_ports=None, cleanup=None):
        transit_net_ports = transit_net_ports or \
            self._get_transit_network_ports()
        cleanup = cleanup or []
        gw_port_id = router['gw_port_id']
        gw_lrouter_name = utils.ovn_gateway_router_name(router_id)
        ext_gw_ip = self._get_external_gateway_ip(context, router)
        if 'join' in cleanup or not cleanup:
            self._disjoin_lrouter_and_gw_lrouter(router, transit_net_ports)
        with self._ovn.transaction(check_error=True) as txn:
            if 'ext_gw_ip_nexthop' in cleanup or not cleanup:
                txn.add(self._ovn.delete_static_route(gw_lrouter_name,
                                                      ip_prefix='0.0.0.0/0',
                                                      nexthop=ext_gw_ip))
            if 'ext_gw_port' in cleanup or not cleanup:
                txn.add(self._ovn.delete_lrouter_port(
                    utils.ovn_lrouter_port_name(gw_port_id),
                    gw_lrouter_name))
        if 'gw_router' in cleanup or not cleanup:
            self._delete_lrouter_in_ovn(router_id, is_gateway_router=True)
        self._check_and_delete_l3_admin_net(context)

    def _join_lrouter_and_gw_lrouter(self, router, transit_net_ports):
        router_id = router['id']
        lswitch_name = utils.ovn_transit_ls_name(router_id)

        dtsp_name = utils.ovn_dtsp_name(router_id)
        dtsp_addresses = transit_net_ports['dtsp']['addresses']

        gtsp_name = utils.ovn_gtsp_name(router_id)
        gtsp_addresses = transit_net_ports['gtsp']['addresses']

        gw_lrouter_name = utils.ovn_gateway_router_name(router_id)
        lrouter_name = utils.ovn_name(router_id)

        gtrp_name = utils.ovn_lrouter_port_name(utils.ovn_gtsp_name(router_id))
        gtrp_mac = transit_net_ports['gtsp']['mac_address']
        gtrp_ip = transit_net_ports['gtsp']['ip']
        cidr = netaddr.IPNetwork(self._l3_admin_net_cidr)
        gtrp_network = "%s/%s" % (gtrp_ip, str(cidr.prefixlen))

        dtrp_name = utils.ovn_lrouter_port_name(utils.ovn_dtsp_name(router_id))
        dtrp_mac = transit_net_ports['dtsp']['mac_address']
        dtrp_ip = transit_net_ports['dtsp']['ip']
        dtrp_network = "%s/%s" % (dtrp_ip, str(cidr.prefixlen))

        with self._ovn.transaction(check_error=True) as txn:
            # 1. Create a transit logical switch
            txn.add(self._ovn.create_lswitch(lswitch_name=lswitch_name))
            # 2. Add dtsp port
            txn.add(self._ovn.create_lswitch_port(lport_name=dtsp_name,
                                                  lswitch_name=lswitch_name,
                                                  addresses=dtsp_addresses,
                                                  enabled='True'))
            # 3. Add gtsp port
            txn.add(self._ovn.create_lswitch_port(lport_name=gtsp_name,
                                                  lswitch_name=lswitch_name,
                                                  addresses=gtsp_addresses,
                                                  enabled='True'))
            # 4. Add dtrp port in logical router
            txn.add(self._ovn.add_lrouter_port(name=dtrp_name,
                                               lrouter=lrouter_name,
                                               mac=dtrp_mac,
                                               networks=dtrp_network))
            txn.add(self._ovn.set_lrouter_port_in_lswitch_port(
                utils.ovn_dtsp_name(router_id), dtrp_name))

            # 5. Add gtrp port in gateway router
            txn.add(self._ovn.add_lrouter_port(name=gtrp_name,
                                               lrouter=gw_lrouter_name,
                                               mac=gtrp_mac,
                                               networks=gtrp_network))
            txn.add(self._ovn.set_lrouter_port_in_lswitch_port(
                utils.ovn_gtsp_name(router_id), gtrp_name))
            # 6. Add default static route in gateway router with nexthop as
            # gtrp ip
            txn.add(self._ovn.add_static_route(lrouter_name,
                                               ip_prefix='0.0.0.0/0',
                                               nexthop=gtrp_ip))

    def _disjoin_lrouter_and_gw_lrouter(self, router, transit_net_ports):
        router_id = router['id']
        lrouter_name = utils.ovn_name(router_id)
        gw_lrouter_name = utils.ovn_gateway_router_name(router_id)

        gtrp_ip = transit_net_ports['gtsp']['ip']
        gtrp_name = utils.ovn_lrouter_port_name(utils.ovn_gtsp_name(router_id))
        dtrp_name = utils.ovn_lrouter_port_name(utils.ovn_dtsp_name(router_id))

        lswitch_name = utils.ovn_transit_ls_name(router_id)
        dtsp_name = utils.ovn_dtsp_name(router_id)
        gtsp_name = utils.ovn_gtsp_name(router_id)

        with self._ovn.transaction(check_error=True) as txn:
            # 1. Delete default static route in gateway router
            txn.add(self._ovn.delete_static_route(
                lrouter_name, ip_prefix="0.0.0.0/0", nexthop=gtrp_ip))
            # 2. Delete gtrp port
            txn.add(self._ovn.delete_lrouter_port(gtrp_name, gw_lrouter_name))
            # 3. Delete dtrp port
            txn.add(self._ovn.delete_lrouter_port(dtrp_name, lrouter_name))
            # 4. Delete gtsp port
            txn.add(self._ovn.delete_lswitch_port(gtsp_name, lswitch_name))
            # 5. Delete dtsp port
            txn.add(self._ovn.delete_lswitch_port(dtsp_name, lswitch_name))
            # 6. Delete transit logical switch
            txn.add(self._ovn.delete_lswitch(lswitch_name))

    def create_router(self, context, router):
        router = super(OVNL3RouterPlugin, self).create_router(context, router)
        try:
            # Create distributed logical router
            self.create_lrouter_in_ovn(router)
            if router.get(l3.EXTERNAL_GW_INFO):
                self._add_router_ext_gw(context, router)
        except Exception:
            with excutils.save_and_reraise_exception():
                # Delete the logical router
                LOG.error(_LE('Unable to create lrouter for %s'), router['id'])
                super(OVNL3RouterPlugin, self).delete_router(context,
                                                             router['id'])
        return router

    def create_lrouter_in_ovn(self, router, is_gateway_router=None):
        """Create lrouter in OVN

        @param router: Router to be created in OVN
        @param is_gateway_router: Is router ovn gateway router
        @param nexthop: Nexthop for router
        @return: Nothing
        """

        external_ids = {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                        router.get('name', 'no_router_name')}
        enabled = router.get('admin_state_up')
        options = {}

        if is_gateway_router:
            lrouter_name = utils.ovn_gateway_router_name(router['id'])
            chassis = self.scheduler.select(self._ovn, self._sb_ovn,
                                            lrouter_name)
            options = {'chassis': chassis}
        else:
            lrouter_name = utils.ovn_name(router['id'])

        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.create_lrouter(lrouter_name,
                                             external_ids=external_ids,
                                             enabled=enabled,
                                             options=options))

    def update_router(self, context, id, router):
        original_router = self.get_router(context, id)
        result = super(OVNL3RouterPlugin, self).update_router(context, id,
                                                              router)
        gateway_new = result.get(l3.EXTERNAL_GW_INFO)
        gateway_old = original_router.get(l3.EXTERNAL_GW_INFO)

        try:
            if gateway_new and not gateway_old:
                # Route gateway is set
                self._add_router_ext_gw(context, result)
            elif gateway_old and not gateway_new:
                # router gateway is removed
                self._delete_router_ext_gw(context, id, original_router)
            elif gateway_new and gateway_old:
                # Check if external gateway has changed, if yes, delete the old
                # gateway and add the new gateway
                if gateway_old['network_id'] != gateway_new['network_id']:
                    self._delete_router_ext_gw(context, id, original_router)
                    self._add_router_ext_gw(context, result)

                # Check if snat has been enabled/disabled and update
                old_snat_state = gateway_old.get('enable_snat', 'True')
                new_snat_state = gateway_new.get('enable_snat', 'True')
                if old_snat_state != new_snat_state:
                    networks = self._get_v4_network_of_all_router_ports(
                        context, id)
                    self._update_snat_and_static_routes_for_networks(
                        context, result, networks, nexthop=None,
                        enable_snat=new_snat_state, update_static_routes=False)
        except Exception:
            with excutils.save_and_reraise_exception():
                revert_router = {}
                LOG.error(_LE('Unable to update lrouter for %s'), id)
                revert_router['router'] = original_router
                super(OVNL3RouterPlugin, self).update_router(context, id,
                                                             revert_router)

        # Check for change in admin_state_up
        update = {}
        router_name = utils.ovn_name(id)
        if 'admin_state_up' in router['router']:
            enabled = router['router']['admin_state_up']
            if enabled != original_router['admin_state_up']:
                update['enabled'] = enabled

        # Check for change in name
        if 'name' in router['router']:
            if router['router']['name'] != original_router['name']:
                external_ids = {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                                router['router']['name']}
                update['external_ids'] = external_ids

        if update:
            try:
                self._ovn.update_lrouter(router_name, **update).execute(
                    check_error=True)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE('Unable to update lrouter for %s'), id)
                    router['router'] = original_router
                    super(OVNL3RouterPlugin, self).update_router(context, id,
                                                                 router)

        # Check for route updates
        added = []
        removed = []
        if 'routes' in router['router']:
            routes = router['router']['routes']
            added, removed = helpers.diff_list_of_dict(
                original_router['routes'], routes)

        if added or removed:
            try:
                self._update_lrouter_routes(context, id, added, removed)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE('Unable to update static routes in lrouter '
                                  '%s'), id)
                    router['router'] = original_router
                    super(OVNL3RouterPlugin, self).update_router(context, id,
                                                                 router)

        return result

    def _update_snat_and_static_routes_for_networks(
            self, context, router, networks, nexthop, enable_snat=True,
            update_static_routes=True):
        apis = {}
        apis['nat'] = self._ovn.add_nat_rule_in_lrouter \
            if enable_snat else self._ovn.delete_nat_rule_in_lrouter
        apis['garp'] = self._ovn.add_nat_ip_to_lrport_peer_options if \
            enable_snat else self._ovn.delete_nat_ip_from_lrport_peer_options
        apis['route'] = self._ovn.add_static_route \
            if enable_snat else self._ovn.delete_static_route

        gw_port_id = router['gw_port_id']
        gw_lrouter_name = utils.ovn_gateway_router_name(router['id'])
        router_ip = self._get_router_ip(context, router)

        with self._ovn.transaction(check_error=True) as txn:
            for network in networks:
                txn.add(apis['nat'](gw_lrouter_name, type='snat',
                                    logical_ip=network,
                                    external_ip=router_ip))
                if update_static_routes:
                    txn.add(apis['route'](gw_lrouter_name, ip_prefix=network,
                                          nexthop=nexthop))
            if networks:
                txn.add(apis['garp'](gw_port_id, nat_ip=router_ip))

    def _update_lrouter_routes(self, context, router_id, add, remove,
                               lrouter_name=None):
        router_ports = lrouter_name or self._get_router_ports(context,
                                                              router_id,
                                                              get_gw_port=True)
        with self._ovn.transaction(check_error=True) as txn:
            for route in add:
                lrouter_name = lrouter_name or (
                    self._get_lrouter_connected_to_nexthop(context, router_id,
                                                           router_ports,
                                                           route['nexthop']))
                txn.add(self._ovn.add_static_route(
                    lrouter_name, ip_prefix=route['destination'],
                    nexthop=route['nexthop']))

            for route in remove:
                lrouter_name = lrouter_name or (
                    self._get_lrouter_connected_to_nexthop(context, router_id,
                                                           router_ports,
                                                           route['nexthop']))
                txn.add(self._ovn.delete_static_route(
                    lrouter_name, ip_prefix=route['destination'],
                    nexthop=route['nexthop']))

    def delete_router(self, context, id):
        original_router = self.get_router(context, id)
        super(OVNL3RouterPlugin, self).delete_router(context, id)
        ext_gw_info = original_router.get(l3.EXTERNAL_GW_INFO)
        try:
            if ext_gw_info:
                self._delete_router_ext_gw(context, id, original_router)
            self._delete_lrouter_in_ovn(id)
        except Exception:
            with excutils.save_and_reraise_exception():
                router = {}
                router['router'] = original_router
                super(OVNL3RouterPlugin, self).create_router(context, router)

    def _delete_lrouter_in_ovn(self, id, is_gateway_router=False):
        if is_gateway_router:
            lrouter_name = utils.ovn_gateway_router_name(id)
        else:
            lrouter_name = utils.ovn_name(id)
        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.delete_lrouter(lrouter_name))

    def get_networks_for_lrouter_port(self, context, port_fixed_ips):
        networks = set()
        for fixed_ip in port_fixed_ips:
            subnet_id = fixed_ip['subnet_id']
            subnet = self._plugin.get_subnet(context, subnet_id)
            cidr = netaddr.IPNetwork(subnet['cidr'])
            networks.add("%s/%s" % (fixed_ip['ip_address'],
                                    str(cidr.prefixlen)))
        return list(networks)

    def create_lrouter_port_in_ovn(self, context, router_id, port,
                                   is_lrouter_gateway_router=False):
        """Create lrouter port in OVN

         @param router_id : LRouter ID for the port that needs to be created
         @param port : LRouter port that needs to be created
         @param is_lrouter_gateway_router : Is gateway router
         @return: Nothing
         """
        lrouter = utils.ovn_name(router_id) if not is_lrouter_gateway_router \
            else utils.ovn_gateway_router_name(router_id)
        networks = self.get_networks_for_lrouter_port(context,
                                                      port['fixed_ips'])

        lrouter_port_name = utils.ovn_lrouter_port_name(port['id'])
        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.add_lrouter_port(name=lrouter_port_name,
                                               lrouter=lrouter,
                                               mac=port['mac_address'],
                                               networks=networks))

            txn.add(self._ovn.set_lrouter_port_in_lswitch_port(
                port['id'], lrouter_port_name))

    def update_lrouter_port_in_ovn(self, context, router_id, port,
                                   networks=None):
        """Update lrouter port in OVN

        @param router id : LRouter ID for the port that needs to be updated
        @param port : LRouter port that needs to be updated
        @param networks : networks needs to be updated for LRouter port
        @return: Nothing
        """
        lrouter = utils.ovn_name(router_id)
        networks = self.get_networks_for_lrouter_port(context,
                                                      port['fixed_ips'])

        lrouter_port_name = utils.ovn_lrouter_port_name(port['id'])
        update = {'networks': networks}
        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.update_lrouter_port(name=lrouter_port_name,
                                                  lrouter=lrouter,
                                                  if_exists=False,
                                                  **update))
            txn.add(self._ovn.set_lrouter_port_in_lswitch_port(
                    port['id'], lrouter_port_name))

    def add_router_interface(self, context, router_id, interface_info):
        router_interface_info = \
            super(OVNL3RouterPlugin, self).add_router_interface(
                context, router_id, interface_info)
        port = self._plugin.get_port(context, router_interface_info['port_id'])

        multi_prefix = False
        if (len(router_interface_info['subnet_ids']) == 1 and
                len(port['fixed_ips']) > 1):
            # NOTE(lizk) It's adding a subnet onto an already existing router
            # interface port, try to update lrouter port 'networks' column.
            self.update_lrouter_port_in_ovn(context, router_id, port)
            multi_prefix = True
        else:
            self.create_lrouter_port_in_ovn(context, router_id, port)

        router = self.get_router(context, router_id)
        if not router.get(l3.EXTERNAL_GW_INFO):
            return router_interface_info

        cidr = None
        for fixed_ip in port['fixed_ips']:
            subnet = self._plugin.get_subnet(context, fixed_ip['subnet_id'])
            if multi_prefix:
                if 'subnet_id' in interface_info:
                    if subnet['id'] is not interface_info['subnet_id']:
                        continue
            if subnet['ip_version'] == 4:
                cidr = subnet['cidr']

        if not cidr:
            return router_interface_info

        try:
            transit_net_ports = self._get_transit_network_ports()
            nexthop = transit_net_ports['dtsp']['ip']
            gw_lrouter_name = utils.ovn_gateway_router_name(router_id)
            if self._is_snat_enabled(router):
                self._update_snat_and_static_routes_for_networks(
                    context, router, networks=[cidr], nexthop=nexthop,
                    enable_snat=True, update_static_routes=True)
            else:
                route = {'destination': cidr, 'nexthop': nexthop}
                self._update_lrouter_routes(
                    context, router_id, add=[route], remove=[],
                    lrouter_name=gw_lrouter_name)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._ovn.delete_lrouter_port(
                    utils.ovn_lrouter_port_name(port['id']),
                    utils.ovn_name(router_id)).execute(check_error=True)
                super(OVNL3RouterPlugin, self).remove_router_interface(
                    context, router_id, router_interface_info)
                LOG.error(_LE('Error updating snat for subnet %(subnet)s in '
                          'router %(router)s'),
                          {'subnet': router_interface_info['subnet_id'],
                           'router': router_id})

        return router_interface_info

    def remove_router_interface(self, context, router_id, interface_info):
        router_interface_info = \
            super(OVNL3RouterPlugin, self).remove_router_interface(
                context, router_id, interface_info)
        router = self.get_router(context, router_id)
        port_id = router_interface_info['port_id']
        multi_prefix = False
        try:
            port = self._plugin.get_port(context, port_id)
            # The router interface port still exists, call ovn to update it.
            self.update_lrouter_port_in_ovn(context, router_id, port)
            multi_prefix = True
        except n_exc.PortNotFound:
            # The router interface port doesn't exist any more, call ovn to
            # delete it.
            self._ovn.delete_lrouter_port(utils.ovn_lrouter_port_name(port_id),
                                          utils.ovn_name(router_id),
                                          if_exists=False
                                          ).execute(check_error=True)

        if not router.get(l3.EXTERNAL_GW_INFO):
            return router_interface_info

        try:
            cidr = None
            if multi_prefix:
                subnet = self._plugin.get_subnet(context,
                                                 interface_info['subnet_id'])
                if subnet['ip_version'] == 4:
                    cidr = subnet['cidr']
            else:
                subnet_ids = router_interface_info.get('subnet_ids')
                for subnet_id in subnet_ids:
                    subnet = self._plugin.get_subnet(context, subnet_id)
                    if subnet['ip_version'] == 4:
                        cidr = subnet['cidr']
                        break

            if not cidr:
                return router_interface_info

            router_name = utils.ovn_gateway_router_name(router_id)
            transit_net_ports = self._get_transit_network_ports()
            nexthop = transit_net_ports['dtsp']['ip']

            if self._is_snat_enabled(router):
                self._update_snat_and_static_routes_for_networks(
                    context, router, networks=[cidr], nexthop=nexthop,
                    enable_snat=False, update_static_routes=True)
            else:
                route = {'destination': cidr, 'nexthop': nexthop}
                self._update_lrouter_routes(
                    context, router_id, add=[route], remove=[],
                    lrouter_name=router_name)
        except Exception:
            with excutils.save_and_reraise_exception():
                super(OVNL3RouterPlugin, self).add_router_interface(
                    context, router_id, interface_info)
                LOG.error(_LE('Error is deleting snat'))

        return router_interface_info

    def create_floatingip(self, context, floatingip,
                          initial_status=n_const.FLOATINGIP_STATUS_ACTIVE):
        fip = super(OVNL3RouterPlugin, self).create_floatingip(
            context, floatingip,
            initial_status=n_const.FLOATINGIP_STATUS_ACTIVE)
        router_id = fip.get('router_id')
        if router_id:
            update_fip = {}
            fip_db = self._get_floatingip(context, fip['id'])
            # Elevating the context here, to pass this test case
            # OVNL3ExtrarouteTests.test_floatingip_association_on_unowned_
            # router
            router = self.get_router(context.elevated(), router_id)
            update_fip['fip_port_id'] = fip_db['floating_port_id']
            update_fip['fip_net_id'] = fip['floating_network_id']
            update_fip['logical_ip'] = fip['fixed_ip_address']
            update_fip['external_ip'] = fip['floating_ip_address']
            update_fip['gw_port_id'] = router['gw_port_id']
            try:
                self._update_floating_ip_in_ovn(context, router_id, update_fip)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE('Unable to create floating ip in gateway'
                              'router'))
        return fip

    def delete_floatingip(self, context, id):
        original_fip = self.get_floatingip(context, id)
        router_id = original_fip.get('router_id')
        super(OVNL3RouterPlugin, self).delete_floatingip(context, id)

        if router_id and original_fip.get('fixed_ip_address'):
            update_fip = {}
            router = self.get_router(context.elevated(), router_id)
            update_fip['logical_ip'] = original_fip['fixed_ip_address']
            update_fip['external_ip'] = original_fip['floating_ip_address']
            update_fip['gw_port_id'] = router['gw_port_id']
            try:
                self._update_floating_ip_in_ovn(context, router_id, update_fip,
                                                associate=False)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE('Error in disassociating floatingip: %s'),
                              id)

    def update_floatingip(self, context, id, floatingip):
        fip_db = self._get_floatingip(context, id)
        previous_fip = self._make_floatingip_dict(fip_db)
        previous_router_id = previous_fip.get('router_id')

        fip = super(OVNL3RouterPlugin, self).update_floatingip(context, id,
                                                               floatingip)
        new_router_id = fip['router_id']
        if previous_router_id:
            update_fip = {}
            router = self.get_router(context.elevated(), previous_router_id)
            update_fip['logical_ip'] = previous_fip['fixed_ip_address']
            update_fip['external_ip'] = fip['floating_ip_address']
            update_fip['gw_port_id'] = router['gw_port_id']
            try:
                self._update_floating_ip_in_ovn(context, previous_router_id,
                                                update_fip, associate=False)
                self.update_floatingip_status(context, id,
                                              n_const.FLOATINGIP_STATUS_DOWN)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE('Unable to update floating ip in '
                                  'gateway router'))

        if new_router_id:
            router = self.get_router(context.elevated(), new_router_id)
            update_fip = {}
            update_fip['fip_port_id'] = fip_db['floating_port_id']
            update_fip['fip_net_id'] = fip['floating_network_id']
            update_fip['logical_ip'] = fip['fixed_ip_address']
            update_fip['external_ip'] = fip['floating_ip_address']
            update_fip['gw_port_id'] = router['gw_port_id']
            try:
                self._update_floating_ip_in_ovn(context, new_router_id,
                                                update_fip)
                self.update_floatingip_status(context, id,
                                              n_const.FLOATINGIP_STATUS_ACTIVE)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE('Unable to update floating ip in '
                                  'gateway router'))

        return fip

    def _update_floating_ip_in_ovn(self, context, router_id, update,
                                   associate=True):
        fip_apis = {}
        fip_apis['nat'] = self._ovn.add_nat_rule_in_lrouter if \
            associate else self._ovn.delete_nat_rule_in_lrouter
        fip_apis['garp'] = self._ovn.add_nat_ip_to_lrport_peer_options if \
            associate else self._ovn.delete_nat_ip_from_lrport_peer_options
        gw_lrouter_name = utils.ovn_gateway_router_name(router_id)
        try:
            with self._ovn.transaction(check_error=True) as txn:
                nat_rule_args = (gw_lrouter_name,)
                if associate:
                    # TODO(chandrav): Since the floating ip port is not
                    # bound to any chassis, packets destined to floating ip
                    # will be dropped. To overcome this, delete the floating
                    # ip port. Proper fix for this would be to redirect packets
                    # destined to floating ip to the router port. This would
                    # require changes in ovn-northd.
                    txn.add(self._ovn.delete_lswitch_port(
                        update['fip_port_id'],
                        utils.ovn_name(update['fip_net_id'])))

                    # Get the list of nat rules and check if the external_ip
                    # with type 'dnat_and_snat' already exists or not.
                    # If exists, set the new value.
                    # This happens when the port associated to a floating ip
                    # is deleted before the disassociation.
                    lrouter_nat_rules = self._ovn.get_lrouter_nat_rules(
                        gw_lrouter_name)
                    for nat_rule in lrouter_nat_rules:
                        if nat_rule['external_ip'] == update['external_ip'] \
                            and nat_rule['type'] == 'dnat_and_snat':
                            fip_apis['nat'] = self._ovn.set_nat_rule_in_lrouter
                            nat_rule_args = (gw_lrouter_name, nat_rule['uuid'])
                            break

                txn.add(fip_apis['nat'](*nat_rule_args, type='dnat_and_snat',
                                        logical_ip=update['logical_ip'],
                                        external_ip=update['external_ip']))
                txn.add(fip_apis['garp'](update['gw_port_id'],
                                         nat_ip=update['external_ip']))
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Unable to update NAT rule in gateway router'))

    def schedule_unhosted_routers(self):
        valid_chassis_list = self._sb_ovn.get_all_chassis()
        unhosted_routers = self._ovn.get_unhosted_routers(valid_chassis_list)
        if unhosted_routers:
            with self._ovn.transaction(check_error=True) as txn:
                for r_name, r_options in unhosted_routers.items():
                    chassis = self.scheduler.select(self._ovn, self._sb_ovn,
                                                    r_name)
                    r_options['chassis'] = chassis
                    txn.add(self._ovn.update_lrouter(r_name,
                                                     options=r_options))

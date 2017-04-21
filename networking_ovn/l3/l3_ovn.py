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

from neutron_lib.api.definitions import l3
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from neutron_lib.utils import helpers
from oslo_log import log
from oslo_utils import excutils

from neutron.db import common_db_mixin
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db

from networking_ovn.common import constants as ovn_const
from networking_ovn.common import extensions
from networking_ovn.common import utils
from networking_ovn.l3 import l3_ovn_scheduler
from networking_ovn.ovsdb import impl_idl_ovn


LOG = log.getLogger(__name__)


@registry.has_registry_receivers
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
        LOG.info("Starting OVNL3RouterPlugin")
        super(OVNL3RouterPlugin, self).__init__()
        self._nb_ovn_idl = None
        self._sb_ovn_idl = None
        self._plugin_property = None
        self.scheduler = l3_ovn_scheduler.get_scheduler()

    @property
    def _ovn(self):
        if self._nb_ovn_idl is None:
            LOG.info("Getting OvsdbNbOvnIdl")
            conn = impl_idl_ovn.get_connection(impl_idl_ovn.OvsdbNbOvnIdl)
            self._nb_ovn_idl = impl_idl_ovn.OvsdbNbOvnIdl(conn)
        return self._nb_ovn_idl

    @property
    def _sb_ovn(self):
        if self._sb_ovn_idl is None:
            LOG.info("Getting OvsdbSbOvnIdl")
            conn = impl_idl_ovn.get_connection(impl_idl_ovn.OvsdbSbOvnIdl)
            self._sb_ovn_idl = impl_idl_ovn.OvsdbSbOvnIdl(conn)
        return self._sb_ovn_idl

    @property
    def _plugin(self):
        if self._plugin_property is None:
            self._plugin_property = directory.get_plugin()
        return self._plugin_property

    def get_plugin_type(self):
        return n_const.L3

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("L3 Router Service Plugin for basic L3 forwarding"
                " using OVN")

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

    def get_external_router_and_gateway_ip(self, context, router):
        ext_gw_info = router.get(l3.EXTERNAL_GW_INFO, {})
        ext_fixed_ips = ext_gw_info.get('external_fixed_ips', [])
        for ext_fixed_ip in ext_fixed_ips:
            subnet_id = ext_fixed_ip['subnet_id']
            subnet = self._plugin.get_subnet(context.elevated(), subnet_id)
            if subnet['ip_version'] == 4:
                return ext_fixed_ip['ip_address'], subnet.get('gateway_ip')
        return '', ''

    def _get_router_ip(self, context, router):
        router_ip, gateway_ip = self.get_external_router_and_gateway_ip(
            context, router)
        return router_ip

    def _get_external_gateway_ip(self, context, router):
        router_ip, gateway_ip = self.get_external_router_and_gateway_ip(
            context, router)
        return gateway_ip

    def _get_v4_network_for_router_port(self, context, port):
        cidr = None
        for fixed_ip in port['fixed_ips']:
            subnet_id = fixed_ip['subnet_id']
            subnet = self._plugin.get_subnet(context, subnet_id)
            if subnet['ip_version'] != 4:
                continue
            cidr = subnet['cidr']
        return cidr

    def _add_router_ext_gw(self, context, router):
        router_id = router['id']
        lrouter_name = utils.ovn_name(router['id'])

        # 1. Add the external gateway router port.
        ext_gw_ip = self._get_external_gateway_ip(context, router)
        gw_port_id = router['gw_port_id']
        port = self._plugin.get_port(context.elevated(), gw_port_id)
        try:
            self.create_lrouter_port_in_ovn(context.elevated(),
                                            router_id, port)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._delete_router_ext_gw(context, router_id, router)
                LOG.error('Unable to add external router port %(id)s to '
                          'lrouter %(name)s',
                          {'id': port['id'], 'name': lrouter_name})

        # 2. Add default route with nexthop as ext_gw_ip
        route = [{'destination': '0.0.0.0/0', 'nexthop': ext_gw_ip}]
        try:
            self._update_lrouter_routes(context, router_id, route, [])
        except Exception:
            with excutils.save_and_reraise_exception():
                self._delete_router_ext_gw(context, router_id, router)
                LOG.error('Error updating routes %(route)s in lrouter '
                          '%(name)s', {'route': route, 'name': lrouter_name})

        # 3. Add snat rules for tenant networks in lrouter if snat is enabled
        if utils.is_snat_enabled(router):
            try:
                networks = self._get_v4_network_of_all_router_ports(context,
                                                                    router_id)
                if networks:
                    self._update_snat_for_networks(context, router, networks,
                                                   enable_snat=True)
            except Exception:
                with excutils.save_and_reraise_exception():
                    self._delete_router_ext_gw(context, router_id, router)
                    LOG.error('Error in updating SNAT for lrouter %s',
                              lrouter_name)

    def _delete_router_ext_gw(self, context, router_id, router,
                              networks=None):
        gw_port_id = router['gw_port_id']
        gw_lrouter_name = utils.ovn_name(router_id)
        ext_gw_ip = self._get_external_gateway_ip(context, router)
        router_ip = self._get_router_ip(context, router)
        # Only get networks when networks is None
        networks = self._get_v4_network_of_all_router_ports(
            context, router_id) if networks is None else networks

        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.delete_static_route(gw_lrouter_name,
                                                  ip_prefix='0.0.0.0/0',
                                                  nexthop=ext_gw_ip))
            txn.add(self._ovn.delete_lrouter_port(
                utils.ovn_lrouter_port_name(gw_port_id),
                gw_lrouter_name))
            for network in networks:
                txn.add(self._ovn.delete_nat_rule_in_lrouter(
                    gw_lrouter_name, type='snat', logical_ip=network,
                    external_ip=router_ip))

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
                LOG.error('Unable to create lrouter for %s', router['id'])
                super(OVNL3RouterPlugin, self).delete_router(context,
                                                             router['id'])
        return router

    def create_lrouter_in_ovn(self, router):
        """Create lrouter in OVN

        @param router: Router to be created in OVN
        @return: Nothing
        """

        external_ids = {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                        router.get('name', 'no_router_name')}
        enabled = router.get('admin_state_up')
        lrouter_name = utils.ovn_name(router['id'])
        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.create_lrouter(lrouter_name,
                                             external_ids=external_ids,
                                             enabled=enabled,
                                             options={}))

    def _check_external_ips_changed(self, gateway_old, gateway_new):
        if gateway_old['network_id'] != gateway_new['network_id']:
            return True
        old_ext_ips = gateway_old.get('external_fixed_ips', [])
        new_ext_ips = gateway_new.get('external_fixed_ips', [])
        old_subnet_ids = set(f['subnet_id'] for f in old_ext_ips
                             if f.get('subnet_id'))
        new_subnet_ids = set(f['subnet_id'] for f in new_ext_ips
                             if f.get('subnet_id'))
        if old_subnet_ids != new_subnet_ids:
            return True
        old_ip_addresses = set(f['ip_address'] for f in old_ext_ips
                               if f.get('ip_address'))
        new_ip_addresses = set(f['ip_address'] for f in new_ext_ips
                               if f.get('ip_address'))
        if old_ip_addresses != new_ip_addresses:
            return True
        return False

    def update_router(self, context, id, router):
        original_router = self.get_router(context, id)
        result = super(OVNL3RouterPlugin, self).update_router(context, id,
                                                              router)
        gateway_new = result.get(l3.EXTERNAL_GW_INFO)
        gateway_old = original_router.get(l3.EXTERNAL_GW_INFO)
        revert_router = {'router': original_router}
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
                if self._check_external_ips_changed(gateway_old, gateway_new):
                    self._delete_router_ext_gw(context, id, original_router)
                    self._add_router_ext_gw(context, result)
                else:
                    # Check if snat has been enabled/disabled and update
                    old_snat_state = gateway_old.get('enable_snat', True)
                    new_snat_state = gateway_new.get('enable_snat', True)
                    if old_snat_state != new_snat_state:
                        networks = self._get_v4_network_of_all_router_ports(
                            context, id)
                        self._update_snat_for_networks(
                            context, result, networks,
                            enable_snat=new_snat_state)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error('Unable to update lrouter for %s', id)
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
                    LOG.error('Unable to update lrouter for %s', id)
                    super(OVNL3RouterPlugin, self).update_router(context, id,
                                                                 revert_router)

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
                    LOG.error(
                        'Unable to update static routes in lrouter %s', id)
                    super(OVNL3RouterPlugin, self).update_router(context, id,
                                                                 revert_router)

        return result

    def _update_snat_for_networks(self, context, router, networks,
                                  enable_snat=True):
        apis = {'nat': self._ovn.add_nat_rule_in_lrouter
                if enable_snat else self._ovn.delete_nat_rule_in_lrouter}
        gw_lrouter_name = utils.ovn_name(router['id'])
        router_ip = self._get_router_ip(context, router)
        with self._ovn.transaction(check_error=True) as txn:
            for network in networks:
                txn.add(apis['nat'](gw_lrouter_name, type='snat',
                                    logical_ip=network,
                                    external_ip=router_ip))

    def _update_lrouter_routes(self, context, router_id, add, remove):
        lrouter_name = utils.ovn_name(router_id)
        with self._ovn.transaction(check_error=True) as txn:
            for route in add:
                txn.add(self._ovn.add_static_route(
                    lrouter_name, ip_prefix=route['destination'],
                    nexthop=route['nexthop']))
            for route in remove:
                txn.add(self._ovn.delete_static_route(
                    lrouter_name, ip_prefix=route['destination'],
                    nexthop=route['nexthop']))

    def delete_router(self, context, id):
        original_router = self.get_router(context, id)
        super(OVNL3RouterPlugin, self).delete_router(context, id)
        try:
            self._delete_lrouter_in_ovn(id)
        except Exception:
            with excutils.save_and_reraise_exception():
                super(OVNL3RouterPlugin, self).create_router(
                    context, {'router': original_router})

    def _delete_lrouter_in_ovn(self, id):
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

    def create_lrouter_port_in_ovn(self, context, router_id, port):
        """Create lrouter port in OVN

         @param router_id : LRouter ID for the port that needs to be created
         @param port : LRouter port that needs to be created
         @return: Nothing
         """
        lrouter = utils.ovn_name(router_id)
        networks = self.get_networks_for_lrouter_port(context,
                                                      port['fixed_ips'])

        lrouter_port_name = utils.ovn_lrouter_port_name(port['id'])
        is_gw_port = n_const.DEVICE_OWNER_ROUTER_GW == port.get(
            'device_owner')
        columns = {}
        if is_gw_port:
            selected_chassis = self.scheduler.select(self._ovn, self._sb_ovn,
                                                     lrouter_port_name)
            columns['options'] = {
                ovn_const.OVN_GATEWAY_CHASSIS_KEY: selected_chassis}
        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.add_lrouter_port(name=lrouter_port_name,
                                               lrouter=lrouter,
                                               mac=port['mac_address'],
                                               networks=networks,
                                               **columns))
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
        networks = networks or self.get_networks_for_lrouter_port(
            context, port['fixed_ips'])

        lrouter_port_name = utils.ovn_lrouter_port_name(port['id'])
        update = {'networks': networks}
        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.update_lrouter_port(name=lrouter_port_name,
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
            if utils.is_snat_enabled(router):
                self._update_snat_for_networks(
                    context, router, networks=[cidr], enable_snat=True)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._ovn.delete_lrouter_port(
                    utils.ovn_lrouter_port_name(port['id']),
                    utils.ovn_name(router_id)).execute(check_error=True)
                super(OVNL3RouterPlugin, self).remove_router_interface(
                    context, router_id, router_interface_info)
                LOG.error('Error updating snat for subnet %(subnet)s in '
                          'router %(router)s',
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

            if utils.is_snat_enabled(router):
                self._update_snat_for_networks(
                    context, router, networks=[cidr], enable_snat=False)
        except Exception:
            with excutils.save_and_reraise_exception():
                super(OVNL3RouterPlugin, self).add_router_interface(
                    context, router_id, interface_info)
                LOG.error('Error is deleting snat')

        return router_interface_info

    def create_floatingip(self, context, floatingip,
                          initial_status=n_const.FLOATINGIP_STATUS_DOWN):
        fip = super(OVNL3RouterPlugin, self).create_floatingip(
            context, floatingip, initial_status)
        router_id = fip.get('router_id')
        if router_id:
            update_fip = {}
            fip_db = self._get_floatingip(context, fip['id'])
            update_fip['fip_port_id'] = fip_db['floating_port_id']
            update_fip['fip_net_id'] = fip['floating_network_id']
            update_fip['logical_ip'] = fip['fixed_ip_address']
            update_fip['external_ip'] = fip['floating_ip_address']
            try:
                self._update_floating_ip_in_ovn(context, router_id, update_fip)
                self.update_floatingip_status(context, fip['id'],
                                              n_const.FLOATINGIP_STATUS_ACTIVE)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error('Unable to create floating ip in gateway router')
        return fip

    def delete_floatingip(self, context, id):
        original_fip = self.get_floatingip(context, id)
        router_id = original_fip.get('router_id')
        super(OVNL3RouterPlugin, self).delete_floatingip(context, id)

        if router_id and original_fip.get('fixed_ip_address'):
            update_fip = {}
            update_fip['logical_ip'] = original_fip['fixed_ip_address']
            update_fip['external_ip'] = original_fip['floating_ip_address']
            try:
                self._update_floating_ip_in_ovn(context, router_id, update_fip,
                                                associate=False)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error('Error in disassociating floatingip: %s', id)

    def update_floatingip(self, context, id, floatingip):
        fip_db = self._get_floatingip(context, id)
        previous_fip = self._make_floatingip_dict(fip_db)
        previous_port_id = previous_fip.get('port_id')

        fip = super(OVNL3RouterPlugin, self).update_floatingip(context, id,
                                                               floatingip)
        new_port_id = fip.get('port_id')
        fip_status = None
        if previous_port_id and (
            previous_port_id != new_port_id or (
                previous_fip['fixed_ip_address'] != fip['fixed_ip_address'])):
            # 1. Floating IP dissociated
            # 2. Floating IP re-associated to a new port
            # 3. Floating IP re-associated to a new fixed_ip (same port)
            update_fip = {}
            update_fip['logical_ip'] = previous_fip['fixed_ip_address']
            update_fip['external_ip'] = fip['floating_ip_address']
            try:
                self._update_floating_ip_in_ovn(context,
                                                previous_fip['router_id'],
                                                update_fip, associate=False)
                fip_status = n_const.FLOATINGIP_STATUS_DOWN
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error('Unable to update floating ip in gateway router')

        if new_port_id:
            update_fip = {}
            update_fip['fip_port_id'] = fip_db['floating_port_id']
            update_fip['fip_net_id'] = fip['floating_network_id']
            update_fip['logical_ip'] = fip['fixed_ip_address']
            update_fip['external_ip'] = fip['floating_ip_address']
            try:
                self._update_floating_ip_in_ovn(context, fip['router_id'],
                                                update_fip)
                fip_status = n_const.FLOATINGIP_STATUS_ACTIVE
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error('Unable to update floating ip in gateway router')

        if fip_status:
            self.update_floatingip_status(context, id, fip_status)

        return fip

    def disassociate_floatingips(self, context, port_id, do_notify=True):
        fips = self.get_floatingips(context.elevated(),
                                    filters={'port_id': [port_id]})
        router_ids = super(OVNL3RouterPlugin, self).disassociate_floatingips(
            context, port_id, do_notify)
        for fip in fips:
            router_id = fip.get('router_id')
            fixed_ip_address = fip.get('fixed_ip_address')
            if router_id and fixed_ip_address:
                update_fip = {'logical_ip': fixed_ip_address,
                              'external_ip': fip['floating_ip_address']}
                try:
                    self._update_floating_ip_in_ovn(
                        context, router_id, update_fip, associate=False)
                    self.update_floatingip_status(
                        context, fip['id'], n_const.FLOATINGIP_STATUS_DOWN)
                except Exception as e:
                    LOG.error('Error in disassociating floatingip %(id)s: '
                              '%(error)s', {'id': fip['id'], 'error': e})
        return router_ids

    def _update_floating_ip_in_ovn(self, context, router_id, update,
                                   associate=True):
        fip_apis = {}
        fip_apis['nat'] = self._ovn.add_nat_rule_in_lrouter if \
            associate else self._ovn.delete_nat_rule_in_lrouter
        gw_lrouter_name = utils.ovn_name(router_id)
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
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error('Unable to update NAT rule in gateway router')

    def schedule_unhosted_gateways(self):
        valid_chassis_list = self._sb_ovn.get_all_chassis()
        unhosted_gateways = self._ovn.get_unhosted_gateways(
            valid_chassis_list)
        if unhosted_gateways:
            with self._ovn.transaction(check_error=True) as txn:
                for g_name, r_options in unhosted_gateways.items():
                    chassis = self.scheduler.select(self._ovn, self._sb_ovn,
                                                    g_name)
                    r_options['redirect-chassis'] = chassis
                    txn.add(self._ovn.update_lrouter_port(g_name,
                                                          options=r_options))

    @staticmethod
    @registry.receives(resources.SUBNET_GATEWAY,
                       [events.BEFORE_UPDATE, events.AFTER_UPDATE])
    def _subnet_gateway_ip_update(resource, event, trigger, **kwargs):
        l3plugin = directory.get_plugin(n_const.L3)
        if not l3plugin:
            return
        context = kwargs['context']
        network_id = kwargs['network_id']
        subnet_id = kwargs['subnet_id']
        gw_ports = l3plugin._plugin.get_ports(context, filters={
            'network_id': [network_id],
            'device_owner': [n_const.DEVICE_OWNER_ROUTER_GW],
            'fixed_ips': {'subnet_id': [subnet_id]},
        })
        router_ids = set(port['device_id'] for port in gw_ports)
        gateway_ip = l3plugin._plugin.get_subnet(context, subnet_id). \
            get('gateway_ip')
        add = []
        remove = []
        if event == events.AFTER_UPDATE:
            add = [{'destination': '0.0.0.0/0', 'nexthop': gateway_ip}]
        elif event == events.BEFORE_UPDATE:
            remove = [{'destination': '0.0.0.0/0', 'nexthop': gateway_ip}]
        for router_id in router_ids:
            l3plugin._update_lrouter_routes(None, router_id, add, remove)

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

from neutron_lib.api.definitions import l3
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from oslo_log import log
from oslo_utils import excutils

from neutron.db import common_db_mixin
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db

from networking_ovn.common import extensions
from networking_ovn.common import ovn_client
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
        self._ovn_client_inst = None
        self.scheduler = l3_ovn_scheduler.get_scheduler()

    @property
    def _ovn_client(self):
        if self._ovn_client_inst is None:
            self._ovn_client_inst = ovn_client.OVNClient(self._ovn,
                                                         self._sb_ovn)
        return self._ovn_client_inst

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

    def _get_v4_network_for_router_port(self, context, port):
        cidr = None
        for fixed_ip in port['fixed_ips']:
            subnet_id = fixed_ip['subnet_id']
            subnet = self._plugin.get_subnet(context, subnet_id)
            if subnet['ip_version'] != 4:
                continue
            cidr = subnet['cidr']
        return cidr

    def create_router(self, context, router):
        router = super(OVNL3RouterPlugin, self).create_router(context, router)
        networks = self._get_v4_network_of_all_router_ports(
            context, router['id'])
        try:
            self._ovn_client.create_router(router, networks=networks)
        except Exception:
            with excutils.save_and_reraise_exception():
                # Delete the logical router
                LOG.error('Unable to create lrouter for %s', router['id'])
                super(OVNL3RouterPlugin, self).delete_router(context,
                                                             router['id'])
        return router

    def update_router(self, context, id, router):
        original_router = self.get_router(context, id)
        result = super(OVNL3RouterPlugin, self).update_router(context, id,
                                                              router)
        networks = self._get_v4_network_of_all_router_ports(context, id)
        try:
            self._ovn_client.update_router(
                result, original_router, router, networks)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception('Unable to update lrouter for %s', id)
                revert_router = {'router': original_router}
                super(OVNL3RouterPlugin, self).update_router(context, id,
                                                             revert_router)
        return result

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
            self._ovn_client.delete_router(id)
        except Exception:
            with excutils.save_and_reraise_exception():
                super(OVNL3RouterPlugin, self).create_router(
                    context, {'router': original_router})

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
            self._ovn_client.update_router_port(router_id, port)
            multi_prefix = True
        else:
            self._ovn_client.create_router_port(router_id, port)

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

        if utils.is_snat_enabled(router) and cidr:
            try:
                self._ovn_client.update_nat_rules(router, networks=[cidr],
                                                  enable_snat=True)
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
            self._ovn_client.update_router_port(router_id, port)
            multi_prefix = True
        except n_exc.PortNotFound:
            # The router interface port doesn't exist any more, call ovn to
            # delete it.
            self._ovn_client.delete_router_port(port_id, router_id)

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

            if utils.is_snat_enabled(router) and cidr:
                self._ovn_client.update_nat_rules(
                    router, networks=[cidr], enable_snat=False)
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
            self._ovn_client.create_floatingip(update_fip, router_id)

            # NOTE(lucasagomes): Revise the expected status
            # of floating ips, setting it to ACTIVE here doesn't
            # see consistent with other drivers (ODL here), see:
            # https://bugs.launchpad.net/networking-ovn/+bug/1657693
            self.update_floatingip_status(context, fip['id'],
                                          n_const.FLOATINGIP_STATUS_ACTIVE)
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
                self._ovn_client.delete_floatingip(update_fip, router_id)
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
                self._ovn_client.update_floatingip(
                    update_fip, previous_fip['router_id'], associate=False)
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
                self._ovn_client.update_floatingip(
                    update_fip, fip['router_id'], associate=True)
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
                    self._ovn_client.disassociate_floatingip(update_fip,
                                                             router_id)
                    self.update_floatingip_status(
                        context, fip['id'], n_const.FLOATINGIP_STATUS_DOWN)
                except Exception as e:
                    LOG.error('Error in disassociating floatingip %(id)s: '
                              '%(error)s', {'id': fip['id'], 'error': e})
        return router_ids

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
    @registry.receives(resources.SUBNET, [events.AFTER_UPDATE])
    def _subnet_update(resource, event, trigger, **kwargs):
        l3plugin = directory.get_plugin(n_const.L3)
        if not l3plugin:
            return
        context = kwargs['context']
        orig = kwargs['original_subnet']
        current = kwargs['subnet']
        orig_gw_ip = orig['gateway_ip']
        current_gw_ip = current['gateway_ip']
        if orig_gw_ip == current_gw_ip:
            return
        gw_ports = l3plugin._plugin.get_ports(context, filters={
            'network_id': [orig['network_id']],
            'device_owner': [n_const.DEVICE_OWNER_ROUTER_GW],
            'fixed_ips': {'subnet_id': [orig['id']]},
        })
        router_ids = set([port['device_id'] for port in gw_ports])
        remove = [{'destination': '0.0.0.0/0', 'nexthop': orig_gw_ip}
                  ] if orig_gw_ip else []
        add = [{'destination': '0.0.0.0/0', 'nexthop': current_gw_ip}
               ] if current_gw_ip else []
        for router_id in router_ids:
            l3plugin._update_lrouter_routes(context, router_id, add, remove)

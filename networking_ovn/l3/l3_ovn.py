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
import six

from neutron.common import utils as n_utils
from neutron_lib import exceptions as n_exc
from oslo_log import log

from neutron.db import common_db_mixin
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron import manager
from neutron.plugins.common import constants
from neutron.services import service_base
from neutron.api.v2 import attributes
from neutron.extensions import l3

from networking_ovn._i18n import _LE, _LI
from networking_ovn.common import constants as ovn_const
from networking_ovn.common import extensions
from networking_ovn.common import utils
from networking_ovn.common import config as cfg
from networking_ovn.l3 import l3_ovn_scheduler
from networking_ovn.ovsdb import impl_idl_ovn


LOG = log.getLogger(__name__)


class OVNL3RouterPlugin(service_base.ServicePluginBase,
                        common_db_mixin.CommonDbMixin,
                        extraroute_db.ExtraRoute_dbonly_mixin):
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
            self._plugin_property = manager.NeutronManager.get_plugin()
        return self._plugin_property

    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("L3 Router Service Plugin for basic L3 forwarding"
                " using OVN")

    def get_gw_router_name(self, router_id):
        return "gateway-" + router_id

    def create_router(self, context, router):
        router = super(OVNL3RouterPlugin, self).create_router(
            context, router)
        try:
            self.create_lrouter_in_ovn(router)
        except Exception:
            LOG.exception(_LE('Unable to create lrouter for %s'),
                          router['id'])
            super(OVNL3RouterPlugin, self).delete_router(context, router['id'])
            raise n_exc.ServiceUnavailable()

        return router

    def create_lrouter_in_ovn(self, router):
        """Create lrouter in OVN

        @param router: Router to be created in OVN
        @return: Nothing
        """

        router_name = utils.ovn_name(router['id'])
        external_ids = {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                        router.get('name', 'no_router_name')}
        enabled = router.get('admin_state_up')
        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.create_lrouter(router_name,
                                             external_ids=external_ids,
                                             enabled=enabled
                                             ))

    def create_gw_router_in_ovn(self, context, router, chassis, gw_port):
        """Create lrouter in OVN

        @param context:
        @param router: neutron Router
        @param chassis: chassis where gateway Router to be created
        @param gw_port: neutorn gw port
        @return: Nothing
        """
        dvr_router_name = utils.ovn_name(router['id'])
        gw_router_name = self.get_gw_router_name(router['id'])
        transit_switch_name = 'transit-'+router['id']
        router_options = {'chassis': chassis}
        with self._ovn.transaction(check_error=True) as txn:
            # add dvr-router-port .
            dvr_to_transit_port = {'mac_address': 'fa:16:3e:00:00:02', 'networks': '169.254.128.2/30'}
            txn.add(self._ovn.add_lrouter_port(
                                            name='dvr-lrp-to-transit-%s' % router['id'],
                                            lrouter=dvr_router_name,
                                            mac=dvr_to_transit_port['mac_address'],
                                            networks=dvr_to_transit_port['networks']
                                            ))
            # create gw router and port
            txn.add(self._ovn.create_lrouter(gw_router_name,
                                             external_ids={'router_type': 'gateway'},
                                             options=router_options,
                                             enabled=True
                                             ))

            # create switch and port
            txn.add(self._ovn.create_lswitch(lswitch_name=transit_switch_name,
                                             external_ids={'switch_type': 'transit'}
                                             ))

        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.create_lswitch_port(
                                            lport_name='lsp-to-dvr-%s' % router['id'],
                                            lswitch_name=transit_switch_name,
                                            addresses=['fa:16:3e:00:00:02 169.254.128.2'],
                                            external_ids=None,
                                            type='router'))
            txn.add(self._ovn.create_lswitch_port(
                                            lport_name='lsp-to-gw-%s' % router['id'],
                                            lswitch_name=transit_switch_name,
                                            addresses=['fa:16:3e:00:00:01 169.254.128.1'],
                                            external_ids=None,
                                            type='router'))

            gw_to_transit_port = {'mac_address': 'fa:16:3e:00:00:01', 'networks': '169.254.128.1/30'}
            txn.add(self._ovn.add_lrouter_port(
                                            name='gw-lrp-to-transit-%s' % router['id'],
                                            lrouter=gw_router_name,
                                            mac=gw_to_transit_port['mac_address'],
                                            networks=gw_to_transit_port['networks']
                                            ))
            txn.add(self._ovn.add_lrouter_port(
                                            name='gw-lrp-to-provnet-%s' % router['id'],
                                            lrouter=gw_router_name,
                                            mac=gw_port['mac_address'],
                                            networks=self.get_networks_for_lrouter_port(context, gw_port['fixed_ips'])
                                            ))

            # connect transit-switch to DVR and Gateway.
        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.set_lrouter_port_in_lswitch_port(
                                            lswitch_port='lsp-to-dvr-%s' % router['id'],
                                            lrouter_port='dvr-lrp-to-transit-%s' % router['id']))
            txn.add(self._ovn.set_lrouter_port_in_lswitch_port(
                                            lswitch_port='lsp-to-gw-%s' % router['id'],
                                            lrouter_port='gw-lrp-to-transit-%s' % router['id']))
            # connect  Gateway to provnet
            txn.add(self._ovn.set_lrouter_port_in_lswitch_port(
                                            lswitch_port=gw_port['id'],
                                            lrouter_port='gw-lrp-to-provnet-%s' % router['id']))
        # add static route for gw_router and dvr-router.
        dvr_default_route = {'destination': '0.0.0.0/0', 'nexthop': '169.254.128.1'}
        gw_default_gateway = self.get_subnet_gateway_ips(context, gw_port['fixed_ips'])[0]  # '10.157.140.254'
        gw_default_route = {'destination': '0.0.0.0/0', 'nexthop': gw_default_gateway}
        with self._ovn.transaction(check_error=True) as txn:
            # add default route for two ovn-router.
            txn.add(self._ovn.add_static_route(dvr_router_name,
                    ip_prefix=dvr_default_route['destination'],
                    nexthop=dvr_default_route['nexthop']))
            txn.add(self._ovn.add_static_route(gw_router_name,
                    ip_prefix=gw_default_route['destination'],
                    nexthop=gw_default_route['nexthop']))
            # todo: add upstream routes which for subnets connected to neutron-router on gw_router .
        # todo: add snat to gw_router .

    def _update_router_gw_info(self, context, router_id, info):
        """override parent method.

        @param router: Router to be created in OVN
        @return: Nothing
        """
        LOG.debug("Class OVNL3RouterPlugin:::")
        router = self._get_router(context, router_id)
        gw_port = router.gw_port
        network_id = self._validate_gw_info(context, gw_port, info, None)

        self._delete_current_gw_port(context, router_id, router, network_id)
        self._create_gw_port(context, router_id, router, network_id, None)

    def _delete_current_gw_port(self, context, router_id, router, new_network):
        """Delete gw port if attached to an old network or IPs changed."""
        LOG.debug("OVNL3RouterPlugin::_delete_current_gw_port")
        #check if port requires delete or not.
        port_requires_deletion = (
            router.gw_port and
            (router.gw_port['network_id'] != new_network)
        )
        if not port_requires_deletion:
            return
        #delete gw_port and db.
        super(OVNL3RouterPlugin, self)._delete_current_gw_port(context, router_id, router, new_network)
        #delete gw router and transit network resources..
        self._delete_gw_router(context, router, None)

    def _delete_gw_router(self, context, router, network_id):
        LOG.debug("Class OVNL3RouterPlugin:::")
        router_name = self.get_gw_router_name(router['id'])
        switch_name = 'transit-'+router['id']
        # delete gw_router and transit_switch.
        self._ovn.delete_lrouter(router_name).execute(check_error=True)
        self._ovn.delete_lswitch(switch_name).execute(check_error=True)
        # delete relative port on dvr-router.
        self._ovn.delete_lrouter_port('dvr-lrp-to-transit-%s' % router['id'],
                                      lrouter=utils.ovn_name(router['id']),
                                      if_exists=False
                                      ).execute(check_error=True)
        # delete default route on dvr-router if exists.
        dvr_default_route = {'destination': '0.0.0.0/0', 'nexthop': '169.254.128.1'}
        with self._ovn.transaction(check_error=True) as txn:
            # clear default route of dvr-router.
            txn.add(self._ovn.delete_static_route(utils.ovn_name(router['id']),
                    ip_prefix=dvr_default_route['destination'],
                    nexthop=dvr_default_route['nexthop']))

    def _create_gw_router(self, context, router, network_id, gw_port):
        LOG.debug("OVNL3RouterPlugin::_create_router_gw_port")
        selected_chassis = self.scheduler.select(self._ovn, self._sb_ovn, None)
        self.create_gw_router_in_ovn(context, router, selected_chassis, gw_port)

    def _create_router_gw_port(self, context, router, network_id, ext_ips ):
        # Port has no 'tenant-id', as it is hidden from user
        LOG.debug("Class OVNL3RouterPlugin:::")
        gw_port = self._core_plugin.create_port(context.elevated(), {
            'port': {'tenant_id': '',  # intentionally not set
                     'network_id': network_id,
                     'mac_address': attributes.ATTR_NOT_SPECIFIED,
                     'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                     'device_id': router['id'],
                     'device_owner': '',  # l3_db.DEVICE_OWNER_ROUTER_GW,
                     'admin_state_up': True,
                     'name': 'Extnet_'+router['name'][0:18]
                     }})

        if not gw_port['fixed_ips']:
            self._core_plugin.delete_port(context.elevated(), gw_port['id'],
                                          l3_port_check=False)
            msg = (_('No IPs available for external network %s') %
                   network_id)
            raise n_exc.BadRequest(resource='router', msg=msg)

        self._create_gw_router(context, router, network_id, gw_port)

        with context.session.begin(subtransactions=True):
            router.gw_port = self._core_plugin._get_port(context.elevated(),
                                                         gw_port['id'])
            router_port = l3_db.RouterPort(
                router_id=router.id,
                port_id=gw_port['id'],
                port_type=l3_db.DEVICE_OWNER_ROUTER_GW
            )
            context.session.add(router)
            context.session.add(router_port)

    def update_router(self, context, id, router):
        original_router = self.get_router(context, id)
        result = super(OVNL3RouterPlugin, self).update_router(
            context, id, router)

        update = {}
        added = []
        removed = []
        router_name = utils.ovn_name(id)
        if 'admin_state_up' in router['router']:
            enabled = router['router']['admin_state_up']
            if enabled != original_router['admin_state_up']:
                update['enabled'] = enabled

        if 'name' in router['router']:
            if router['router']['name'] != original_router['name']:
                external_ids = {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                                router['router']['name']}
                update['external_ids'] = external_ids

        """ Update static routes """
        if 'routes' in router['router']:
            routes = router['router']['routes']
            added, removed = n_utils.diff_list_of_dict(
                original_router['routes'], routes)

        if update or added or removed:
            try:
                with self._ovn.transaction(check_error=True) as txn:
                    if update:
                        txn.add(self._ovn.update_lrouter(router_name,
                                **update))

                    for route in added:
                        txn.add(self._ovn.add_static_route(router_name,
                                ip_prefix=route['destination'],
                                nexthop=route['nexthop']))

                    for route in removed:
                        txn.add(self._ovn.delete_static_route(router_name,
                                ip_prefix=route['destination'],
                                nexthop=route['nexthop']))
            except Exception:
                LOG.exception(_LE('Unable to update lrouter for %s'), id)
                super(OVNL3RouterPlugin, self).update_router(context,
                                                             id,
                                                             original_router)
                raise n_exc.ServiceUnavailable()

        return result

    def delete_router(self, context, id):
        router_name = utils.ovn_name(id)
        ret_val = super(OVNL3RouterPlugin, self).delete_router(context, id)
        self._ovn.delete_lrouter(router_name).execute(check_error=True)
        return ret_val

    def get_networks_for_lrouter_port(self, context, port_fixed_ips):
        networks = set()
        for fixed_ip in port_fixed_ips:
            subnet_id = fixed_ip['subnet_id']
            subnet = self._plugin.get_subnet(context, subnet_id)
            cidr = netaddr.IPNetwork(subnet['cidr'])
            networks.add("%s/%s" % (fixed_ip['ip_address'],
                                    str(cidr.prefixlen)))
        return list(networks)

    def get_subnet_gateway_ips(self, context, port_fixed_ips):
        gw_ips = set()
        for fixed_ip in port_fixed_ips:
            subnet_id = fixed_ip['subnet_id']
            subnet = self._plugin.get_subnet(context, subnet_id)
            if subnet['gateway_ip']:
                gw_ips.add(subnet['gateway_ip'])
        return list(gw_ips)

    def create_lrouter_port_in_ovn(self, context, router_id, port):
        """Create lrouter port in OVN

        @param router id : LRouter ID for the port that needs to be created
        @param port : LRouter port that needs to be created
        @return: Nothing
        """
        lrouter = utils.ovn_name(router_id)
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
        if not networks:
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
        if (len(router_interface_info['subnet_ids']) == 1 and
                len(port['fixed_ips']) > 1):
            # NOTE(lizk) It's adding a subnet onto an already existing router
            # interface port, try to update lrouter port 'networks' column.
            self.update_lrouter_port_in_ovn(context, router_id, port)
        else:
            self.create_lrouter_port_in_ovn(context, router_id, port)

        # todo: add static route and snat to gw-router if gw_port exists.

        return router_interface_info

    def remove_router_interface(self, context, router_id, interface_info):
        router_interface_info = \
            super(OVNL3RouterPlugin, self).remove_router_interface(
                context, router_id, interface_info)
        port_id = router_interface_info['port_id']
        try:
            port = self._plugin.get_port(context, port_id)
            # The router interface port still exists, call ovn to update it.
            self.update_lrouter_port_in_ovn(context, router_id, port)
        except n_exc.PortNotFound:
            # The router interface port doesn't exist any more, call ovn to
            # delete it.
            self._ovn.delete_lrouter_port(utils.ovn_lrouter_port_name(port_id),
                                          utils.ovn_name(router_id),
                                          if_exists=False
                                          ).execute(check_error=True)

        # todo: delete static route and snat to gw_router if gw_port exists.

        return router_interface_info

    def schedule_unhosted_routers(self):
        valid_chassis_list = self._sb_ovn.get_all_chassis(cfg.get_ovn_l3_chassis_type())
        unhosted_routers = self._ovn.get_unhosted_routers(valid_chassis_list)
        if unhosted_routers:
            with self._ovn.transaction(check_error=True) as txn:
                for r_name, r_options in six.iteritems(unhosted_routers):
                    chassis = self.scheduler.select(self._ovn, self._sb_ovn,
                                                    r_name)
                    r_options['chassis'] = chassis
                    txn.add(self._ovn.update_lrouter(r_name,
                                                     options=r_options))

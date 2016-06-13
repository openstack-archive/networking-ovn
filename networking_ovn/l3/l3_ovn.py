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

from neutron.common import utils as n_utils
from neutron_lib import exceptions as n_exc
from oslo_log import log

from neutron.db import common_db_mixin
from neutron.db import extraroute_db
from neutron import manager
from neutron.plugins.common import constants
from neutron.services import service_base

from networking_ovn._i18n import _LE, _LI
from networking_ovn.common import constants as ovn_const
from networking_ovn.common import extensions
from networking_ovn.common import utils
from networking_ovn.ovsdb import impl_idl_ovn


LOG = log.getLogger(__name__)


class OVNL3RouterPlugin(service_base.ServicePluginBase,
                        common_db_mixin.CommonDbMixin,
                        extraroute_db.ExtraRoute_db_mixin):
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
        self._nb_ovn = None
        self._plugin_property = None

    @property
    def _ovn(self):
        if self._nb_ovn is None:
            LOG.info(_LI("Getting OvsdbNbOvnIdl"))
            self._nb_ovn = impl_idl_ovn.OvsdbNbOvnIdl(self)
        return self._nb_ovn

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

    def create_lrouter_port_in_ovn(self, context, router_id, port):
        """Create lrouter port in OVN

        @param router id : LRouter ID for the port that needs to be created
        @param port : LRouter port that needs to be created
        @return: Nothing
        """
        subnet_id = port['fixed_ips'][0]['subnet_id']
        subnet = self._plugin.get_subnet(context, subnet_id)
        lrouter = utils.ovn_name(router_id)
        cidr = netaddr.IPNetwork(subnet['cidr'])
        network = "%s/%s" % (port['fixed_ips'][0]['ip_address'],
                             str(cidr.prefixlen))

        lrouter_port_name = utils.ovn_lrouter_port_name(port['id'])
        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.add_lrouter_port(name=lrouter_port_name,
                                               lrouter=lrouter,
                                               mac=port['mac_address'],
                                               network=network))

            txn.add(self._ovn.set_lrouter_port_in_lswitch_port(
                    port['id'], lrouter_port_name))

    def add_router_interface(self, context, router_id, interface_info):
        router_interface_info = \
            super(OVNL3RouterPlugin, self).add_router_interface(
                context, router_id, interface_info)

        port = self._plugin.get_port(context, router_interface_info['port_id'])
        self.create_lrouter_port_in_ovn(context, router_id, port)
        return router_interface_info

    def remove_router_interface(self, context, router_id, interface_info):
        router_interface_info = \
            super(OVNL3RouterPlugin, self).remove_router_interface(
                context, router_id, interface_info)
        port_id = router_interface_info['port_id']
        self._ovn.delete_lrouter_port(utils.ovn_lrouter_port_name(port_id),
                                      utils.ovn_name(router_id),
                                      if_exists=False
                                      ).execute(check_error=True)
        return router_interface_info

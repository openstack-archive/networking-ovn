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

from neutron import context as n_context
from neutron_lib import constants as n_const
from oslo_log import log
from oslo_utils import excutils

from networking_ovn._i18n import _, _LE
from networking_ovn.common import constants as ovn_const
from networking_ovn.common import exceptions as exc


LOG = log.getLogger(__name__)
L3_ADMIN_NET_DESCR = 'Admin network created by OVN L3 plugin for connecting ' \
                     'logical router with gateway router'
L3_ADMIN_SUBNET_DESCR = 'Admin subnet created by OVN L3 plugin'
L3_ADMIN_NET_PORT_DESCR = 'Created by OVN L3 plugin to connect logical ' \
                          'router with the gateway router'


class OVNL3AdminNetwork(object):
    def __init__(self, nb_ovn_idl, plugin, cidr,):
        self._nb_ovn_idl = nb_ovn_idl
        self._plugin = plugin
        self._cidr = cidr

    # TODO(chandrav): The current implementation of connecting distributed
    # router with a gateway router uses ports created in neutron admin network.
    # This can be replaced by using IPAM support in ovn. Bug #1629077 to track
    # this.
    def _get_admin_context(self):
        return n_context.get_admin_context()

    def _get_l3_admin_net_query_filter(self):
        return {'name': [ovn_const.OVN_L3_ADMIN_NET_NAME],
                'tenant_id': ['']}

    def _get_l3_admin_net_ports_query_filter(self, device_id, device_owner):
        return {'device_id': [device_id],
                'device_owner': [device_owner],
                'tenant_id': ['']}

    def _create_l3_admin_net(self, context):
        net_params = {'network': {'tenant_id': '',
                                  'name': ovn_const.OVN_L3_ADMIN_NET_NAME,
                                  'description': L3_ADMIN_NET_DESCR,
                                  'admin_state_up': False,
                                  'shared': False,
                                  'status': 'ACTIVE'}}
        return self._plugin.create_network(context, net_params)

    def _create_l3_admin_subnet(self, context, net_id):
        subnet_params = {
            'subnet': {
                'tenant_id': '',
                'network_id': net_id,
                'admin_state_up': True,
                'name': ovn_const.OVN_L3_ADMIN_NET_SUBNET_NAME,
                'description': L3_ADMIN_SUBNET_DESCR,
                'cidr': self._cidr,
                'enable_dhcp': False,
                'no-gateway': True,
                'allocation_pools': n_const.ATTR_NOT_SPECIFIED,
                'ip_version': 4,
                'dns_nameservers': n_const.ATTR_NOT_SPECIFIED,
                'host_routes': n_const.ATTR_NOT_SPECIFIED}}
        return self._plugin.create_subnet(context, subnet_params)

    def _create_l3_admin_net_ports(self, context, net_id, names, device_id,
                                   device_owner):
        port_list = []
        for name in names:
            port = {'tenant_id': '',
                    'network_id': net_id,
                    'name': name,
                    'description': L3_ADMIN_NET_PORT_DESCR,
                    'admin_state_up': False,
                    'device_id': device_id,
                    'device_owner': device_owner,
                    'mac_address': n_const.ATTR_NOT_SPECIFIED,
                    'fixed_ips': n_const.ATTR_NOT_SPECIFIED,
                    'port_security_enabled': False}
            port_list.append({'port': port})

        return self._plugin.create_port_bulk(context, {'ports': port_list})

    def _validate_l3_admin_subnet(self, context, subnet_id):
        subnet = None
        try:
            subnet = self._plugin.get_subnet(context, subnet_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('L3 admin subnet not found'))
        if subnet.get('cidr') != self._cidr:
            msg = _('Subnet CIDR %(a)s does not match configured value '
                    '%(e)s.') % {'a': subnet.get('cidr'), 'e': self._cidr}
            raise exc.L3AdminNetSubnetError(error_message=msg)

        if subnet.get('name') != ovn_const.OVN_L3_ADMIN_NET_SUBNET_NAME:
            msg = _('Subnet name %(a)s does not match expected name '
                    '%(e)s.') % {'a': subnet.get('name'),
                                 'e': ovn_const.OVN_L3_ADMIN_NET_SUBNET_NAME}
            raise exc.L3AdminNetSubnetError(error_message=msg)

    def _validate_l3_admin_net_ports(self, ports, names):
        network = netaddr.IPNetwork(self._cidr)
        for port in ports:
            fixed_ips = port.get('fixed_ips', [])
            if not fixed_ips or (fixed_ips and len(fixed_ips) > 1):
                msg = _('Unexpected fixed ips %(f)s for port %(n)s.') % {
                    'f': fixed_ips, 'n': port.get('name')}
                raise exc.L3AdminNetPortsError(error_message=msg)

            ip = netaddr.IPAddress(fixed_ips[0]['ip_address'])
            if ip not in network:
                msg = _('IP %(ip)s of port %(n)s is not in l3 admin subnet '
                        'cidr %(c)s.') % {'ip': ip, 'n': port.get('name'),
                                          'c': self._cidr}
                raise exc.L3AdminNetPortsError(error_message=msg)

        port_names = [port['name'] for port in ports]
        if sorted(port_names) != sorted(names):
            msg = _('Port names %(a)r does not match expected names '
                    '%(e)r.') % {'a': port_names, 'e': names}
            raise exc.L3AdminNetPortsError(error_message=msg)

    def _get_l3_admin_net(self, create=False):
        network = None
        context = self._get_admin_context()
        filters = self._get_l3_admin_net_query_filter()
        networks = self._plugin.get_networks(context, filters=filters)

        if len(networks) == 0 and create:
            try:
                network = self._create_l3_admin_net(context)
                self._create_l3_admin_subnet(context, network['id'])
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Error in creating L3 admin network."))
        elif len(networks) == 1:
            network = networks[0]
            subnet_ids = network.get('subnets')
            net_id = network['id']
            if not subnet_ids and create:
                try:
                    self._create_l3_admin_subnet(context, net_id)
                except Exception:
                    with excutils.save_and_reraise_exception():
                        LOG.error(_LE('Error in creating l3 admin subnet.'))
            elif len(subnet_ids) == 1:
                self._validate_l3_admin_subnet(context, subnet_ids[0])
            else:
                msg = _('Expected number of subnets in l3 admin network is '
                        '1, found %d.') % len(subnet_ids)
                raise exc.L3AdminNetSubnetError(error_message=msg)
        else:
            msg = _('Expected number of l3 admin networks is 1, found '
                    '%d.') % len(networks)
            raise exc.L3AdminNetError(error_message=msg)
        return network

    def get_l3_admin_net_ports(self, names, device_id, device_owner,
                               create=False):
        ctx = self._get_admin_context()
        filters = self._get_l3_admin_net_ports_query_filter(device_id,
                                                            device_owner)
        ports = self._plugin.get_ports(ctx, filters=filters)
        if len(ports) == 0 and create:
            try:
                network = self._get_l3_admin_net(create=True)
                net_id = network['id']
                ports = self._create_l3_admin_net_ports(
                    ctx, net_id, names, device_id, device_owner)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE('Error in creating l3 admin net ports %r.'),
                              names)
        elif len(ports) == len(names):
            self._validate_l3_admin_net_ports(ports, names)
        else:
            msg = _('Expected number of l3 admin net ports %(e)d, '
                    'found %(f)d.') % {'e': len(names), 'f': len(ports)}
            raise exc.L3AdminNetPortsError(error_message=msg)

        return ports

    def delete_l3_admin_net_ports(self, context, names, device_id,
                                  device_owner):
        admin_context = self._get_admin_context()
        net_id = None
        ports = self.get_l3_admin_net_ports(names, device_id, device_owner)
        if ports:
            net_id = ports[0]['network_id']
        for port in ports:
            self._plugin.delete_port(admin_context, port['id'])
        ports = self._plugin.get_ports(admin_context,
                                       filters={'network_id': [net_id]})
        if not ports:
            # No more ports in admin net, delete the network
            net_id = net_id or self._get_l3_admin_net()['id']
            self._plugin.delete_network(admin_context, net_id)

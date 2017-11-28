# Copyright 2017 Red Hat, Inc.
# All Rights Reserved.
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

import collections
import copy

import netaddr
from neutron.plugins.common import utils as p_utils
from neutron_lib.api.definitions import l3
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib import constants as const
from neutron_lib import context as n_context
from neutron_lib.plugins import directory
from neutron_lib.utils import helpers
from neutron_lib.utils import net as n_net
from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils

from networking_ovn.agent.metadata import agent as metadata_agent
from networking_ovn.common import acl as ovn_acl
from networking_ovn.common import config
from networking_ovn.common import constants as ovn_const
from networking_ovn.common import utils
from networking_ovn.l3 import l3_ovn_scheduler
from networking_ovn.ml2 import qos_driver

LOG = log.getLogger(__name__)


OvnPortInfo = collections.namedtuple('OvnPortInfo', ['type', 'options',
                                                     'addresses',
                                                     'port_security',
                                                     'parent_name', 'tag',
                                                     'dhcpv4_options',
                                                     'dhcpv6_options',
                                                     'cidrs'])


class OVNClient(object):

    def __init__(self, nb_idl, sb_idl):
        self._nb_idl = nb_idl
        self._sb_idl = sb_idl

        self._plugin_property = None

        qos_driver.OVNQosNotificationDriver.create()
        self._qos_driver = qos_driver.OVNQosDriver(self)
        self._ovn_scheduler = l3_ovn_scheduler.get_scheduler()

    @property
    def _plugin(self):
        if self._plugin_property is None:
            self._plugin_property = directory.get_plugin()
        return self._plugin_property

    def _get_allowed_addresses_from_port(self, port):
        if not port.get(psec.PORTSECURITY):
            return []

        if utils.is_lsp_trusted(port):
            return []

        allowed_addresses = set()
        addresses = port['mac_address']
        for ip in port.get('fixed_ips', []):
            addresses += ' ' + ip['ip_address']

        for allowed_address in port.get('allowed_address_pairs', []):
            # If allowed address pair has same mac as the port mac,
            # append the allowed ip address to the 'addresses'.
            # Else we will have multiple entries for the same mac in
            # 'Logical_Switch_Port.port_security'.
            if allowed_address['mac_address'] == port['mac_address']:
                addresses += ' ' + allowed_address['ip_address']
            else:
                allowed_addresses.add(allowed_address['mac_address'] + ' ' +
                                      allowed_address['ip_address'])

        allowed_addresses.add(addresses)

        return list(allowed_addresses)

    def _get_subnet_dhcp_options_for_port(self, port, ip_version):
        """Returns the subnet dhcp options for the port.

        Return the first found DHCP options belong for the port.
        """
        subnets = [
            fixed_ip['subnet_id']
            for fixed_ip in port['fixed_ips']
            if netaddr.IPAddress(fixed_ip['ip_address']).version == ip_version]
        get_opts = self._nb_idl.get_subnets_dhcp_options(subnets)
        if get_opts:
            if ip_version == const.IP_VERSION_6:
                # Always try to find a dhcpv6 stateful v6 subnet to return.
                # This ensures port can get one stateful v6 address when port
                # has multiple dhcpv6 stateful and stateless subnets.
                for opts in get_opts:
                    # We are setting ovn_const.DHCPV6_STATELESS_OPT to "true"
                    # in _get_ovn_dhcpv6_opts, so entries in DHCP_Options table
                    # should have unicode type 'true' if they were defined as
                    # dhcpv6 stateless.
                    if opts['options'].get(
                        ovn_const.DHCPV6_STATELESS_OPT) != 'true':
                        return opts
            return get_opts[0]

    def _get_port_dhcp_options(self, port, ip_version):
        """Return dhcp options for port.

        In case the port is dhcp disabled, or IP addresses it has belong
        to dhcp disabled subnets, returns None.
        Otherwise, returns a dict:
         - with content from a existing DHCP_Options row for subnet, if the
           port has no extra dhcp options.
         - with only one item ('cmd', AddDHCPOptionsCommand(..)), if the port
           has extra dhcp options. The command should be processed in the same
           transaction with port creating or updating command to avoid orphan
           row issue happen.
        """
        lsp_dhcp_disabled, lsp_dhcp_opts = utils.get_lsp_dhcp_opts(
            port, ip_version)

        if lsp_dhcp_disabled:
            return

        subnet_dhcp_options = self._get_subnet_dhcp_options_for_port(
            port, ip_version)

        if not subnet_dhcp_options:
            # NOTE(lizk): It's possible for Neutron to configure a port with IP
            # address belongs to subnet disabled dhcp. And no DHCP_Options row
            # will be inserted for such a subnet. So in that case, the subnet
            # dhcp options here will be None.
            return

        if not lsp_dhcp_opts:
            return subnet_dhcp_options

        # This port has extra DHCP options defined, so we will create a new
        # row in DHCP_Options table for it.
        subnet_dhcp_options['options'].update(lsp_dhcp_opts)
        subnet_dhcp_options['external_ids'].update(
            {'port_id': port['id']})
        subnet_id = subnet_dhcp_options['external_ids']['subnet_id']
        add_dhcp_opts_cmd = self._nb_idl.add_dhcp_options(
            subnet_id, port_id=port['id'],
            cidr=subnet_dhcp_options['cidr'],
            options=subnet_dhcp_options['options'],
            external_ids=subnet_dhcp_options['external_ids'])
        return {'cmd': add_dhcp_opts_cmd}

    def _get_port_options(self, port, qos_options=None):
        binding_prof = utils.validate_and_get_data_from_binding_profile(port)
        if qos_options is None:
            qos_options = self._qos_driver.get_qos_options(port)
        vtep_physical_switch = binding_prof.get('vtep-physical-switch')

        cidrs = ''
        if vtep_physical_switch:
            vtep_logical_switch = binding_prof.get('vtep-logical-switch')
            port_type = 'vtep'
            options = {'vtep-physical-switch': vtep_physical_switch,
                       'vtep-logical-switch': vtep_logical_switch}
            addresses = "unknown"
            parent_name = []
            tag = []
            port_security = []
        else:
            options = qos_options
            parent_name = binding_prof.get('parent_name', [])
            tag = binding_prof.get('tag', [])
            addresses = port['mac_address']
            for ip in port.get('fixed_ips', []):
                addresses += ' ' + ip['ip_address']
                subnet = self._plugin.get_subnet(n_context.get_admin_context(),
                                                 ip['subnet_id'])
                cidrs += ' {}/{}'.format(ip['ip_address'],
                                         subnet['cidr'].split('/')[1])
            port_security = self._get_allowed_addresses_from_port(port)
            port_type = ovn_const.OVN_NEUTRON_OWNER_TO_PORT_TYPE.get(
                port['device_owner'], '')

        dhcpv4_options = self._get_port_dhcp_options(port, const.IP_VERSION_4)
        dhcpv6_options = self._get_port_dhcp_options(port, const.IP_VERSION_6)

        return OvnPortInfo(port_type, options, [addresses], port_security,
                           parent_name, tag, dhcpv4_options, dhcpv6_options,
                           cidrs.strip())

    def create_port(self, port):
        if utils.is_lsp_ignored(port):
            return

        port_info = self._get_port_options(port)
        external_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port['name'],
                        ovn_const.OVN_DEVID_EXT_ID_KEY: port['device_id'],
                        ovn_const.OVN_PROJID_EXT_ID_KEY: port['project_id'],
                        ovn_const.OVN_CIDRS_EXT_ID_KEY: port_info.cidrs}
        lswitch_name = utils.ovn_name(port['network_id'])
        admin_context = n_context.get_admin_context()
        sg_cache = {}
        subnet_cache = {}

        # It's possible to have a network created on one controller and then a
        # port created on a different controller quickly enough that the second
        # controller does not yet see that network in its local cache of the
        # OVN northbound database.  Check if the logical switch is present
        # or not in the idl's local copy of the database before creating
        # the lswitch port.
        self._nb_idl.check_for_row_by_value_and_retry(
            'Logical_Switch', 'name', lswitch_name)

        with self._nb_idl.transaction(check_error=True) as txn:
            if not port_info.dhcpv4_options:
                dhcpv4_options = []
            elif 'cmd' in port_info.dhcpv4_options:
                dhcpv4_options = txn.add(port_info.dhcpv4_options['cmd'])
            else:
                dhcpv4_options = [port_info.dhcpv4_options['uuid']]
            if not port_info.dhcpv6_options:
                dhcpv6_options = []
            elif 'cmd' in port_info.dhcpv6_options:
                dhcpv6_options = txn.add(port_info.dhcpv6_options['cmd'])
            else:
                dhcpv6_options = [port_info.dhcpv6_options['uuid']]
            # The lport_name *must* be neutron port['id'].  It must match the
            # iface-id set in the Interfaces table of the Open_vSwitch
            # database which nova sets to be the port ID.
            txn.add(self._nb_idl.create_lswitch_port(
                    lport_name=port['id'],
                    lswitch_name=lswitch_name,
                    addresses=port_info.addresses,
                    external_ids=external_ids,
                    parent_name=port_info.parent_name,
                    tag=port_info.tag,
                    enabled=port.get('admin_state_up'),
                    options=port_info.options,
                    type=port_info.type,
                    port_security=port_info.port_security,
                    dhcpv4_options=dhcpv4_options,
                    dhcpv6_options=dhcpv6_options))

            acls_new = ovn_acl.add_acls(self._plugin, admin_context,
                                        port, sg_cache, subnet_cache)
            for acl in acls_new:
                txn.add(self._nb_idl.add_acl(**acl))

            sg_ids = utils.get_lsp_security_groups(port)
            if port.get('fixed_ips') and sg_ids:
                addresses = ovn_acl.acl_port_ips(port)
                # NOTE(rtheis): Fail port creation if the address set doesn't
                # exist. This prevents ports from being created on any security
                # groups out-of-sync between neutron and OVN.
                for sg_id in sg_ids:
                    for ip_version in addresses:
                        if addresses[ip_version]:
                            txn.add(self._nb_idl.update_address_set(
                                name=utils.ovn_addrset_name(sg_id,
                                                            ip_version),
                                addrs_add=addresses[ip_version],
                                addrs_remove=None,
                                if_exists=False))

    def update_port(self, port, original_port, qos_options=None):
        if utils.is_lsp_ignored(port):
            return

        port_info = self._get_port_options(port, qos_options)
        external_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port['name'],
                        ovn_const.OVN_DEVID_EXT_ID_KEY: port['device_id'],
                        ovn_const.OVN_PROJID_EXT_ID_KEY: port['project_id'],
                        ovn_const.OVN_CIDRS_EXT_ID_KEY: port_info.cidrs}
        admin_context = n_context.get_admin_context()
        sg_cache = {}
        subnet_cache = {}

        with self._nb_idl.transaction(check_error=True) as txn:
            columns_dict = {}
            if port.get('device_owner') in [const.DEVICE_OWNER_ROUTER_INTF,
                                            const.DEVICE_OWNER_ROUTER_GW]:
                port_info.options.update(
                    self._nb_idl.get_router_port_options(port['id']))
            else:
                columns_dict['type'] = port_info.type
                columns_dict['addresses'] = port_info.addresses
            if not port_info.dhcpv4_options:
                dhcpv4_options = []
            elif 'cmd' in port_info.dhcpv4_options:
                dhcpv4_options = txn.add(port_info.dhcpv4_options['cmd'])
            else:
                dhcpv4_options = [port_info.dhcpv4_options['uuid']]
            if not port_info.dhcpv6_options:
                dhcpv6_options = []
            elif 'cmd' in port_info.dhcpv6_options:
                dhcpv6_options = txn.add(port_info.dhcpv6_options['cmd'])
            else:
                dhcpv6_options = [port_info.dhcpv6_options['uuid']]
            # NOTE(lizk): Fail port updating if port doesn't exist. This
            # prevents any new inserted resources to be orphan, such as port
            # dhcp options or ACL rules for port, e.g. a port was created
            # without extra dhcp options and security group, while updating
            # includes the new attributes setting to port.
            txn.add(self._nb_idl.set_lswitch_port(
                    lport_name=port['id'],
                    external_ids=external_ids,
                    parent_name=port_info.parent_name,
                    tag=port_info.tag,
                    options=port_info.options,
                    enabled=port['admin_state_up'],
                    port_security=port_info.port_security,
                    dhcpv4_options=dhcpv4_options,
                    dhcpv6_options=dhcpv6_options,
                    if_exists=False,
                    **columns_dict))

            # Determine if security groups or fixed IPs are updated.
            old_sg_ids = set(utils.get_lsp_security_groups(original_port))
            new_sg_ids = set(utils.get_lsp_security_groups(port))
            detached_sg_ids = old_sg_ids - new_sg_ids
            attached_sg_ids = new_sg_ids - old_sg_ids
            is_fixed_ips_updated = \
                original_port.get('fixed_ips') != port.get('fixed_ips')

            # Refresh ACLs for changed security groups or fixed IPs.
            if detached_sg_ids or attached_sg_ids or is_fixed_ips_updated:
                # Note that update_acls will compare the port's ACLs to
                # ensure only the necessary ACLs are added and deleted
                # on the transaction.
                acls_new = ovn_acl.add_acls(self._plugin,
                                            admin_context,
                                            port,
                                            sg_cache,
                                            subnet_cache)
                txn.add(self._nb_idl.update_acls([port['network_id']],
                                                 [port],
                                                 {port['id']: acls_new},
                                                 need_compare=True))

            # Refresh address sets for changed security groups or fixed IPs.
            if (len(port.get('fixed_ips')) != 0 or
                    len(original_port.get('fixed_ips')) != 0):
                addresses = ovn_acl.acl_port_ips(port)
                addresses_old = ovn_acl.acl_port_ips(original_port)
                # Add current addresses to attached security groups.
                for sg_id in attached_sg_ids:
                    for ip_version in addresses:
                        if addresses[ip_version]:
                            txn.add(self._nb_idl.update_address_set(
                                name=utils.ovn_addrset_name(sg_id, ip_version),
                                addrs_add=addresses[ip_version],
                                addrs_remove=None))
                # Remove old addresses from detached security groups.
                for sg_id in detached_sg_ids:
                    for ip_version in addresses_old:
                        if addresses_old[ip_version]:
                            txn.add(self._nb_idl.update_address_set(
                                name=utils.ovn_addrset_name(sg_id, ip_version),
                                addrs_add=None,
                                addrs_remove=addresses_old[ip_version]))

                if is_fixed_ips_updated:
                    # We have refreshed address sets for attached and detached
                    # security groups, so now we only need to take care of
                    # unchanged security groups.
                    unchanged_sg_ids = new_sg_ids & old_sg_ids
                    for sg_id in unchanged_sg_ids:
                        for ip_version in addresses:
                            addr_add = (set(addresses[ip_version]) -
                                        set(addresses_old[ip_version])) or None
                            addr_remove = (set(addresses_old[ip_version]) -
                                           set(addresses[ip_version])) or None

                            if addr_add or addr_remove:
                                txn.add(self._nb_idl.update_address_set(
                                        name=utils.ovn_addrset_name(
                                            sg_id, ip_version),
                                        addrs_add=addr_add,
                                        addrs_remove=addr_remove))

    def delete_port(self, port):
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.delete_lswitch_port(port['id'],
                    utils.ovn_name(port['network_id'])))
            txn.add(self._nb_idl.delete_acl(
                    utils.ovn_name(port['network_id']), port['id']))

            if port.get('fixed_ips'):
                addresses = ovn_acl.acl_port_ips(port)
                # Set skip_trusted_port False for deleting port
                for sg_id in utils.get_lsp_security_groups(port, False):
                    for ip_version in addresses:
                        if addresses[ip_version]:
                            txn.add(self._nb_idl.update_address_set(
                                name=utils.ovn_addrset_name(sg_id, ip_version),
                                addrs_add=None,
                                addrs_remove=addresses[ip_version]))

    def _update_floatingip(self, floatingip, router_id, associate=True):
        fip_apis = {}
        fip_apis['nat'] = self._nb_idl.add_nat_rule_in_lrouter if \
            associate else self._nb_idl.delete_nat_rule_in_lrouter
        gw_lrouter_name = utils.ovn_name(router_id)
        try:
            with self._nb_idl.transaction(check_error=True) as txn:
                nat_rule_args = (gw_lrouter_name,)
                if associate:
                    # TODO(chandrav): Since the floating ip port is not
                    # bound to any chassis, packets destined to floating ip
                    # will be dropped. To overcome this, delete the floating
                    # ip port. Proper fix for this would be to redirect packets
                    # destined to floating ip to the router port. This would
                    # require changes in ovn-northd.
                    txn.add(self._nb_idl.delete_lswitch_port(
                        floatingip['fip_port_id'],
                        utils.ovn_name(floatingip['fip_net_id'])))

                    # Get the list of nat rules and check if the external_ip
                    # with type 'dnat_and_snat' already exists or not.
                    # If exists, set the new value.
                    # This happens when the port associated to a floating ip
                    # is deleted before the disassociation.
                    lrouter_nat_rules = self._nb_idl.get_lrouter_nat_rules(
                        gw_lrouter_name)
                    for nat_rule in lrouter_nat_rules:
                        if (nat_rule['external_ip'] ==
                                floatingip['external_ip'] and
                                nat_rule['type'] == 'dnat_and_snat'):
                            fip_apis['nat'] = (
                                self._nb_idl.set_nat_rule_in_lrouter)
                            nat_rule_args = (gw_lrouter_name, nat_rule['uuid'])
                            break

                txn.add(fip_apis['nat'](*nat_rule_args, type='dnat_and_snat',
                                        logical_ip=floatingip['logical_ip'],
                                        external_ip=floatingip['external_ip']))
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error('Unable to update NAT rule in gateway '
                          'router. Error: %s', e)

    def create_floatingip(self, floatingip, router_id):
        try:
            self._update_floatingip(floatingip, router_id)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error('Unable to create floating ip in gateway '
                          'router. Error: %s', e)

    def update_floatingip(self, floatingip, router_id, associate=True):
        try:
            self._update_floatingip(floatingip, router_id,
                                    associate=associate)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error('Unable to update floating ip in gateway '
                          'router. Error: %s', e)

    def delete_floatingip(self, floatingip, router_id):
        try:
            self._update_floatingip(floatingip, router_id,
                                    associate=False)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error('Unable to delete floating ip in gateway '
                          'router. Error: %s', e)

    def disassociate_floatingip(self, floatingip, router_id):
        try:
            self._update_floatingip(floatingip, router_id,
                                    associate=False)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error('Unable to disassociate floating ip in gateway '
                          'router. Error: %s', e)

    def _get_external_router_and_gateway_ip(self, context, router):
        ext_gw_info = router.get(l3.EXTERNAL_GW_INFO, {})
        ext_fixed_ips = ext_gw_info.get('external_fixed_ips', [])
        for ext_fixed_ip in ext_fixed_ips:
            subnet_id = ext_fixed_ip['subnet_id']
            subnet = self._plugin.get_subnet(context, subnet_id)
            if subnet['ip_version'] == 4:
                return ext_fixed_ip['ip_address'], subnet.get('gateway_ip')
        return '', ''

    def _update_router_routes(self, context, router_id, add, remove):
        lrouter_name = utils.ovn_name(router_id)
        with self._nb_idl.transaction(check_error=True) as txn:
            for route in add:
                txn.add(self._nb_idl.add_static_route(
                    lrouter_name, ip_prefix=route['destination'],
                    nexthop=route['nexthop']))
            for route in remove:
                txn.add(self._nb_idl.delete_static_route(
                    lrouter_name, ip_prefix=route['destination'],
                    nexthop=route['nexthop']))

    def _delete_router_ext_gw(self, context, router, networks):
        if not networks:
            networks = []
        router_id = router['id']
        gw_port_id = router['gw_port_id']
        gw_lrouter_name = utils.ovn_name(router_id)
        router_ip, ext_gw_ip = self._get_external_router_and_gateway_ip(
            context, router)

        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.delete_static_route(gw_lrouter_name,
                                                     ip_prefix='0.0.0.0/0',
                                                     nexthop=ext_gw_ip))
            txn.add(self._nb_idl.delete_lrouter_port(
                utils.ovn_lrouter_port_name(gw_port_id),
                gw_lrouter_name))
            for network in networks:
                txn.add(self._nb_idl.delete_nat_rule_in_lrouter(
                    gw_lrouter_name, type='snat', logical_ip=network,
                    external_ip=router_ip))

    def _get_networks_for_router_port(self, port_fixed_ips):
        context = n_context.get_admin_context()
        networks = set()
        for fixed_ip in port_fixed_ips:
            subnet_id = fixed_ip['subnet_id']
            subnet = self._plugin.get_subnet(context, subnet_id)
            cidr = netaddr.IPNetwork(subnet['cidr'])
            networks.add("%s/%s" % (fixed_ip['ip_address'],
                                    str(cidr.prefixlen)))
        return list(networks)

    def _add_router_ext_gw(self, context, router, networks):
        router_id = router['id']
        lrouter_name = utils.ovn_name(router['id'])

        # 1. Add the external gateway router port.
        _, ext_gw_ip = self._get_external_router_and_gateway_ip(context,
                                                                router)
        gw_port_id = router['gw_port_id']
        port = self._plugin.get_port(context, gw_port_id)
        try:
            self.create_router_port(router_id, port)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._delete_router_ext_gw(context, router, networks)
                LOG.error('Unable to add external router port %(id)s to '
                          'lrouter %(name)s',
                          {'id': port['id'], 'name': lrouter_name})

        # 2. Add default route with nexthop as ext_gw_ip
        route = [{'destination': '0.0.0.0/0', 'nexthop': ext_gw_ip}]
        try:
            self._update_router_routes(context, router_id, route, [])
        except Exception:
            with excutils.save_and_reraise_exception():
                self._delete_router_ext_gw(context, router, networks)
                LOG.error('Error updating routes %(route)s in lrouter '
                          '%(name)s', {'route': route, 'name': lrouter_name})

        # 3. Add snat rules for tenant networks in lrouter if snat is enabled
        if utils.is_snat_enabled(router) and networks:
            try:
                self.update_nat_rules(router, networks, enable_snat=True)
            except Exception:
                with excutils.save_and_reraise_exception():
                    self._delete_router_ext_gw(context, router, networks)
                    LOG.error('Error in updating SNAT for lrouter %s',
                              lrouter_name)

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

    def _update_lrouter_routes(self, context, router_id, add, remove):
        if not any([add, remove]):
            return
        lrouter_name = utils.ovn_name(router_id)
        with self._nb_idl.transaction(check_error=True) as txn:
            for route in add:
                txn.add(self._nb_idl.add_static_route(
                    lrouter_name, ip_prefix=route['destination'],
                    nexthop=route['nexthop']))
            for route in remove:
                txn.add(self._nb_idl.delete_static_route(
                    lrouter_name, ip_prefix=route['destination'],
                    nexthop=route['nexthop']))

    def create_router(self, router, networks=None):
        """Create a logical router."""
        context = n_context.get_admin_context()
        external_ids = {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                        router.get('name', 'no_router_name')}
        enabled = router.get('admin_state_up')
        lrouter_name = utils.ovn_name(router['id'])
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.create_lrouter(lrouter_name,
                                                external_ids=external_ids,
                                                enabled=enabled,
                                                options={}))

        if router.get(l3.EXTERNAL_GW_INFO) and networks is not None:
            self._add_router_ext_gw(context, router, networks)

    def update_router(self, new_router, original_router, delta, networks):
        """Update a logical router."""
        context = n_context.get_admin_context()
        router_id = new_router['id']
        gateway_new = new_router.get(l3.EXTERNAL_GW_INFO)
        gateway_old = original_router.get(l3.EXTERNAL_GW_INFO)
        try:
            if gateway_new and not gateway_old:
                # Route gateway is set
                self._add_router_ext_gw(context, new_router, networks)
            elif gateway_old and not gateway_new:
                # router gateway is removed
                self._delete_router_ext_gw(context, original_router,
                                           networks)
            elif gateway_new and gateway_old:
                # Check if external gateway has changed, if yes, delete
                # the old gateway and add the new gateway
                if self._check_external_ips_changed(gateway_old, gateway_new):
                    self._delete_router_ext_gw(
                        context, original_router, networks)
                    self._add_router_ext_gw(context, new_router, networks)
                else:
                    # Check if snat has been enabled/disabled and update
                    old_snat_state = gateway_old.get('enable_snat', True)
                    new_snat_state = gateway_new.get('enable_snat', True)
                    if old_snat_state != new_snat_state:
                        if utils.is_snat_enabled(new_router) and networks:
                            self.update_nat_rules(new_router, networks,
                                                  enable_snat=new_snat_state)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error('Unable to update router %(router)s. '
                          'Error: %(error)s', {'router': router_id,
                                               'error': e})
        # Check for change in admin_state_up
        update = {}
        router_name = utils.ovn_name(router_id)
        enabled = delta['router'].get('admin_state_up')
        if enabled is not None and (
                enabled != original_router['admin_state_up']):
            update['enabled'] = enabled

        # Check for change in name
        name = delta['router'].get('name')
        if name and name != original_router['name']:
            external_ids = {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: name}
            update['external_ids'] = external_ids

        if update:
            try:
                with self._nb_idl.transaction(check_error=True) as txn:
                    txn.add(self._nb_idl.update_lrouter(router_name, **update))
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.error('Unable to update router %(router)s. '
                              'Error: %(error)s', {'router': router_id,
                                                   'error': e})
        # Check for route updates
        routes = delta['router'].get('routes')
        if routes:
            added, removed = helpers.diff_list_of_dict(
                original_router['routes'], routes)
            try:
                self._update_lrouter_routes(context, router_id, added, removed)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.error('Unable to update static routes in router '
                              '%(router)s. Error: %(error)s',
                              {'router': router_id, 'error': e})

    def delete_router(self, router_id):
        """Delete a logical router."""
        lrouter_name = utils.ovn_name(router_id)
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.delete_lrouter(lrouter_name))

    def get_candidates_for_scheduling(self, extnet):
        if extnet.get(pnet.NETWORK_TYPE) in [const.TYPE_FLAT,
                                             const.TYPE_VLAN]:
            physnet = extnet.get(pnet.PHYSICAL_NETWORK)
            if not physnet:
                return []
            chassis_physnets = self._sb_idl.get_chassis_and_physnets()
            return [chassis for chassis, physnets in chassis_physnets.items()
                    if physnet in physnets]
        return []

    def create_router_port(self, router_id, port):
        """Create a logical router port."""
        lrouter = utils.ovn_name(router_id)
        networks = self._get_networks_for_router_port(port['fixed_ips'])
        lrouter_port_name = utils.ovn_lrouter_port_name(port['id'])
        is_gw_port = const.DEVICE_OWNER_ROUTER_GW == port.get(
            'device_owner')
        columns = {}
        if is_gw_port:
            context = n_context.get_admin_context()
            candidates = self.get_candidates_for_scheduling(
                self._plugin.get_network(context, port['network_id']))
            selected_chassis = self._ovn_scheduler.select(
                self._nb_idl, self._sb_idl, lrouter_port_name,
                candidates=candidates)
            columns['options'] = {
                ovn_const.OVN_GATEWAY_CHASSIS_KEY: selected_chassis}
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.add_lrouter_port(name=lrouter_port_name,
                                                  lrouter=lrouter,
                                                  mac=port['mac_address'],
                                                  networks=networks,
                                                  **columns))
            txn.add(self._nb_idl.set_lrouter_port_in_lswitch_port(
                port['id'], lrouter_port_name))

    def update_router_port(self, router_id, port, networks=None):
        """Update a logical router port."""
        if networks is None:
            networks = self._get_networks_for_router_port(port['fixed_ips'])

        lrouter_port_name = utils.ovn_lrouter_port_name(port['id'])
        update = {'networks': networks}
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.update_lrouter_port(name=lrouter_port_name,
                                                     if_exists=False,
                                                     **update))
            txn.add(self._nb_idl.set_lrouter_port_in_lswitch_port(
                    port['id'], lrouter_port_name))

    def delete_router_port(self, port_id, router_id):
        """Delete a logical router port."""
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.delete_lrouter_port(
                utils.ovn_lrouter_port_name(port_id),
                utils.ovn_name(router_id), if_exists=True))

    def update_nat_rules(self, router, networks, enable_snat):
        """Update the NAT rules in a logical router."""
        context = n_context.get_admin_context()
        func = (self._nb_idl.add_nat_rule_in_lrouter if enable_snat else
                self._nb_idl.delete_nat_rule_in_lrouter)
        gw_lrouter_name = utils.ovn_name(router['id'])
        router_ip, _ = self._get_external_router_and_gateway_ip(context,
                                                                router)
        with self._nb_idl.transaction(check_error=True) as txn:
            for network in networks:
                txn.add(func(gw_lrouter_name, type='snat', logical_ip=network,
                             external_ip=router_ip))

    def _create_provnet_port(self, txn, network, physnet, tag):
        txn.add(self._nb_idl.create_lswitch_port(
            lport_name=utils.ovn_provnet_port_name(network['id']),
            lswitch_name=utils.ovn_name(network['id']),
            addresses=['unknown'],
            external_ids={},
            type='localnet',
            tag=tag if tag else [],
            options={'network_name': physnet}))

    def create_network(self, network, physnet=None, segid=None):
        # Create a logical switch with a name equal to the Neutron network
        # UUID.  This provides an easy way to refer to the logical switch
        # without having to track what UUID OVN assigned to it.
        ext_ids = {
            ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: network['name']
        }

        lswitch_name = utils.ovn_name(network['id'])
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.create_lswitch(
                lswitch_name=lswitch_name,
                external_ids=ext_ids))
            if physnet is not None:
                tag = int(segid) if segid else None
                self._create_provnet_port(txn, network, physnet, tag)

        self.create_metadata_port(n_context.get_admin_context(), network)

        return network

    def delete_network(self, network_id):
        self._nb_idl.delete_lswitch(
            utils.ovn_name(network_id), if_exists=True).execute(
                check_error=True)

    def update_network(self, network, original_network):
        if network['name'] != original_network['name']:
            ext_id = [ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY, network['name']]
            self._nb_idl.set_lswitch_ext_id(
                utils.ovn_name(network['id']), ext_id).execute(
                    check_error=True)
        self._qos_driver.update_network(network, original_network)

    def _add_subnet_dhcp_options(self, subnet, network, ovn_dhcp_options=None,
                                 metadata_port_ip=None):
        if utils.is_dhcp_options_ignored(subnet):
            return

        if not ovn_dhcp_options:
            ovn_dhcp_options = self._get_ovn_dhcp_options(
                subnet, network, metadata_port_ip=metadata_port_ip)

        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.add_dhcp_options(
                subnet['id'], **ovn_dhcp_options))

    def _get_ovn_dhcp_options(self, subnet, network, server_mac=None,
                              metadata_port_ip=None):
        external_ids = {'subnet_id': subnet['id']}
        dhcp_options = {'cidr': subnet['cidr'], 'options': {},
                        'external_ids': external_ids}

        if subnet['enable_dhcp']:
            if subnet['ip_version'] == const.IP_VERSION_4:
                dhcp_options['options'] = self._get_ovn_dhcpv4_opts(
                    subnet, network, server_mac=server_mac,
                    metadata_port_ip=metadata_port_ip)
            else:
                dhcp_options['options'] = self._get_ovn_dhcpv6_opts(
                    subnet, server_id=server_mac)

        return dhcp_options

    def _get_ovn_dhcpv4_opts(self, subnet, network, server_mac=None,
                             metadata_port_ip=None):
        if not subnet['gateway_ip']:
            return {}

        default_lease_time = str(config.get_ovn_dhcp_default_lease_time())
        mtu = network['mtu']
        options = {
            'server_id': subnet['gateway_ip'],
            'lease_time': default_lease_time,
            'mtu': str(mtu),
            'router': subnet['gateway_ip']
        }

        if server_mac:
            options['server_mac'] = server_mac
        else:
            options['server_mac'] = n_net.get_random_mac(
                cfg.CONF.base_mac.split(':'))

        if subnet['dns_nameservers']:
            dns_servers = '{%s}' % ', '.join(subnet['dns_nameservers'])
            options['dns_server'] = dns_servers

        # If subnet hostroutes are defined, add them in the
        # 'classless_static_route' dhcp option
        classless_static_routes = "{"
        if metadata_port_ip:
            classless_static_routes += ("%s/32,%s, ") % (
                metadata_agent.METADATA_DEFAULT_IP, metadata_port_ip)

        for route in subnet['host_routes']:
            classless_static_routes += ("%s,%s, ") % (
                route['destination'], route['nexthop'])

        if classless_static_routes != "{":
            # if there are static routes, then we need to add the
            # default route in this option. As per RFC 3442 dhcp clients
            # should ignore 'router' dhcp option (option 3)
            # if option 121 is present.
            classless_static_routes += "0.0.0.0/0,%s}" % (subnet['gateway_ip'])
            options['classless_static_route'] = classless_static_routes

        return options

    def _get_ovn_dhcpv6_opts(self, subnet, server_id=None):
        """Returns the DHCPv6 options"""

        dhcpv6_opts = {
            'server_id': server_id or n_net.get_random_mac(
                cfg.CONF.base_mac.split(':'))
        }

        if subnet['dns_nameservers']:
            dns_servers = '{%s}' % ', '.join(subnet['dns_nameservers'])
            dhcpv6_opts['dns_server'] = dns_servers

        if subnet.get('ipv6_address_mode') == const.DHCPV6_STATELESS:
            dhcpv6_opts[ovn_const.DHCPV6_STATELESS_OPT] = 'true'

        return dhcpv6_opts

    def _remove_subnet_dhcp_options(self, subnet_id):
        with self._nb_idl.transaction(check_error=True) as txn:
            dhcp_options = self._nb_idl.get_subnet_and_ports_dhcp_options(
                subnet_id)
            # Remove subnet and port DHCP_Options rows, the DHCP options in
            # lsp rows will be removed by related UUID
            for dhcp_option in dhcp_options:
                txn.add(self._nb_idl.delete_dhcp_options(dhcp_option['uuid']))

    def _enable_subnet_dhcp_options(self, subnet, network,
                                    metadata_port_ip=None):
        if utils.is_dhcp_options_ignored(subnet):
            return

        filters = {'fixed_ips': {'subnet_id': [subnet['id']]}}
        all_ports = self._plugin.get_ports(n_context.get_admin_context(),
                                           filters=filters)
        ports = [p for p in all_ports if not p['device_owner'].startswith(
            const.DEVICE_OWNER_PREFIXES)]

        subnet_dhcp_options = self._get_ovn_dhcp_options(
            subnet, network, metadata_port_ip=metadata_port_ip)
        subnet_dhcp_cmd = self._nb_idl.add_dhcp_options(subnet['id'],
                                                        **subnet_dhcp_options)
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(subnet_dhcp_cmd)
        with self._nb_idl.transaction(check_error=True) as txn:
            # Traverse ports to add port DHCP_Options rows
            for port in ports:
                lsp_dhcp_disabled, lsp_dhcp_opts = utils.get_lsp_dhcp_opts(
                    port, subnet['ip_version'])
                if lsp_dhcp_disabled:
                    continue
                elif not lsp_dhcp_opts:
                    lsp_dhcp_options = [subnet_dhcp_cmd.result]
                else:
                    port_dhcp_options = copy.deepcopy(subnet_dhcp_options)
                    port_dhcp_options['options'].update(lsp_dhcp_opts)
                    port_dhcp_options['external_ids'].update(
                        {'port_id': port['id']})
                    lsp_dhcp_options = txn.add(self._nb_idl.add_dhcp_options(
                        subnet['id'], port_id=port['id'],
                        **port_dhcp_options))
                columns = {'dhcpv6_options': lsp_dhcp_options} if \
                    subnet['ip_version'] == const.IP_VERSION_6 else {
                    'dhcpv4_options': lsp_dhcp_options}

                # Set lsp DHCP options
                txn.add(self._nb_idl.set_lswitch_port(
                        lport_name=port['id'],
                        **columns))

    def _update_subnet_dhcp_options(self, subnet, network,
                                    metadata_port_ip=None):
        if utils.is_dhcp_options_ignored(subnet):
            return
        original_options = self._nb_idl.get_subnet_dhcp_options(subnet['id'])
        mac = None
        if original_options:
            if subnet['ip_version'] == const.IP_VERSION_6:
                mac = original_options['options'].get('server_id')
            else:
                mac = original_options['options'].get('server_mac')
        new_options = self._get_ovn_dhcp_options(
            subnet, network, mac, metadata_port_ip=metadata_port_ip)
        # Check whether DHCP changed
        if (original_options and
                original_options['cidr'] == new_options['cidr'] and
                original_options['options'] == new_options['options']):
            return

        txn_commands = self._nb_idl.compose_dhcp_options_commands(
            subnet['id'], **new_options)
        with self._nb_idl.transaction(check_error=True) as txn:
            for cmd in txn_commands:
                txn.add(cmd)

    def create_subnet(self, subnet, network):
        if subnet['enable_dhcp']:
            metadata_port_ip = None
            if subnet['ip_version'] == 4:
                context = n_context.get_admin_context()
                self.update_metadata_port(context, network['id'])
                metadata_port_ip = self._find_metadata_port_ip(context, subnet)

            self._add_subnet_dhcp_options(subnet, network,
                                          metadata_port_ip=metadata_port_ip)

    def update_subnet(self, subnet, original_subnet, network):
        if not subnet['enable_dhcp'] and not original_subnet['enable_dhcp']:
            return

        context = n_context.get_admin_context()
        self.update_metadata_port(context, network['id'])
        metadata_port_ip = self._find_metadata_port_ip(context, subnet)
        if not original_subnet['enable_dhcp']:
            self._enable_subnet_dhcp_options(subnet, network, metadata_port_ip)
        elif not subnet['enable_dhcp']:
            self._remove_subnet_dhcp_options(subnet['id'])
        else:
            self._update_subnet_dhcp_options(subnet, network, metadata_port_ip)

    def delete_subnet(self, subnet_id):
        self._remove_subnet_dhcp_options(subnet_id)

    def _process_security_group(self, security_group, func, external_ids=True):
        with self._nb_idl.transaction(check_error=True) as txn:
            for ip_version in ('ip4', 'ip6'):
                kwargs = {'name': utils.ovn_addrset_name(security_group['id'],
                                                         ip_version)}
                if external_ids:
                    kwargs['external_ids'] = {ovn_const.OVN_SG_NAME_EXT_ID_KEY:
                                              security_group['name']}
                txn.add(func(**kwargs))

    def create_security_group(self, security_group):
        self._process_security_group(
            security_group, self._nb_idl.create_address_set)

    def delete_security_group(self, security_group):
        self._process_security_group(
            security_group, self._nb_idl.delete_address_set,
            external_ids=False)

    def update_security_group(self, security_group):
        self._process_security_group(
            security_group, self._nb_idl.update_address_set_ext_ids)

    def _process_security_group_rule(self, rule, is_add_acl=True):
        admin_context = n_context.get_admin_context()
        ovn_acl.update_acls_for_security_group(
            self._plugin, admin_context, self._nb_idl,
            rule['security_group_id'], rule, is_add_acl=is_add_acl)

    def create_security_group_rule(self, rule):
        self._process_security_group_rule(rule)

    def delete_security_group_rule(self, rule):
        self._process_security_group_rule(rule, is_add_acl=False)

    def _find_metadata_port(self, context, network_id):
        if not config.is_ovn_metadata_enabled():
            return

        ports = self._plugin.get_ports(context, filters=dict(
            network_id=[network_id], device_owner=['network:dhcp']))
        # There should be only one metadata port per network
        if len(ports) == 1:
            return ports[0]
        LOG.error("Metadata port couldn't be found for network %s", network_id)

    def _find_metadata_port_ip(self, context, subnet):
        metadata_port = self._find_metadata_port(context, subnet['network_id'])
        if metadata_port:
            for fixed_ip in metadata_port['fixed_ips']:
                if fixed_ip['subnet_id'] == subnet['id']:
                    return fixed_ip['ip_address']

    def create_metadata_port(self, context, network):
        if config.is_ovn_metadata_enabled():
            # Create a neutron port for DHCP/metadata services
            port = {'port':
                    {'network_id': network['id'],
                     'tenant_id': network['project_id'],
                     'device_owner': const.DEVICE_OWNER_DHCP}}
            p_utils.create_port(self._plugin, context, port)

    def update_metadata_port(self, context, network_id):
        """Update metadata port.

        This function will allocate an IP address for the metadata port of
        the given network in all its IPv4 subnets.
        """
        # Retrieve the metadata port of this network
        metadata_port = self._find_metadata_port(context, network_id)
        if not metadata_port:
            return

        # Retrieve all subnets in this network
        subnets = self._plugin.get_subnets(context, filters=dict(
            network_id=[network_id], ip_version=[4]))

        subnet_ids = set(s['id'] for s in subnets)
        port_subnet_ids = set(ip['subnet_id'] for ip in
                              metadata_port['fixed_ips'])

        # Find all subnets where metadata port doesn't have an IP in and
        # allocate one.
        if subnet_ids != port_subnet_ids:
            wanted_fixed_ips = []
            for fixed_ip in metadata_port['fixed_ips']:
                wanted_fixed_ips.append(
                    {'subnet_id': fixed_ip['subnet_id'],
                     'ip_address': fixed_ip['ip_address']})
            wanted_fixed_ips.extend(
                dict(subnet_id=s)
                for s in subnet_ids - port_subnet_ids)

            port = {'id': metadata_port['id'],
                    'port': {'network_id': network_id,
                             'fixed_ips': wanted_fixed_ips}}
            self._plugin.update_port(n_context.get_admin_context(),
                                     metadata_port['id'], port)

    def get_parent_port(self, port_id):
        return self._nb_idl.get_parent_port(port_id)

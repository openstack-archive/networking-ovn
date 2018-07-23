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
from neutron_lib.api.definitions import l3
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib import constants as const
from neutron_lib import context as n_context
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as p_utils
from neutron_lib.utils import helpers
from neutron_lib.utils import net as n_net
from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from ovsdbapp.backend.ovs_idl import idlutils

from networking_ovn.agent.metadata import agent as metadata_agent
from networking_ovn.common import acl as ovn_acl
from networking_ovn.common import config
from networking_ovn.common import constants as ovn_const
from networking_ovn.common import utils
from networking_ovn.db import revision as db_rev
from networking_ovn.l3 import l3_ovn_scheduler
from networking_ovn.ml2 import qos_driver

LOG = log.getLogger(__name__)


OvnPortInfo = collections.namedtuple(
    'OvnPortInfo', ['type', 'options', 'addresses', 'port_security',
                    'parent_name', 'tag', 'dhcpv4_options', 'dhcpv6_options',
                    'cidrs', 'device_owner', 'security_group_ids'])


GW_INFO = collections.namedtuple('GatewayInfo', ['network_id', 'subnet_id',
                                                 'router_ip', 'gateway_ip'])


class OVNClient(object):

    def __init__(self, nb_idl, sb_idl):
        self._nb_idl = nb_idl
        self._sb_idl = sb_idl

        self._plugin_property = None
        self._l3_plugin_property = None

        self._qos_driver = qos_driver.OVNQosDriver(self)
        self._ovn_scheduler = l3_ovn_scheduler.get_scheduler()

    @property
    def _plugin(self):
        if self._plugin_property is None:
            self._plugin_property = directory.get_plugin()
        return self._plugin_property

    @property
    def _l3_plugin(self):
        if self._l3_plugin_property is None:
            self._l3_plugin_property = directory.get_plugin(
                plugin_constants.L3)
        return self._l3_plugin_property

    def _transaction(self, commands, txn=None):
        """Create a new transaction or add the commands to an existing one."""
        if txn is None:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in commands:
                    txn.add(cmd)
        else:
            for cmd in commands:
                txn.add(cmd)

    def _get_allowed_addresses_from_port(self, port):
        if not port.get(psec.PORTSECURITY):
            return [], []

        if utils.is_lsp_trusted(port):
            return [], []

        allowed_addresses = set()
        new_macs = set()
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
                new_macs.add(allowed_address['mac_address'])

        allowed_addresses.add(addresses)

        return list(allowed_addresses), list(new_macs)

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
            addresses = ["unknown"]
            parent_name = []
            tag = []
            port_security = []
        else:
            options = qos_options
            parent_name = binding_prof.get('parent_name', [])
            tag = binding_prof.get('tag', [])
            address = port['mac_address']
            for ip in port.get('fixed_ips', []):
                address += ' ' + ip['ip_address']
                subnet = self._plugin.get_subnet(n_context.get_admin_context(),
                                                 ip['subnet_id'])
                cidrs += ' {}/{}'.format(ip['ip_address'],
                                         subnet['cidr'].split('/')[1])
            port_security, new_macs = \
                self._get_allowed_addresses_from_port(port)
            addresses = [address]
            addresses.extend(new_macs)
            port_type = ovn_const.OVN_NEUTRON_OWNER_TO_PORT_TYPE.get(
                port['device_owner'], '')

        dhcpv4_options = self._get_port_dhcp_options(port, const.IP_VERSION_4)
        dhcpv6_options = self._get_port_dhcp_options(port, const.IP_VERSION_6)

        options.update({'requested-chassis':
                        port.get(portbindings.HOST_ID, '')})
        device_owner = port.get('device_owner', '')
        sg_ids = ' '.join(utils.get_lsp_security_groups(port))
        return OvnPortInfo(port_type, options, addresses, port_security,
                           parent_name, tag, dhcpv4_options, dhcpv6_options,
                           cidrs.strip(), device_owner, sg_ids)

    def create_port(self, port):
        if utils.is_lsp_ignored(port):
            return

        port_info = self._get_port_options(port)
        external_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port['name'],
                        ovn_const.OVN_DEVID_EXT_ID_KEY: port['device_id'],
                        ovn_const.OVN_PROJID_EXT_ID_KEY: port['project_id'],
                        ovn_const.OVN_CIDRS_EXT_ID_KEY: port_info.cidrs,
                        ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                            port_info.device_owner,
                        ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY:
                            utils.ovn_name(port['network_id']),
                        ovn_const.OVN_SG_IDS_EXT_ID_KEY:
                            port_info.security_group_ids,
                        ovn_const.OVN_REV_NUM_EXT_ID_KEY: str(
                            utils.get_revision_number(
                                port, ovn_const.TYPE_PORTS))}
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
                                        port, sg_cache, subnet_cache,
                                        self._nb_idl)
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

            if self.is_dns_required_for_port(port):
                self.add_txns_to_sync_port_dns_records(txn, port)

        db_rev.bump_revision(port, ovn_const.TYPE_PORTS)

    # TODO(lucasagomes): Remove this helper method in the Rocky release
    def _get_lsp_backward_compat_sgs(self, ovn_port, port_object=None,
                                     skip_trusted_port=True):
        if ovn_const.OVN_SG_IDS_EXT_ID_KEY in ovn_port.external_ids:
            return utils.get_ovn_port_security_groups(
                ovn_port, skip_trusted_port=skip_trusted_port)
        elif port_object is not None:
            return utils.get_lsp_security_groups(
                port_object, skip_trusted_port=skip_trusted_port)
        return []

    # TODO(lucasagomes): The ``port_object`` parameter was added to
    # keep things backward compatible. Remove it in the Rocky release.
    def update_port(self, port, qos_options=None, port_object=None):
        if utils.is_lsp_ignored(port):
            return

        port_info = self._get_port_options(port, qos_options)
        external_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port['name'],
                        ovn_const.OVN_DEVID_EXT_ID_KEY: port['device_id'],
                        ovn_const.OVN_PROJID_EXT_ID_KEY: port['project_id'],
                        ovn_const.OVN_CIDRS_EXT_ID_KEY: port_info.cidrs,
                        ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                            port_info.device_owner,
                        ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY:
                            utils.ovn_name(port['network_id']),
                        ovn_const.OVN_SG_IDS_EXT_ID_KEY:
                            port_info.security_group_ids,
                        ovn_const.OVN_REV_NUM_EXT_ID_KEY: str(
                            utils.get_revision_number(
                                port, ovn_const.TYPE_PORTS))}
        admin_context = n_context.get_admin_context()
        sg_cache = {}
        subnet_cache = {}

        check_rev_cmd = self._nb_idl.check_revision_number(
            port['id'], port, ovn_const.TYPE_PORTS)
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(check_rev_cmd)
            columns_dict = {}
            if utils.is_lsp_router_port(port):
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

            ovn_port = self._nb_idl.lookup('Logical_Switch_Port', port['id'])
            # Determine if security groups or fixed IPs are updated.
            old_sg_ids = set(self._get_lsp_backward_compat_sgs(
                ovn_port, port_object=port_object))
            new_sg_ids = set(utils.get_lsp_security_groups(port))
            detached_sg_ids = old_sg_ids - new_sg_ids
            attached_sg_ids = new_sg_ids - old_sg_ids
            old_fixed_ips = utils.remove_macs_from_lsp_addresses(
                ovn_port.addresses)
            new_fixed_ips = [x['ip_address'] for x in
                             port.get('fixed_ips', [])]
            old_allowed_address_pairs = (
                utils.get_allowed_address_pairs_ip_addresses_from_ovn_port(
                    ovn_port))
            new_allowed_address_pairs = (
                utils.get_allowed_address_pairs_ip_addresses(port))
            is_fixed_ips_updated = (
                sorted(old_fixed_ips) != sorted(new_fixed_ips))
            is_allowed_ips_updated = (sorted(old_allowed_address_pairs) !=
                                      sorted(new_allowed_address_pairs))

            port_security_changed = utils.is_port_security_enabled(port) != (
                bool(ovn_port.port_security))

            # Refresh ACLs for changed security groups or fixed IPs.
            if detached_sg_ids or attached_sg_ids or is_fixed_ips_updated or (
                    port_security_changed):
                # Note that update_acls will compare the port's ACLs to
                # ensure only the necessary ACLs are added and deleted
                # on the transaction.
                acls_new = ovn_acl.add_acls(self._plugin,
                                            admin_context,
                                            port,
                                            sg_cache,
                                            subnet_cache,
                                            self._nb_idl)
                txn.add(self._nb_idl.update_acls([port['network_id']],
                                                 [port],
                                                 {port['id']: acls_new},
                                                 need_compare=True))

            # Refresh address sets for changed security groups or fixed IPs.
            if len(old_fixed_ips) != 0 or len(new_fixed_ips) != 0:
                addresses = ovn_acl.acl_port_ips(port)
                addresses_old = utils.sort_ips_by_version(
                    utils.get_ovn_port_addresses(ovn_port))
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

                if is_fixed_ips_updated or is_allowed_ips_updated:
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

            if self.is_dns_required_for_port(port):
                self.add_txns_to_sync_port_dns_records(
                    txn, port, original_port=port_object)
            elif port_object and self.is_dns_required_for_port(port_object):
                # We need to remove the old entries
                self.add_txns_to_remove_port_dns_records(txn, port_object)

        if check_rev_cmd.result == ovn_const.TXN_COMMITTED:
            db_rev.bump_revision(port, ovn_const.TYPE_PORTS)

    def _delete_port(self, port_id, port_object=None):
        ovn_port = self._nb_idl.lookup('Logical_Switch_Port', port_id)
        network_id = ovn_port.external_ids.get(
            ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY)

        # TODO(lucasagomes): For backward compatibility, if network_id
        # is not in the OVNDB, look at the port_object
        if not network_id and port_object:
            network_id = port_object['network_id']

        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.delete_lswitch_port(
                port_id, network_id))
            txn.add(self._nb_idl.delete_acl(network_id, port_id))

            addresses = utils.sort_ips_by_version(
                utils.get_ovn_port_addresses(ovn_port))
            sec_groups = self._get_lsp_backward_compat_sgs(
                ovn_port, port_object=port_object, skip_trusted_port=False)
            for sg_id in sec_groups:
                for ip_version, addr_list in addresses.items():
                    if not addr_list:
                        continue
                    txn.add(self._nb_idl.update_address_set(
                        name=utils.ovn_addrset_name(sg_id, ip_version),
                        addrs_add=None,
                        addrs_remove=addr_list))

            if port_object and self.is_dns_required_for_port(port_object):
                self.add_txns_to_remove_port_dns_records(txn, port_object)

    # TODO(lucasagomes): The ``port_object`` parameter was added to
    # keep things backward compatible. Remove it in the Rocky release.
    def delete_port(self, port_id, port_object=None):
        try:
            self._delete_port(port_id, port_object=port_object)
        except idlutils.RowNotFound:
            pass
        db_rev.delete_revision(port_id, ovn_const.TYPE_PORTS)

    def _create_or_update_floatingip(self, floatingip, txn=None):
        router_id = floatingip.get('router_id')
        if not router_id:
            return

        commands = []
        context = n_context.get_admin_context()
        fip_db = self._l3_plugin._get_floatingip(context, floatingip['id'])

        func = self._nb_idl.add_nat_rule_in_lrouter
        gw_lrouter_name = utils.ovn_name(router_id)
        nat_rule_args = (gw_lrouter_name,)
        # TODO(chandrav): Since the floating ip port is not
        # bound to any chassis, packets destined to floating ip
        # will be dropped. To overcome this, delete the floating
        # ip port. Proper fix for this would be to redirect packets
        # destined to floating ip to the router port. This would
        # require changes in ovn-northd.
        commands.append(self._nb_idl.delete_lswitch_port(
                        fip_db['floating_port_id'],
                        utils.ovn_name(floatingip['floating_network_id'])))

        # Get the list of nat rules and check if the external_ip
        # with type 'dnat_and_snat' already exists or not.
        # If exists, set the new value.
        # This happens when the port associated to a floating ip
        # is deleted before the disassociation.
        lrouter_nat_rules = self._nb_idl.get_lrouter_nat_rules(
            gw_lrouter_name)
        for nat_rule in lrouter_nat_rules:
            if (nat_rule['external_ip'] ==
                    floatingip['floating_ip_address'] and
                    nat_rule['type'] == 'dnat_and_snat'):
                func = self._nb_idl.set_nat_rule_in_lrouter
                nat_rule_args = (gw_lrouter_name, nat_rule['uuid'])
                break

        ext_ids = {
            ovn_const.OVN_FIP_EXT_ID_KEY: floatingip['id'],
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: str(utils.get_revision_number(
                floatingip, ovn_const.TYPE_FLOATINGIPS)),
            ovn_const.OVN_FIP_PORT_EXT_ID_KEY: floatingip['port_id'],
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: gw_lrouter_name}
        columns = {'type': 'dnat_and_snat',
                   'logical_ip': floatingip['fixed_ip_address'],
                   'external_ip': floatingip['floating_ip_address']}

        # TODO(dalvarez): remove this check once the minimum OVS required
        # version contains the column (when OVS 2.8.2 is released).
        if self._nb_idl.is_col_present('NAT', 'external_ids'):
            columns['external_ids'] = ext_ids

        if config.is_ovn_distributed_floating_ip():
            port = self._plugin.get_port(
                context, fip_db['floating_port_id'])
            columns['external_mac'] = port['mac_address']
            columns['logical_port'] = floatingip['port_id']
        commands.append(func(*nat_rule_args, **columns))
        self._transaction(commands, txn=txn)

    def _delete_floatingip(self, fip, lrouter, txn=None):
        commands = [self._nb_idl.delete_nat_rule_in_lrouter(
                    lrouter, type='dnat_and_snat',
                    logical_ip=fip['logical_ip'],
                    external_ip=fip['external_ip'])]
        self._transaction(commands, txn=txn)

    def update_floatingip_status(self, floatingip):
        # NOTE(lucasagomes): OVN doesn't care about the floating ip
        # status, this method just bumps the revision number
        check_rev_cmd = self._nb_idl.check_revision_number(
            floatingip['id'], floatingip, ovn_const.TYPE_FLOATINGIPS)
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(check_rev_cmd)
        if check_rev_cmd.result == ovn_const.TXN_COMMITTED:
            db_rev.bump_revision(floatingip, ovn_const.TYPE_FLOATINGIPS)

    def create_floatingip(self, floatingip):
        try:
            self._create_or_update_floatingip(floatingip)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error('Unable to create floating ip in gateway '
                          'router. Error: %s', e)

        db_rev.bump_revision(floatingip, ovn_const.TYPE_FLOATINGIPS)

        # NOTE(lucasagomes): Revise the expected status
        # of floating ips, setting it to ACTIVE here doesn't
        # see consistent with other drivers (ODL here), see:
        # https://bugs.launchpad.net/networking-ovn/+bug/1657693
        if floatingip.get('router_id'):
            self._l3_plugin.update_floatingip_status(
                n_context.get_admin_context(), floatingip['id'],
                const.FLOATINGIP_STATUS_ACTIVE)

    # TODO(lucasagomes): The ``fip_object`` parameter was added to
    # keep things backward compatible since old FIPs might not have
    # the OVN_FIP_EXT_ID_KEY in their external_ids field. Remove it
    # in the Rocky release.
    def update_floatingip(self, floatingip, fip_object=None):
        fip_status = None
        router_id = None
        ovn_fip = self._nb_idl.get_floatingip(floatingip['id'])

        if not ovn_fip and fip_object:
            router_id = fip_object.get('router_id')
            ovn_fip = self._nb_idl.get_floatingip_by_ips(
                router_id, fip_object['fixed_ip_address'],
                fip_object['floating_ip_address'])

        check_rev_cmd = self._nb_idl.check_revision_number(
            floatingip['id'], floatingip, ovn_const.TYPE_FLOATINGIPS)
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(check_rev_cmd)
            if (ovn_fip and
                (floatingip['fixed_ip_address'] != ovn_fip['logical_ip'] or
                 floatingip['port_id'] != ovn_fip['external_ids'].get(
                    ovn_const.OVN_FIP_PORT_EXT_ID_KEY))):

                lrouter = ovn_fip['external_ids'].get(
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY,
                    utils.ovn_name(router_id))

                self._delete_floatingip(ovn_fip, lrouter, txn=txn)
                fip_status = const.FLOATINGIP_STATUS_DOWN

            if floatingip.get('port_id'):
                self._create_or_update_floatingip(floatingip, txn=txn)
                fip_status = const.FLOATINGIP_STATUS_ACTIVE

        if check_rev_cmd.result == ovn_const.TXN_COMMITTED:
            db_rev.bump_revision(floatingip, ovn_const.TYPE_FLOATINGIPS)

        if fip_status:
            self._l3_plugin.update_floatingip_status(
                n_context.get_admin_context(), floatingip['id'], fip_status)

    # TODO(lucasagomes): The ``fip_object`` parameter was added to
    # keep things backward compatible since old FIPs might not have
    # the OVN_FIP_EXT_ID_KEY in their external_ids field. Remove it
    # in the Rocky release.
    def delete_floatingip(self, fip_id, fip_object=None):
        router_id = None
        ovn_fip = self._nb_idl.get_floatingip(fip_id)

        if not ovn_fip and fip_object:
            router_id = fip_object.get('router_id')
            ovn_fip = self._nb_idl.get_floatingip_by_ips(
                router_id, fip_object['fixed_ip_address'],
                fip_object['floating_ip_address'])

        if ovn_fip:
            lrouter = ovn_fip['external_ids'].get(
                ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY,
                utils.ovn_name(router_id))
            try:
                self._delete_floatingip(ovn_fip, lrouter)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.error('Unable to delete floating ip in gateway '
                              'router. Error: %s', e)
        db_rev.delete_revision(fip_id, ovn_const.TYPE_FLOATINGIPS)

    def disassociate_floatingip(self, floatingip, router_id):
        lrouter = utils.ovn_name(router_id)
        try:
            self._delete_floatingip(floatingip, lrouter)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error('Unable to disassociate floating ip in gateway '
                          'router. Error: %s', e)

    def _get_gw_info(self, context, router):
        ext_gw_info = router.get(l3.EXTERNAL_GW_INFO, {})
        network_id = ext_gw_info.get('network_id', '')
        for ext_fixed_ip in ext_gw_info.get('external_fixed_ips', []):
            subnet_id = ext_fixed_ip['subnet_id']
            subnet = self._plugin.get_subnet(context, subnet_id)
            if subnet['ip_version'] == 4:
                return GW_INFO(
                    network_id, subnet_id, ext_fixed_ip['ip_address'],
                    subnet.get('gateway_ip'))
        return GW_INFO('', '', '', '')

    def _delete_router_ext_gw(self, context, router, networks, txn):
        if not networks:
            networks = []
        router_id = router['id']
        gw_port_id = router['gw_port_id']
        gw_lrouter_name = utils.ovn_name(router_id)
        gw_info = self._get_gw_info(context, router)
        txn.add(self._nb_idl.delete_static_route(gw_lrouter_name,
                                                 ip_prefix='0.0.0.0/0',
                                                 nexthop=gw_info.gateway_ip))
        txn.add(self._nb_idl.delete_lrouter_port(
            utils.ovn_lrouter_port_name(gw_port_id),
            gw_lrouter_name))
        for network in networks:
            txn.add(self._nb_idl.delete_nat_rule_in_lrouter(
                gw_lrouter_name, type='snat', logical_ip=network,
                external_ip=gw_info.router_ip))

    def _get_nets_and_ipv6_ra_confs_for_router_port(
            self, port_fixed_ips):
        context = n_context.get_admin_context()
        networks = set()
        ipv6_ra_configs = {}
        ipv6_ra_configs_supported = self._nb_idl.is_col_present(
            'Logical_Router_Port', 'ipv6_ra_configs')

        for fixed_ip in port_fixed_ips:
            subnet_id = fixed_ip['subnet_id']
            subnet = self._plugin.get_subnet(context, subnet_id)
            cidr = netaddr.IPNetwork(subnet['cidr'])
            networks.add("%s/%s" % (fixed_ip['ip_address'],
                                    str(cidr.prefixlen)))

            if subnet.get('ipv6_address_mode') and not ipv6_ra_configs and (
                    ipv6_ra_configs_supported):
                ipv6_ra_configs['address_mode'] = (
                    utils.get_ovn_ipv6_address_mode(
                        subnet['ipv6_address_mode']))
                ipv6_ra_configs['send_periodic'] = 'true'
                net = self._plugin.get_network(context, subnet['network_id'])
                ipv6_ra_configs['mtu'] = str(net['mtu'])

        return list(networks), ipv6_ra_configs

    def _add_router_ext_gw(self, context, router, networks, txn):
        router_id = router['id']
        # 1. Add the external gateway router port.
        gw_info = self._get_gw_info(context, router)
        gw_port_id = router['gw_port_id']
        port = self._plugin.get_port(context, gw_port_id)
        self.create_router_port(router_id, port, txn=txn)

        # TODO(lucasagomes): Remove this check after OVS 2.8.2 is tagged
        # (prior to that, the external_ids column didn't exist in this
        # table).
        columns = {}
        if self._nb_idl.is_col_present('Logical_Router_Static_Route',
                                       'external_ids'):
            columns['external_ids'] = {
                ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                ovn_const.OVN_SUBNET_EXT_ID_KEY: gw_info.subnet_id}

        # 2. Add default route with nexthop as gateway ip
        lrouter_name = utils.ovn_name(router_id)
        txn.add(self._nb_idl.add_static_route(
            lrouter_name, ip_prefix='0.0.0.0/0', nexthop=gw_info.gateway_ip,
            **columns))

        # 3. Add snat rules for tenant networks in lrouter if snat is enabled
        if utils.is_snat_enabled(router) and networks:
            self.update_nat_rules(router, networks, enable_snat=True, txn=txn)
        return port

    def _check_external_ips_changed(self, context, ovn_snats, ovn_static_route,
                                    router):
        gw_info = self._get_gw_info(context, router)
        if self._nb_idl.is_col_present('Logical_Router_Static_Route',
                                       'external_ids'):
            ext_ids = getattr(ovn_static_route, 'external_ids', {})
            if (ext_ids.get(ovn_const.OVN_SUBNET_EXT_ID_KEY) !=
               gw_info.subnet_id):
                return True

        for snat in ovn_snats:
            if snat.external_ip != gw_info.router_ip:
                return True

        return False

    def update_router_routes(self, context, router_id, add, remove,
                             txn=None):
        if not any([add, remove]):
            return
        lrouter_name = utils.ovn_name(router_id)
        commands = []
        for route in add:
            commands.append(
                self._nb_idl.add_static_route(
                    lrouter_name, ip_prefix=route['destination'],
                    nexthop=route['nexthop']))
        for route in remove:
            commands.append(
                self._nb_idl.delete_static_route(
                    lrouter_name, ip_prefix=route['destination'],
                    nexthop=route['nexthop']))
        self._transaction(commands, txn=txn)

    def _get_router_ports(self, context, router_id, get_gw_port=False):
        router_db = self._l3_plugin._get_router(context, router_id)
        if get_gw_port:
            return [p.port for p in router_db.attached_ports]
        else:
            # When the existing deployment is migrated to OVN
            # we may need to consider other port types - DVR_INTERFACE/HA_INTF.
            return [p.port for p in router_db.attached_ports
                    if p.port_type in [const.DEVICE_OWNER_ROUTER_INTF,
                                       const.DEVICE_OWNER_DVR_INTERFACE,
                                       const.DEVICE_OWNER_HA_REPLICATED_INT,
                                       const.DEVICE_OWNER_ROUTER_HA_INTF]]

    def _get_v4_network_for_router_port(self, context, port):
        cidr = None
        for fixed_ip in port['fixed_ips']:
            subnet_id = fixed_ip['subnet_id']
            subnet = self._plugin.get_subnet(context, subnet_id)
            if subnet['ip_version'] != 4:
                continue
            cidr = subnet['cidr']
        return cidr

    def _get_v4_network_of_all_router_ports(self, context, router_id,
                                            ports=None):
        networks = []
        ports = ports or self._get_router_ports(context, router_id)
        for port in ports:
            network = self._get_v4_network_for_router_port(context, port)
            if network:
                networks.append(network)

        return networks

    def _gen_router_ext_ids(self, router):
        return {
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                router.get('name', 'no_router_name'),
            ovn_const.OVN_GW_PORT_EXT_ID_KEY:
                router.get('gw_port_id') or '',
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: str(utils.get_revision_number(
                router, ovn_const.TYPE_ROUTERS))}

    def create_router(self, router, add_external_gateway=True):
        """Create a logical router."""
        context = n_context.get_admin_context()
        external_ids = self._gen_router_ext_ids(router)
        enabled = router.get('admin_state_up')
        lrouter_name = utils.ovn_name(router['id'])
        added_gw_port = None
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.create_lrouter(lrouter_name,
                                                external_ids=external_ids,
                                                enabled=enabled,
                                                options={}))
            # TODO(lucasagomes): add_external_gateway is being only used
            # by the ovn_db_sync.py script, remove it after the database
            # synchronization work
            if add_external_gateway:
                networks = self._get_v4_network_of_all_router_ports(
                    context, router['id'])
                if router.get(l3.EXTERNAL_GW_INFO) and networks is not None:
                    added_gw_port = self._add_router_ext_gw(context, router,
                                                            networks, txn)

        if added_gw_port:
            db_rev.bump_revision(added_gw_port,
                                 ovn_const.TYPE_ROUTER_PORTS)
        db_rev.bump_revision(router, ovn_const.TYPE_ROUTERS)

    # TODO(lucasagomes): The ``router_object`` parameter was added to
    # keep things backward compatible with old routers created prior to
    # the database sync work. Remove it in the Rocky release.
    def update_router(self, new_router, router_object=None):
        """Update a logical router."""
        context = n_context.get_admin_context()
        router_id = new_router['id']
        router_name = utils.ovn_name(router_id)
        ovn_router = self._nb_idl.get_lrouter(router_name)
        gateway_new = new_router.get(l3.EXTERNAL_GW_INFO)
        gateway_old = utils.get_lrouter_ext_gw_static_route(ovn_router)
        added_gw_port = None
        deleted_gw_port_id = None

        if router_object:
            gateway_old = gateway_old or router_object.get(l3.EXTERNAL_GW_INFO)
        ovn_snats = utils.get_lrouter_snats(ovn_router)
        networks = self._get_v4_network_of_all_router_ports(context, router_id)
        try:
            check_rev_cmd = self._nb_idl.check_revision_number(
                router_name, new_router, ovn_const.TYPE_ROUTERS)
            with self._nb_idl.transaction(check_error=True) as txn:
                txn.add(check_rev_cmd)
                if gateway_new and not gateway_old:
                    # Route gateway is set
                    added_gw_port = self._add_router_ext_gw(
                        context, new_router, networks, txn)
                elif gateway_old and not gateway_new:
                    # router gateway is removed
                    txn.add(self._nb_idl.delete_lrouter_ext_gw(router_name))
                    if router_object:
                        self._delete_router_ext_gw(context, router_object,
                                                   networks, txn)
                        deleted_gw_port_id = router_object['gw_port_id']
                elif gateway_new and gateway_old:
                    # Check if external gateway has changed, if yes, delete
                    # the old gateway and add the new gateway
                    if self._check_external_ips_changed(
                        context, ovn_snats, gateway_old, new_router):
                        txn.add(self._nb_idl.delete_lrouter_ext_gw(
                            router_name))
                        if router_object:
                            self._delete_router_ext_gw(context, router_object,
                                                       networks, txn)
                            deleted_gw_port_id = router_object['gw_port_id']
                        added_gw_port = self._add_router_ext_gw(
                            context, new_router, networks, txn)
                    else:
                        # Check if snat has been enabled/disabled and update
                        new_snat_state = gateway_new.get('enable_snat', True)
                        if bool(ovn_snats) != new_snat_state:
                            if utils.is_snat_enabled(new_router) and networks:
                                self.update_nat_rules(
                                    new_router, networks,
                                    enable_snat=new_snat_state, txn=txn)

                update = {'external_ids': self._gen_router_ext_ids(new_router)}
                update['enabled'] = new_router.get('admin_state_up') or False
                txn.add(self._nb_idl.update_lrouter(router_name, **update))

                # Check for route updates
                routes = new_router.get('routes')
                if routes:
                    old_routes = utils.get_lrouter_non_gw_routes(ovn_router)
                    added, removed = helpers.diff_list_of_dict(
                        old_routes, routes)
                    self.update_router_routes(
                        context, router_id, added, removed, txn=txn)

            if check_rev_cmd.result == ovn_const.TXN_COMMITTED:
                db_rev.bump_revision(new_router, ovn_const.TYPE_ROUTERS)

            if added_gw_port:
                db_rev.bump_revision(added_gw_port,
                                     ovn_const.TYPE_ROUTER_PORTS)

            if deleted_gw_port_id:
                db_rev.delete_revision(deleted_gw_port_id,
                                       ovn_const.TYPE_ROUTER_PORTS)

        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error('Unable to update router %(router)s. '
                          'Error: %(error)s', {'router': router_id,
                                               'error': e})

    def delete_router(self, router_id):
        """Delete a logical router."""
        lrouter_name = utils.ovn_name(router_id)
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.delete_lrouter(lrouter_name))
        db_rev.delete_revision(router_id, ovn_const.TYPE_ROUTERS)

    def get_candidates_for_scheduling(self, physnet, cms=None,
                                      chassis_physnets=None):
        """Return chassis for scheduling gateway router.

        Criteria for selecting chassis as candidates
        1) chassis from cms with proper bridge mappings
        2) if no chassis is available from 1) then,
           select chassis with proper bridge mappings
        """
        cms = cms or self._sb_idl.get_gateway_chassis_from_cms_options()
        chassis_physnets = (chassis_physnets or
                            self._sb_idl.get_chassis_and_physnets())
        cms_bmaps = []
        bmaps = []
        for chassis, physnets in chassis_physnets.items():
            if physnet and physnet in physnets:
                if chassis in cms:
                    cms_bmaps.append(chassis)
                else:
                    bmaps.append(chassis)
        candidates = cms_bmaps or bmaps
        if not cms_bmaps:
            LOG.debug("No eligible chassis with external connectivity"
                      " through ovn-cms-options.")
        LOG.debug("Chassis candidates with external connectivity: %s",
                  candidates)
        return candidates

    def _get_physnet(self, net_id):
        extnet = self._plugin.get_network(n_context.get_admin_context(),
                                          net_id)
        if extnet.get(pnet.NETWORK_TYPE) in [const.TYPE_FLAT,
                                             const.TYPE_VLAN]:
            return extnet.get(pnet.PHYSICAL_NETWORK)

    def _gen_router_port_ext_ids(self, port):
        return {
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: str(utils.get_revision_number(
                port, ovn_const.TYPE_ROUTER_PORTS))}

    def create_router_port(self, router_id, port, txn=None):
        """Create a logical router port."""
        lrouter = utils.ovn_name(router_id)
        networks, ipv6_ra_configs = (
            self._get_nets_and_ipv6_ra_confs_for_router_port(
                port['fixed_ips']))
        lrouter_port_name = utils.ovn_lrouter_port_name(port['id'])
        is_gw_port = const.DEVICE_OWNER_ROUTER_GW == port.get(
            'device_owner')
        columns = {}
        if is_gw_port:
            physnet = self._get_physnet(port['network_id'])
            candidates = self.get_candidates_for_scheduling(physnet)
            selected_chassis = self._ovn_scheduler.select(
                self._nb_idl, self._sb_idl, lrouter_port_name,
                candidates=candidates)
            if selected_chassis:
                columns['gateway_chassis'] = selected_chassis
        if ipv6_ra_configs:
            columns['ipv6_ra_configs'] = ipv6_ra_configs

        commands = [
            self._nb_idl.add_lrouter_port(
                name=lrouter_port_name,
                lrouter=lrouter,
                mac=port['mac_address'],
                networks=networks,
                may_exist=True,
                external_ids=self._gen_router_port_ext_ids(port),
                **columns),
            self._nb_idl.set_lrouter_port_in_lswitch_port(
                port['id'], lrouter_port_name, is_gw_port=is_gw_port)]
        self._transaction(commands, txn=txn)
        # NOTE(mangelajo): we don't bump the revision here, but we do
        # in the higher level add_router_interface function, because
        # we can't consider it done until the Nat rules are updated

    def update_router_port(self, port, bump_db_rev=True, if_exists=False):
        """Update a logical router port."""
        networks, ipv6_ra_configs = (
            self._get_nets_and_ipv6_ra_confs_for_router_port(
                port['fixed_ips']))

        lrouter_port_name = utils.ovn_lrouter_port_name(port['id'])
        update = {'networks': networks, 'ipv6_ra_configs': ipv6_ra_configs}
        is_gw_port = const.DEVICE_OWNER_ROUTER_GW == port.get(
            'device_owner')
        check_rev_cmd = self._nb_idl.check_revision_number(
            lrouter_port_name, port, ovn_const.TYPE_ROUTER_PORTS)
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(check_rev_cmd)
            txn.add(self._nb_idl.update_lrouter_port(
                    name=lrouter_port_name,
                    external_ids=self._gen_router_port_ext_ids(port),
                    if_exists=if_exists,
                    **update))
            txn.add(self._nb_idl.set_lrouter_port_in_lswitch_port(
                    port['id'], lrouter_port_name, is_gw_port=is_gw_port))

        if bump_db_rev and check_rev_cmd.result == ovn_const.TXN_COMMITTED:
            db_rev.bump_revision(port, ovn_const.TYPE_ROUTER_PORTS)
        else:
            # NOTE(mangelajo): we don't bump the revision here, but we do
            # in the higher level add_router_interface function, because
            # we can't consider it done until the Nat rules are updated
            pass

    def delete_router_port(self, port_id, router_id=None):
        """Delete a logical router port."""
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.lrp_del(
                utils.ovn_lrouter_port_name(port_id),
                utils.ovn_name(router_id) if router_id else None,
                if_exists=True))
        db_rev.delete_revision(port_id, ovn_const.TYPE_ROUTER_PORTS)

    def update_nat_rules(self, router, networks, enable_snat, txn=None):
        """Update the NAT rules in a logical router."""
        context = n_context.get_admin_context()
        func = (self._nb_idl.add_nat_rule_in_lrouter if enable_snat else
                self._nb_idl.delete_nat_rule_in_lrouter)
        gw_lrouter_name = utils.ovn_name(router['id'])
        gw_info = self._get_gw_info(context, router)
        commands = []
        for network in networks:
            commands.append(
                func(gw_lrouter_name, type='snat', logical_ip=network,
                     external_ip=gw_info.router_ip))
        self._transaction(commands, txn=txn)

    def _create_provnet_port(self, txn, network, physnet, tag):
        txn.add(self._nb_idl.create_lswitch_port(
            lport_name=utils.ovn_provnet_port_name(network['id']),
            lswitch_name=utils.ovn_name(network['id']),
            addresses=['unknown'],
            external_ids={},
            type='localnet',
            tag=tag if tag else [],
            options={'network_name': physnet}))

    def _gen_network_external_ids(self, network):
        ext_ids = {
            ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: network['name'],
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: str(
                utils.get_revision_number(network, ovn_const.TYPE_NETWORKS))}

        # NOTE(lucasagomes): There's a difference between the
        # "qos_policy_id" key existing and it being None, the latter is a
        # valid value. Since we can't save None in OVSDB, we are converting
        # it to "null" as a placeholder.
        if 'qos_policy_id' in network:
            ext_ids[ovn_const.OVN_QOS_POLICY_EXT_ID_KEY] = (
                network['qos_policy_id'] or 'null')
        return ext_ids

    def create_network(self, network):
        # Create a logical switch with a name equal to the Neutron network
        # UUID.  This provides an easy way to refer to the logical switch
        # without having to track what UUID OVN assigned to it.
        ext_ids = self._gen_network_external_ids(network)
        lswitch_name = utils.ovn_name(network['id'])
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.ls_add(lswitch_name, external_ids=ext_ids,
                                        may_exist=True))
            physnet = network.get(pnet.PHYSICAL_NETWORK)
            if physnet:
                self._create_provnet_port(txn, network, physnet,
                                          network.get(pnet.SEGMENTATION_ID))
        db_rev.bump_revision(network, ovn_const.TYPE_NETWORKS)
        self.create_metadata_port(n_context.get_admin_context(), network)
        return network

    def delete_network(self, network_id):
        with self._nb_idl.transaction(check_error=True) as txn:
            ls, ls_dns_record = self._nb_idl.get_ls_and_dns_record(
                utils.ovn_name(network_id))

            txn.add(self._nb_idl.ls_del(utils.ovn_name(network_id),
                    if_exists=True))
            if ls_dns_record:
                txn.add(self._nb_idl.dns_del(ls_dns_record.uuid))
        db_rev.delete_revision(network_id, ovn_const.TYPE_NETWORKS)

    def _is_qos_update_required(self, network):
        # Is qos service enabled
        if 'qos_policy_id' not in network:
            return False

        # Check if qos service wasn't enabled before
        ovn_net = self._nb_idl.get_lswitch(utils.ovn_name(network['id']))
        if ovn_const.OVN_QOS_POLICY_EXT_ID_KEY not in ovn_net.external_ids:
            return True

        # Check if the policy_id has changed
        new_qos_id = network['qos_policy_id'] or 'null'
        return new_qos_id != ovn_net.external_ids[
            ovn_const.OVN_QOS_POLICY_EXT_ID_KEY]

    def update_network(self, network):
        lswitch_name = utils.ovn_name(network['id'])
        # Check if QoS needs to be update, before updating OVNDB
        qos_update_required = self._is_qos_update_required(network)
        check_rev_cmd = self._nb_idl.check_revision_number(
            lswitch_name, network, ovn_const.TYPE_NETWORKS)

        # TODO(numans) - When a network's dns domain name is updated, we need
        # to update the DNS records for this network in DNS OVN NB DB table.
        # (https://bugs.launchpad.net/networking-ovn/+bug/1777978)
        # Eg. if the network n1's dns domain name was "test1" and if it has
        # 2 bound ports - p1 and p2, we would have created the below dns
        # records
        # ===========================
        # p1 = P1_IP
        # p1.test1 = P1_IP
        # p1.default_domain = P1_IP
        # p2 = P2_IP
        # p2.test1 = P2_IP
        # p2.default_domain = P2_IP
        # ===========================
        # if the network n1's dns domain name is updated to test2, then we need
        # to delete the below DNS records
        # ===========================
        # p1.test1 = P1_IP
        # p2.test1 = P2_IP
        # ===========================
        # and add the new ones
        # ===========================
        # p1.test2 = P1_IP
        # p2.test2 = P2_IP
        # ===========================
        # in the DNS row for this network.

        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(check_rev_cmd)
            ext_ids = self._gen_network_external_ids(network)
            txn.add(self._nb_idl.set_lswitch_ext_ids(lswitch_name, ext_ids))

        if check_rev_cmd.result == ovn_const.TXN_COMMITTED:
            if qos_update_required:
                self._qos_driver.update_network(network)
            db_rev.bump_revision(network, ovn_const.TYPE_NETWORKS)

    def _add_subnet_dhcp_options(self, subnet, network,
                                 ovn_dhcp_options=None):
        if utils.is_dhcp_options_ignored(subnet):
            return

        if not ovn_dhcp_options:
            ovn_dhcp_options = self._get_ovn_dhcp_options(subnet, network)

        with self._nb_idl.transaction(check_error=True) as txn:
            rev_num = {ovn_const.OVN_REV_NUM_EXT_ID_KEY: str(
                utils.get_revision_number(subnet, ovn_const.TYPE_SUBNETS))}
            ovn_dhcp_options['external_ids'].update(rev_num)
            txn.add(self._nb_idl.add_dhcp_options(subnet['id'],
                                                  **ovn_dhcp_options))

    def _get_ovn_dhcp_options(self, subnet, network, server_mac=None):
        external_ids = {
            'subnet_id': subnet['id'],
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: str(utils.get_revision_number(
                subnet, ovn_const.TYPE_SUBNETS))}
        dhcp_options = {'cidr': subnet['cidr'], 'options': {},
                        'external_ids': external_ids}

        if subnet['enable_dhcp']:
            if subnet['ip_version'] == const.IP_VERSION_4:
                dhcp_options['options'] = self._get_ovn_dhcpv4_opts(
                    subnet, network, server_mac=server_mac)
            else:
                dhcp_options['options'] = self._get_ovn_dhcpv6_opts(
                    subnet, server_id=server_mac)

        return dhcp_options

    def _get_ovn_dhcpv4_opts(self, subnet, network, server_mac=None):
        metadata_port_ip = self._find_metadata_port_ip(
            n_context.get_admin_context(), subnet)
        # TODO(dongj): Currently the metadata port is created only when
        # ovn_metadata_enabled is true, therefore this is a restriction for
        # supporting DHCP of subnet without gateway IP.
        # We will remove this restriction later.
        service_id = subnet['gateway_ip'] or metadata_port_ip
        if not service_id:
            return {}

        default_lease_time = str(config.get_ovn_dhcp_default_lease_time())
        mtu = network['mtu']
        options = {
            'server_id': service_id,
            'lease_time': default_lease_time,
            'mtu': str(mtu),
        }

        if subnet['gateway_ip']:
            options['router'] = subnet['gateway_ip']

        if server_mac:
            options['server_mac'] = server_mac
        else:
            options['server_mac'] = n_net.get_random_mac(
                cfg.CONF.base_mac.split(':'))

        dns_servers = (subnet.get('dns_nameservers') or
                       config.get_dns_servers() or
                       utils.get_system_dns_resolvers())
        if dns_servers:
            options['dns_server'] = '{%s}' % ', '.join(dns_servers)
        else:
            LOG.warning("No relevant dns_servers defined for subnet %s. Check "
                        "the /etc/resolv.conf file",
                        subnet['id'])

        routes = []
        if metadata_port_ip:
            routes.append('%s/32,%s' % (
                metadata_agent.METADATA_DEFAULT_IP, metadata_port_ip))

        # Add subnet host_routes to 'classless_static_route' dhcp option
        routes.extend(['%s,%s' % (route['destination'], route['nexthop'])
                      for route in subnet['host_routes']])

        if routes:
            # if there are static routes, then we need to add the
            # default route in this option. As per RFC 3442 dhcp clients
            # should ignore 'router' dhcp option (option 3)
            # if option 121 is present.
            if subnet['gateway_ip']:
                routes.append('0.0.0.0/0,%s' % subnet['gateway_ip'])

            options['classless_static_route'] = '{' + ', '.join(routes) + '}'

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

    def _remove_subnet_dhcp_options(self, subnet_id, txn):
        dhcp_options = self._nb_idl.get_subnet_dhcp_options(
            subnet_id, with_ports=True)

        if dhcp_options['subnet'] is not None:
            txn.add(self._nb_idl.delete_dhcp_options(
                dhcp_options['subnet']['uuid']))

        # Remove subnet and port DHCP_Options rows, the DHCP options in
        # lsp rows will be removed by related UUID
        for opt in dhcp_options['ports']:
            txn.add(self._nb_idl.delete_dhcp_options(opt['uuid']))

    def _enable_subnet_dhcp_options(self, subnet, network, txn):
        if utils.is_dhcp_options_ignored(subnet):
            return

        filters = {'fixed_ips': {'subnet_id': [subnet['id']]}}
        all_ports = self._plugin.get_ports(n_context.get_admin_context(),
                                           filters=filters)
        ports = [p for p in all_ports if not utils.is_network_device_port(p)]

        dhcp_options = self._get_ovn_dhcp_options(subnet, network)
        subnet_dhcp_cmd = self._nb_idl.add_dhcp_options(subnet['id'],
                                                        **dhcp_options)
        subnet_dhcp_option = txn.add(subnet_dhcp_cmd)
        # Traverse ports to add port DHCP_Options rows
        for port in ports:
            lsp_dhcp_disabled, lsp_dhcp_opts = utils.get_lsp_dhcp_opts(
                port, subnet['ip_version'])
            if lsp_dhcp_disabled:
                continue
            elif not lsp_dhcp_opts:
                lsp_dhcp_options = subnet_dhcp_option
            else:
                port_dhcp_options = copy.deepcopy(dhcp_options)
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

    def _update_subnet_dhcp_options(self, subnet, network, txn):
        if utils.is_dhcp_options_ignored(subnet):
            return
        original_options = self._nb_idl.get_subnet_dhcp_options(
            subnet['id'])['subnet']
        mac = None
        if original_options:
            if subnet['ip_version'] == const.IP_VERSION_6:
                mac = original_options['options'].get('server_id')
            else:
                mac = original_options['options'].get('server_mac')
        new_options = self._get_ovn_dhcp_options(subnet, network, mac)
        # Check whether DHCP changed
        if (original_options and
                original_options['cidr'] == new_options['cidr'] and
                original_options['options'] == new_options['options']):
            return
        txn.add(self._nb_idl.add_dhcp_options(subnet['id'], **new_options))
        dhcp_options = self._nb_idl.get_subnet_dhcp_options(
            subnet['id'], with_ports=True)

        # When a subnet dns_nameserver is updated, then we should update
        # the port dhcp options for ports (with no port specific dns_server
        # defined).
        if 'options' in new_options and 'options' in original_options:
            orig_dns_server = original_options['options'].get('dns_server')
            new_dns_server = new_options['options'].get('dns_server')
            dns_server_changed = (orig_dns_server != new_dns_server)
        else:
            dns_server_changed = False

        for opt in dhcp_options['ports']:
            if not new_options.get('options'):
                continue
            options = dict(new_options['options'])
            p_dns_server = opt['options'].get('dns_server')
            if dns_server_changed and (orig_dns_server == p_dns_server):
                # If port has its own dns_server option defined, then
                # orig_dns_server and p_dns_server will not match.
                opt['options']['dns_server'] = new_dns_server
            options.update(opt['options'])

            port_id = opt['external_ids']['port_id']
            txn.add(self._nb_idl.add_dhcp_options(
                subnet['id'], port_id=port_id, options=options))

    def create_subnet(self, subnet, network):
        if subnet['enable_dhcp']:
            if subnet['ip_version'] == 4:
                context = n_context.get_admin_context()
                self.update_metadata_port(context, network['id'])

            self._add_subnet_dhcp_options(subnet, network)
        db_rev.bump_revision(subnet, ovn_const.TYPE_SUBNETS)

    def update_subnet(self, subnet, network):
        ovn_subnet = self._nb_idl.get_subnet_dhcp_options(
            subnet['id'])['subnet']

        if subnet['enable_dhcp'] or ovn_subnet:
            context = n_context.get_admin_context()
            self.update_metadata_port(context, network['id'])

        check_rev_cmd = self._nb_idl.check_revision_number(
            subnet['id'], subnet, ovn_const.TYPE_SUBNETS)
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(check_rev_cmd)
            if subnet['enable_dhcp'] and not ovn_subnet:
                self._enable_subnet_dhcp_options(subnet, network, txn)
            elif not subnet['enable_dhcp'] and ovn_subnet:
                self._remove_subnet_dhcp_options(subnet['id'], txn)
            elif subnet['enable_dhcp'] and ovn_subnet:
                self._update_subnet_dhcp_options(subnet, network, txn)

        if check_rev_cmd.result == ovn_const.TXN_COMMITTED:
            db_rev.bump_revision(subnet, ovn_const.TYPE_SUBNETS)

    def delete_subnet(self, subnet_id):
        with self._nb_idl.transaction(check_error=True) as txn:
            self._remove_subnet_dhcp_options(subnet_id, txn)
        db_rev.delete_revision(subnet_id, ovn_const.TYPE_FLOATINGIPS)

    def create_security_group(self, security_group):
        with self._nb_idl.transaction(check_error=True) as txn:
            for ip_version in ('ip4', 'ip6'):
                name = utils.ovn_addrset_name(security_group['id'], ip_version)
                ext_ids = {ovn_const.OVN_SG_EXT_ID_KEY: security_group['id']}
                txn.add(self._nb_idl.create_address_set(
                    name=name, external_ids=ext_ids))
        db_rev.bump_revision(security_group, ovn_const.TYPE_SECURITY_GROUPS)

    def delete_security_group(self, security_group_id):
        with self._nb_idl.transaction(check_error=True) as txn:
            for ip_version in ('ip4', 'ip6'):
                name = utils.ovn_addrset_name(security_group_id, ip_version)
                txn.add(self._nb_idl.delete_address_set(name=name))
        db_rev.delete_revision(security_group_id,
                               ovn_const.TYPE_SECURITY_GROUPS)

    def _process_security_group_rule(self, rule, is_add_acl=True):
        admin_context = n_context.get_admin_context()
        ovn_acl.update_acls_for_security_group(
            self._plugin, admin_context, self._nb_idl,
            rule['security_group_id'], rule, is_add_acl=is_add_acl)

    def create_security_group_rule(self, rule):
        self._process_security_group_rule(rule)
        db_rev.bump_revision(rule, ovn_const.TYPE_SECURITY_GROUP_RULES)

    def delete_security_group_rule(self, rule):
        self._process_security_group_rule(rule, is_add_acl=False)
        db_rev.delete_revision(rule['id'], ovn_const.TYPE_SECURITY_GROUP_RULES)

    def _find_metadata_port(self, context, network_id):
        if not config.is_ovn_metadata_enabled():
            return

        ports = self._plugin.get_ports(context, filters=dict(
            network_id=[network_id], device_owner=[const.DEVICE_OWNER_DHCP]))
        # There should be only one metadata port per network
        if len(ports) == 1:
            return ports[0]

    def _find_metadata_port_ip(self, context, subnet):
        metadata_port = self._find_metadata_port(context, subnet['network_id'])
        if metadata_port:
            for fixed_ip in metadata_port['fixed_ips']:
                if fixed_ip['subnet_id'] == subnet['id']:
                    return fixed_ip['ip_address']

    def _get_metadata_ports(self, context, network_id):
        if not config.is_ovn_metadata_enabled():
            return

        return self._plugin.get_ports(context, filters=dict(
            network_id=[network_id], device_owner=[const.DEVICE_OWNER_DHCP]))

    def create_metadata_port(self, context, network):
        if config.is_ovn_metadata_enabled():
            metadata_ports = self._get_metadata_ports(context, network['id'])
            if not metadata_ports:
                # Create a neutron port for DHCP/metadata services
                port = {'port':
                        {'network_id': network['id'],
                         'tenant_id': network['project_id'],
                         'device_owner': const.DEVICE_OWNER_DHCP}}
                # TODO(boden): rehome create_port into neutron-lib
                p_utils.create_port(self._plugin, context, port)
            elif len(metadata_ports) > 1:
                LOG.error("More than one metadata ports found for network %s. "
                          "Please run the neutron-ovn-db-sync-util to fix it.",
                          network['id'])

    def update_metadata_port(self, context, network_id):
        """Update metadata port.

        This function will allocate an IP address for the metadata port of
        the given network in all its IPv4 subnets.
        """
        if not config.is_ovn_metadata_enabled():
            return

        # Retrieve the metadata port of this network
        metadata_port = self._find_metadata_port(context, network_id)
        if not metadata_port:
            LOG.error("Metadata port couldn't be found for network %s",
                      network_id)
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

    def is_dns_required_for_port(self, port):
        try:
            if not all([port['dns_name'], port['dns_assignment'],
                       port['device_id']]):
                return False
        except KeyError:
            # Possible that dns extension is not enabled.
            return False

        if not self._nb_idl.is_table_present('DNS'):
            return False

        return True

    def get_port_dns_records(self, port):
        port_dns_records = {}
        net = port.get('network', {})
        net_dns_domain = net.get('dns_domain', '').rstrip('.')

        for dns_assignment in port.get('dns_assignment', []):
            hostname = dns_assignment['hostname']
            fqdn = dns_assignment['fqdn'].rstrip('.')
            net_dns_fqdn = hostname + '.' + net_dns_domain
            if hostname not in port_dns_records:
                port_dns_records[hostname] = dns_assignment['ip_address']
                if net_dns_domain and net_dns_fqdn != fqdn:
                    port_dns_records[net_dns_fqdn] = (
                        dns_assignment['ip_address'])
            else:
                port_dns_records[hostname] += " " + (
                    dns_assignment['ip_address'])
                if net_dns_domain and net_dns_fqdn != fqdn:
                    port_dns_records[hostname + '.' + net_dns_domain] += (
                        " " + dns_assignment['ip_address'])

            if fqdn not in port_dns_records:
                port_dns_records[fqdn] = dns_assignment['ip_address']
            else:
                port_dns_records[fqdn] += " " + dns_assignment['ip_address']

        return port_dns_records

    def add_txns_to_sync_port_dns_records(self, txn, port, original_port=None):
        # NOTE(numans): - This implementation has certain known limitations
        # and that will be addressed in the future patches
        # https://bugs.launchpad.net/networking-ovn/+bug/1739257.
        # Please see the bug report for more information, but just to sum up
        # here
        #  - We will have issues if two ports have same dns name
        #  - If a port is deleted with dns name 'd1' and a new port is
        #    added with the same dns name 'd1'.
        records_to_add = self.get_port_dns_records(port)
        lswitch_name = utils.ovn_name(port['network_id'])
        ls, ls_dns_record = self._nb_idl.get_ls_and_dns_record(lswitch_name)

        # If ls_dns_record is None, then we need to create a DNS row for the
        # logical switch.
        if ls_dns_record is None:
            dns_add_txn = txn.add(self._nb_idl.dns_add(
                external_ids={'ls_name': ls.name}, records=records_to_add))
            txn.add(self._nb_idl.ls_set_dns_records(ls.uuid, dns_add_txn))
            return

        if original_port:
            old_records = self.get_port_dns_records(original_port)

            for old_hostname, old_ips in old_records.items():
                if records_to_add.get(old_hostname) != old_ips:
                    txn.add(self._nb_idl.dns_remove_record(
                        ls_dns_record.uuid, old_hostname))

        for hostname, ips in records_to_add.items():
            if ls_dns_record.records.get(hostname) != ips:
                txn.add(self._nb_idl.dns_add_record(
                        ls_dns_record.uuid, hostname, ips))

    def add_txns_to_remove_port_dns_records(self, txn, port):
        lswitch_name = utils.ovn_name(port['network_id'])
        ls, ls_dns_record = self._nb_idl.get_ls_and_dns_record(lswitch_name)

        if ls_dns_record is None:
            return

        net = port.get('network', {})
        net_dns_domain = net.get('dns_domain', '').rstrip('.')

        hostnames = []
        for dns_assignment in port['dns_assignment']:
            hostname = dns_assignment['hostname']
            fqdn = dns_assignment['fqdn'].rstrip('.')
            if hostname not in hostnames:
                hostnames.append(hostname)
                net_dns_fqdn = hostname + '.' + net_dns_domain
                if net_dns_domain and net_dns_fqdn != fqdn:
                    hostnames.append(net_dns_fqdn)

            if fqdn not in hostnames:
                hostnames.append(fqdn)

        for hostname in hostnames:
            if ls_dns_record.records.get(hostname):
                txn.add(self._nb_idl.dns_remove_record(
                        ls_dns_record.uuid, hostname))

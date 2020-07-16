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
from neutron_lib import exceptions as n_exc
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
                                                 'router_ip', 'gateway_ip',
                                                 'ip_version', 'ip_prefix'])


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
            with self._nb_idl.transaction(check_error=True) as new_txn:
                for cmd in commands:
                    new_txn.add(cmd)
        else:
            for cmd in commands:
                txn.add(cmd)

    def _is_virtual_port_supported(self):
        # TODO(lucasagomes): Remove this method in the future. The
        # "virtual" port type was added in the version 2.12 of OVN
        return self._sb_idl.is_col_present('Port_Binding', 'virtual_parent')

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

    def get_virtual_port_parents(self, virtual_ip, port):
        ls = self._nb_idl.ls_get(utils.ovn_name(port['network_id'])).execute(
            check_error=True)
        return [lsp.name for lsp in ls.ports
                if lsp.name != port['id'] and
                virtual_ip in utils.get_ovn_port_addresses(lsp)]

    def _get_port_options(self, port, qos_options=None):
        context = n_context.get_admin_context()
        binding_prof = utils.validate_and_get_data_from_binding_profile(port)
        if qos_options is None:
            qos_options = self._qos_driver.get_qos_options(port)
        vtep_physical_switch = binding_prof.get('vtep-physical-switch')

        port_type = ''
        cidrs = ''
        if vtep_physical_switch:
            vtep_logical_switch = binding_prof.get('vtep-logical-switch')
            port_type = 'vtep'
            options = {'vtep-physical-switch': vtep_physical_switch,
                       'vtep-logical-switch': vtep_logical_switch}
            addresses = [ovn_const.UNKNOWN_ADDR]
            parent_name = []
            tag = []
            port_security = []
        else:
            options = qos_options
            parent_name = binding_prof.get('parent_name', [])
            tag = binding_prof.get('tag', [])
            address = port['mac_address']
            for ip in port.get('fixed_ips', []):
                try:
                    subnet = self._plugin.get_subnet(context, ip['subnet_id'])
                except n_exc.SubnetNotFound:
                    continue
                ip_addr = ip['ip_address']
                address += ' ' + ip_addr
                cidrs += ' {}/{}'.format(ip['ip_address'],
                                         subnet['cidr'].split('/')[1])

                # Check if the port being created is a virtual port
                if (self._is_virtual_port_supported() and
                        not port['device_owner']):
                    parents = self.get_virtual_port_parents(ip_addr, port)
                    if parents:
                        port_type = ovn_const.LSP_TYPE_VIRTUAL
                        options[ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY] = ip_addr
                        options[ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY] = (
                            ','.join(parents))

            port_security, new_macs = \
                self._get_allowed_addresses_from_port(port)
            addresses = [address]
            addresses.extend(new_macs)

            # Only adjust the OVN type if the port is not owned by Neutron
            # DHCP agents.
            if (port['device_owner'] == const.DEVICE_OWNER_DHCP and
                    not utils.is_neutron_dhcp_agent_port(port)):
                port_type = 'localport'

            # The "unknown" address should only be set for the normal LSP
            # ports (the ones which type is empty)
            if not port_security and not port_type:
                # Port security is disabled for this port.
                # So this port can send traffic with any mac address.
                # OVN allows any mac address from a port if "unknown"
                # is added to the Logical_Switch_Port.addresses column.
                # So add it.
                addresses.append(ovn_const.UNKNOWN_ADDR)

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

            kwargs = {
                'lport_name': port['id'],
                'lswitch_name': lswitch_name,
                'addresses': port_info.addresses,
                'external_ids': external_ids,
                'parent_name': port_info.parent_name,
                'tag': port_info.tag,
                'enabled': port.get('admin_state_up'),
                'options': port_info.options,
                'type': port_info.type,
                'port_security': port_info.port_security,
                'dhcpv4_options': dhcpv4_options,
                'dhcpv6_options': dhcpv6_options
            }

            # TODO(lucasgomes): Remove this workaround in the future,
            # the core OVN version >= 2.12 supports the "virtual" port
            # type which deals with these situations.
            # NOTE(mjozefcz): Do not set addresses if the port is not
            # bound and has no device_owner - possibly it is a VirtualIP
            # port used for Octavia (VRRP).
            # For more details check related bug #1789686.
            if (not self._is_virtual_port_supported() and
                not port.get('device_owner') and
                port.get(portbindings.VIF_TYPE) ==
                    portbindings.VIF_TYPE_UNBOUND):
                kwargs['addresses'] = []

            # Check if the parent port was created with the
            # allowed_address_pairs already set
            allowed_address_pairs = port.get('allowed_address_pairs', [])
            if (self._is_virtual_port_supported() and
                    allowed_address_pairs and
                    port_info.type != ovn_const.LSP_TYPE_VIRTUAL):
                addrs = [addr['ip_address'] for addr in allowed_address_pairs]
                self._set_unset_virtual_port_type(
                    admin_context, txn, port, addrs)

            port_cmd = txn.add(self._nb_idl.create_lswitch_port(
                **kwargs))

            # Handle ACL's for this port. If we're not using Port Groups
            # because either the schema doesn't support it or we didn't
            # migrate old SGs from Address Sets to Port Groups, then we
            # keep the old behavior. For those SGs this port belongs to
            # that are modelled as a Port Group, we'll use it.
            sg_ids = utils.get_lsp_security_groups(port)
            if self._nb_idl.is_port_groups_supported():
                # If this is not a trusted port or port security is enabled,
                # add it to the default drop Port Group so that all traffic
                # is dropped by default.
                if not utils.is_lsp_trusted(port) or port_info.port_security:
                    self._add_port_to_drop_port_group(port_cmd, txn)
                # For SGs modelled as OVN Port Groups, just add the port to
                # its Port Group.
                for sg in sg_ids:
                    txn.add(self._nb_idl.pg_add_ports(
                        utils.ovn_port_group_name(sg), port_cmd))
            else:
                # SGs modelled as Address Sets:
                acls_new = ovn_acl.add_acls(self._plugin, admin_context,
                                            port, sg_cache, subnet_cache,
                                            self._nb_idl)
                for acl in acls_new:
                    txn.add(self._nb_idl.add_acl(**acl))

                if port.get('fixed_ips') and sg_ids:
                    addresses = ovn_acl.acl_port_ips(port)
                    # NOTE(rtheis): Fail port creation if the address set
                    # doesn't exist. This prevents ports from being created on
                    # any security groups out-of-sync between neutron and OVN.
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

    def _set_unset_virtual_port_type(self, context, txn, parent_port,
                                     addresses, unset=False):
        cmd = self._nb_idl.set_lswitch_port_to_virtual_type
        if unset:
            cmd = self._nb_idl.unset_lswitch_port_to_virtual_type

        for addr in addresses:
            virt_port = self._plugin.get_ports(context, filters={
                portbindings.VIF_TYPE: portbindings.VIF_TYPE_UNBOUND,
                'network_id': [parent_port['network_id']],
                'fixed_ips': {'ip_address': [addr]}})
            if not virt_port:
                continue
            virt_port = virt_port[0]
            args = {'lport_name': virt_port['id'],
                    'virtual_parent': parent_port['id'],
                    'if_exists': True}
            LOG.debug("Parent port %(virtual_parent)s found for "
                      "virtual port %(lport_name)s", args)
            if not unset:
                args['vip'] = addr
            txn.add(cmd(**args))

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

            # TODO(lucasgomes): Remove this workaround in the future,
            # the core OVN version >= 2.12 supports the "virtual" port
            # type which deals with these situations.
            # NOTE(mjozefcz): Do not set addresses if the port is not
            # bound and has no device_owner - possibly it is a VirtualIP
            # port used for Octavia (VRRP).
            # For more details check related bug #1789686.
            if (not self._is_virtual_port_supported() and
                not port.get('device_owner') and
                port.get(portbindings.VIF_TYPE) ==
                    portbindings.VIF_TYPE_UNBOUND):
                columns_dict['addresses'] = []

            ovn_port = self._nb_idl.lookup('Logical_Switch_Port', port['id'])
            addr_pairs_diff = utils.compute_address_pairs_diff(ovn_port, port)

            if (self._is_virtual_port_supported() and
                    port_info.type != ovn_const.LSP_TYPE_VIRTUAL):
                self._set_unset_virtual_port_type(
                    admin_context, txn, port, addr_pairs_diff.added)
                self._set_unset_virtual_port_type(
                    admin_context, txn, port, addr_pairs_diff.removed,
                    unset=True)

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
            old_sg_ids = set(self._get_lsp_backward_compat_sgs(
                ovn_port, port_object=port_object))
            new_sg_ids = set(utils.get_lsp_security_groups(port))
            detached_sg_ids = old_sg_ids - new_sg_ids
            attached_sg_ids = new_sg_ids - old_sg_ids

            if self._nb_idl.is_port_groups_supported():
                for sg in detached_sg_ids:
                    txn.add(self._nb_idl.pg_del_ports(
                        utils.ovn_port_group_name(sg), port['id']))
                for sg in attached_sg_ids:
                    txn.add(self._nb_idl.pg_add_ports(
                        utils.ovn_port_group_name(sg), port['id']))
                if (not utils.is_lsp_trusted(port) and
                        utils.is_port_security_enabled(port)):
                    self._add_port_to_drop_port_group(port['id'], txn)
                # If the port doesn't belong to any security group and
                # port_security is disabled, or it's a trusted port, then
                # allow all traffic.
                elif ((not new_sg_ids and
                      not utils.is_port_security_enabled(port)) or
                      utils.is_lsp_trusted(port)):
                    self._del_port_from_drop_port_group(port['id'], txn)
            else:

                old_fixed_ips = utils.remove_macs_from_lsp_addresses(
                    ovn_port.addresses)
                new_fixed_ips = [x['ip_address'] for x in
                                 port.get('fixed_ips', [])]
                is_fixed_ips_updated = (
                    sorted(old_fixed_ips) != sorted(new_fixed_ips))
                port_security_changed = (
                    utils.is_port_security_enabled(port) !=
                    bool(ovn_port.port_security))
                # Refresh ACLs for changed security groups or fixed IPs.
                if (detached_sg_ids or attached_sg_ids or
                        is_fixed_ips_updated or port_security_changed):
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

                # Refresh address sets for changed security groups or fixed
                # IPs.
                if len(old_fixed_ips) != 0 or len(new_fixed_ips) != 0:
                    addresses = ovn_acl.acl_port_ips(port)
                    addresses_old = utils.sort_ips_by_version(
                        utils.get_ovn_port_addresses(ovn_port))
                    # Add current addresses to attached security groups.
                    for sg_id in attached_sg_ids:
                        for ip_version in addresses:
                            if addresses[ip_version]:
                                txn.add(self._nb_idl.update_address_set(
                                    name=utils.ovn_addrset_name(sg_id,
                                        ip_version),
                                    addrs_add=addresses[ip_version],
                                    addrs_remove=None))
                    # Remove old addresses from detached security groups.
                    for sg_id in detached_sg_ids:
                        for ip_version in addresses_old:
                            if addresses_old[ip_version]:
                                txn.add(self._nb_idl.update_address_set(
                                    name=utils.ovn_addrset_name(sg_id,
                                        ip_version),
                                    addrs_add=None,
                                    addrs_remove=addresses_old[ip_version]))

                    if is_fixed_ips_updated or addr_pairs_diff.changed:
                        # We have refreshed address sets for attached and
                        # detached security groups, so now we only need to take
                        # care of unchanged security groups.
                        unchanged_sg_ids = new_sg_ids & old_sg_ids
                        for sg_id in unchanged_sg_ids:
                            for ip_version in addresses:
                                addr_add = ((set(addresses[ip_version]) -
                                             set(addresses_old[ip_version])) or
                                            None)
                                addr_remove = (
                                    (set(addresses_old[ip_version]) -
                                     set(addresses[ip_version])) or None)

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
        ovn_port = self._nb_idl.lookup(
            'Logical_Switch_Port', port_id, default=None)
        if ovn_port is None:
            return

        network_id = ovn_port.external_ids.get(
            ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY)

        # TODO(lucasagomes): For backward compatibility, if network_id
        # is not in the OVNDB, look at the port_object
        if not network_id and port_object:
            network_id = port_object['network_id']

        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.delete_lswitch_port(
                port_id, network_id))

            if not self._nb_idl.is_port_groups_supported():
                txn.add(self._nb_idl.delete_acl(
                    network_id, port_id, if_exists=True))

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
                            addrs_remove=addr_list,
                            if_exists=True))

            if port_object and self.is_dns_required_for_port(port_object):
                self.add_txns_to_remove_port_dns_records(txn, port_object)

            # Check if the port being deleted is a virtual parent
            if (ovn_port.type != ovn_const.LSP_TYPE_VIRTUAL and
                    self._is_virtual_port_supported()):
                ls = self._nb_idl.ls_get(network_id).execute(
                    check_error=True)
                cmd = self._nb_idl.unset_lswitch_port_to_virtual_type
                for lsp in ls.ports:
                    if lsp.type != ovn_const.LSP_TYPE_VIRTUAL:
                        continue
                    if port_id in lsp.options.get(
                            ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY, ''):
                        txn.add(cmd(lsp.name, port_id, if_exists=True))

    # TODO(lucasagomes): The ``port_object`` parameter was added to
    # keep things backward compatible. Remove it in the Rocky release.
    def delete_port(self, port_id, port_object=None):
        try:
            self._delete_port(port_id, port_object=port_object)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error('Failed to delete port %(port)s. Error: '
                          '%(error)s', {'port': port_id, 'error': e})
        db_rev.delete_revision(port_id, ovn_const.TYPE_PORTS)

    def _create_or_update_floatingip(self, floatingip, txn=None):
        router_id = floatingip.get('router_id')
        if not router_id:
            return

        commands = []
        context = n_context.get_admin_context()
        fip_db = self._l3_plugin._get_floatingip(context, floatingip['id'])

        gw_lrouter_name = utils.ovn_name(router_id)
        # TODO(chandrav): Since the floating ip port is not
        # bound to any chassis, packets destined to floating ip
        # will be dropped. To overcome this, delete the floating
        # ip port. Proper fix for this would be to redirect packets
        # destined to floating ip to the router port. This would
        # require changes in ovn-northd.
        commands.append(self._nb_idl.delete_lswitch_port(
                        fip_db['floating_port_id'],
                        utils.ovn_name(floatingip['floating_network_id'])))

        ext_ids = {
            ovn_const.OVN_FIP_EXT_ID_KEY: floatingip['id'],
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: str(utils.get_revision_number(
                floatingip, ovn_const.TYPE_FLOATINGIPS)),
            ovn_const.OVN_FIP_PORT_EXT_ID_KEY: floatingip['port_id'],
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: gw_lrouter_name}
        columns = {'type': 'dnat_and_snat',
                   'logical_ip': floatingip['fixed_ip_address'],
                   'external_ip': floatingip['floating_ip_address']}

        if config.is_ovn_distributed_floating_ip():
            port = self._plugin.get_port(
                context, fip_db['floating_port_id'])
            columns['logical_port'] = floatingip['port_id']
            ext_ids[ovn_const.OVN_FIP_EXT_MAC_KEY] = port['mac_address']
            if self._nb_idl.lsp_get_up(floatingip['port_id']).execute():
                columns['external_mac'] = port['mac_address']

        # TODO(dalvarez): remove this check once the minimum OVS required
        # version contains the column (when OVS 2.8.2 is released).
        if self._nb_idl.is_col_present('NAT', 'external_ids'):
            columns['external_ids'] = ext_ids

        # TODO(mjozefcz): Remove this workaround when OVN LB
        # will support both decentralized FIPs on LB and member.
        lb_member_fip = self._is_lb_member_fip(context, floatingip)
        if (config.is_ovn_distributed_floating_ip() and
                lb_member_fip):
            LOG.warning("Port %s is configured as a member "
                        "of one of OVN Load_Balancers and "
                        "Load_Balancer has FIP assigned. "
                        "In order to make traffic work member "
                        "FIP needs to be centralized, even if "
                        "this environment is configured as DVR. "
                        "Removing logical_port and external_mac from "
                        "NAT entry.", floatingip['port_id'])
            columns.pop('logical_port', None)
            columns.pop('external_mac', None)
        commands.append(self._nb_idl.add_nat_rule_in_lrouter(gw_lrouter_name,
                                                             **columns))

        # Get the logical port (of the private network) and set the field
        # external_ids:fip=<FIP>. This will be used by the ovn octavia driver
        # to add the floating ip as vip in the Load_Balancer.vips column.
        private_lsp = self._nb_idl.get_lswitch_port(floatingip['port_id'])

        if private_lsp:
            port_fip = {
                ovn_const.OVN_PORT_FIP_EXT_ID_KEY:
                    floatingip['floating_ip_address']}
            commands.append(
                self._nb_idl.db_set('Logical_Switch_Port', private_lsp.uuid,
                                    ('external_ids', port_fip))
            )
            if not lb_member_fip:
                commands.extend(
                    self._handle_lb_fip_cmds(
                        context, private_lsp,
                        action=ovn_const.FIP_ACTION_ASSOCIATE))
        else:
            LOG.warning("LSP for floatingip %s, has not been found! "
                        "Cannot set FIP on VIP.",
                        floatingip['id'])
        self._transaction(commands, txn=txn)

    def _is_lb_member_fip(self, context, fip):
        port = self._plugin.get_port(
            context, fip['port_id'])
        member_subnet = [ip['subnet_id'] for ip in port['fixed_ips']
                         if ip['ip_address'] == fip['fixed_ip_address']]
        if not member_subnet:
            return False
        member_subnet = member_subnet[0]

        ls = self._nb_idl.lookup(
            'Logical_Switch', utils.ovn_name(port['network_id']))
        for lb in ls.load_balancer:
            for ext_id in lb.external_ids.keys():
                if ext_id.startswith(ovn_const.LB_EXT_IDS_POOL_PREFIX):
                    members = lb.external_ids[ext_id]
                    if not members:
                        continue
                    for member in members.split(','):
                        if ('%s:' % fip['fixed_ip_address'] in member and
                                '_%s' % member_subnet in member):
                            return True
        return False

    def _handle_lb_fip_cmds(self, context, lb_lsp,
                            action=ovn_const.FIP_ACTION_ASSOCIATE):
        commands = []
        if not config.is_ovn_distributed_floating_ip():
            return commands

        lb_lsp_fip_port = lb_lsp.external_ids.get(
            ovn_const.OVN_PORT_NAME_EXT_ID_KEY, '')

        if not lb_lsp_fip_port.startswith(ovn_const.LB_VIP_PORT_PREFIX):
            return commands

        # This is a FIP on LB VIP.
        # Loop over members and delete FIP external_mac/logical_port enteries.
        # Find all LBs with this LSP as VIP.
        lbs = self._nb_idl.db_find_rows(
            'Load_Balancer',
            ('external_ids', '=', {
                ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: lb_lsp.name})
        ).execute(check_error=True)
        for lb in lbs:
            # GET all LS where given LB is linked.
            ls_linked = [
                item
                for item in self._nb_idl.db_find_rows(
                    'Logical_Switch').execute(check_error=True)
                if lb in item.load_balancer]

            if not ls_linked:
                return

            # Find out IP addresses and subnets of configured members.
            members_to_verify = []
            for ext_id in lb.external_ids.keys():
                if ext_id.startswith(ovn_const.LB_EXT_IDS_POOL_PREFIX):
                    members = lb.external_ids[ext_id]
                    if not members:
                        continue
                    for member in members.split(','):
                        # NOTE(mjozefcz): Remove this workaround in W release.
                        # Last argument of member info is a subnet_id from
                        # from which member comes from.
                        # member_`id`_`ip`:`port`_`subnet_ip`
                        member_info = member.split('_')
                        if len(member_info) >= 4:
                            m = {}
                            m['id'] = member_info[1]
                            m['ip'] = member_info[2].split(':')[0]
                            m['subnet_id'] = member_info[3]
                            try:
                                subnet = self._plugin.get_subnet(
                                    context, m['subnet_id'])
                                m['network_id'] = subnet['network_id']
                                members_to_verify.append(m)
                            except n_exc.SubnetNotFound:
                                LOG.debug("Cannot find subnet details "
                                          "for OVN LB member "
                                          "%s.", m['id'])

        # Find a member LSPs from all linked LS to this LB.
        for member in members_to_verify:
            ls = self._nb_idl.lookup(
                'Logical_Switch', utils.ovn_name(member['network_id']))
            for lsp in ls.ports:
                if not lsp.addresses:
                    continue
                if member['ip'] in utils.remove_macs_from_lsp_addresses(
                        lsp.addresses):
                    member['lsp'] = lsp
                    nats = self._nb_idl.db_find_rows(
                        'NAT',
                        ('external_ids', '=', {
                            ovn_const.OVN_FIP_PORT_EXT_ID_KEY: lsp.name})
                    ).execute(check_error=True)

                    for nat in nats:
                        if action == ovn_const.FIP_ACTION_ASSOCIATE:
                            # NOTE(mjozefcz): We should delete logical_port
                            # and external_mac entries from member NAT in
                            # order to make traffic work.
                            LOG.warning(
                                "Port %s is configured as a member "
                                "of one of OVN Load_Balancers and "
                                "Load_Balancer has FIP assigned. "
                                "In order to make traffic work member "
                                "FIP needs to be centralized, even if "
                                "this environment is configured as "
                                "DVR. Removing logical_port and "
                                "external_mac from NAT entry.",
                                lsp.name)
                            commands.extend([
                                self._nb_idl.db_clear(
                                    'NAT', nat.uuid, 'external_mac'),
                                self._nb_idl.db_clear(
                                    'NAT', nat.uuid, 'logical_port')])
                        else:
                            # NOTE(mjozefcz): The FIP from LB VIP is
                            # dissassociated now. We can decentralize
                            # member FIPs now.
                            LOG.warning(
                                "Port %s is configured as a member "
                                "of one of OVN Load_Balancers and "
                                "Load_Balancer has FIP disassociated. "
                                "DVR for this port can be enabled back.",
                                lsp.name)
                            commands.append(self._nb_idl.db_set(
                                'NAT', nat.uuid,
                                ('logical_port', lsp.name)))
                            port = self._plugin.get_port(context, lsp.name)
                            if port['status'] == const.PORT_STATUS_ACTIVE:
                                commands.append(
                                    self._nb_idl.db_set(
                                        'NAT', nat.uuid,
                                        ('external_mac',
                                         port['mac_address'])))

        return commands

    def _delete_floatingip(self, fip, lrouter, txn=None):
        commands = [self._nb_idl.delete_nat_rule_in_lrouter(
                    lrouter, type='dnat_and_snat',
                    logical_ip=fip['logical_ip'],
                    external_ip=fip['external_ip'])]
        try:
            port_id = (
                fip['external_ids'].get(ovn_const.OVN_FIP_PORT_EXT_ID_KEY))
            if port_id:
                private_lsp = self._nb_idl.get_lswitch_port(port_id)
                if private_lsp:
                    commands.append(
                        self._nb_idl.db_remove(
                            'Logical_Switch_Port', private_lsp.uuid,
                            'external_ids',
                            (ovn_const.OVN_PORT_FIP_EXT_ID_KEY)))
                    commands.extend(
                        self._handle_lb_fip_cmds(
                            n_context.get_admin_context(),
                            private_lsp,
                            action=ovn_const.FIP_ACTION_DISASSOCIATE))
        except KeyError:
            LOG.debug("FIP %s doesn't have external_ids.", fip)
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
            if ovn_fip:
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
        gateways_info = []
        ext_gw_info = router.get(l3.EXTERNAL_GW_INFO, {})
        network_id = ext_gw_info.get('network_id', '')
        for ext_fixed_ip in ext_gw_info.get('external_fixed_ips', []):
            subnet_id = ext_fixed_ip['subnet_id']
            subnet = self._plugin.get_subnet(context, subnet_id)
            gateways_info.append(GW_INFO(
                network_id, subnet_id, ext_fixed_ip['ip_address'],
                subnet.get('gateway_ip'), subnet['ip_version'],
                const.IPv4_ANY if subnet['ip_version'] == const.IP_VERSION_4
                else const.IPv6_ANY))
        return gateways_info

    def _delete_router_ext_gw(self, context, router, networks, txn):
        if not networks:
            networks = []
        router_id = router['id']
        gw_port_id = router['gw_port_id']
        gw_lrouter_name = utils.ovn_name(router_id)
        gateways = self._get_gw_info(context, router)
        for gw_info in gateways:
            if gw_info.ip_version == const.IP_VERSION_4:
                for network in networks:
                    txn.add(self._nb_idl.delete_nat_rule_in_lrouter(
                        gw_lrouter_name, type='snat', logical_ip=network,
                        external_ip=gw_info.router_ip))
            txn.add(self._nb_idl.delete_static_route(
                gw_lrouter_name, ip_prefix=gw_info.ip_prefix,
                nexthop=gw_info.gateway_ip))
        txn.add(self._nb_idl.delete_lrouter_port(
            utils.ovn_lrouter_port_name(gw_port_id),
            gw_lrouter_name))

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
        gateways = self._get_gw_info(context, router)
        gw_port_id = router['gw_port_id']
        port = self._plugin.get_port(context, gw_port_id)
        self._create_lrouter_port(router_id, port, txn=txn)

        def _build_extids(gw_info):
            # TODO(lucasagomes): Remove this check after OVS 2.8.2 is tagged
            # (prior to that, the external_ids column didn't exist in this
            # table).
            columns = {}
            if self._nb_idl.is_col_present('Logical_Router_Static_Route',
                                           'external_ids'):
                columns['external_ids'] = {
                    ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                    ovn_const.OVN_SUBNET_EXT_ID_KEY: gw_info.subnet_id}
            return columns

        # 2. Add default route with nexthop as gateway ip
        lrouter_name = utils.ovn_name(router_id)
        for gw_info in gateways:
            columns = _build_extids(gw_info)
            txn.add(self._nb_idl.add_static_route(
                lrouter_name, ip_prefix=gw_info.ip_prefix,
                nexthop=gw_info.gateway_ip, **columns))

        # 3. Add snat rules for tenant networks in lrouter if snat is enabled
        if utils.is_snat_enabled(router) and networks:
            self.update_nat_rules(router, networks, enable_snat=True, txn=txn)
        return port

    def _check_external_ips_changed(self, context, ovn_snats,
                                    ovn_static_routes, router):
        gateways = self._get_gw_info(context, router)
        ovn_gw_subnets = None
        if self._nb_idl.is_col_present('Logical_Router_Static_Route',
                                       'external_ids'):
            ovn_gw_subnets = [
                getattr(route, 'external_ids', {}).get(
                    ovn_const.OVN_SUBNET_EXT_ID_KEY) for route in
                ovn_static_routes]

        for gw_info in gateways:
            if ovn_gw_subnets and gw_info.subnet_id not in ovn_gw_subnets:
                return True
            if gw_info.ip_version == 6:
                continue
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
                      " through ovn-cms-options for %s", physnet)
        LOG.debug("Chassis candidates with external connectivity: %s",
                  candidates)
        return candidates

    def _get_physnet(self, network):
        if network.get(pnet.NETWORK_TYPE) in [const.TYPE_FLAT,
                                              const.TYPE_VLAN]:
            return network.get(pnet.PHYSICAL_NETWORK)

    def _gen_router_port_ext_ids(self, port):
        ext_ids = {
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: str(utils.get_revision_number(
                port, ovn_const.TYPE_ROUTER_PORTS)),
            ovn_const.OVN_SUBNET_EXT_IDS_KEY:
                ' '.join(utils.get_port_subnet_ids(port)),
            ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY:
                utils.ovn_name(port['network_id'])}

        router_id = port.get('device_id')
        if router_id:
            ext_ids[ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY] = router_id

        return ext_ids

    def _create_lrouter_port(self, router_id, port, txn=None):
        """Create a logical router port."""
        lrouter = utils.ovn_name(router_id)
        networks, ipv6_ra_configs = (
            self._get_nets_and_ipv6_ra_confs_for_router_port(
                port['fixed_ips']))
        lrouter_port_name = utils.ovn_lrouter_port_name(port['id'])
        is_gw_port = const.DEVICE_OWNER_ROUTER_GW == port.get(
            'device_owner')
        columns = {}
        port_net = self._plugin.get_network(n_context.get_admin_context(),
                                            port['network_id'])
        # For VLAN type networks we need to set the
        # "reside-on-redirect-chassis" option so the routing for this
        # logical router port is centralized in the chassis hosting the
        # distributed gateway port.
        # https://github.com/openvswitch/ovs/commit/85706c34d53d4810f54bec1de662392a3c06a996
        if port_net.get(pnet.NETWORK_TYPE) == const.TYPE_VLAN:
            columns['options'] = {'reside-on-redirect-chassis': 'true'}

        if is_gw_port:
            physnet = self._get_physnet(port_net)
            candidates = self.get_candidates_for_scheduling(physnet)
            selected_chassis = self._ovn_scheduler.select(
                self._nb_idl, self._sb_idl, lrouter_port_name,
                candidates=candidates)
            if selected_chassis:
                columns['gateway_chassis'] = selected_chassis

        lsp_address = ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER
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
                port['id'], lrouter_port_name, is_gw_port=is_gw_port,
                lsp_address=lsp_address)]
        self._transaction(commands, txn=txn)

    def create_router_port(self, router_id, router_interface):
        context = n_context.get_admin_context()
        port = self._plugin.get_port(context, router_interface['port_id'])
        with self._nb_idl.transaction(check_error=True) as txn:
            multi_prefix = False
            if (len(router_interface.get('subnet_ids', [])) == 1 and
                    len(port['fixed_ips']) > 1):

                # NOTE(lizk) It's adding a subnet onto an already
                # existing router interface port, try to update lrouter port
                # 'networks' column.
                self._update_lrouter_port(port, txn=txn)
                multi_prefix = True
            else:
                self._create_lrouter_port(router_id, port, txn=txn)

            router = self._l3_plugin.get_router(context, router_id)
            if router.get(l3.EXTERNAL_GW_INFO):
                cidr = None
                for fixed_ip in port['fixed_ips']:
                    subnet = self._plugin.get_subnet(context,
                                                     fixed_ip['subnet_id'])
                    if multi_prefix:
                        if 'subnet_id' in router_interface:
                            if subnet['id'] != router_interface['subnet_id']:
                                continue
                    if subnet['ip_version'] == 4:
                        cidr = subnet['cidr']

                if utils.is_snat_enabled(router) and cidr:
                    self.update_nat_rules(router, networks=[cidr],
                                          enable_snat=True, txn=txn)

        db_rev.bump_revision(port, ovn_const.TYPE_ROUTER_PORTS)

    def _update_lrouter_port(self, port, if_exists=False, txn=None):
        """Update a logical router port."""
        networks, ipv6_ra_configs = (
            self._get_nets_and_ipv6_ra_confs_for_router_port(
                port['fixed_ips']))

        lsp_address = ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER
        lrp_name = utils.ovn_lrouter_port_name(port['id'])
        update = {'networks': networks, 'ipv6_ra_configs': ipv6_ra_configs}
        is_gw_port = const.DEVICE_OWNER_ROUTER_GW == port.get(
            'device_owner')
        commands = [
            self._nb_idl.update_lrouter_port(
                name=lrp_name,
                external_ids=self._gen_router_port_ext_ids(port),
                if_exists=if_exists,
                **update),
            self._nb_idl.set_lrouter_port_in_lswitch_port(
                port['id'], lrp_name, is_gw_port=is_gw_port,
                lsp_address=lsp_address)]

        self._transaction(commands, txn=txn)

    def update_router_port(self, port, if_exists=False):
        lrp_name = utils.ovn_lrouter_port_name(port['id'])
        check_rev_cmd = self._nb_idl.check_revision_number(
            lrp_name, port, ovn_const.TYPE_ROUTER_PORTS)
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(check_rev_cmd)
            self._update_lrouter_port(port, if_exists=if_exists, txn=txn)

        if check_rev_cmd.result == ovn_const.TXN_COMMITTED:
            db_rev.bump_revision(port, ovn_const.TYPE_ROUTER_PORTS)

    def _delete_lrouter_port(self, port_id, router_id=None, txn=None):
        """Delete a logical router port."""
        commands = [self._nb_idl.lrp_del(
            utils.ovn_lrouter_port_name(port_id),
            utils.ovn_name(router_id) if router_id else None,
            if_exists=True)]
        self._transaction(commands, txn=txn)
        db_rev.delete_revision(port_id, ovn_const.TYPE_ROUTER_PORTS)

    def delete_router_port(self, port_id, router_id=None, subnet_ids=None):
        try:
            ovn_port = self._nb_idl.lookup(
                'Logical_Router_Port', utils.ovn_lrouter_port_name(port_id))
        except idlutils.RowNotFound:
            return

        subnet_ids = subnet_ids or []
        context = n_context.get_admin_context()
        port_removed = False
        with self._nb_idl.transaction(check_error=True) as txn:
            port = None
            try:
                port = self._plugin.get_port(context, port_id)
                # The router interface port still exists, call ovn to
                # update it
                self._update_lrouter_port(port, txn=txn)
            except n_exc.PortNotFound:
                # The router interface port doesn't exist any more,
                # we will call ovn to delete it once we remove the snat
                # rules in the router itself if we have to
                port_removed = True

            router_id = router_id or ovn_port.external_ids.get(
                ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY)
            if not router_id:
                router_id = port.get('device_id')

            router = None
            if router_id:
                router = self._l3_plugin.get_router(context, router_id)

            if not router.get(l3.EXTERNAL_GW_INFO):
                if port_removed:
                    self._delete_lrouter_port(port_id, router_id, txn=txn)
                return

            if not subnet_ids:
                subnet_ids = ovn_port.external_ids.get(
                    ovn_const.OVN_SUBNET_EXT_IDS_KEY, [])
                subnet_ids = subnet_ids.split()
            elif port:
                subnet_ids = utils.get_port_subnet_ids(port)

            cidr = None
            for sid in subnet_ids:
                subnet = self._plugin.get_subnet(context, sid)
                if subnet['ip_version'] == 4:
                    cidr = subnet['cidr']
                    break

            if router and utils.is_snat_enabled(router) and cidr:
                self.update_nat_rules(
                    router, networks=[cidr], enable_snat=False, txn=txn)

            # NOTE(mangelajo): If the port doesn't exist anymore, we
            # delete the router port as the last operation and update the
            # revision database to ensure consistency
            if port_removed:
                self._delete_lrouter_port(port_id, router_id, txn=txn)
            else:
                # otherwise, we just update the revision database
                db_rev.bump_revision(port, ovn_const.TYPE_ROUTER_PORTS)

    def update_nat_rules(self, router, networks, enable_snat, txn=None):
        """Update the NAT rules in a logical router."""
        context = n_context.get_admin_context()
        func = (self._nb_idl.add_nat_rule_in_lrouter if enable_snat else
                self._nb_idl.delete_nat_rule_in_lrouter)
        gw_lrouter_name = utils.ovn_name(router['id'])
        gateways = self._get_gw_info(context, router)
        # Update NAT rules only for IPv4 subnets
        commands = [func(gw_lrouter_name, type='snat', logical_ip=network,
                         external_ip=gw_info.router_ip) for gw_info in gateways
                    if gw_info.ip_version != const.IP_VERSION_6
                    for network in networks]
        self._transaction(commands, txn=txn)

    def _create_provnet_port(self, txn, network, physnet, tag):
        txn.add(self._nb_idl.create_lswitch_port(
            lport_name=utils.ovn_provnet_port_name(network['id']),
            lswitch_name=utils.ovn_name(network['id']),
            addresses=[ovn_const.UNKNOWN_ADDR],
            external_ids={},
            type=ovn_const.LSP_TYPE_LOCALNET,
            tag=tag if tag else [],
            options={'network_name': physnet}))

    def _gen_network_external_ids(self, network):
        ext_ids = {
            ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: network['name'],
            ovn_const.OVN_NETWORK_MTU_EXT_ID_KEY: str(network['mtu']),
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
            lswitch = self._nb_idl.get_lswitch(lswitch_name)
            txn.add(self._nb_idl.set_lswitch_ext_ids(lswitch_name, ext_ids))
            # Check if previous mtu is different than current one,
            # checking will help reduce number of operations
            if (not lswitch or
                    lswitch.external_ids.get(
                        ovn_const.OVN_NETWORK_MTU_EXT_ID_KEY) !=
                    str(network['mtu'])):
                context = n_context.get_admin_context()
                subnets = self._plugin.get_subnets_by_network(
                    context, network['id'])
                for subnet in subnets:
                    self.update_subnet(subnet, network, txn)

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

    def _process_global_dhcp_opts(self, options, ip_version):
        if ip_version == 4:
            global_options = config.get_global_dhcpv4_opts()
        else:
            global_options = config.get_global_dhcpv6_opts()

        for option, value in global_options.items():
            if option in ovn_const.GLOBAL_DHCP_OPTS_BLACKLIST[ip_version]:
                # This option is not allowed to be set with a global setting
                LOG.debug('DHCP option %s is not permitted to be set in '
                          'global options. This option will be ignored.')
                continue
            # If the value is null (i.e. config ntp_server:), treat it as
            # a request to remove the option
            if value:
                options[option] = value
            else:
                try:
                    del(options[option])
                except KeyError:
                    # Option not present, job done
                    pass

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

        net_dns_domain = network.get('dns_domain', '').rstrip('.')
        if net_dns_domain:
            # NOTE(mjozefcz): String field should be with quotes,
            # otherwise ovn will try to resolve it as variable.
            options['domain_name'] = '"%s"' % net_dns_domain

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

        self._process_global_dhcp_opts(options, ip_version=4)

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

        self._process_global_dhcp_opts(dhcpv6_opts, ip_version=6)

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

    def _modify_subnet_dhcp_options(self, subnet, ovn_subnet, network, txn):
        if subnet['enable_dhcp'] and not ovn_subnet:
            self._enable_subnet_dhcp_options(subnet, network, txn)
        elif subnet['enable_dhcp'] and ovn_subnet:
            self._update_subnet_dhcp_options(subnet, network, txn)
        elif not subnet['enable_dhcp'] and ovn_subnet:
            self._remove_subnet_dhcp_options(subnet['id'], txn)

    def update_subnet(self, subnet, network, txn=None):
        ovn_subnet = self._nb_idl.get_subnet_dhcp_options(
            subnet['id'])['subnet']

        if subnet['enable_dhcp'] or ovn_subnet:
            context = n_context.get_admin_context()
            self.update_metadata_port(context, network['id'])

        check_rev_cmd = self._nb_idl.check_revision_number(
            subnet['id'], subnet, ovn_const.TYPE_SUBNETS)
        if not txn:
            with self._nb_idl.transaction(check_error=True) as txn_n:
                txn_n.add(check_rev_cmd)
                self._modify_subnet_dhcp_options(subnet, ovn_subnet, network,
                                                 txn_n)
        else:
            self._modify_subnet_dhcp_options(subnet, ovn_subnet, network, txn)
        if check_rev_cmd.result == ovn_const.TXN_COMMITTED:
            db_rev.bump_revision(subnet, ovn_const.TYPE_SUBNETS)

    def delete_subnet(self, subnet_id):
        with self._nb_idl.transaction(check_error=True) as txn:
            self._remove_subnet_dhcp_options(subnet_id, txn)
        db_rev.delete_revision(subnet_id, ovn_const.TYPE_SUBNETS)

    def create_security_group(self, security_group):
        # If the OVN schema supports Port Groups, we'll model security groups
        # as such. Otherwise, for backwards compatibility, we'll keep creating
        # two Address Sets for each Neutron SG (one for IPv4 and one for
        # IPv6).
        with self._nb_idl.transaction(check_error=True) as txn:
            ext_ids = {ovn_const.OVN_SG_EXT_ID_KEY: security_group['id']}
            if self._nb_idl.is_port_groups_supported():
                name = utils.ovn_port_group_name(security_group['id'])
                txn.add(self._nb_idl.pg_add(
                    name=name, acls=[], external_ids=ext_ids))
                # When a SG is created, it comes with some default rules,
                # so we'll apply them to the Port Group.
                ovn_acl.add_acls_for_sg_port_group(self._nb_idl,
                                                   security_group, txn)
            else:
                for ip_version in ('ip4', 'ip6'):
                    name = utils.ovn_addrset_name(security_group['id'],
                                                  ip_version)
                    txn.add(self._nb_idl.create_address_set(
                        name=name, external_ids=ext_ids))
        db_rev.bump_revision(security_group, ovn_const.TYPE_SECURITY_GROUPS)

    def create_default_drop_port_group(self, ports=None):
        pg_name = ovn_const.OVN_DROP_PORT_GROUP_NAME
        with self._nb_idl.transaction(check_error=True) as txn:
            if not self._nb_idl.get_port_group(pg_name):
                # If drop Port Group doesn't exist yet, create it.
                txn.add(self._nb_idl.pg_add(pg_name, acls=[], may_exist=True))
                # Add ACLs to this Port Group so that all traffic is dropped.
                acls = ovn_acl.add_acls_for_drop_port_group(pg_name)
                for acl in acls:
                    txn.add(self._nb_idl.pg_acl_add(may_exist=True, **acl))

            if ports:
                ports_ids = [port['id'] for port in ports]
                # Add the ports to the default Port Group
                txn.add(self._nb_idl.pg_add_ports(pg_name, ports_ids))

    def _add_port_to_drop_port_group(self, port, txn):
        self.create_default_drop_port_group()
        txn.add(self._nb_idl.pg_add_ports(ovn_const.OVN_DROP_PORT_GROUP_NAME,
                port))

    def _del_port_from_drop_port_group(self, port, txn):
        pg_name = ovn_const.OVN_DROP_PORT_GROUP_NAME
        if self._nb_idl.get_port_group(pg_name):
            txn.add(self._nb_idl.pg_del_ports(pg_name, port))

    def delete_security_group(self, security_group_id):
        with self._nb_idl.transaction(check_error=True) as txn:
            if self._nb_idl.is_port_groups_supported():
                name = utils.ovn_port_group_name(security_group_id)
                txn.add(self._nb_idl.pg_del(name=name))
            else:
                for ip_version in ('ip4', 'ip6'):
                    name = utils.ovn_addrset_name(security_group_id,
                                                  ip_version)
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

        # Metadata ports are DHCP ports not belonging to the Neutron
        # DHCP agents
        for port in ports:
            if not utils.is_neutron_dhcp_agent_port(port):
                return port

    def _find_metadata_port_ip(self, context, subnet):
        metadata_port = self._find_metadata_port(context, subnet['network_id'])
        if metadata_port:
            for fixed_ip in metadata_port['fixed_ips']:
                if fixed_ip['subnet_id'] == subnet['id']:
                    return fixed_ip['ip_address']

    def create_metadata_port(self, context, network):
        if config.is_ovn_metadata_enabled():
            metadata_port = self._find_metadata_port(context, network['id'])
            if not metadata_port:
                # Create a neutron port for DHCP/metadata services
                port = {'port':
                        {'network_id': network['id'],
                         'tenant_id': network['project_id'],
                         'device_owner': const.DEVICE_OWNER_DHCP,
                         'device_id': 'ovnmeta-%s' % network['id']}}
                # TODO(boden): rehome create_port into neutron-lib
                p_utils.create_port(self._plugin, context, port)

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
                        ls_dns_record.uuid, old_hostname, if_exists=True))

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
                        ls_dns_record.uuid, hostname, if_exists=True))

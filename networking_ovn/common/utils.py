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

import os

from neutron_lib.api.definitions import extra_dhcp_opt as edo_ext
from neutron_lib.api.definitions import l3
from neutron_lib.api import validators
from neutron_lib import constants as const
from neutron_lib import context as n_context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.utils import net as n_utils

from networking_ovn.common import constants


def ovn_name(id):
    # The name of the OVN entry will be neutron-<UUID>
    # This is due to the fact that the OVN application checks if the name
    # is a UUID. If so then there will be no matches.
    # We prefix the UUID to enable us to use the Neutron UUID when
    # updating, deleting etc.
    return 'neutron-%s' % id


def ovn_lrouter_port_name(id):
    # The name of the OVN lrouter port entry will be lrp-<UUID>
    # This is to distinguish with the name of the connected lswitch patch port,
    # which is named with neutron port uuid, so that OVS patch ports are
    # generated properly. The pairing patch port names will be:
    #   - patch-lrp-<UUID>-to-<UUID>
    #   - patch-<UUID>-to-lrp-<UUID>
    # lrp stands for Logical Router Port
    return 'lrp-%s' % id


def ovn_provnet_port_name(network_id):
    # The name of OVN lswitch provider network port entry will be
    # provnet-<Network-UUID>. The port is created for network having
    # provider:physical_network attribute.
    return constants.OVN_PROVNET_PORT_NAME_PREFIX + '%s' % network_id


def ovn_vhu_sockpath(sock_dir, port_id):
    # Frame the socket path of a virtio socket
    return os.path.join(
        sock_dir,
        # this parameter will become the virtio port name,
        # so it should not exceed IFNAMSIZ(16).
        (const.VHOST_USER_DEVICE_PREFIX + port_id)[:14])


def ovn_addrset_name(sg_id, ip_version):
    # The name of the address set for the given security group id and ip
    # version. The format is:
    #   as-<ip version>-<security group uuid>
    # with all '-' replaced with '_'. This replacement is necessary
    # because OVN doesn't support '-' in an address set name.
    return ('as-%s-%s' % (ip_version, sg_id)).replace('-', '_')


def get_lsp_dhcp_opts(port, ip_version):
    # Get dhcp options from Neutron port, for setting DHCP_Options row
    # in OVN.
    lsp_dhcp_disabled = False
    lsp_dhcp_opts = {}
    if port['device_owner'].startswith(const.DEVICE_OWNER_PREFIXES):
        lsp_dhcp_disabled = True
    else:
        for edo in port.get(edo_ext.EXTRADHCPOPTS, []):
            if edo['ip_version'] != ip_version:
                continue

            if edo['opt_name'] == 'dhcp_disabled' and (
                    edo['opt_value'] in ['True', 'true']):
                # OVN native DHCP is disabled on this port
                lsp_dhcp_disabled = True
                # Make sure return value behavior not depends on the order and
                # content of the extra DHCP options for the port
                lsp_dhcp_opts.clear()
                break

            if edo['opt_name'] not in (
                    constants.SUPPORTED_DHCP_OPTS[ip_version]):
                continue

            opt = edo['opt_name'].replace('-', '_')
            lsp_dhcp_opts[opt] = edo['opt_value']

    return (lsp_dhcp_disabled, lsp_dhcp_opts)


def is_lsp_trusted(port):
    return n_utils.is_port_trusted(port) if port.get('device_owner') else False


def get_lsp_security_groups(port, skip_trusted_port=True):
    # In other agent link OVS, skipping trusted port is processed in security
    # groups RPC.  We haven't that step, so we do it here.
    return [] if (skip_trusted_port and is_lsp_trusted(port)
                  ) else port.get('security_groups', [])


def is_snat_enabled(router):
    return router.get(l3.EXTERNAL_GW_INFO, {}).get('enable_snat', True)


def validate_and_get_data_from_binding_profile(port):
    if (constants.OVN_PORT_BINDING_PROFILE not in port or
            not validators.is_attr_set(
                port[constants.OVN_PORT_BINDING_PROFILE])):
        return {}
    param_set = {}
    param_dict = {}
    for param_set in constants.OVN_PORT_BINDING_PROFILE_PARAMS:
        param_keys = param_set.keys()
        for param_key in param_keys:
            try:
                param_dict[param_key] = (port[
                    constants.OVN_PORT_BINDING_PROFILE][param_key])
            except KeyError:
                pass
        if len(param_dict) == 0:
            continue
        if len(param_dict) != len(param_keys):
            msg = _('Invalid binding:profile. %s are all '
                    'required.') % param_keys
            raise n_exc.InvalidInput(error_message=msg)
        if (len(port[constants.OVN_PORT_BINDING_PROFILE]) != len(
                param_keys)):
            msg = _('Invalid binding:profile. too many parameters')
            raise n_exc.InvalidInput(error_message=msg)
        break

    if not param_dict:
        return {}

    for param_key, param_type in param_set.items():
        if param_type is None:
            continue
        param_value = param_dict[param_key]
        if not isinstance(param_value, param_type):
            msg = _('Invalid binding:profile. %(key)s %(value)s '
                    'value invalid type') % {'key': param_key,
                                             'value': param_value}
            raise n_exc.InvalidInput(error_message=msg)

    # Make sure we can successfully look up the port indicated by
    # parent_name.  Just let it raise the right exception if there is a
    # problem.
    if 'parent_name' in param_set:
        plugin = directory.get_plugin()
        plugin.get_port(n_context.get_admin_context(),
                        param_dict['parent_name'])

    if 'tag' in param_set:
        tag = int(param_dict['tag'])
        if tag < 0 or tag > 4095:
            msg = _('Invalid binding:profile. tag "%s" must be '
                    'an integer between 0 and 4095, inclusive') % tag
            raise n_exc.InvalidInput(error_message=msg)

    return param_dict

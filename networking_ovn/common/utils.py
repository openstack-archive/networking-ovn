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

from networking_ovn.common import constants
from neutron.extensions import extra_dhcp_opt as edo_ext
from neutron_lib import constants as const


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


def get_lsp_dhcpv4_opts(port):
    # Get dhcpv4 options from Neutron port, for setting DHCP_Options row
    # in OVN.
    lsp_dhcp_disabled = False
    lsp_dhcpv4_opts = {}
    if port['device_owner'].startswith(const.DEVICE_OWNER_PREFIXES):
        lsp_dhcp_disabled = True
    else:
        for edo in port.get(edo_ext.EXTRADHCPOPTS, []):
            if edo['ip_version'] != 4:
                continue

            if edo['opt_name'] == 'dhcp_disabled' and (
                    edo['opt_value'] in ['True', 'true']):
                # OVN native DHCPv4 is disabled on this port
                lsp_dhcp_disabled = True
                # Make sure return value behavior not depends on the order and
                # content of the extra DHCP options for the port
                lsp_dhcpv4_opts.clear()
                break

            if edo['opt_name'] not in constants.SUPPORTED_DHCP_OPTS:
                continue

            opt = edo['opt_name'].replace('-', '_')
            lsp_dhcpv4_opts[opt] = edo['opt_value']

    return (lsp_dhcp_disabled, lsp_dhcpv4_opts)

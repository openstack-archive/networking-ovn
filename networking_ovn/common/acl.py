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

from neutron_lib import constants as const

from neutron.common import constants as n_const

from networking_ovn.common import constants as ovn_const
from networking_ovn.common import utils


def acl_direction(r, port):
    if r['direction'] == 'ingress':
        portdir = 'outport'
        remote_portdir = 'inport'
    else:
        portdir = 'inport'
        remote_portdir = 'outport'
    match = '%s == "%s"' % (portdir, port['id'])
    return match, remote_portdir


def acl_ethertype(r):
    match = ''
    ip_version = None
    icmp = None
    if r['ethertype'] == 'IPv4':
        match = ' && ip4'
        ip_version = 'ip4'
        icmp = 'icmp4'
    elif r['ethertype'] == 'IPv6':
        match = ' && ip6'
        ip_version = 'ip6'
        icmp = 'icmp6'
    return match, ip_version, icmp


def acl_remote_ip_prefix(r, ip_version):
    if not r['remote_ip_prefix']:
        return ''
    src_or_dst = 'src' if r['direction'] == 'ingress' else 'dst'
    return ' && %s.%s == %s' % (ip_version, src_or_dst,
                                r['remote_ip_prefix'])


def acl_protocol_and_ports(r, icmp):
    protocol = None
    match = ''
    if r['protocol'] in ('tcp', 'udp',
                         str(const.PROTO_NUM_TCP),
                         str(const.PROTO_NUM_UDP)):
        # OVN expects the protocol name not number
        if r['protocol'] == str(const.PROTO_NUM_TCP):
            protocol = 'tcp'
        elif r['protocol'] == str(const.PROTO_NUM_UDP):
            protocol = 'udp'
        else:
            protocol = r['protocol']
        port_match = '%s.dst' % protocol
    elif r.get('protocol') in (const.PROTO_NAME_ICMP,
                               const.PROTO_NAME_IPV6_ICMP,
                               n_const.PROTO_NAME_IPV6_ICMP_LEGACY,
                               str(const.PROTO_NUM_ICMP),
                               str(const.PROTO_NUM_IPV6_ICMP)):
        protocol = icmp
        port_match = '%s.type' % icmp
    if protocol:
        match += ' && %s' % protocol
        # If min or max are set to -1, then we just treat it like it wasn't
        # specified at all and don't match on it.
        min_port = r['port_range_min']
        max_port = r['port_range_max']
        if (min_port and min_port == max_port and min_port != -1):
            match += ' && %s == %d' % (port_match, min_port)
        else:
            if min_port and min_port != -1:
                match += ' && %s >= %d' % (port_match, min_port)
            if max_port and max_port != -1:
                match += ' && %s <= %d' % (port_match, max_port)
    return match


def drop_all_ip_traffic_for_port(port):
    acl_list = []
    for direction, p in (('from-lport', 'inport'),
                         ('to-lport', 'outport')):
        lswitch = utils.ovn_name(port['network_id'])
        lport = port['id']
        acl = {"lswitch": lswitch, "lport": lport,
               "priority": ovn_const.ACL_PRIORITY_DROP,
               "action": ovn_const.ACL_ACTION_DROP,
               "log": False,
               "direction": direction,
               "match": '%s == "%s" && ip' % (p, port['id']),
               "external_ids": {'neutron:lport': port['id']}}
        acl_list.append(acl)
    return acl_list


def add_sg_rule_acl_for_port(port, r, match):
    dir_map = {
        'ingress': 'to-lport',
        'egress': 'from-lport',
    }
    acl = {"lswitch": utils.ovn_name(port['network_id']),
           "lport": port['id'],
           "priority": ovn_const.ACL_PRIORITY_ALLOW,
           "action": ovn_const.ACL_ACTION_ALLOW_RELATED,
           "log": False,
           "direction": dir_map[r['direction']],
           "match": match,
           "external_ids": {'neutron:lport': port['id']}}
    return acl


def add_acl_dhcp(port, subnet):
    # Allow DHCP responses through from source IPs on the local subnet.
    # We do this even if DHCP isn't enabled.  It could be enabled later.
    # We could hook into handling when it's enabled/disabled for a subnet,
    # but this code is temporary anyway.  It's likely no longer needed
    # once OVN native DHCP support merges, which is under development and
    # review already.
    # TODO(russellb) Remove this once OVN native DHCP support is merged.
    acl_list = []
    acl = {"lswitch": utils.ovn_name(port['network_id']),
           "lport": port['id'],
           "priority": ovn_const.ACL_PRIORITY_ALLOW,
           "action": ovn_const.ACL_ACTION_ALLOW,
           "log": False,
           "direction": 'to-lport',
           "match": ('outport == "%s" && ip4 && ip4.src == %s && '
                     'udp && udp.src == 67 && udp.dst == 68'
                     ) % (port['id'], subnet['cidr']),
           "external_ids": {'neutron:lport': port['id']}}
    acl_list.append(acl)
    acl = {"lswitch": utils.ovn_name(port['network_id']),
           "lport": port['id'],
           "priority": ovn_const.ACL_PRIORITY_ALLOW,
           "action": ovn_const.ACL_ACTION_ALLOW,
           "log": False,
           "direction": 'from-lport',
           "match": ('inport == "%s" && ip4 && '
                     '(ip4.dst == 255.255.255.255 || '
                     'ip4.dst == %s) && '
                     'udp && udp.src == 68 && udp.dst == 67'
                     ) % (port['id'], subnet['cidr']),
           "external_ids": {'neutron:lport': port['id']}}
    acl_list.append(acl)
    return acl_list


def _get_subnet_from_cache(plugin, admin_context, subnet_cache, subnet_id):
    if subnet_id in subnet_cache:
        return subnet_cache[subnet_id]
    else:
        subnet = plugin.get_subnet(admin_context, subnet_id)
        if subnet:
            subnet_cache[subnet_id] = subnet
        return subnet


def _get_sg_ports_from_cache(plugin, admin_context, sg_ports_cache, sg_id):
    if sg_id in sg_ports_cache:
        return sg_ports_cache[sg_id]
    else:
        filters = {'security_group_id': [sg_id]}
        sg_ports = plugin._get_port_security_group_bindings(
            admin_context, filters)
        if sg_ports:
            sg_ports_cache[sg_id] = sg_ports
        return sg_ports

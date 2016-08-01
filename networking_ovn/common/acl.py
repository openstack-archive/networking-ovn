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

from neutron_lib import constants as const
from oslo_config import cfg


from networking_ovn.common import config
from networking_ovn.common import constants as ovn_const
from networking_ovn.common import utils


def is_sg_enabled():
    return cfg.CONF.SECURITYGROUP.enable_security_group


def acl_direction(r, port):
    if r['direction'] == 'ingress':
        portdir = 'outport'
    else:
        portdir = 'inport'
    return '%s == "%s"' % (portdir, port['id'])


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
                               const.PROTO_NAME_IPV6_ICMP_LEGACY,
                               str(const.PROTO_NUM_ICMP),
                               str(const.PROTO_NUM_IPV6_ICMP)):
        protocol = icmp
        port_match = '%s.type' % icmp
    if protocol:
        match += ' && %s' % protocol
        # If min or max are set to -1, then we just treat it like it wasn't
        # specified at all and don't match on it.
        min_port = -1 if r['port_range_min'] is None else r['port_range_min']
        max_port = -1 if r['port_range_max'] is None else r['port_range_max']
        if protocol != icmp:
            if (min_port > -1 and min_port == max_port):
                match += ' && %s == %d' % (port_match, min_port)
            else:
                if min_port > -1:
                    match += ' && %s >= %d' % (port_match, min_port)
                if max_port > -1:
                    match += ' && %s <= %d' % (port_match, max_port)
        # It's invalid to create security group rule for ICMP and ICMPv6 with
        # ICMP(v6) code but without ICMP(v6) type.
        elif protocol == icmp and min_port > -1:
            match += ' && %s == %d' % (port_match, min_port)
            if max_port > -1:
                match += ' && %s.code == %s' % (icmp, max_port)
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
    # We do this even if DHCP isn't enabled for the subnet.  It could be
    # enabled later. We could hook into handling when it's enabled/disabled
    # for a subnet, but this only used when OVN native DHCP is disabled.
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


def _get_sg_from_cache(plugin, admin_context, sg_cache, sg_id):
    if sg_id in sg_cache:
        return sg_cache[sg_id]
    else:
        sg = plugin.get_security_group(admin_context, sg_id)
        if sg:
            sg_cache[sg_id] = sg
        return sg


def acl_remote_group_id(r, ip_version):
    if not r['remote_group_id']:
        return ''

    src_or_dst = 'src' if r['direction'] == 'ingress' else 'dst'
    addrset_name = utils.ovn_addrset_name(r['remote_group_id'],
                                          ip_version)
    return ' && %s.%s == $%s' % (ip_version, src_or_dst, addrset_name)


def _add_sg_rule_acl_for_port(port, r):
    # Update the match based on which direction this rule is for (ingress
    # or egress).
    match = acl_direction(r, port)

    # Update the match for IPv4 vs IPv6.
    ip_match, ip_version, icmp = acl_ethertype(r)
    match += ip_match

    # Update the match if an IPv4 or IPv6 prefix was specified.
    match += acl_remote_ip_prefix(r, ip_version)

    # Update the match if remote group id was specified.
    match += acl_remote_group_id(r, ip_version)

    # Update the match for the protocol (tcp, udp, icmp) and port/type
    # range if specified.
    match += acl_protocol_and_ports(r, icmp)

    # Finally, create the ACL entry for the direction specified.
    return add_sg_rule_acl_for_port(port, r, match)


def update_acls_for_security_group(plugin,
                                   admin_context,
                                   ovn,
                                   security_group_id,
                                   security_group_rule,
                                   sg_ports_cache=None,
                                   is_add_acl=True):
    # Skip ACLs if security groups aren't enabled
    if not is_sg_enabled():
        return

    # Get the security group ports.
    sg_ports_cache = sg_ports_cache or {}
    sg_ports = _get_sg_ports_from_cache(plugin,
                                        admin_context,
                                        sg_ports_cache,
                                        security_group_id)

    # ACLs associated with a security group may span logical switches
    sg_port_ids = [binding['port_id'] for binding in sg_ports]
    sg_port_ids = list(set(sg_port_ids))
    port_list = plugin.get_ports(admin_context,
                                 filters={'id': sg_port_ids})
    lswitch_names = set([p['network_id'] for p in port_list])
    acl_new_values_dict = {}

    # NOTE(lizk): We can directly locate the affected acl records,
    # so no need to compare new acl values with existing acl objects.
    for port in port_list:
        acl = _add_sg_rule_acl_for_port(port, security_group_rule)
        if acl:
            # Remove lport and lswitch since we don't need them
            acl.pop('lport')
            acl.pop('lswitch')
            acl_new_values_dict[port['id']] = acl

    ovn.update_acls(list(lswitch_names),
                    iter(port_list),
                    acl_new_values_dict,
                    need_compare=False,
                    is_add_acl=is_add_acl).execute(check_error=True)


def add_acls(plugin, admin_context, port, sg_cache, subnet_cache):
    acl_list = []

    # Skip ACLs if security groups aren't enabled
    if not is_sg_enabled():
        return acl_list

    sec_groups = port.get('security_groups', [])
    if not sec_groups:
        return acl_list

    # Drop all IP traffic to and from the logical port by default.
    acl_list += drop_all_ip_traffic_for_port(port)

    # Add DHCP ACLs if not using OVN native DHCP.
    if not config.is_ovn_dhcp():
        port_subnet_ids = set()
        for ip in port['fixed_ips']:
            if netaddr.IPNetwork(ip['ip_address']).version != 4:
                continue
            subnet = _get_subnet_from_cache(plugin,
                                            admin_context,
                                            subnet_cache,
                                            ip['subnet_id'])
            # Ignore duplicate DHCP ACLs for the subnet.
            if subnet['id'] not in port_subnet_ids:
                acl_list += add_acl_dhcp(port, subnet)
                port_subnet_ids.add(subnet['id'])

    # We create an ACL entry for each rule on each security group applied
    # to this port.
    for sg_id in sec_groups:
        sg = _get_sg_from_cache(plugin,
                                admin_context,
                                sg_cache,
                                sg_id)
        for r in sg['security_group_rules']:
            acl = _add_sg_rule_acl_for_port(port, r)
            if acl and acl not in acl_list:
                acl_list.append(acl)

    return acl_list


def acl_port_ips(port):
    # Skip ACLs if security groups aren't enabled
    if not is_sg_enabled():
        return {'ip4': [], 'ip6': []}

    ip_addresses = {4: [], 6: []}
    for fixed_ip in port['fixed_ips']:
        ip_version = netaddr.IPNetwork(fixed_ip['ip_address']).version
        ip_addresses[ip_version].append(fixed_ip['ip_address'])

    return {'ip4': ip_addresses[4],
            'ip6': ip_addresses[6]}

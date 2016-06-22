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
from oslo_config import cfg

from networking_ovn.common import constants as ovn_const
from networking_ovn.common import utils


def is_sg_enabled():
    return cfg.CONF.SECURITYGROUP.enable_security_group


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


def _get_sg_from_cache(plugin, admin_context, sg_cache, sg_id):
    if sg_id in sg_cache:
        return sg_cache[sg_id]
    else:
        sg = plugin.get_security_group(admin_context, sg_id)
        if sg:
            sg_cache[sg_id] = sg
        return sg


def _acl_remote_match_ip(plugin, admin_context,
                         sg_ports, subnet_cache,
                         ip_version, src_or_dst):
    ip_version_map = {'ip4': 4,
                      'ip6': 6}
    match = ''
    port_ids = [sg_port['port_id'] for sg_port in sg_ports]
    ports = plugin.get_ports(admin_context,
                             filters={'id': port_ids})
    for port in ports:
        for fixed_ip in port['fixed_ips']:
            subnet = _get_subnet_from_cache(plugin,
                                            admin_context,
                                            subnet_cache,
                                            fixed_ip['subnet_id'])
            if subnet['ip_version'] == ip_version_map.get(ip_version):
                match += '%s.%s == %s || ' % (ip_version,
                                              src_or_dst,
                                              fixed_ip['ip_address'])

    if match:
        match = match[:-4]  # Remove the last ' || '
        match = ' && (%s)' % match

    return match


def _acl_remote_group_id(plugin, admin_context, r,
                         sg_ports_cache, subnet_cache,
                         port, remote_portdir, ip_version):
    if not r['remote_group_id']:
        return '', False
    match = ''
    sg_ports = _get_sg_ports_from_cache(plugin,
                                        admin_context,
                                        sg_ports_cache,
                                        r['remote_group_id'])
    sg_ports = [p for p in sg_ports if p['port_id'] != port['id']]
    if not sg_ports:
        # If there are no other ports on this security group, then this
        # rule can never match, so no ACL row will be created for this
        # rule.
        return '', True

    src_or_dst = 'src' if r['direction'] == 'ingress' else 'dst'
    remote_group_match = _acl_remote_match_ip(plugin,
                                              admin_context,
                                              sg_ports,
                                              subnet_cache,
                                              ip_version,
                                              src_or_dst)

    match += remote_group_match

    return match, False


def _add_sg_rule_acl_for_port(plugin, admin_context, port, r,
                              sg_ports_cache, subnet_cache):
    # Update the match based on which direction this rule is for (ingress
    # or egress).
    match, remote_portdir = acl_direction(r, port)

    # Update the match for IPv4 vs IPv6.
    ip_match, ip_version, icmp = acl_ethertype(r)
    match += ip_match

    # Update the match if an IPv4 or IPv6 prefix was specified.
    match += acl_remote_ip_prefix(r, ip_version)

    group_match, empty_match = _acl_remote_group_id(plugin,
                                                    admin_context,
                                                    r,
                                                    sg_ports_cache,
                                                    subnet_cache,
                                                    port,
                                                    remote_portdir,
                                                    ip_version)
    if empty_match:
        # If there are no other ports on this security group, then this
        # rule can never match, so no ACL row will be created for this
        # rule.
        return None
    match += group_match

    # Update the match for the protocol (tcp, udp, icmp) and port/type
    # range if specified.
    match += acl_protocol_and_ports(r, icmp)

    # Finally, create the ACL entry for the direction specified.
    return add_sg_rule_acl_for_port(port, r, match)


def update_acls_for_security_group(plugin,
                                   admin_context,
                                   ovn,
                                   security_group_id,
                                   sg_cache=None,
                                   sg_ports_cache=None,
                                   subnet_cache=None,
                                   exclude_ports=None,
                                   rule=None,
                                   is_add_acl=True):
    # Skip ACLs if security groups aren't enabled
    if not is_sg_enabled():
        return

    # Setup the caches or use cache provided.
    sg_cache = sg_cache or {}
    sg_ports_cache = sg_ports_cache or {}
    subnet_cache = subnet_cache or {}
    exclude_ports = exclude_ports or []

    sg_ports = _get_sg_ports_from_cache(plugin,
                                        admin_context,
                                        sg_ports_cache,
                                        security_group_id)

    # ACLs associated with a security group may span logical switches
    sg_port_ids = [binding['port_id'] for binding in sg_ports]
    sg_port_ids = list(set(sg_port_ids) - set(exclude_ports))
    port_list = plugin.get_ports(admin_context,
                                 filters={'id': sg_port_ids})
    lswitch_names = set([p['network_id'] for p in port_list])
    acl_new_values_dict = {}

    # NOTE(lizk): When a certain rule is given, we can directly locate
    # the affected acl records, so no need to compare new acl values with
    # existing acl objects, such as case create_security_group_rule or
    # delete_security_group_rule is calling this. But for other cases,
    # since we don't know which acl records need be updated, compare will
    # be needed.
    need_compare = True
    if rule:
        need_compare = False
        for port in port_list:
            acl = _add_sg_rule_acl_for_port(
                plugin, admin_context, port, rule,
                sg_ports_cache, subnet_cache)
            if acl:
                # Remove lport and lswitch since we don't need them
                acl.pop('lport')
                acl.pop('lswitch')
                acl_new_values_dict[port['id']] = acl
    else:
        for port in port_list:
            acls_new = add_acls(plugin,
                                admin_context,
                                port,
                                sg_cache,
                                sg_ports_cache,
                                subnet_cache)
            acl_new_values_dict[port['id']] = acls_new

    ovn.update_acls(list(lswitch_names),
                    iter(port_list),
                    acl_new_values_dict,
                    need_compare=need_compare,
                    is_add_acl=is_add_acl).execute(check_error=True)


def add_acls(plugin, admin_context, port, sg_cache,
             sg_ports_cache, subnet_cache):
    acl_list = []

    # Skip ACLs if security groups aren't enabled
    if not is_sg_enabled():
        return acl_list

    sec_groups = port.get('security_groups', [])
    if not sec_groups:
        return acl_list

    # Drop all IP traffic to and from the logical port by default.
    acl_list += drop_all_ip_traffic_for_port(port)

    for ip in port['fixed_ips']:
        subnet = _get_subnet_from_cache(plugin,
                                        admin_context,
                                        subnet_cache,
                                        ip['subnet_id'])
        if subnet['ip_version'] != 4:
            continue
        acl_list += add_acl_dhcp(port, subnet)

    # We create an ACL entry for each rule on each security group applied
    # to this port.
    for sg_id in sec_groups:
        sg = _get_sg_from_cache(plugin,
                                admin_context,
                                sg_cache,
                                sg_id)
        for r in sg['security_group_rules']:
            acl = _add_sg_rule_acl_for_port(plugin,
                                            admin_context,
                                            port, r,
                                            sg_ports_cache,
                                            subnet_cache)
            if acl and acl not in acl_list:
                acl_list.append(acl)

    return acl_list


def refresh_remote_security_group(plugin,
                                  admin_context,
                                  ovn,
                                  sec_group,
                                  sg_cache=None,
                                  sg_ports_cache=None,
                                  subnet_cache=None,
                                  exclude_ports=None):
    # Skip ACLs if security groups aren't enabled
    if not is_sg_enabled():
        return

    # For sec_group, refresh acls for all other security groups that have
    # rules referencing sec_group as 'remote_group'.
    filters = {'remote_group_id': [sec_group]}
    refering_rules = plugin.get_security_group_rules(
        admin_context, filters, fields=['security_group_id'])
    sg_ids = set(r['security_group_id'] for r in refering_rules)
    for sg_id in sg_ids:
        update_acls_for_security_group(plugin,
                                       admin_context,
                                       ovn,
                                       sg_id,
                                       sg_cache,
                                       sg_ports_cache,
                                       subnet_cache,
                                       exclude_ports)

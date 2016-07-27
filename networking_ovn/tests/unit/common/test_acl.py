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

import copy
import mock

from neutron_lib import constants as const

from networking_ovn.common import acl as ovn_acl
from networking_ovn.common import constants as ovn_const
from networking_ovn.common import utils as ovn_utils
from networking_ovn.ovsdb import commands as cmd
from networking_ovn.tests import base
from networking_ovn.tests.unit import fakes


class TestACLs(base.TestCase):

    def setUp(self):
        super(TestACLs, self).setUp()
        self.driver = mock.Mock()
        self.driver._nb_ovn = fakes.FakeOvsdbNbOvnIdl()
        self.plugin = fakes.FakePlugin()
        self.admin_context = mock.Mock()
        self.fake_port = fakes.FakePort.create_one_port({
            'id': 'fake_port_id1',
            'network_id': 'network_id1',
            'fixed_ips': [{'subnet_id': 'subnet_id1',
                           'ip_address': '1.1.1.1'}],
        }).info()
        self.fake_subnet = fakes.FakeSubnet.create_one_subnet({
            'id': 'subnet_id1',
            'ip_version': 4,
            'cidr': '1.1.1.0/24',
        }).info()
        patcher = mock.patch(
            'neutron.agent.ovsdb.native.idlutils.row_by_value',
            lambda *args, **kwargs: mock.MagicMock())
        patcher.start()

    def test_drop_all_ip_traffic_for_port(self):
        acls = ovn_acl.drop_all_ip_traffic_for_port(self.fake_port)
        acl_to_lport = {'action': 'drop', 'direction': 'to-lport',
                        'external_ids': {'neutron:lport':
                                         self.fake_port['id']},
                        'log': False, 'lport': self.fake_port['id'],
                        'lswitch': 'neutron-network_id1',
                        'match': 'outport == "fake_port_id1" && ip',
                        'priority': 1001}
        acl_from_lport = {'action': 'drop', 'direction': 'from-lport',
                          'external_ids': {'neutron:lport':
                                           self.fake_port['id']},
                          'log': False, 'lport': self.fake_port['id'],
                          'lswitch': 'neutron-network_id1',
                          'match': 'inport == "fake_port_id1" && ip',
                          'priority': 1001}
        for acl in acls:
            if 'to-lport' in acl.values():
                self.assertEqual(acl_to_lport, acl)
            if 'from-lport' in acl.values():
                self.assertEqual(acl_from_lport, acl)

    def test_add_acl_dhcp(self):
        acls = ovn_acl.add_acl_dhcp(self.fake_port, self.fake_subnet)

        expected_match_to_lport = (
            'outport == "%s" && ip4 && ip4.src == %s && udp && udp.src == 67 '
            '&& udp.dst == 68') % (self.fake_port['id'],
                                   self.fake_subnet['cidr'])
        acl_to_lport = {'action': 'allow', 'direction': 'to-lport',
                        'external_ids': {'neutron:lport': 'fake_port_id1'},
                        'log': False, 'lport': 'fake_port_id1',
                        'lswitch': 'neutron-network_id1',
                        'match': expected_match_to_lport, 'priority': 1002}
        expected_match_from_lport = (
            'inport == "%s" && ip4 && '
            '(ip4.dst == 255.255.255.255 || ip4.dst == %s) && '
            'udp && udp.src == 68 && udp.dst == 67'
        ) % (self.fake_port['id'], self.fake_subnet['cidr'])
        acl_from_lport = {'action': 'allow', 'direction': 'from-lport',
                          'external_ids': {'neutron:lport': 'fake_port_id1'},
                          'log': False, 'lport': 'fake_port_id1',
                          'lswitch': 'neutron-network_id1',
                          'match': expected_match_from_lport, 'priority': 1002}
        for acl in acls:
            if 'to-lport' in acl.values():
                self.assertEqual(acl_to_lport, acl)
            if 'from-lport' in acl.values():
                self.assertEqual(acl_from_lport, acl)

    def _test_add_sg_rule_acl_for_port(self, sg_rule, direction, match):
        port = {'id': 'port-id',
                'network_id': 'network-id'}
        acl = ovn_acl.add_sg_rule_acl_for_port(port, sg_rule, match)
        self.assertEqual(acl, {'lswitch': 'neutron-network-id',
                               'lport': 'port-id',
                               'priority': ovn_const.ACL_PRIORITY_ALLOW,
                               'action': ovn_const.ACL_ACTION_ALLOW_RELATED,
                               'log': False,
                               'direction': direction,
                               'match': match,
                               'external_ids': {'neutron:lport': 'port-id'}})

    def test_add_sg_rule_acl_for_port_remote_ip_prefix(self):
        sg_rule = {'direction': 'ingress',
                   'ethertype': 'IPv4',
                   'remote_group_id': None,
                   'remote_ip_prefix': '1.1.1.0/24',
                   'protocol': None}
        match = 'outport == "port-id" && ip4 && ip4.src == 1.1.1.0/24'
        self._test_add_sg_rule_acl_for_port(sg_rule,
                                            'to-lport',
                                            match)
        sg_rule['direction'] = 'egress'
        match = 'inport == "port-id" && ip4 && ip4.dst == 1.1.1.0/24'
        self._test_add_sg_rule_acl_for_port(sg_rule,
                                            'from-lport',
                                            match)

    def test_add_sg_rule_acl_for_port_remote_group(self):
        sg_rule = {'direction': 'ingress',
                   'ethertype': 'IPv4',
                   'remote_group_id': 'sg1',
                   'remote_ip_prefix': None,
                   'protocol': None}
        match = 'outport == "port-id" && ip4 && (ip4.src == 1.1.1.100' \
                ' || ip4.src == 1.1.1.101' \
                ' || ip4.src == 1.1.1.102)'

        self._test_add_sg_rule_acl_for_port(sg_rule,
                                            'to-lport',
                                            match)
        sg_rule['direction'] = 'egress'
        match = 'inport == "port-id" && ip4 && (ip4.dst == 1.1.1.100' \
                ' || ip4.dst == 1.1.1.101' \
                ' || ip4.dst == 1.1.1.102)'
        self._test_add_sg_rule_acl_for_port(sg_rule,
                                            'from-lport',
                                            match)

    def test__update_acls_compute_difference(self):
        lswitch_name = 'lswitch-1'
        port1 = {'id': 'port-id1',
                 'network_id': lswitch_name,
                 'fixed_ips': [{'subnet_id': 'subnet-id',
                                'ip_address': '1.1.1.101'},
                               {'subnet_id': 'subnet-id-v6',
                                'ip_address': '2001:0db8::1:0:0:1'}]}
        port2 = {'id': 'port-id2',
                 'network_id': lswitch_name,
                 'fixed_ips': [{'subnet_id': 'subnet-id',
                                'ip_address': '1.1.1.102'},
                               {'subnet_id': 'subnet-id-v6',
                                'ip_address': '2001:0db8::1:0:0:2'}]}
        ports = [port1, port2]
        # OLD ACLs, allow IPv4 communication
        aclport1_old1 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port1['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip4 && (ip.src == %s)' %
                         (port1['id'], port1['fixed_ips'][0]['ip_address'])}
        aclport1_old2 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port1['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip6 && (ip.src == %s)' %
                         (port1['id'], port1['fixed_ips'][1]['ip_address'])}
        aclport1_old3 = {'priority': 1002, 'direction': 'to-lport',
                         'lport': port1['id'], 'lswitch': lswitch_name,
                         'match': 'ip4 && (ip.src == %s)' %
                         (port2['fixed_ips'][0]['ip_address'])}
        port1_acls_old = [aclport1_old1, aclport1_old2, aclport1_old3]
        aclport2_old1 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port2['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip4 && (ip.src == %s)' %
                         (port2['id'], port2['fixed_ips'][0]['ip_address'])}
        aclport2_old2 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port2['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip6 && (ip.src == %s)' %
                         (port2['id'], port2['fixed_ips'][1]['ip_address'])}
        aclport2_old3 = {'priority': 1002, 'direction': 'to-lport',
                         'lport': port2['id'], 'lswitch': lswitch_name,
                         'match': 'ip4 && (ip.src == %s)' %
                         (port1['fixed_ips'][0]['ip_address'])}
        port2_acls_old = [aclport2_old1, aclport2_old2, aclport2_old3]
        acls_old_dict = {'%s' % (port1['id']): port1_acls_old,
                         '%s' % (port2['id']): port2_acls_old}
        acl_obj_dict = {str(aclport1_old1): 'row1',
                        str(aclport1_old2): 'row2',
                        str(aclport1_old3): 'row3',
                        str(aclport2_old1): 'row4',
                        str(aclport2_old2): 'row5',
                        str(aclport2_old3): 'row6'}
        # NEW ACLs, allow IPv6 communication
        aclport1_new1 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port1['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip4 && (ip.src == %s)' %
                         (port1['id'], port1['fixed_ips'][0]['ip_address'])}
        aclport1_new2 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port1['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip6 && (ip.src == %s)' %
                         (port1['id'], port1['fixed_ips'][1]['ip_address'])}
        aclport1_new3 = {'priority': 1002, 'direction': 'to-lport',
                         'lport': port1['id'], 'lswitch': lswitch_name,
                         'match': 'ip6 && (ip.src == %s)' %
                         (port2['fixed_ips'][1]['ip_address'])}
        port1_acls_new = [aclport1_new1, aclport1_new2, aclport1_new3]
        aclport2_new1 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port2['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip4 && (ip.src == %s)' %
                         (port2['id'], port2['fixed_ips'][0]['ip_address'])}
        aclport2_new2 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port2['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip6 && (ip.src == %s)' %
                         (port2['id'], port2['fixed_ips'][1]['ip_address'])}
        aclport2_new3 = {'priority': 1002, 'direction': 'to-lport',
                         'lport': port2['id'], 'lswitch': lswitch_name,
                         'match': 'ip6 && (ip.src == %s)' %
                         (port1['fixed_ips'][1]['ip_address'])}
        port2_acls_new = [aclport2_new1, aclport2_new2, aclport2_new3]
        acls_new_dict = {'%s' % (port1['id']): port1_acls_new,
                         '%s' % (port2['id']): port2_acls_new}

        acls_new_dict_copy = copy.deepcopy(acls_new_dict)

        # Invoke _compute_acl_differences
        update_cmd = cmd.UpdateACLsCommand(self.driver._nb_ovn,
                                           [lswitch_name],
                                           iter(ports),
                                           acls_new_dict
                                           )
        acl_dels, acl_adds =\
            update_cmd._compute_acl_differences(iter(ports),
                                                acls_old_dict,
                                                acls_new_dict,
                                                acl_obj_dict)
        # Expected Difference (Sorted)
        acl_del_exp = {lswitch_name: ['row3', 'row6']}
        acl_adds_exp = {lswitch_name:
                        [{'priority': 1002, 'direction': 'to-lport',
                          'match': 'ip6 && (ip.src == %s)' %
                          (port2['fixed_ips'][1]['ip_address'])},
                         {'priority': 1002, 'direction': 'to-lport',
                          'match': 'ip6 && (ip.src == %s)' %
                          (port1['fixed_ips'][1]['ip_address'])}]}
        self.assertEqual(acl_dels, acl_del_exp)
        self.assertEqual(acl_adds, acl_adds_exp)

        # make sure argument add_acl=False will take no affect in
        # need_compare=True scenario
        update_cmd_with_acl = cmd.UpdateACLsCommand(self.driver._nb_ovn,
                                                    [lswitch_name],
                                                    iter(ports),
                                                    acls_new_dict_copy,
                                                    need_compare=True,
                                                    is_add_acl=False)
        new_acl_dels, new_acl_adds =\
            update_cmd_with_acl._compute_acl_differences(iter(ports),
                                                         acls_old_dict,
                                                         acls_new_dict_copy,
                                                         acl_obj_dict)
        self.assertEqual(acl_dels, new_acl_dels)
        self.assertEqual(acl_adds, new_acl_adds)

    def test__get_update_data_without_compare(self):
        lswitch_name = 'lswitch-1'
        port1 = {'id': 'port-id1',
                 'network_id': lswitch_name,
                 'fixed_ips': mock.Mock()}
        port2 = {'id': 'port-id2',
                 'network_id': lswitch_name,
                 'fixed_ips': mock.Mock()}
        ports = [port1, port2]
        aclport1_new = {'priority': 1002, 'direction': 'to-lport',
                        'match': 'outport == %s && ip4 && icmp4' %
                        (port1['id'])}
        aclport2_new = {'priority': 1002, 'direction': 'to-lport',
                        'match': 'outport == %s && ip4 && icmp4' %
                        (port2['id'])}
        acls_new_dict = {'%s' % (port1['id']): aclport1_new,
                         '%s' % (port2['id']): aclport2_new}

        # test for creating new acls
        update_cmd_add_acl = cmd.UpdateACLsCommand(self.driver._nb_ovn,
                                                   [lswitch_name],
                                                   iter(ports),
                                                   acls_new_dict,
                                                   need_compare=False,
                                                   is_add_acl=True)
        lswitch_dict, acl_del_dict, acl_add_dict = \
            update_cmd_add_acl._get_update_data_without_compare()
        self.assertIn('neutron-lswitch-1', lswitch_dict)
        self.assertEqual({}, acl_del_dict)
        expected_acls = {'neutron-lswitch-1': [aclport1_new, aclport2_new]}
        self.assertEqual(expected_acls, acl_add_dict)

        # test for deleting existing acls
        acl1 = mock.Mock(
            match='outport == port-id1 && ip4 && icmp4')
        acl2 = mock.Mock(
            match='outport == port-id2 && ip4 && icmp4')
        acl3 = mock.Mock(
            match='outport == port-id1 && ip4 && (ip4.src == fake_ip)')
        lswitch_obj = mock.Mock(
            name='neutron-lswitch-1', acls=[acl1, acl2, acl3])
        with mock.patch('neutron.agent.ovsdb.native.idlutils.row_by_value',
                        return_value=lswitch_obj):
            update_cmd_del_acl = cmd.UpdateACLsCommand(self.driver._nb_ovn,
                                                       [lswitch_name],
                                                       iter(ports),
                                                       acls_new_dict,
                                                       need_compare=False,
                                                       is_add_acl=False)
            lswitch_dict, acl_del_dict, acl_add_dict = \
                update_cmd_del_acl._get_update_data_without_compare()
            self.assertIn('neutron-lswitch-1', lswitch_dict)
            expected_acls = {'neutron-lswitch-1': [acl1, acl2]}
            self.assertEqual(expected_acls, acl_del_dict)
            self.assertEqual({}, acl_add_dict)

    def test_acl_protocol_and_ports_for_tcp_and_udp_number(self):
        sg_rule = {'port_range_min': None,
                   'port_range_max': None}

        sg_rule['protocol'] = str(const.PROTO_NUM_TCP)
        match = ovn_acl.acl_protocol_and_ports(sg_rule, None)
        self.assertEqual(' && tcp', match)

        sg_rule['protocol'] = str(const.PROTO_NUM_UDP)
        match = ovn_acl.acl_protocol_and_ports(sg_rule, None)
        self.assertEqual(' && udp', match)

    def test_acl_protocol_and_ports_for_ipv6_icmp_protocol(self):
        sg_rule = {'port_range_min': None,
                   'port_range_max': None}
        icmp = 'icmp6'
        expected_match = ' && icmp6'

        sg_rule['protocol'] = const.PROTO_NAME_ICMP
        match = ovn_acl.acl_protocol_and_ports(sg_rule, icmp)
        self.assertEqual(expected_match, match)

        sg_rule['protocol'] = str(const.PROTO_NUM_ICMP)
        match = ovn_acl.acl_protocol_and_ports(sg_rule, icmp)
        self.assertEqual(expected_match, match)

        sg_rule['protocol'] = const.PROTO_NAME_IPV6_ICMP
        match = ovn_acl.acl_protocol_and_ports(sg_rule, icmp)
        self.assertEqual(expected_match, match)

        sg_rule['protocol'] = const.PROTO_NAME_IPV6_ICMP_LEGACY
        match = ovn_acl.acl_protocol_and_ports(sg_rule, icmp)
        self.assertEqual(expected_match, match)

        sg_rule['protocol'] = str(const.PROTO_NUM_IPV6_ICMP)
        match = ovn_acl.acl_protocol_and_ports(sg_rule, icmp)
        self.assertEqual(expected_match, match)

    def test_acl_protocol_and_ports_for_icmp4_and_icmp6_port_range(self):
        match_list = [
            (None, None, ' && icmp4'),
            (0, None, ' && icmp4 && icmp4.type == 0'),
            (0, 0, ' && icmp4 && icmp4.type == 0 && icmp4.code == 0'),
            (0, 5, ' && icmp4 && icmp4.type == 0 && icmp4.code == 5')]
        v6_match_list = [
            (None, None, ' && icmp6'),
            (133, None, ' && icmp6 && icmp6.type == 133'),
            (1, 1, ' && icmp6 && icmp6.type == 1 && icmp6.code == 1'),
            (138, 1, ' && icmp6 && icmp6.type == 138 && icmp6.code == 1')]

        sg_rule = {'protocol': const.PROTO_NAME_ICMP}
        icmp = 'icmp4'
        for pmin, pmax, expected_match in match_list:
            sg_rule['port_range_min'] = pmin
            sg_rule['port_range_max'] = pmax
            match = ovn_acl.acl_protocol_and_ports(sg_rule, icmp)
            self.assertEqual(expected_match, match)

        sg_rule = {'protocol': const.PROTO_NAME_IPV6_ICMP}
        icmp = 'icmp6'
        for pmin, pmax, expected_match in v6_match_list:
            sg_rule['port_range_min'] = pmin
            sg_rule['port_range_max'] = pmax
            match = ovn_acl.acl_protocol_and_ports(sg_rule, icmp)
            self.assertEqual(expected_match, match)

    def test_acl_direction(self):
        sg_rule = fakes.FakeSecurityGroupRule.create_one_security_group_rule({
            'direction': 'ingress'
        }).info()

        match = ovn_acl.acl_direction(sg_rule, self.fake_port)
        self.assertEqual('outport == "' + self.fake_port['id'] + '"', match)

        sg_rule['direction'] = 'egress'
        match = ovn_acl.acl_direction(sg_rule, self.fake_port)
        self.assertEqual('inport == "' + self.fake_port['id'] + '"', match)

    def test_acl_ethertype(self):
        sg_rule = fakes.FakeSecurityGroupRule.create_one_security_group_rule({
            'ethertype': 'IPv4'
        }).info()

        match, ip_version, icmp = ovn_acl.acl_ethertype(sg_rule)
        self.assertEqual(' && ip4', match)
        self.assertEqual('ip4', ip_version)
        self.assertEqual('icmp4', icmp)

        sg_rule['ethertype'] = 'IPv6'
        match, ip_version, icmp = ovn_acl.acl_ethertype(sg_rule)
        self.assertEqual(' && ip6', match)
        self.assertEqual('ip6', ip_version)
        self.assertEqual('icmp6', icmp)

    def test_acl_remote_ip_prefix(self):
        sg_rule = fakes.FakeSecurityGroupRule.create_one_security_group_rule({
            'direction': 'ingress',
            'remote_ip_prefix': None
        }).info()
        ip_version = 'ip4'
        remote_ip_prefix = '10.10.0.0/24'

        match = ovn_acl.acl_remote_ip_prefix(sg_rule, ip_version)
        self.assertEqual('', match)

        sg_rule['remote_ip_prefix'] = remote_ip_prefix
        match = ovn_acl.acl_remote_ip_prefix(sg_rule, ip_version)
        expected_match = ' && %s.src == %s' % (ip_version, remote_ip_prefix)
        self.assertEqual(expected_match, match)

        sg_rule['direction'] = 'egress'
        match = ovn_acl.acl_remote_ip_prefix(sg_rule, ip_version)
        expected_match = ' && %s.dst == %s' % (ip_version, remote_ip_prefix)
        self.assertEqual(expected_match, match)

    def test_acl_remote_group_id(self):
        sg_rule = fakes.FakeSecurityGroupRule.create_one_security_group_rule({
            'direction': 'ingress',
            'remote_group_id': None
        }).info()
        ip_version = 'ip4'
        sg_id = sg_rule['security_group_id']

        addrset_name = ovn_utils.ovn_addrset_name(sg_id, ip_version)

        match = ovn_acl.acl_remote_group_id(sg_rule, ip_version)
        self.assertEqual('', match)

        sg_rule['remote_group_id'] = sg_id
        match = ovn_acl.acl_remote_group_id(sg_rule, ip_version)
        self.assertEqual(' && ip4.src == $' + addrset_name, match)

        sg_rule['direction'] = 'egress'
        match = ovn_acl.acl_remote_group_id(sg_rule, ip_version)
        self.assertEqual(' && ip4.dst == $' + addrset_name, match)

    def test_update_acls_for_security_group(self):
        sg = fakes.FakeSecurityGroup.create_one_security_group().info()
        remote_sg = fakes.FakeSecurityGroup.create_one_security_group().info()
        sg_rule = fakes.FakeSecurityGroupRule.create_one_security_group_rule({
            'security_group_id': sg['id'],
            'remote_group_id': remote_sg['id']
        }).info()
        port = fakes.FakePort.create_one_port({
            'security_groups': [sg['id']]
        }).info()
        self.plugin.get_ports.return_value = [port]
        sg_ports_cache = {sg['id']: [{'port_id': port['id']}],
                          remote_sg['id']: []}

        # Build ACL for validation.
        expected_acl = ovn_acl._add_sg_rule_acl_for_port(port, sg_rule)
        expected_acl.pop('lport')
        expected_acl.pop('lswitch')

        # Validate ACLs when port has security groups.
        ovn_acl.update_acls_for_security_group(self.plugin,
                                               self.admin_context,
                                               self.driver._nb_ovn,
                                               sg['id'],
                                               sg_rule,
                                               sg_ports_cache=sg_ports_cache)
        self.driver._nb_ovn.update_acls.assert_called_once_with(
            [port['network_id']],
            mock.ANY,
            {port['id']: expected_acl},
            need_compare=False,
            is_add_acl=True
        )

    def test_acl_port_ips(self):
        port4 = fakes.FakePort.create_one_port({
            'fixed_ips': [{'subnet_id': 'subnet-ipv4',
                           'ip_address': '10.0.0.1'}],
        }).info()
        port46 = fakes.FakePort.create_one_port({
            'fixed_ips': [{'subnet_id': 'subnet-ipv4',
                           'ip_address': '10.0.0.2'},
                          {'subnet_id': 'subnet-ipv6',
                           'ip_address': 'fde3:d45:df72::1'}],
        }).info()
        port6 = fakes.FakePort.create_one_port({
            'fixed_ips': [{'subnet_id': 'subnet-ipv6',
                           'ip_address': '2001:db8::8'}],
        }).info()

        addresses = ovn_acl.acl_port_ips(port4)
        self.assertEqual({'ip4': [port4['fixed_ips'][0]['ip_address']],
                          'ip6': []},
                         addresses)

        addresses = ovn_acl.acl_port_ips(port46)
        self.assertEqual({'ip4': [port46['fixed_ips'][0]['ip_address']],
                          'ip6': [port46['fixed_ips'][1]['ip_address']]},
                         addresses)

        addresses = ovn_acl.acl_port_ips(port6)
        self.assertEqual({'ip4': [],
                          'ip6': [port6['fixed_ips'][0]['ip_address']]},
                         addresses)

    def test_sg_disabled(self):
        sg = fakes.FakeSecurityGroup.create_one_security_group().info()
        port = fakes.FakePort.create_one_port({
            'security_groups': [sg['id']]
        }).info()

        with mock.patch('networking_ovn.common.acl.is_sg_enabled',
                        return_value=False):
            acl_list = ovn_acl.add_acls(self.plugin,
                                        self.admin_context,
                                        port, {}, {})
            self.assertEqual([], acl_list)

            ovn_acl.update_acls_for_security_group(self.plugin,
                                                   self.admin_context,
                                                   self.driver._ovn,
                                                   sg['id'],
                                                   None)
            self.driver._ovn.update_acls.assert_not_called()

            addresses = ovn_acl.acl_port_ips(port)
            self.assertEqual({'ip4': [], 'ip6': []}, addresses)

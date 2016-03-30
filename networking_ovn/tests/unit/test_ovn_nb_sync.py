# Copyright 2016 Red Hat, Inc.
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

import mock

from networking_ovn import ovn_nb_sync
from networking_ovn.ovsdb import impl_idl_ovn
from networking_ovn.tests.unit import test_ovn_plugin


class TestOvnNbSync(test_ovn_plugin.OVNPluginTestCase):
    def setUp(self):
        super(TestOvnNbSync, self).setUp()
        self.plugin._ovn = self._ovn = impl_idl_ovn.OvsdbOvnIdl(self,
                                                                mock.ANY)
        self.subnet = {'cidr': '10.0.0.0/24',
                       'id': 'subnet1',
                       'subnetpool_id': None,
                       'name': 'private-subnet',
                       'enable_dhcp': True,
                       'network_id': 'n1',
                       'tenant_id': 'tenant1',
                       'gateway_ip': '10.0.0.1',
                       'ip_version': 4,
                       'shared': False}
        self.matches = [["", True], ["", False], ["", True], ["", False]]

        self.networks = [{'id': 'n1'},
                         {'id': 'n2'}]

        self.security_groups = [
            {'id': 'sg1', 'tenant_id': 'tenant1',
             'security_group_rules': [{'remote_group_id': None,
                                       'direction': 'ingress',
                                       'remote_ip_prefix': '0.0.0.0/0',
                                       'protocol': 'tcp',
                                       'ethertype': 'IPv4',
                                       'tenant_id': 'tenant1',
                                       'port_range_max': 65535,
                                       'port_range_min': 1,
                                       'id': 'ruleid1',
                                       'security_group_id': 'sg1'}],
             'name': 'all-tcp'},
            {'id': 'sg2', 'tenant_id': 'tenant1',
             'security_group_rules': [{'remote_group_id': 'sg2',
                                       'direction': 'egress',
                                       'remote_ip_prefix': '0.0.0.0/0',
                                       'protocol': 'tcp',
                                       'ethertype': 'IPv4',
                                       'tenant_id': 'tenant1',
                                       'port_range_max': 65535,
                                       'port_range_min': 1,
                                       'id': 'ruleid1',
                                       'security_group_id': 'sg2'}],
             'name': 'all-tcpe'}]
        self.ports = [
            {'id': 'p1n1',
             'fixed_ips':
                 [{'subnet_id': 'b142f5e3-d434-4740-8e88-75e8e5322a40',
                   'ip_address': '10.0.0.4'},
                  {'subnet_id': 'subnet1',
                   'ip_address': 'fd79:e1c:a55::816:eff:eff:ff2'}],
             'security_groups': ['sg1'],
             'network_id': 'n1'},
            {'id': 'p2n1',
             'fixed_ips':
                 [{'subnet_id': 'b142f5e3-d434-4740-8e88-75e8e5322a40',
                   'ip_address': '10.0.0.4'},
                  {'subnet_id': 'subnet1',
                   'ip_address': 'fd79:e1c:a55::816:eff:eff:ff2'}],
             'security_groups': ['sg2'],
             'network_id': 'n1'},
            {'id': 'p1n2',
             'fixed_ips':
                 [{'subnet_id': 'b142f5e3-d434-4740-8e88-75e8e5322a40',
                   'ip_address': '10.0.0.4'},
                  {'subnet_id': 'subnet1',
                   'ip_address': 'fd79:e1c:a55::816:eff:eff:ff2'}],
             'security_groups': ['sg1'],
             'network_id': 'n2'},
            {'id': 'p2n2',
             'fixed_ips':
                 [{'subnet_id': 'b142f5e3-d434-4740-8e88-75e8e5322a40',
                   'ip_address': '10.0.0.4'},
                  {'subnet_id': 'subnet1',
                   'ip_address': 'fd79:e1c:a55::816:eff:eff:ff2'}],
             'security_groups': ['sg2'],
             'network_id': 'n2'}]
        self.acls_ovn = {
            'lport1':
            # ACLs need to be removed by the sync tool
            [{'id': 'acl1', 'priority': 00, 'policy': 'allow',
              'lswitch': 'lswitch1', 'lport': 'lport1'}],
            'lport2':
            [{'id': 'acl2', 'priority': 00, 'policy': 'drop',
             'lswitch': 'lswitch2', 'lport': 'lport2'}],
            # ACLs need to be kept as-is by the sync tool
            'p2n2':
            [{'lport': 'p2n2', 'direction': 'to-lport',
              'log': False, 'lswitch': 'neutron-n2',
              'priority': 1001, 'action': 'drop',
             'external_ids': {'neutron:lport': 'p2n2'},
              'match': 'outport == "p2n2" && ip'},
             {'lport': 'p2n2', 'direction': 'to-lport',
              'log': False, 'lswitch': 'neutron-n2',
              'priority': 1002, 'action': 'allow',
              'external_ids': {'neutron:lport': 'p2n2'},
              'match': 'outport == "p2n2" && ip4 && '
              'ip4.src == 10.0.0.0/24 && udp && '
              'udp.src == 67 && udp.dst == 68'}]}

        self.lswitches_with_ports = [{'name': 'neutron-n1',
                                      'ports': ['p1n1', 'p3n1']},
                                     {'name': 'neutron-n3',
                                      'ports': ['p1n3', 'p2n3']}]

    def _test_ovn_nb_sync_helper(self, mode, networks, ports,
                                 create_network_list, create_port_list,
                                 del_network_list, del_port_list):

        self.ovn_nb_sync = ovn_nb_sync.OvnNbSynchronizer(
            self.plugin, self.plugin._ovn, mode)

        self.plugin.get_networks = mock.Mock()
        self.plugin.get_networks.return_value = self.networks

        # following block is used for acl syncing unit-test

        # With the given set of values in the unit testing,
        # 19 neutron acls should have been there,
        # 4 acls are returned as current ovn acls,
        # two of which will match with neutron.
        # So, in this example 17 will be added, 2 removed
        self.plugin.get_ports = mock.Mock()
        self.plugin.get_ports.return_value = self.ports
        self.plugin.get_security_groups = mock.Mock()
        self.plugin.get_security_groups.return_value = self.security_groups
        self.plugin._acl_get_subnet_from_cache = mock.Mock()
        self.plugin._acl_get_subnet_from_cache.return_value = self.subnet
        self.plugin._acl_remote_group_id = mock.MagicMock(
            side_effect=self.matches)
        self.plugin.get_security_group = mock.MagicMock(
            side_effect=self.security_groups)
        self.ovn_nb_sync.get_acls = mock.Mock()
        self.ovn_nb_sync.get_acls.return_value = self.acls_ovn
        # end of acl-sync block

        self.plugin._ovn.get_all_logical_switches_with_ports = mock.Mock()
        self.plugin._ovn.get_all_logical_switches_with_ports.return_value = (
            self.lswitches_with_ports)

        self.ovn_nb_sync.ovn_api.transaction = mock.MagicMock()

        self.plugin.create_network_in_ovn = mock.Mock()
        self.plugin.create_port_in_ovn = mock.Mock()
        self.plugin.get_ovn_port_options = mock.Mock()
        self.plugin.get_ovn_port_options.return_value = mock.ANY
        self.ovn_nb_sync.ovn_api.delete_lswitch = mock.Mock()
        self.ovn_nb_sync.ovn_api.delete_lport = mock.Mock()

        self.ovn_nb_sync.sync_networks_and_ports(mock.ANY)
        self.ovn_nb_sync.sync_acls(mock.ANY)

        self.assertEqual(self.plugin.get_security_groups.call_count, 1)
        self.plugin.get_security_groups.assert_has_calls([mock.ANY],
                                                         any_order=True)

        get_security_group_calls = [mock.call(mock.ANY, sg['id'])
                                    for sg in self.security_groups]
        self.assertEqual(self.plugin.get_security_group.call_count,
                         len(self.security_groups))
        self.plugin.get_security_group.assert_has_calls(
            get_security_group_calls, any_order=True)

        create_network_calls = [mock.call(net['net'], net['ext_ids'])
                                for net in create_network_list]
        self.assertEqual(self.plugin.create_network_in_ovn.call_count,
                         len(create_network_list))
        self.plugin.create_network_in_ovn.assert_has_calls(
            create_network_calls, any_order=True)

        create_port_calls = [mock.call(mock.ANY, port, mock.ANY)
                             for port in create_port_list]
        self.assertEqual(self.plugin.create_port_in_ovn.call_count,
                         len(create_port_list))
        self.plugin.create_port_in_ovn.assert_has_calls(create_port_calls,
                                                        any_order=True)

        self.assertEqual(self.ovn_nb_sync.ovn_api.delete_lswitch.call_count,
                         len(del_network_list))
        delete_lswitch_calls = [mock.call(lswitch_name=net_name)
                                for net_name in del_network_list]
        self.ovn_nb_sync.ovn_api.delete_lswitch.assert_has_calls(
            delete_lswitch_calls, any_order=True)

        self.assertEqual(self.ovn_nb_sync.ovn_api.delete_lport.call_count,
                         len(del_port_list))
        delete_lport_calls = [mock.call(lport_name=port['id'],
                                        lswitch=port['lswitch'])
                              for port in del_port_list]
        self.ovn_nb_sync.ovn_api.delete_lport.assert_has_calls(
            delete_lport_calls, any_order=True)

    def test_ovn_nb_sync_mode_repair(self):
        create_network_list = [{'net': {'id': 'n2'}, 'ext_ids': {}}]
        del_network_list = ['neutron-n3']
        del_port_list = [{'id': 'p3n1', 'lswitch': 'neutron-n1'},
                         {'id': 'p1n1', 'lswitch': 'neutron-n1'}]
        create_port_list = self.ports
        for port in create_port_list:
            if port['id'] == 'p1n1':
                # this will be skipped by the logic,
                # because it is already in lswitch-port list
                create_port_list.remove(port)

        self._test_ovn_nb_sync_helper('repair', self.networks, self.ports,
                                      create_network_list, create_port_list,
                                      del_network_list, del_port_list)

    def test_ovn_nb_sync_mode_log(self):
        create_network_list = []
        create_port_list = []
        del_network_list = []
        del_port_list = []

        self._test_ovn_nb_sync_helper('log', self.networks, self.ports,
                                      create_network_list, create_port_list,
                                      del_network_list, del_port_list)

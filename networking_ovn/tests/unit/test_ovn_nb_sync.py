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
        self.networks = [{'id': 'n1'},
                         {'id': 'n2'}]
        self.ports = [
            {'id': 'p1n1',
             'network_id': 'n1'},
            {'id': 'p2n1',
             'network_id': 'n1'},
            {'id': 'p1n2',
             'network_id': 'n2'},
            {'id': 'p2n2',
             'network_id': 'n2'},
        ]

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
        self.plugin.get_ports = mock.Mock()
        self.plugin.get_ports.return_value = self.ports

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
        create_port_list = [{'id': 'p2n1', 'network_id': 'n1'},
                            {'id': 'p1n2', 'network_id': 'n2'},
                            {'id': 'p2n2', 'network_id': 'n2'}]
        del_network_list = ['neutron-n3']
        del_port_list = [{'id': 'p3n1', 'lswitch': 'neutron-n1'}]

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

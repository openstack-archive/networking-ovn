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
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.extensions import test_extraroute
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit.extensions import test_l3_ext_gw_mode as test_l3_gw
from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg

from networking_ovn.tests.unit import fakes
from networking_ovn.tests.unit.ml2 import test_mech_driver


class OVNL3RouterPlugin(test_mech_driver.OVNMechanismDriverTestCase):

    l3_plugin = 'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin'

    def _start_mock(self, path, return_value, new_callable=None):
        patcher = mock.patch(path, return_value=return_value,
                             new_callable=new_callable)
        patcher.start()
        self.addCleanup(patcher.stop)

    def setUp(self):
        super(OVNL3RouterPlugin, self).setUp()
        self.fake_router_port = {'device_id': '',
                                 'device_owner': 'network:router_interface',
                                 'mac_address': 'aa:aa:aa:aa:aa:aa',
                                 'fixed_ips': [{'ip_address': '10.0.0.100',
                                                'subnet_id': 'subnet-id'}],
                                 'id': 'router-port-id'}
        self.fake_router_port_assert = {'lrouter': 'neutron-router-id',
                                        'mac': 'aa:aa:aa:aa:aa:aa',
                                        'name': 'lrp-router-port-id',
                                        'networks': ['10.0.0.100/24']}
        self.fake_router_ports = [self.fake_router_port]
        self.fake_subnet = {'id': 'subnet-id',
                            'ip_version': 4,
                            'cidr': '10.0.0.0/24'}
        self.fake_router = {'id': 'router-id',
                            'name': 'router',
                            'admin_state_up': False,
                            'routes': [{'destination': '1.1.1.0/24',
                                        'nexthop': '10.0.0.2'}]}
        self.fake_router_interface_info = {
            'port_id': 'router-port-id',
            'device_id': '',
            'mac_address': 'aa:aa:aa:aa:aa:aa',
            'subnet_id': 'subnet-id',
            'subnet_ids': ['subnet-id'],
            'fixed_ips': [{'ip_address': '10.0.0.100',
                           'subnet_id': 'subnet-id'}],
            'id': 'router-port-id'}
        self.fake_external_fixed_ips = {
            'network_id': 'ext-network-id',
            'external_fixed_ips': [{'ip_address': '192.168.1.1',
                                    'subnet_id': 'ext-subnet-id'}]}
        self.fake_router_with_ext_gw = {
            'id': 'router-id',
            'name': 'router',
            'admin_state_up': True,
            'external_gateway_info': self.fake_external_fixed_ips,
            'gw_port_id': 'gw-port-id'
        }
        self.fake_router_without_ext_gw = {
            'id': 'router-id',
            'name': 'router',
            'admin_state_up': True,
        }
        self.fake_ext_subnet = {'id': 'ext-subnet-id',
                                'ip_version': 4,
                                'cidr': '192.168.1.0/24',
                                'gateway_ip': '192.168.1.254'}
        self.fake_ext_gw_port = {'device_id': '',
                                 'device_owner': 'network:router_gateway',
                                 'fixed_ips': [{'ip_address': '192.168.1.1',
                                                'subnet_id': 'ext-subnet-id'}],
                                 'mac_address': '00:00:00:02:04:06',
                                 'id': 'gw-port-id'}
        self.fake_ext_gw_port_assert = {'lrouter': 'neutron-router-id',
                                        'mac': '00:00:00:02:04:06',
                                        'name': 'lrp-gw-port-id',
                                        'networks': ['192.168.1.1/24'],
                                        'options': {'redirect-chassis': 'hv1'}}
        self.fake_floating_ip = {'id': 'fip-id',
                                 'tenant_id': '',
                                 'floating_ip_address': '192.168.0.10',
                                 'floating_network_id': 'fip-net-id',
                                 'router_id': 'router-id',
                                 # API level attribute
                                 'port_id': 'port_id',
                                 'fixed_port_id': 'port_id',
                                 'floating_port_id': 'fip-port-id',
                                 'fixed_ip_address': '10.0.0.10',
                                 'status': 'Active'}
        self.fake_floating_ip_new = {'id': 'fip-id',
                                     'tenant_id': '',
                                     'floating_ip_address': '192.168.0.10',
                                     'floating_network_id': 'fip-net-id',
                                     'router_id': 'new-router-id',
                                     # API level attribute
                                     'port_id': 'new-port_id',
                                     'fixed_port_id': 'new-port_id',
                                     'floating_port_id': 'fip-port-id',
                                     'fixed_ip_address': '10.10.10.10',
                                     'status': 'Active'}
        self.l3_inst = directory.get_plugin(plugin_constants.L3)
        self._start_mock(
            'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._ovn',
            new_callable=mock.PropertyMock,
            return_value=fakes.FakeOvsdbNbOvnIdl())
        self._start_mock(
            'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._sb_ovn',
            new_callable=mock.PropertyMock,
            return_value=fakes.FakeOvsdbSbOvnIdl())
        self._start_mock(
            'neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port',
            return_value=self.fake_router_port)
        self._start_mock(
            'neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet',
            return_value=self.fake_subnet)
        self._start_mock(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router',
            return_value=self.fake_router)
        self._start_mock(
            'neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.update_router',
            return_value=self.fake_router)
        self._start_mock(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin.remove_router_interface',
            return_value=self.fake_router_interface_info)
        self._start_mock(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin.create_router',
            return_value=self.fake_router_with_ext_gw)
        self._start_mock(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin.delete_router',
            return_value={})
        self._start_mock(
            'networking_ovn.l3.l3_ovn_scheduler.'
            'OVNGatewayLeastLoadedScheduler._schedule_gateway',
            return_value='hv1')
        self._start_mock(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin.create_floatingip',
            return_value=self.fake_floating_ip)
        self._start_mock(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin._get_floatingip',
            return_value=self.fake_floating_ip)

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.add_router_interface')
    def test_add_router_interface(self, func):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        func.return_value = self.fake_router_interface_info
        self.l3_inst.add_router_interface(self.context, router_id,
                                          interface_info)
        self.l3_inst._ovn.add_lrouter_port.assert_called_once_with(
            **self.fake_router_port_assert)
        self.l3_inst._ovn.set_lrouter_port_in_lswitch_port.\
            assert_called_once_with('router-port-id', 'lrp-router-port-id')

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.add_router_interface')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    def test_add_router_interface_update_lrouter_port(self, getp, func):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        func.return_value = {'id': router_id,
                             'port_id': 'router-port-id',
                             'subnet_id': 'subnet-id1',
                             'subnet_ids': ['subnet-id1'],
                             'fixed_ips': [
                                 {'ip_address': '2001:db8::1',
                                  'subnet_id': 'subnet-id1'},
                                 {'ip_address': '2001:dba::1',
                                  'subnet_id': 'subnet-id2'}],
                             'mac_address': 'aa:aa:aa:aa:aa:aa'
                             }
        getp.return_value = {
            'id': 'router-port-id',
            'fixed_ips': [
                {'ip_address': '2001:db8::1', 'subnet_id': 'subnet-id1'},
                {'ip_address': '2001:dba::1', 'subnet_id': 'subnet-id2'}],
            'mac_address': 'aa:aa:aa:aa:aa:aa'
            }
        fake_rtr_intf_networks = ['2001:db8::1/24', '2001:dba::1/24']
        self.l3_inst.add_router_interface(self.context, router_id,
                                          interface_info)
        called_args_dict = (
            self.l3_inst._ovn.update_lrouter_port.call_args_list[0][1])
        self.assertEqual(1, self.l3_inst._ovn.update_lrouter_port.call_count)
        self.assertItemsEqual(fake_rtr_intf_networks,
                              called_args_dict.get('networks', []))
        self.l3_inst._ovn.set_lrouter_port_in_lswitch_port.\
            assert_called_once_with('router-port-id', 'lrp-router-port-id')

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    def test_remove_router_interface(self, getp):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        getp.side_effect = n_exc.PortNotFound(port_id='router-port-id')

        self.l3_inst.remove_router_interface(
            self.context, router_id, interface_info)

        self.l3_inst._ovn.delete_lrouter_port.assert_called_once_with(
            'lrp-router-port-id', 'neutron-router-id', if_exists=True)

    def test_remove_router_interface_update_lrouter_port(self):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        self.l3_inst.remove_router_interface(
            self.context, router_id, interface_info)

        self.l3_inst._ovn.update_lrouter_port.assert_called_once_with(
            if_exists=False, name='lrp-router-port-id',
            networks=['10.0.0.100/24'])

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.update_router')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    def test_update_router_admin_state_no_change(self, get_rps, func):
        router_id = 'router-id'
        update_data = {'router': {'admin_state_up': False}}
        self.l3_inst.update_router(self.context, router_id, update_data)
        self.assertFalse(self.l3_inst._ovn.update_lrouter.called)

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.update_router')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    def test_update_router_admin_state_change(self, get_rps, func):
        router_id = 'router-id'
        update_data = {'router': {'admin_state_up': True}}
        self.l3_inst.update_router(self.context, router_id, update_data)
        self.l3_inst._ovn.update_lrouter.assert_called_once_with(
            'neutron-router-id', enabled=True)

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.update_router')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    def test_update_router_name_no_change(self, get_rps, func):
        router_id = 'router-id'
        update_data = {'router': {'name': 'router'}}
        self.l3_inst.update_router(self.context, router_id, update_data)
        self.assertFalse(self.l3_inst._ovn.update_lrouter.called)

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.update_router')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    def test_update_router_name_change(self, get_rps, func):
        router_id = 'router-id'
        update_data = {'router': {'name': 'test'}}
        self.l3_inst.update_router(self.context, router_id, update_data)
        self.l3_inst._ovn.update_lrouter.assert_called_once_with(
            'neutron-router-id',
            external_ids={'neutron:router_name': 'test'})

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.update_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin._get_router')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    def test_update_router_static_route_no_change(self, get_rps, get_r, func):
        router_id = 'router-id'
        get_rps.return_value = [{'device_id': '',
                                'device_owner': 'network:router_interface',
                                 'mac_address': 'aa:aa:aa:aa:aa:aa',
                                 'fixed_ips': [{'ip_address': '10.0.0.100',
                                                'subnet_id': 'subnet-id'}],
                                 'id': 'router-port-id'}]
        update_data = {'router': {'routes': [{'destination': '1.1.1.0/24',
                                              'nexthop': '10.0.0.2'}]}}
        self.l3_inst.update_router(self.context, router_id, update_data)
        self.assertFalse(self.l3_inst._ovn.add_static_route.called)
        self.assertFalse(self.l3_inst._ovn.delete_static_route.called)

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.update_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin._get_router')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    def test_update_router_static_route_change(self, get_rps, get_r, func):
        router_id = 'router-id'
        get_rps.return_value = [{'device_id': '',
                                'device_owner': 'network:router_interface',
                                 'mac_address': 'aa:aa:aa:aa:aa:aa',
                                 'fixed_ips': [{'ip_address': '10.0.0.100',
                                                'subnet_id': 'subnet-id'}],
                                 'id': 'router-port-id'}]
        update_data = {'router': {'routes': [{'destination': '2.2.2.0/24',
                                              'nexthop': '10.0.0.3'}]}}
        self.l3_inst.update_router(self.context, router_id, update_data)
        self.l3_inst._ovn.add_static_route.assert_called_once_with(
            'neutron-router-id',
            ip_prefix='2.2.2.0/24', nexthop='10.0.0.3')
        self.l3_inst._ovn.delete_static_route.assert_called_once_with(
            'neutron-router-id',
            ip_prefix='1.1.1.0/24', nexthop='10.0.0.2')

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    def test_create_router_with_ext_gw(self, get_rps, get_subnet, get_port):
        router = {'router': {'name': 'router'}}
        get_subnet.return_value = self.fake_ext_subnet
        get_port.return_value = self.fake_ext_gw_port
        get_rps.return_value = []

        self.l3_inst.create_router(self.context, router)

        external_ids = {'neutron:router_name': 'router'}
        self.l3_inst._ovn.create_lrouter.assert_called_once_with(
            'neutron-router-id', external_ids=external_ids,
            enabled=True, options={})
        self.l3_inst._ovn.add_lrouter_port.assert_called_once_with(
            **self.fake_ext_gw_port_assert)
        expected_calls = [mock.call('neutron-router-id',
                                    ip_prefix='0.0.0.0/0',
                                    nexthop='192.168.1.254')]
        self.l3_inst._ovn.add_static_route.assert_has_calls(expected_calls)

    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    def test_delete_router_with_ext_gw(self, gs, gr, gprs):
        gr.return_value = self.fake_router_with_ext_gw
        gs.return_value = self.fake_ext_subnet

        self.l3_inst.delete_router(self.context, 'router-id')

        self.l3_inst._ovn.delete_lrouter.assert_called_once_with(
            'neutron-router-id')

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.add_router_interface')
    def test_add_router_interface_with_gateway_set(self, ari, gr, grps,
                                                   gs, gp):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        ari.return_value = self.fake_router_interface_info
        gr.return_value = self.fake_router_with_ext_gw
        gs.return_value = self.fake_subnet
        gp.return_value = self.fake_router_port

        self.l3_inst.add_router_interface(self.context, router_id,
                                          interface_info)

        self.l3_inst._ovn.add_lrouter_port.assert_called_once_with(
            **self.fake_router_port_assert)
        self.l3_inst._ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', logical_ip='10.0.0.0/24',
            external_ip='192.168.1.1', type='snat')

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.add_router_interface')
    def test_add_router_interface_with_gateway_set_and_snat_disabled(
            self, ari, gr, grps, gs, gp):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        ari.return_value = self.fake_router_interface_info
        gr.return_value = self.fake_router_with_ext_gw
        gr.return_value['external_gateway_info']['enable_snat'] = False
        gs.return_value = self.fake_subnet
        gp.return_value = self.fake_router_port

        self.l3_inst.add_router_interface(self.context, router_id,
                                          interface_info)

        self.l3_inst._ovn.add_lrouter_port.assert_called_once_with(
            **self.fake_router_port_assert)
        self.l3_inst._ovn.add_nat_rule_in_lrouter.assert_not_called()

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    def test_remove_router_interface_with_gateway_set(self, gr, gs, gp):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id',
                          'subnet_id': 'subnet-id'}
        gr.return_value = self.fake_router_with_ext_gw
        gs.return_value = self.fake_subnet
        gp.side_effect = n_exc.PortNotFound(port_id='router-port-id')
        self.l3_inst.remove_router_interface(
            self.context, router_id, interface_info)

        self.l3_inst._ovn.delete_lrouter_port.assert_called_once_with(
            'lrp-router-port-id', 'neutron-router-id', if_exists=True)
        self.l3_inst._ovn.delete_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', logical_ip='10.0.0.0/24',
            external_ip='192.168.1.1', type='snat')

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    def test_update_router_with_ext_gw(self, gr, ur, gs, grps, gp):
        router = {'router': {'name': 'router'}}
        gr.return_value = self.fake_router_without_ext_gw
        ur.return_value = self.fake_router_with_ext_gw
        gs.side_effect = lambda ctx, sid: {
            'ext-subnet-id': self.fake_ext_subnet}.get(sid, self.fake_subnet)
        gp.return_value = self.fake_ext_gw_port
        grps.return_value = self.fake_router_ports

        self.l3_inst.update_router(self.context, 'router-id', router)

        self.l3_inst._ovn.add_lrouter_port.assert_called_once_with(
            **self.fake_ext_gw_port_assert)
        self.l3_inst._ovn.add_static_route.assert_called_once_with(
            'neutron-router-id', ip_prefix='0.0.0.0/0',
            nexthop='192.168.1.254')
        self.l3_inst._ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', type='snat',
            logical_ip='10.0.0.0/24', external_ip='192.168.1.1')

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    def test_update_router_ext_gw_change_subnet(self, gr, ur, gs,
                                                grps, gp):
        router = {'router': {'name': 'router'}}
        fake_old_ext_subnet = {'id': 'old-ext-subnet-id',
                               'ip_version': 4,
                               'cidr': '192.168.2.0/24',
                               'gateway_ip': '192.168.2.254'}
        # Old gateway info with same network and different subnet
        gr.return_value = copy.copy(self.fake_router_with_ext_gw)
        gr.return_value['external_gateway_info'] = {
            'network_id': 'ext-network-id',
            'external_fixed_ips': [{'ip_address': '192.168.2.1',
                                    'subnet_id': 'old-ext-subnet-id'}]}
        gr.return_value['gw_port_id'] = 'old-gw-port-id'
        ur.return_value = self.fake_router_with_ext_gw
        gs.side_effect = lambda ctx, sid: {
            'ext-subnet-id': self.fake_ext_subnet,
            'old-ext-subnet-id': fake_old_ext_subnet}.get(sid,
                                                          self.fake_subnet)
        gp.return_value = self.fake_ext_gw_port
        grps.return_value = self.fake_router_ports

        self.l3_inst.update_router(self.context, 'router-id', router)

        # Check deleting old router gateway
        self.l3_inst._ovn.delete_lrouter_port.assert_called_once_with(
            'lrp-old-gw-port-id', 'neutron-router-id')
        self.l3_inst._ovn.delete_static_route.assert_called_once_with(
            'neutron-router-id', ip_prefix='0.0.0.0/0',
            nexthop='192.168.2.254')
        self.l3_inst._ovn.delete_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', logical_ip='10.0.0.0/24',
            external_ip='192.168.2.1', type='snat')

        # Check adding new router gateway
        self.l3_inst._ovn.add_lrouter_port.assert_called_once_with(
            **self.fake_ext_gw_port_assert)
        self.l3_inst._ovn.add_static_route.assert_called_once_with(
            'neutron-router-id', ip_prefix='0.0.0.0/0',
            nexthop='192.168.1.254')
        self.l3_inst._ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', type='snat',
            logical_ip='10.0.0.0/24', external_ip='192.168.1.1')

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    def test_update_router_ext_gw_change_ip_address(self, gr, ur, gs,
                                                    grps, gp):
        router = {'router': {'name': 'router'}}
        # Old gateway info with same subnet and different ip address
        gr_value = copy.deepcopy(self.fake_router_with_ext_gw)
        gr_value['external_gateway_info'][
            'external_fixed_ips'][0]['ip_address'] = '192.168.1.2'
        gr_value['gw_port_id'] = 'old-gw-port-id'
        gr.return_value = gr_value
        ur.return_value = self.fake_router_with_ext_gw
        gs.side_effect = lambda ctx, sid: {
            'ext-subnet-id': self.fake_ext_subnet}.get(sid, self.fake_subnet)
        gp.return_value = self.fake_ext_gw_port
        grps.return_value = self.fake_router_ports

        self.l3_inst.update_router(self.context, 'router-id', router)

        # Check deleting old router gateway
        self.l3_inst._ovn.delete_lrouter_port.assert_called_once_with(
            'lrp-old-gw-port-id', 'neutron-router-id')
        self.l3_inst._ovn.delete_static_route.assert_called_once_with(
            'neutron-router-id', ip_prefix='0.0.0.0/0',
            nexthop='192.168.1.254')
        self.l3_inst._ovn.delete_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', logical_ip='10.0.0.0/24',
            external_ip='192.168.1.2', type='snat')
        # Check adding new router gateway
        self.l3_inst._ovn.add_lrouter_port.assert_called_once_with(
            **self.fake_ext_gw_port_assert)
        self.l3_inst._ovn.add_static_route.assert_called_once_with(
            'neutron-router-id', ip_prefix='0.0.0.0/0',
            nexthop='192.168.1.254')
        self.l3_inst._ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', type='snat',
            logical_ip='10.0.0.0/24', external_ip='192.168.1.1')

    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    def test_update_router_ext_gw_no_change(self, gr, ur, get_rps):
        router = {'router': {'name': 'router'}}
        gr.return_value = self.fake_router_with_ext_gw
        ur.return_value = self.fake_router_with_ext_gw

        self.l3_inst.update_router(self.context, 'router-id', router)

        self.l3_inst._ovn.delete_lrouter_port.assert_not_called()
        self.l3_inst._ovn.delete_static_route.assert_not_called()
        self.l3_inst._ovn.delete_nat_rule_in_lrouter.assert_not_called()
        self.l3_inst._ovn.add_static_route.assert_not_called()
        self.l3_inst._ovn.add_nat_rule_in_lrouter.assert_not_called()

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    def test_update_router_with_ext_gw_and_disabled_snat(self, gr, ur,
                                                         gs, grps, gp):
        router = {'router': {'name': 'router'}}
        gr.return_value = self.fake_router_without_ext_gw
        ur.return_value = self.fake_router_with_ext_gw
        ur.return_value['external_gateway_info']['enable_snat'] = False
        gs.side_effect = lambda ctx, sid: {
            'ext-subnet-id': self.fake_ext_subnet}.get(sid, self.fake_subnet)
        gp.return_value = self.fake_ext_gw_port
        grps.return_value = self.fake_router_ports

        self.l3_inst.update_router(self.context, 'router-id', router)

        # Need not check lsp and lrp here, it has been tested in other cases
        self.l3_inst._ovn.add_static_route.assert_called_once_with(
            'neutron-router-id', ip_prefix='0.0.0.0/0',
            nexthop='192.168.1.254')
        self.l3_inst._ovn.add_nat_rule_in_lrouter.assert_not_called()

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    def test_enable_snat(self, gr, ur, gs, grps, gp):
        router = {'router': {'name': 'router'}}
        gr.return_value = copy.deepcopy(self.fake_router_with_ext_gw)
        gr.return_value['external_gateway_info']['enable_snat'] = False
        ur.return_value = self.fake_router_with_ext_gw
        gs.side_effect = lambda ctx, sid: {
            'ext-subnet-id': self.fake_ext_subnet}.get(sid, self.fake_subnet)
        gp.return_value = self.fake_ext_gw_port
        grps.return_value = self.fake_router_ports

        self.l3_inst.update_router(self.context, 'router-id', router)

        self.l3_inst._ovn.delete_static_route.assert_not_called()
        self.l3_inst._ovn.delete_nat_rule_in_lrouter.assert_not_called()
        self.l3_inst._ovn.add_static_route.assert_not_called()
        self.l3_inst._ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', type='snat', logical_ip='10.0.0.0/24',
            external_ip='192.168.1.1')

    @mock.patch('networking_ovn.common.utils.is_snat_enabled',
                mock.Mock(return_value=True))
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    def test_disable_snat(self, gr, ur, gs, grps, gp):
        router = {'router': {'name': 'router'}}
        gr.return_value = self.fake_router_with_ext_gw
        ur.return_value = copy.deepcopy(self.fake_router_with_ext_gw)
        ur.return_value['external_gateway_info']['enable_snat'] = False
        gs.side_effect = lambda ctx, sid: {
            'ext-subnet-id': self.fake_ext_subnet}.get(sid, self.fake_subnet)
        gp.return_value = self.fake_ext_gw_port
        grps.return_value = self.fake_router_ports

        self.l3_inst.update_router(self.context, 'router-id', router)

        self.l3_inst._ovn.delete_static_route.assert_not_called()
        self.l3_inst._ovn.delete_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', type='snat', logical_ip='10.0.0.0/24',
            external_ip='192.168.1.1')
        self.l3_inst._ovn.add_static_route.assert_not_called()
        self.l3_inst._ovn.add_nat_rule_in_lrouter.assert_not_called()

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin._get_floatingip')
    def test_create_floatingip(self, gf):
        gf.return_value = {'floating_port_id': 'fip-port-id'}
        self.l3_inst.create_floatingip(self.context, 'floatingip')
        self.l3_inst._ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10')
        self.l3_inst._ovn.delete_lswitch_port.assert_called_once_with(
            'fip-port-id', 'neutron-fip-net-id')

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin._get_floatingip')
    def test_create_floatingip_external_ip_present_in_nat_rule(self, gf):
        gf.return_value = {'floating_port_id': 'fip-port-id'}
        self.l3_inst._ovn.get_lrouter_nat_rules.return_value = [
            {'external_ip': '192.168.0.10', 'logical_ip': '10.0.0.6',
             'type': 'dnat_and_snat', 'uuid': 'uuid1'}]
        self.l3_inst.create_floatingip(self.context, 'floatingip')
        self.l3_inst._ovn.add_nat_rule_in_lrouter.assert_not_called()
        self.l3_inst._ovn.set_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id', 'uuid1',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10')
        self.l3_inst._ovn.delete_lswitch_port.assert_called_once_with(
            'fip-port-id', 'neutron-fip-net-id')

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin._get_floatingip')
    def test_create_floatingip_external_ip_present_type_snat(self, gf):
        gf.return_value = {'floating_port_id': 'fip-port-id'}
        self.l3_inst._ovn.get_lrouter_nat_rules.return_value = [
            {'external_ip': '192.168.0.10', 'logical_ip': '10.0.0.0/24',
             'type': 'snat', 'uuid': 'uuid1'}]
        self.l3_inst.create_floatingip(self.context, 'floatingip')
        self.l3_inst._ovn.set_nat_rule_in_lrouter.assert_not_called()
        self.l3_inst._ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10')
        self.l3_inst._ovn.delete_lswitch_port.assert_called_once_with(
            'fip-port-id', 'neutron-fip-net-id')

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.delete_floatingip')
    def test_delete_floatingip(self, df):
        self.l3_inst.delete_floatingip(self.context, 'floatingip-id')
        self.l3_inst._ovn.delete_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10')

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin._get_floatingip')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_floatingip')
    def test_update_floatingip(self, uf, gf):
        gf.return_value = self.fake_floating_ip
        uf.return_value = self.fake_floating_ip_new
        self.l3_inst.update_floatingip(self.context, 'id', 'floatingip')
        self.l3_inst._ovn.delete_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10')
        self.l3_inst._ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-new-router-id',
            type='dnat_and_snat',
            logical_ip='10.10.10.10',
            external_ip='192.168.0.10')

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin._get_floatingip')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_floatingip')
    def test_update_floatingip_associate(self, uf, gf):
        self.fake_floating_ip.update({'fixed_port_id': None})
        gf.return_value = self.fake_floating_ip
        uf.return_value = self.fake_floating_ip_new
        self.l3_inst.update_floatingip(self.context, 'id', 'floatingip')
        self.l3_inst._ovn.delete_nat_rule_in_lrouter.assert_not_called()
        self.l3_inst._ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-new-router-id',
            type='dnat_and_snat',
            logical_ip='10.10.10.10',
            external_ip='192.168.0.10')

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin._get_floatingip')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_floatingip')
    def test_update_floatingip_association_not_changed(self, uf, gf):
        self.fake_floating_ip.update({'fixed_port_id': None})
        self.fake_floating_ip_new.update({'port_id': None})
        gf.return_value = self.fake_floating_ip
        uf.return_value = self.fake_floating_ip_new
        self.l3_inst.update_floatingip(self.context, 'id', 'floatingip')

        self.l3_inst._ovn.delete_nat_rule_in_lrouter.assert_not_called()

        self.l3_inst._ovn. \
            add_nat_rule_in_lrouter.assert_not_called()

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin._get_floatingip')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_floatingip')
    def test_update_floatingip_reassociate_to_same_port_diff_fixed_ip(
            self, uf, gf):
        self.fake_floating_ip_new.update({'port_id': 'port_id',
                                          'fixed_port_id': 'port_id'})
        gf.return_value = self.fake_floating_ip
        uf.return_value = self.fake_floating_ip_new
        self.l3_inst.update_floatingip(self.context, 'id', 'floatingip')

        self.l3_inst._ovn.delete_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-router-id',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10')
        self.l3_inst._ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'neutron-new-router-id',
            type='dnat_and_snat',
            logical_ip='10.10.10.10',
            external_ip='192.168.0.10')

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_floatingips')
    def test_disassociate_floatingips(self, gfs):
        gfs.return_value = [{'id': 'fip-id1',
                             'floating_ip_address': '192.168.0.10',
                             'router_id': 'router-id',
                             'port_id': 'port_id',
                             'floating_port_id': 'fip-port-id1',
                             'fixed_ip_address': '10.0.0.10'},
                            {'id': 'fip-id2',
                             'floating_ip_address': '192.167.0.10',
                             'router_id': 'router-id',
                             'port_id': 'port_id',
                             'floating_port_id': 'fip-port-id2',
                             'fixed_ip_address': '10.0.0.11'}]
        self.l3_inst.disassociate_floatingips(self.context, 'port_id',
                                              do_notify=False)

        delete_nat_calls = [mock.call('neutron-router-id',
                                      type='dnat_and_snat',
                                      logical_ip=fip['fixed_ip_address'],
                                      external_ip=fip['floating_ip_address'])
                            for fip in gfs.return_value]
        self.assertEqual(
            len(delete_nat_calls),
            self.l3_inst._ovn.delete_nat_rule_in_lrouter.call_count)
        self.l3_inst._ovn.delete_nat_rule_in_lrouter.assert_has_calls(
            delete_nat_calls, any_order=True)


class OVNL3ExtrarouteTests(test_l3_gw.ExtGwModeIntTestCase,
                           test_l3.L3NatDBIntTestCase,
                           test_extraroute.ExtraRouteDBTestCaseBase):

    # TODO(lucasagomes): Ideally, this method should be moved to a base
    # class which all tests classes in networking-ovn inherits from but,
    # this base class doesn't seem to exist for now so we need to duplicate
    # it here
    def _start_mock(self, path, return_value, new_callable=None):
        patcher = mock.patch(path, return_value=return_value,
                             new_callable=new_callable)
        patcher.start()
        self.addCleanup(patcher.stop)

    def setUp(self):
        plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        l3_plugin = ('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin')
        service_plugins = {'l3_plugin_name': l3_plugin}
        # For these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        cfg.CONF.set_default('max_routes', 3)
        ext_mgr = test_extraroute.ExtraRouteTestExtensionManager()
        super(test_l3.L3BaseForIntTests, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr,
            service_plugins=service_plugins)
        l3_gw_mgr = test_l3_gw.TestExtensionManager()
        test_extensions.setup_extensions_middleware(l3_gw_mgr)
        self.l3_inst = directory.get_plugin(plugin_constants.L3)
        self._start_mock(
            'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._ovn',
            new_callable=mock.PropertyMock,
            return_value=fakes.FakeOvsdbNbOvnIdl())
        self._start_mock(
            'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._sb_ovn',
            new_callable=mock.PropertyMock,
            return_value=fakes.FakeOvsdbSbOvnIdl())
        self._start_mock(
            'networking_ovn.l3.l3_ovn_scheduler.'
            'OVNGatewayScheduler._schedule_gateway',
            return_value='hv1')
        self._start_mock(
            'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin.'
            '_get_v4_network_of_all_router_ports',
            return_value=[])
        self.setup_notification_driver()

    # Note(dongj): According to bug #1657693, status of an unassociated
    # floating IP is set to DOWN. Revise expected_status to DOWN for related
    # test cases.
    def test_floatingip_update(
            self, expected_status=constants.FLOATINGIP_STATUS_DOWN):
        super(OVNL3ExtrarouteTests, self).test_floatingip_update(
            expected_status)

    def test_floatingip_update_to_same_port_id_twice(
            self, expected_status=constants.FLOATINGIP_STATUS_DOWN):
        super(OVNL3ExtrarouteTests, self).\
            test_floatingip_update_to_same_port_id_twice(expected_status)

    def test_floatingip_update_subnet_gateway_disabled(
            self, expected_status=constants.FLOATINGIP_STATUS_DOWN):
        super(OVNL3ExtrarouteTests, self).\
            test_floatingip_update_subnet_gateway_disabled(expected_status)

    def test_update_subnet_gateway_for_external_net(self):
        super(OVNL3ExtrarouteTests, self). \
            test_update_subnet_gateway_for_external_net()
        self.l3_inst._ovn.add_static_route.assert_called_once_with(
            'neutron-fake_device', ip_prefix='0.0.0.0/0', nexthop='120.0.0.2')
        self.l3_inst._ovn.delete_static_route.assert_called_once_with(
            'neutron-fake_device', ip_prefix='0.0.0.0/0', nexthop='120.0.0.1')

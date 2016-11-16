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

import mock

from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log

from neutron.tests.unit.extensions import test_extraroute
from neutron.tests.unit.extensions import test_l3

from networking_ovn.tests.unit import fakes
from networking_ovn.tests.unit.ml2 import test_mech_driver

LOG = log.getLogger(__name__)


class OVNL3RouterPlugin(test_mech_driver.OVNMechanismDriverTestCase):

    l3_plugin = 'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin'

    def setUp(self):
        super(OVNL3RouterPlugin, self).setUp()
        self.fake_router_port = {'device_id': '',
                                 'mac_address': 'aa:aa:aa:aa:aa:aa',
                                 'fixed_ips': [{'ip_address': '10.0.0.100',
                                                'subnet_id': 'subnet-id'}],
                                 'id': 'router-port-id'}
        self.fake_subnet = {'id': 'subnet-id',
                            'cidr': '10.0.0.1/24'}
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
            'id': 'router-id'}
        self.fake_l3_admin_network_ports = {
            'dtsp': {'name': 'DTSP',
                     'id': 'dtsp-id',
                     'mac_address': '00:00:00:01:02:03',
                     'ip': '169.254.128.1',
                     'addresses': '00:00:00:01:02:03 169.254.128.1'},
            'gtsp': {'name': 'GTSP',
                     'id': 'gtsp-id',
                     'mac_address': '00:00:00:01:02:04',
                     'ip': '169.254.128.2',
                     'addresses': '00:00:00:01:02:04 169.254.128.2'}
        }
        self.fake_external_fixed_ips = {
            'external_fixed_ips': [{'ip_address': '192.168.1.1',
                                    'subnet_id': 'subnet-id'}]}
        self.fake_router_with_ext_gw = {
            'id': 'router-id',
            'name': 'router',
            'admin_state_up': True,
            'external_gateway_info': self.fake_external_fixed_ips,
            'gw_port_id': 'gw-port-id'
        }
        self.fake_ext_subnet = {'subnet_id': 'ext-subnet-id',
                                'ip_version': 4,
                                'cidr': '192.168.1.0/24',
                                'gateway_ip': '192.168.1.254'}
        self.fake_floating_ip = {'id': 'fip-id',
                                 'tenant_id': '',
                                 'floating_ip_address': '192.168.0.10',
                                 'floating_network_id': 'fip-net-id',
                                 'router_id': 'router-id',
                                 'fixed_port_id': 'port_id',
                                 'floating_port_id': 'fip-port-id',
                                 'fixed_ip_address': '10.0.0.10',
                                 'status': 'Active'}
        self.fake_floating_ip_new = {'id': 'fip-id',
                                     'tenant_id': '',
                                     'floating_ip_address': '192.168.0.10',
                                     'floating_network_id': 'fip-net-id',
                                     'router_id': 'new-router-id',
                                     'fixed_port_id': 'new-port_id',
                                     'floating_port_id': 'fip-port-id',
                                     'fixed_ip_address': '10.10.10.10',
                                     'status': 'Active'}
        self.l3_plugin = directory.get_plugin(constants.L3)
        mock.patch(
            'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._ovn',
            new_callable=mock.PropertyMock,
            return_value=fakes.FakeOvsdbNbOvnIdl()
        ).start()
        mock.patch(
            'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._sb_ovn',
            new_callable=mock.PropertyMock,
            return_value=fakes.FakeOvsdbSbOvnIdl()
        ).start()
        mock.patch(
            'neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port',
            return_value=self.fake_router_port
        ).start()
        mock.patch(
            'neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet',
            return_value=self.fake_subnet
        ).start()
        mock.patch(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router',
            return_value=self.fake_router
        ).start()
        mock.patch(
            'neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.update_router',
            return_value=self.fake_router
        ).start()
        mock.patch(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin.remove_router_interface',
            return_value=self.fake_router_interface_info
        ).start()
        mock.patch(
            'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin.'
            '_get_transit_network_ports',
            return_value=self.fake_l3_admin_network_ports
        ).start()
        mock.patch(
            'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin.'
            '_check_and_delete_l3_admin_net',
            return_value=None
        ).start()
        mock.patch(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin.create_router',
            return_value=self.fake_router_with_ext_gw
        ).start()
        mock.patch(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin.delete_router',
            return_value={}
        ).start()
        mock.patch(
            'networking_ovn.l3.l3_ovn_scheduler.'
            'OVNGatewayLeastLoadedScheduler._schedule_gateway',
            return_value='hv1'
        ).start()
        mock.patch(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin.create_floatingip',
            return_value=self.fake_floating_ip
        ).start()
        mock.patch(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin._get_floatingip',
            return_value=self.fake_floating_ip
        ).start()

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.add_router_interface')
    def test_add_router_interface(self, func):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        func.return_value = {'port_id': 'router-port-id',
                             'device_id': '',
                             'mac_address': 'aa:aa:aa:aa:aa:aa',
                             'subnet_id': 'subnet-id',
                             'subnet_ids': ['subnet-id'],
                             'fixed_ips': [{'ip_address': '10.0.0.100',
                                            'subnet_id': 'subnet-id'}],
                             'id': 'router-id'}
        self.l3_plugin.add_router_interface(self.context, router_id,
                                            interface_info)
        self.l3_plugin._ovn.add_lrouter_port.assert_called_once_with(
            lrouter='neutron-router-id',
            mac='aa:aa:aa:aa:aa:aa',
            name='lrp-router-port-id',
            networks=['10.0.0.100/24'])
        self.l3_plugin._ovn.set_lrouter_port_in_lswitch_port.\
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
        self.l3_plugin.add_router_interface(self.context, router_id,
                                            interface_info)
        called_args_dict = (
            self.l3_plugin._ovn.update_lrouter_port.call_args_list[0][1])
        self.assertEqual(1, self.l3_plugin._ovn.update_lrouter_port.call_count)
        self.assertItemsEqual(fake_rtr_intf_networks,
                              called_args_dict.get('networks', []))
        self.l3_plugin._ovn.set_lrouter_port_in_lswitch_port.\
            assert_called_once_with('router-port-id', 'lrp-router-port-id')

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    def test_remove_router_interface(self, getp):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        getp.side_effect = n_exc.PortNotFound(port_id='router-port-id')

        self.l3_plugin.remove_router_interface(
            self.context, router_id, interface_info)

        self.l3_plugin._ovn.delete_lrouter_port.assert_called_once_with(
            'lrp-router-port-id', 'neutron-router-id', if_exists=False)

    def test_remove_router_interface_update_lrouter_port(self):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        self.l3_plugin.remove_router_interface(
            self.context, router_id, interface_info)

        self.l3_plugin._ovn.update_lrouter_port.assert_called_once_with(
            if_exists=False, lrouter='neutron-router-id',
            name='lrp-router-port-id', networks=['10.0.0.100/24'])

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.update_router')
    def test_update_router_admin_state_no_change(self, func):
        router_id = 'router-id'
        update_data = {'router': {'admin_state_up': False}}
        self.l3_plugin.update_router(self.context, router_id, update_data)
        self.assertFalse(self.l3_plugin._ovn.update_lrouter.called)

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.update_router')
    def test_update_router_admin_state_change(self, func):
        router_id = 'router-id'
        update_data = {'router': {'admin_state_up': True}}
        self.l3_plugin.update_router(self.context, router_id, update_data)
        self.l3_plugin._ovn.update_lrouter.assert_called_once_with(
            'neutron-router-id', enabled=True)

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.update_router')
    def test_update_router_name_no_change(self, func):
        router_id = 'router-id'
        update_data = {'router': {'name': 'router'}}
        self.l3_plugin.update_router(self.context, router_id, update_data)
        self.assertFalse(self.l3_plugin._ovn.update_lrouter.called)

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.update_router')
    def test_update_router_name_change(self, func):
        router_id = 'router-id'
        update_data = {'router': {'name': 'test'}}
        self.l3_plugin.update_router(self.context, router_id, update_data)
        self.l3_plugin._ovn.update_lrouter.assert_called_once_with(
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
        self.l3_plugin.update_router(self.context, router_id, update_data)
        self.assertFalse(self.l3_plugin._ovn.add_static_route.called)
        self.assertFalse(self.l3_plugin._ovn.delete_static_route.called)

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
        self.l3_plugin.update_router(self.context, router_id, update_data)
        self.l3_plugin._ovn.add_static_route.assert_called_once_with(
            'neutron-router-id',
            ip_prefix='2.2.2.0/24', nexthop='10.0.0.3')
        self.l3_plugin._ovn.delete_static_route.assert_called_once_with(
            'neutron-router-id',
            ip_prefix='1.1.1.0/24', nexthop='10.0.0.2')

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    def test_create_router_with_ext_gw(self, get_rps, get_subnet, get_port):
        router = {'router': {'name': 'router'}}
        get_subnet.return_value = self.fake_ext_subnet
        get_port.return_value = {
            'fixed_ips': [{'ip_address': '192.168.1.1',
                           'subnet_id': 'ext-subnet-id'}],
            'mac_address': '00:00:00:02:04:06',
            'id': 'gw-port-id'}
        get_rps.return_value = []

        external_ids = {'neutron:router_name': 'router'}
        expected_calls = [mock.call('neutron-router-id',
                                    external_ids=external_ids,
                                    enabled=True,
                                    options={}),
                          mock.call('ogr-router-id',
                                    external_ids=external_ids,
                                    enabled=True,
                                    options={'chassis': 'hv1'})]
        self.l3_plugin.create_router(self.context, router)
        self.l3_plugin._ovn.create_lrouter.assert_has_calls(expected_calls)
        self.l3_plugin._ovn.create_lswitch.assert_has_calls(
            [mock.call(lswitch_name='otls-router-id')])
        expected_calls = \
            [mock.call(addresses='00:00:00:01:02:03 169.254.128.1',
                       enabled='True', lport_name='dtsp-router-id',
                       lswitch_name='otls-router-id'),
             mock.call(addresses='00:00:00:01:02:04 169.254.128.2',
                       enabled='True', lport_name='gtsp-router-id',
                       lswitch_name='otls-router-id')]
        self.l3_plugin._ovn.create_lswitch_port.assert_has_calls(
            expected_calls)
        expected_calls = [mock.call(lrouter='ogr-router-id',
                                    mac='00:00:00:02:04:06',
                                    name='lrp-gw-port-id',
                                    networks=['192.168.1.1/24']),
                          mock.call(lrouter='neutron-router-id',
                                    mac='00:00:00:01:02:03',
                                    name='lrp-dtsp-router-id',
                                    networks='169.254.128.1/30'),
                          mock.call(lrouter='ogr-router-id',
                                    mac='00:00:00:01:02:04',
                                    name='lrp-gtsp-router-id',
                                    networks='169.254.128.2/30')]
        self.l3_plugin._ovn.add_lrouter_port.assert_has_calls(expected_calls)
        expected_calls = [mock.call('ogr-router-id',
                                    ip_prefix='0.0.0.0/0',
                                    nexthop='192.168.1.254'),
                          mock.call('neutron-router-id',
                                    ip_prefix='0.0.0.0/0',
                                    nexthop='169.254.128.2')]
        self.l3_plugin._ovn.add_static_route.assert_has_calls(expected_calls)

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    def test_delete_router_with_ext_gw(self, gs, gr):
        gr.return_value = self.fake_router_with_ext_gw
        gs.return_value = self.fake_ext_subnet
        self.l3_plugin.delete_router(self.context, 'router-id')
        expected_calls = [mock.call('ogr-router-id'),
                          mock.call('neutron-router-id')]
        self.l3_plugin._ovn.delete_lrouter.assert_has_calls(expected_calls)
        self.assertEqual(2, self.l3_plugin._ovn.delete_lrouter.call_count)
        self.l3_plugin._ovn.delete_lswitch.assert_has_calls(
            [mock.call('otls-router-id')])
        expected_calls = [mock.call('gtsp-router-id',
                                    'otls-router-id'),
                          mock.call('dtsp-router-id',
                                    'otls-router-id')]
        self.l3_plugin._ovn.delete_lswitch_port.assert_has_calls(
            expected_calls)
        self.assertEqual(2, self.l3_plugin._ovn.delete_lswitch_port.call_count)
        expected_calls = [mock.call('lrp-gw-port-id',
                                    'ogr-router-id'),
                          mock.call('lrp-gtsp-router-id',
                                    'ogr-router-id'),
                          mock.call('lrp-dtsp-router-id',
                                    'neutron-router-id')]
        self.l3_plugin._ovn.delete_lrouter_port.assert_has_calls(
            expected_calls, any_order=True)
        self.assertEqual(3, self.l3_plugin._ovn.delete_lrouter_port.call_count)
        expected_calls = [mock.call('neutron-router-id',
                                    ip_prefix='0.0.0.0/0',
                                    nexthop='169.254.128.2'),
                          mock.call('ogr-router-id',
                                    ip_prefix='0.0.0.0/0',
                                    nexthop='192.168.1.254')]
        self.l3_plugin._ovn.delete_static_route.assert_has_calls(
            expected_calls)
        self.assertEqual(2, self.l3_plugin._ovn.delete_static_route.call_count)

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.add_router_interface')
    def test_add_router_interface_with_gateway_set(self, ari, gr, grps, gs,
                                                   gp):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        ari.return_value = {'port_id': 'router-port-id',
                            'device_id': '',
                            'mac_address': '00:00:00:01:02:03',
                            'subnet_id': 'subnet-id',
                            'subnet_ids': ['subnet-id'],
                            'fixed_ips': [{'ip_address': '10.0.0.1',
                                           'subnet_id': 'subnet-id'}],
                            'id': 'router-id'}
        gr.return_value = self.fake_router_with_ext_gw
        gs.return_value = {'subnet_id': 'subnet-id',
                           'ip_version': 4,
                           'cidr': '10.0.0.0/24'}

        gp.return_value = {
            'fixed_ips': [{'ip_address': '10.0.0.1',
                           'subnet_id': 'subnet-id'}],
            'mac_address': '00:00:00:01:02:03',
            'id': 'router-port-id'}
        self.l3_plugin.add_router_interface(self.context, router_id,
                                            interface_info)
        expected_calls = [mock.call(lrouter='neutron-router-id',
                                    mac='00:00:00:01:02:03',
                                    name='lrp-router-port-id',
                                    networks=['10.0.0.1/24'])]
        self.l3_plugin._ovn.add_lrouter_port.assert_has_calls(expected_calls)
        expected_calls = [mock.call('ogr-router-id',
                                    ip_prefix='10.0.0.0/24',
                                    nexthop='169.254.128.1')]
        self.l3_plugin._ovn.add_static_route.assert_has_calls(expected_calls)
        self.l3_plugin._ovn.add_nat_rule_in_lrouter.called_once_with(
            'ogr-router-id', logical_ip='10.0.0.0/24',
            external_ip='192.168.1.1', type='snat')
        self.l3_plugin._ovn.add_nat_ip_to_lrport_peer_options.\
            assert_called_once_with('gw-port-id', nat_ip='192.168.1.1')

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    def test_remove_router_interface_with_gateway_set(self, gr, gs, gp):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id',
                          'subnet_id': 'subnet-id'}
        gr.return_value = self.fake_router_with_ext_gw
        gs.return_value = {'subnet_id': 'subnet-id',
                           'ip_version': 4,
                           'cidr': '10.0.0.0/24'}
        gp.side_effect = n_exc.PortNotFound(port_id='router-port-id')
        self.l3_plugin.remove_router_interface(
            self.context, router_id, interface_info)

        expected_calls = [mock.call('lrp-router-port-id', 'neutron-router-id',
                                    if_exists=False)]
        self.l3_plugin._ovn.delete_lrouter_port.assert_has_calls(
            expected_calls)
        expected_calls = [mock.call('ogr-router-id',
                                    ip_prefix='10.0.0.0/24',
                                    nexthop='169.254.128.1')]
        self.l3_plugin._ovn.delete_static_route.assert_has_calls(
            expected_calls)
        self.l3_plugin._ovn.delete_nat_rule_in_lrouter.called_once_with(
            'ogr-router-id', logical_ip='10.0.0.0/24',
            external_ip='192.168.1.1', type='snat')
        self.l3_plugin._ovn.delete_nat_ip_from_lrport_peer_options.\
            assert_called_once_with('gw-port-id', nat_ip='192.168.1.1')

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin._get_router')
    def test_update_router_with_ext_gw(self, gr, ur, gs, grps, gp):
        router = {'router': {'name': 'router'}}
        ur.return_value = self.fake_router_with_ext_gw
        gs.return_value = self.fake_ext_subnet
        gr.return_value = {'id': 'router-id',
                           'name': 'router',
                           'admin_state_up': True}
        gp.return_value = {
            'fixed_ips': [{'ip_address': '192.168.1.1',
                           'subnet_id': 'ext-subnet-id'}],
            'mac_address': '00:00:00:02:04:06',
            'id': 'gw-port-id'}
        grps.return_value = [{'device_id': '',
                              'device_owner': 'network:router_interface',
                              'mac_address': 'aa:aa:aa:aa:aa:aa',
                              'fixed_ips': [{'ip_address': '10.0.0.100',
                                             'subnet_id': 'subnet-id'}],
                              'id': 'router-port-id'}]
        self.l3_plugin.update_router(self.context, 'router-id', router)
        external_ids = {'neutron:router_name': 'router'}
        expected_calls = [mock.call('ogr-router-id',
                                    external_ids=external_ids,
                                    enabled=True,
                                    options={'chassis': 'hv1'})]
        self.l3_plugin._ovn.create_lrouter.assert_has_calls(expected_calls)
        self.assertEqual(1, self.l3_plugin._ovn.create_lrouter.call_count)

        self.l3_plugin._ovn.create_lswitch.assert_called_once_with(
            lswitch_name='otls-router-id')
        expected_calls = \
            [mock.call(addresses='00:00:00:01:02:03 169.254.128.1',
                       enabled='True', lport_name='dtsp-router-id',
                       lswitch_name='otls-router-id'),
             mock.call(addresses='00:00:00:01:02:04 169.254.128.2',
                       enabled='True', lport_name='gtsp-router-id',
                       lswitch_name='otls-router-id')]
        self.l3_plugin._ovn.create_lswitch_port.assert_has_calls(
            expected_calls)
        self.assertEqual(2, self.l3_plugin._ovn.create_lswitch_port.call_count)
        expected_calls = [mock.call(lrouter='ogr-router-id',
                                    mac='00:00:00:02:04:06',
                                    name='lrp-gw-port-id',
                                    networks=['192.168.1.1/24']),
                          mock.call(lrouter='neutron-router-id',
                                    mac='00:00:00:01:02:03',
                                    name='lrp-dtsp-router-id',
                                    networks='169.254.128.1/30'),
                          mock.call(lrouter='ogr-router-id',
                                    mac='00:00:00:01:02:04',
                                    name='lrp-gtsp-router-id',
                                    networks='169.254.128.2/30')]
        self.l3_plugin._ovn.add_lrouter_port.assert_has_calls(expected_calls)
        self.assertEqual(3, self.l3_plugin._ovn.add_lrouter_port.call_count)
        expected_calls = [mock.call('ogr-router-id',
                                    ip_prefix='0.0.0.0/0',
                                    nexthop='192.168.1.254'),
                          mock.call('neutron-router-id',
                                    ip_prefix='0.0.0.0/0',
                                    nexthop='169.254.128.2'),
                          mock.call('ogr-router-id',
                                    ip_prefix='192.168.1.0/24',
                                    nexthop='169.254.128.1')]
        self.l3_plugin._ovn.add_static_route.assert_has_calls(expected_calls)
        self.assertEqual(3, self.l3_plugin._ovn.add_static_route.call_count)
        self.l3_plugin._ovn.add_nat_ip_to_lrport_peer_options.\
            assert_called_once_with('gw-port-id', nat_ip='192.168.1.1')

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin._get_router')
    def test_disable_snat(self, gr, ur, gs, grps, gp):
        router = {'router': {'name': 'router'}}
        ur.return_value = self.fake_router_with_ext_gw
        ur.return_value['external_gateway_info']['enable_snat'] = 'False'
        gs.return_value = self.fake_ext_subnet
        gr.return_value = {'id': 'router-id',
                           'name': 'router',
                           'admin_state_up': True}
        gp.return_value = {
            'fixed_ips': [{'ip_address': '192.168.1.1',
                           'subnet_id': 'ext-subnet-id'}],
            'mac_address': '00:00:00:02:04:06',
            'id': 'gw-port-id'}
        grps.return_value = [{'device_id': '',
                              'device_owner': 'network:router_interface',
                              'mac_address': 'aa:aa:aa:aa:aa:aa',
                              'fixed_ips': [{'ip_address': '10.0.0.100',
                                             'subnet_id': 'subnet-id'}],
                              'id': 'router-port-id'}]
        self.l3_plugin.update_router(self.context, 'router-id', router)
        external_ids = {'neutron:router_name': 'router'}
        expected_calls = [mock.call('ogr-router-id',
                                    external_ids=external_ids,
                                    enabled=True,
                                    options={'chassis': 'hv1'})]
        self.l3_plugin._ovn.create_lrouter.assert_has_calls(expected_calls)
        self.assertEqual(1, self.l3_plugin._ovn.create_lrouter.call_count)

        self.l3_plugin._ovn.create_lswitch.assert_called_once_with(
            lswitch_name='otls-router-id')
        expected_calls = \
            [mock.call(addresses='00:00:00:01:02:03 169.254.128.1',
                       enabled='True', lport_name='dtsp-router-id',
                       lswitch_name='otls-router-id'),
             mock.call(addresses='00:00:00:01:02:04 169.254.128.2',
                       enabled='True', lport_name='gtsp-router-id',
                       lswitch_name='otls-router-id')]
        self.l3_plugin._ovn.create_lswitch_port.assert_has_calls(
            expected_calls)
        self.assertEqual(2, self.l3_plugin._ovn.create_lswitch_port.call_count)
        expected_calls = [mock.call(lrouter='ogr-router-id',
                                    mac='00:00:00:02:04:06',
                                    name='lrp-gw-port-id',
                                    networks=['192.168.1.1/24']),
                          mock.call(lrouter='neutron-router-id',
                                    mac='00:00:00:01:02:03',
                                    name='lrp-dtsp-router-id',
                                    networks='169.254.128.1/30'),
                          mock.call(lrouter='ogr-router-id',
                                    mac='00:00:00:01:02:04',
                                    name='lrp-gtsp-router-id',
                                    networks='169.254.128.2/30')]
        self.l3_plugin._ovn.add_lrouter_port.assert_has_calls(expected_calls)
        self.assertEqual(3, self.l3_plugin._ovn.add_lrouter_port.call_count)
        expected_calls = [mock.call('ogr-router-id',
                                    ip_prefix='0.0.0.0/0',
                                    nexthop='192.168.1.254'),
                          mock.call('neutron-router-id',
                                    ip_prefix='0.0.0.0/0',
                                    nexthop='169.254.128.2'),
                          mock.call('ogr-router-id',
                                    ip_prefix='192.168.1.0/24',
                                    nexthop='169.254.128.1')]
        self.l3_plugin._ovn.add_static_route.assert_has_calls(expected_calls)
        self.assertEqual(3, self.l3_plugin._ovn.add_static_route.call_count)
        self.assertEqual(
            0,
            self.l3_plugin._ovn.add_nat_ip_to_lrport_peer_options.call_count)

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    @mock.patch('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._get_router_ports')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.add_router_interface')
    def test_add_router_interface_with_gateway_set_and_snat_disabled(
            self, ari, gr, grp, gs, gp):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        ari.return_value = {'port_id': 'router-port-id',
                            'device_id': '',
                            'mac_address': '00:00:00:01:02:03',
                            'subnet_id': 'subnet-id',
                            'subnet_ids': ['subnet-id'],
                            'fixed_ips': [{'ip_address': '10.0.0.1',
                                           'subnet_id': 'subnet-id'}],
                            'id': 'router-id'}
        gr.return_value = self.fake_router_with_ext_gw
        gr.return_value['external_gateway_info']['enable_snat'] = 'False'
        gs.return_value = {'subnet_id': 'subnet-id',
                           'ip_version': 4,
                           'cidr': '10.0.0.0/24'}
        gp.return_value = {
            'fixed_ips': [{'ip_address': '10.0.0.1',
                           'subnet_id': 'subnet-id'}],
            'mac_address': '00:00:00:01:02:03',
            'id': 'router-port-id'}
        self.l3_plugin.add_router_interface(self.context, router_id,
                                            interface_info)
        expected_calls = [mock.call(lrouter='neutron-router-id',
                                    mac='00:00:00:01:02:03',
                                    name='lrp-router-port-id',
                                    networks=['10.0.0.1/24'])]
        self.l3_plugin._ovn.add_lrouter_port.assert_has_calls(expected_calls)
        self.assertEqual(1, self.l3_plugin._ovn.add_lrouter_port.call_count)
        expected_calls = [mock.call('ogr-router-id',
                                    ip_prefix='10.0.0.0/24',
                                    nexthop='169.254.128.1')]
        self.l3_plugin._ovn.add_static_route.assert_has_calls(expected_calls)
        self.assertEqual(1, self.l3_plugin._ovn.add_static_route.call_count)
        self.assertEqual(
            0, self.l3_plugin._ovn.add_nat_rule_in_lrouter.call_count)
        self.assertEqual(
            0,
            self.l3_plugin._ovn.add_nat_ip_to_lrport_peer_options.call_count)

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin._get_floatingip')
    def test_create_floatingip(self, gf, gr):
        gf.return_value = {'floating_port_id': 'fip-port-id'}
        gr.return_value = {'gw_port_id': 'gw-port-id'}
        self.l3_plugin.create_floatingip(self.context, 'floatingip')
        self.l3_plugin._ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'ogr-router-id',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10')
        self.l3_plugin._ovn.add_nat_ip_to_lrport_peer_options.\
            assert_called_once_with('gw-port-id', nat_ip='192.168.0.10')
        self.l3_plugin._ovn.delete_lswitch_port.assert_called_once_with(
            'fip-port-id', 'neutron-fip-net-id')

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin._get_floatingip')
    def test_create_floatingip_external_ip_present_in_nat_rule(self, gf, gr):
        gf.return_value = {'floating_port_id': 'fip-port-id'}
        gr.return_value = {'gw_port_id': 'gw-port-id'}
        self.l3_plugin._ovn.get_lrouter_nat_rules.return_value = [
            {'external_ip': '192.168.0.10', 'logical_ip': '10.0.0.6',
             'type': 'dnat_and_snat', 'uuid': 'uuid1'}]
        self.l3_plugin.create_floatingip(self.context, 'floatingip')
        self.l3_plugin._ovn.add_nat_rule_in_lrouter.assert_not_called()
        self.l3_plugin._ovn.set_nat_rule_in_lrouter.assert_called_once_with(
            'ogr-router-id', 'uuid1',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10')
        self.l3_plugin._ovn.add_nat_ip_to_lrport_peer_options.\
            assert_called_once_with('gw-port-id', nat_ip='192.168.0.10')
        self.l3_plugin._ovn.delete_lswitch_port.assert_called_once_with(
            'fip-port-id', 'neutron-fip-net-id')

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin._get_floatingip')
    def test_create_floatingip_external_ip_present_type_snat(self, gf, gr):
        gf.return_value = {'floating_port_id': 'fip-port-id'}
        gr.return_value = {'gw_port_id': 'gw-port-id'}
        self.l3_plugin._ovn.get_lrouter_nat_rules.return_value = [
            {'external_ip': '192.168.0.10', 'logical_ip': '10.0.0.0/24',
             'type': 'snat', 'uuid': 'uuid1'}]
        self.l3_plugin.create_floatingip(self.context, 'floatingip')
        self.l3_plugin._ovn.set_nat_rule_in_lrouter.assert_not_called()
        self.l3_plugin._ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'ogr-router-id',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10')
        self.l3_plugin._ovn.add_nat_ip_to_lrport_peer_options.\
            assert_called_once_with('gw-port-id', nat_ip='192.168.0.10')
        self.l3_plugin._ovn.delete_lswitch_port.assert_called_once_with(
            'fip-port-id', 'neutron-fip-net-id')

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.delete_floatingip')
    def test_delete_floatingip(self, df, gr):
        gr.return_value = {'gw_port_id': 'gw-port-id'}
        self.l3_plugin.delete_floatingip(self.context, 'floatingip-id')
        self.l3_plugin._ovn.delete_nat_rule_in_lrouter.assert_called_once_with(
            'ogr-router-id',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10')
        self.l3_plugin._ovn.delete_nat_ip_from_lrport_peer_options. \
            assert_called_once_with('gw-port-id', nat_ip='192.168.0.10')

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_router')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin._get_floatingip')
    @mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                'update_floatingip')
    def test_update_floatingip(self, uf, gf, gr):
        gf.return_value = self.fake_floating_ip
        uf.return_value = self.fake_floating_ip_new
        gr.return_value = {'gw_port_id': 'gw-port-id'}
        self.l3_plugin.update_floatingip(self.context, 'id', 'floatingip')
        self.l3_plugin._ovn.delete_nat_rule_in_lrouter.assert_called_once_with(
            'ogr-router-id',
            type='dnat_and_snat',
            logical_ip='10.0.0.10',
            external_ip='192.168.0.10')
        self.l3_plugin._ovn.delete_nat_ip_from_lrport_peer_options. \
            assert_called_once_with('gw-port-id', nat_ip='192.168.0.10')
        self.l3_plugin._ovn.add_nat_rule_in_lrouter.assert_called_once_with(
            'ogr-new-router-id',
            type='dnat_and_snat',
            logical_ip='10.10.10.10',
            external_ip='192.168.0.10')
        self.l3_plugin._ovn.add_nat_ip_to_lrport_peer_options. \
            assert_called_once_with('gw-port-id', nat_ip='192.168.0.10')


class OVNL3ExtrarouteTests(test_l3.L3NatDBIntTestCase,
                           test_extraroute.ExtraRouteDBTestCaseBase):

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
        mock.patch(
            'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._ovn',
            new_callable=mock.PropertyMock,
            return_value=fakes.FakeOvsdbNbOvnIdl()
        ).start()
        mock.patch(
            'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._sb_ovn',
            new_callable=mock.PropertyMock,
            return_value=fakes.FakeOvsdbNbOvnIdl()
        ).start()
        mock.patch(
            'networking_ovn.l3.l3_ovn_scheduler.'
            'OVNGatewayScheduler._schedule_gateway',
            return_value='hv1'
        ).start()
        mock.patch(
            'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin.'
            '_get_transit_network_ports',
            return_value={
                'dtsp': {'name': 'DTSP',
                         'id': 'dtsp-id',
                         'mac_address': '00:00:00:01:02:03',
                         'ip': '169.254.128.1',
                         'addresses': '00:00:00:01:02:03 169.254.128.1'},
                'gtsp': {'name': 'GTSP',
                         'id': 'gtsp-id',
                         'mac_address': '00:00:00:01:02:04',
                         'ip': '169.254.128.2',
                         'addresses': '00:00:00:01:02:04 169.254.128.2'}}
        ).start()
        mock.patch(
            'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin.'
            '_check_and_delete_l3_admin_net',
            return_value=None
        ).start()
        self.setup_notification_driver()

    # TODO(rtheis): Skip the following test cases since they are for
    # L3 service plugins that support L3 agent RPC. These tests should
    # be refactored in neutron.

    def test__notify_subnetpool_address_scope_update(self):
        pass

    def test_router_add_interface_subnet(self):
        pass

    def test_router_add_interface_ipv6_subnet(self):
        pass

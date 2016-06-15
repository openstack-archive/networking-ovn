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

from oslo_config import cfg

from neutron import manager
from neutron.plugins.common import constants as service_constants
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.extensions import test_extraroute
from neutron.tests.unit.extensions import test_l3

from networking_ovn.ovsdb import impl_idl_ovn
from networking_ovn.tests.unit import fakes
from networking_ovn.tests.unit.ml2 import test_mech_driver


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
                                        'nexthop': '2.2.2.3'}]}
        mgr = manager.NeutronManager.get_instance()
        self.l3_plugin = mgr.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        mock.patch(
            'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._ovn',
            new_callable=mock.PropertyMock,
            return_value=fakes.FakeOvsdbNbOvnIdl()
        ).start()
        mock.patch(
            'neutron.db.l3_db.L3_NAT_db_mixin.notify_router_interface_action'
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

    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.add_router_interface')
    def test_add_router_interface(self, func):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        self.l3_plugin.add_router_interface(self.context, router_id,
                                            interface_info)
        self.l3_plugin._ovn.add_lrouter_port.assert_called_once_with(
            lrouter='neutron-router-id',
            mac='aa:aa:aa:aa:aa:aa',
            name='lrp-router-port-id',
            network='10.0.0.100/24')
        self.l3_plugin._ovn.set_lrouter_port_in_lswitch_port.\
            assert_called_once_with('router-port-id', 'lrp-router-port-id')

    def test_remove_router_interface(self):
        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        with mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.'
                        'remove_router_interface',
                        return_value=interface_info):
            self.l3_plugin.remove_router_interface(
                self.context, router_id, interface_info)

        self.l3_plugin._ovn.delete_lrouter_port.assert_called_once_with(
            'lrp-router-port-id', 'neutron-router-id', if_exists=False)

    @mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.update_router')
    def test_update_router_admin_state_no_change(self, func):
        router_id = 'router-id'
        update_data = {'router': {'admin_state_up': False}}
        self.l3_plugin.update_router(self.context, router_id, update_data)
        self.assertFalse(self.l3_plugin._ovn.update_lrouter.called)

    @mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.update_router')
    def test_update_router_admin_state_change(self, func):
        router_id = 'router-id'
        update_data = {'router': {'admin_state_up': True}}
        self.l3_plugin.update_router(self.context, router_id, update_data)
        self.l3_plugin._ovn.update_lrouter.assert_called_once_with(
            'neutron-router-id', enabled=True)

    @mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.update_router')
    def test_update_router_name_no_change(self, func):
        router_id = 'router-id'
        update_data = {'router': {'name': 'router'}}
        self.l3_plugin.update_router(self.context, router_id, update_data)
        self.assertFalse(self.l3_plugin._ovn.update_lrouter.called)

    @mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.update_router')
    def test_update_router_name_change(self, func):
        router_id = 'router-id'
        update_data = {'router': {'name': 'test'}}
        self.l3_plugin.update_router(self.context, router_id, update_data)
        self.l3_plugin._ovn.update_lrouter.assert_called_once_with(
            'neutron-router-id',
            external_ids={'neutron:router_name': 'test'})

    @mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.update_router')
    def test_update_router_static_route_no_change(self, func):
        router_id = 'router-id'
        update_data = {'router': {'routes': [{'destination': '1.1.1.0/24',
                                              'nexthop': '2.2.2.3'}]}}
        self.l3_plugin.update_router(self.context, router_id, update_data)
        self.assertFalse(self.l3_plugin._ovn.add_static_route.called)
        self.assertFalse(self.l3_plugin._ovn.delete_static_route.called)

    @mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.update_router')
    def test_update_router_static_route_change(self, func):
        router_id = 'router-id'
        update_data = {'router': {'routes': [{'destination': '2.2.2.0/24',
                                              'nexthop': '3.3.3.3'}]}}
        self.l3_plugin.update_router(self.context, router_id, update_data)
        self.l3_plugin._ovn.add_static_route.assert_called_once_with(
            'neutron-router-id',
            ip_prefix='2.2.2.0/24', nexthop='3.3.3.3')
        self.l3_plugin._ovn.delete_static_route.assert_called_once_with(
            'neutron-router-id',
            ip_prefix='1.1.1.0/24', nexthop='2.2.2.3')


class OVNL3BaseForTests(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self):
        plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        l3_plugin = ('networking_ovn.l3.l3_ovn.OVNL3RouterPlugin')
        service_plugins = {'l3_plugin_name': l3_plugin}
        # For these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        ext_mgr = test_l3.L3TestExtensionManager()
        impl_idl_ovn.OvsdbNbOvnIdl = mock.Mock()
        super(OVNL3BaseForTests, self).setUp(plugin=plugin,
                                             ext_mgr=ext_mgr,
                                             service_plugins=service_plugins)
        mgr = manager.NeutronManager.get_instance()
        self.plugin = mgr.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        patcher = mock.patch(
            'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._ovn',
            new_callable=mock.PropertyMock,
            return_value=fakes.FakeOvsdbNbOvnIdl())
        patcher.start()
        self.setup_notification_driver()


class OVNL3TestCase(OVNL3BaseForTests,
                    test_l3.L3NatTestCaseBase,
                    test_l3.L3NatDBTestCaseMixin):

    # NOTE(rtheis): Skip test since the test L3 plugin doesn't
    # implement the update_port() method.
    def test_router_add_interface_port(self):
        pass


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
        impl_idl_ovn.OvsdbNbOvnIdl = mock.Mock()
        super(test_l3.L3BaseForIntTests, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr,
            service_plugins=service_plugins)
        patcher = mock.patch(
            'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin._ovn',
            new_callable=mock.PropertyMock,
            return_value=fakes.FakeOvsdbNbOvnIdl())
        patcher.start()
        self.setup_notification_driver()

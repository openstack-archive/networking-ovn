# Copyright (c) 2015 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import mock

from webob import exc

from neutron.tests import tools
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_extra_dhcp_opt as test_dhcpopts
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin


from networking_ovn.common import constants as ovn_const
from networking_ovn.ovsdb import impl_idl_ovn

from oslo_config import cfg

PLUGIN_NAME = ('networking_ovn.plugin.OVNPlugin')


class OVNPluginTestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        impl_idl_ovn.OvsdbOvnIdl = mock.Mock()
        super(OVNPluginTestCase, self).setUp(plugin=plugin,
                                             ext_mgr=ext_mgr)
        self.plugin._ovn = mock.MagicMock()
        patcher = mock.patch(
            'neutron.agent.ovsdb.native.idlutils.row_by_value',
            lambda *args, **kwargs: mock.MagicMock())
        patcher.start()

        def _fake(*args, **kwargs):
            return mock.MagicMock()

        self.plugin._ovn.transaction = _fake
        self.context = _fake


class TestNetworksV2(test_plugin.TestNetworksV2, OVNPluginTestCase):
    pass


class TestPortsV2(test_plugin.TestPortsV2, OVNPluginTestCase):
    pass


class TestBasicGet(test_plugin.TestBasicGet, OVNPluginTestCase):
    pass


class TestV2HTTPResponse(test_plugin.TestV2HTTPResponse, OVNPluginTestCase):
    pass


class TestSubnetsV2(test_plugin.TestSubnetsV2, OVNPluginTestCase):
    pass


class TestOvnPlugin(OVNPluginTestCase):

    supported_extension_aliases = ["allowed-address-pairs", "port-security"]

    def test_port_invalid_binding_profile(self):
        invalid_binding_profiles = [
            {'tag': 0,
             'parent_name': 'fakename'},
            {'tag': 1024},
            {'tag': 1024, 'parent_name': 1024},
            {'parent_name': 'test'},
            {'tag': 'test'},
            {'vtep_physical_switch': 'psw1'},
            {'vtep_logical_switch': 'lsw1'},
            {'vtep_physical_switch': 'psw1', 'vtep_logical_switch': 1234},
            {'vtep_physical_switch': 1234, 'vtep_logical_switch': 'lsw1'},
            {'vtep_physical_switch': 'psw1', 'vtep_logical_switch': 'lsw1',
             'tag': 1024},
            {'vtep_physical_switch': 'psw1', 'vtep_logical_switch': 'lsw1',
             'parent_name': 'fakename'},
            {'vtep_physical_switch': 'psw1', 'vtep_logical_switch': 'lsw1',
             'tag': 1024, 'parent_name': 'fakename'},
        ]
        with self.network(set_context=True, tenant_id='test') as net1:
            with self.subnet(network=net1) as subnet1:
                # succeed without binding:profile
                with self.port(subnet=subnet1,
                               set_context=True, tenant_id='test'):
                    pass
                # fail with invalid binding profiles
                for invalid_profile in invalid_binding_profiles:
                    try:
                        kwargs = {ovn_const.OVN_PORT_BINDING_PROFILE:
                                  invalid_profile}
                        with self.port(
                                subnet=subnet1,
                                expected_res_status=403,
                                arg_list=(
                                ovn_const.OVN_PORT_BINDING_PROFILE,),
                                set_context=True, tenant_id='test',
                                **kwargs):
                            pass
                    except exc.HTTPClientError:
                        pass

    def test_create_port_security(self):
        self.plugin._ovn.create_lport = mock.Mock()
        self.plugin._ovn.set_lport = mock.Mock()
        kwargs = {'mac_address': '00:00:00:00:00:01'}
        with self.network(set_context=True, tenant_id='test') as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               arg_list=('mac_address',),
                               set_context=True, tenant_id='test',
                               **kwargs) as port:
                    self.assertTrue(
                        self.plugin._ovn.create_lport.called)
                    called_args_dict = (
                        (self.plugin._ovn.create_lport
                         ).call_args_list[1][1])
                    self.assertEqual(['00:00:00:00:00:01'],
                                     called_args_dict.get('port_security'))

                    data = {'port': {'mac_address': '00:00:00:00:00:02'}}
                    req = self.new_update_request(
                        'ports',
                        data, port['port']['id'])
                    req.get_response(self.api)
                    self.assertTrue(
                        self.plugin._ovn.set_lport.called)
                    called_args_dict = (
                        (self.plugin._ovn.set_lport
                         ).call_args_list[0][1])
                    self.assertEqual(['00:00:00:00:00:02'],
                                     called_args_dict.get('port_security'))

    def test_create_port_with_disabled_security(self):
        self.skipTest("Fix this after port-security extension is supported")
        self.plugin._ovn.create_lport = mock.Mock()
        self.plugin._ovn.set_lport = mock.Mock()
        kwargs = {'port_security_enabled': False}
        with self.network(set_context=True, tenant_id='test') as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               arg_list=('port_security_enabled',),
                               set_context=True, tenant_id='test',
                               **kwargs) as port:
                    self.assertTrue(
                        self.plugin._ovn.create_lport.called)
                    called_args_dict = (
                        (self.plugin._ovn.create_lport
                         ).call_args_list[0][1])
                    self.assertEqual([],
                                     called_args_dict.get('port_security'))

                    data = {'port': {'mac_address': '00:00:00:00:00:01'}}
                    req = self.new_update_request(
                        'ports',
                        data, port['port']['id'])
                    req.get_response(self.api)
                    self.assertTrue(
                        self.plugin._ovn.set_lport.called)
                    called_args_dict = (
                        (self.plugin._ovn.set_lport
                         ).call_args_list[0][1])
                    self.assertEqual([],
                                     called_args_dict.get('port_security'))

    def test_create_port_security_allowed_address_pairs(self):
        self.skipTest("Fix this after allowed-address-pairs"
                      " extension is supported")
        self.plugin._ovn.create_lport = mock.Mock()
        self.plugin._ovn.set_lport = mock.Mock()
        kwargs = {'allowed_address_pairs':
                  [{"ip_address": "1.1.1.1",
                    "mac_address": "22:22:22:22:22:22"}]}
        with self.network(set_context=True, tenant_id='test') as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               arg_list=('allowed_address_pairs',),
                               set_context=True, tenant_id='test',
                               **kwargs) as port:
                    self.assertTrue(
                        self.plugin._ovn.create_lport.called)
                    called_args_dict = (
                        (self.plugin._ovn.create_lport
                         ).call_args_list[0][1])
                    self.assertEqual(
                        tools.UnorderedList("22:22:22:22:22:22",
                                            port['port']['mac_address']),
                        called_args_dict.get('port_security'))

                    data = {'port': {'mac_address': '00:00:00:00:00:01'}}
                    req = self.new_update_request(
                        'ports',
                        data, port['port']['id'])
                    req.get_response(self.api)
                    self.assertTrue(
                        self.plugin._ovn.set_lport.called)
                    called_args_dict = (
                        (self.plugin._ovn.set_lport
                         ).call_args_list[0][1])
                    self.assertEqual(tools.UnorderedList("22:22:22:22:22:22",
                                                         "00:00:00:00:00:01"),
                                     called_args_dict.get('port_security'))


class TestOvnPluginL3(OVNPluginTestCase):

    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(TestOvnPluginL3, self).setUp(plugin=plugin,
                                           ext_mgr=ext_mgr,
                                           service_plugins=service_plugins)

        self.fake_router_port = {'mac_address': 'aa:aa:aa:aa:aa:aa',
                                 'fixed_ips': [{'ip_address': '10.0.0.100',
                                                'subnet_id': 'subnet-id'}],
                                 'id': 'router-port-id'}

        self.fake_subnet = {'id': 'subnet-id',
                            'cidr': '10.0.0.1/24'}

    @mock.patch('neutron.db.l3_gwmode_db.L3_NAT_db_mixin.'
                'add_router_interface')
    def test_add_router_interface(self, func):
        self.plugin._ovn.add_lrouter_port = mock.Mock()
        self.plugin._ovn.set_lrouter_port_in_lport = mock.Mock()
        cfg.CONF.set_override('ovn_l3_mode', True, 'ovn')

        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        with mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.'
                        'get_port',
                        return_value=self.fake_router_port):
            with mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.'
                            'get_subnet',
                            return_value=self.fake_subnet):
                self.plugin.add_router_interface(self.context, router_id,
                                                 interface_info)

        self.plugin._ovn.add_lrouter_port.assert_called_once_with(
            lrouter='neutron-router-id',
            mac='aa:aa:aa:aa:aa:aa',
            name='lrp-router-port-id',
            network='10.0.0.100/24')
        self.plugin._ovn.set_lrouter_port_in_lport.assert_called_once_with(
            'router-port-id', 'lrp-router-port-id')

    @mock.patch('neutron.db.l3_gwmode_db.L3_NAT_db_mixin.'
                'remove_router_interface')
    def test_remove_router_interface(self, func):
        self.plugin._ovn.delete_lrouter_port = mock.Mock()
        cfg.CONF.set_override('ovn_l3_mode', True, 'ovn')

        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        with mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.'
                        'get_port',
                        return_value=self.fake_router_port):
            with mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.'
                            'get_ports',
                            return_value=[self.fake_router_port]):
                self.plugin.remove_router_interface(self.context, router_id,
                                                    interface_info)

        self.plugin._ovn.delete_lrouter_port.assert_called_once_with(
            'lrp-router-port-id', 'neutron-router-id', if_exists=False)


class TestL3NatTestCase(test_l3_plugin.L3NatDBIntTestCase,
                        OVNPluginTestCase):
    pass


class DHCPOptsTestCase(test_dhcpopts.TestExtraDhcpOpt, OVNPluginTestCase):

    def setUp(self, plugin=None):
        super(test_dhcpopts.ExtraDhcpOptDBTestCase, self).setUp(
            plugin=PLUGIN_NAME)

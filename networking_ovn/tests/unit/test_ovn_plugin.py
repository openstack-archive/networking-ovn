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

from networking_ovn.common import constants as ovn_const
from networking_ovn.ovsdb import impl_idl_ovn

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
                    self.assertEqual(called_args_dict.get('port_security'),
                                     ['00:00:00:00:00:01'])

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
                    self.assertEqual(called_args_dict.get('port_security'),
                                     ['00:00:00:00:00:02'])

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
                    self.assertEqual(called_args_dict.get('port_security'),
                                     [])

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
                    self.assertEqual(called_args_dict.get('port_security'),
                                     [])

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
                        called_args_dict.get('port_security'),
                        tools.UnorderedList("22:22:22:22:22:22",
                                            port['port']['mac_address']))

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
                    self.assertEqual(called_args_dict.get('port_security'),
                                     tools.UnorderedList("22:22:22:22:22:22",
                                                         "00:00:00:00:00:01"))

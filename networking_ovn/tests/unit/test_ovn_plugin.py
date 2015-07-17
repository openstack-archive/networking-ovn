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

from neutron.common import exceptions as n_exc
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

    def test_port_invalid_binding_profile(self):
        self.skipTest("Fix these tests after we converted from ml2")
        context = mock.Mock()
        binding_profile = {'tag': 0,
                           'parent_name': 'fakename'}
        context.current = self._create_dummy_port()
        context.current[ovn_const.OVN_PORT_BINDING_PROFILE] = binding_profile
        self.assertRaises(n_exc.InvalidInput,
                          self.driver.create_port_precommit, context)

        binding_profile = {'tag': 1024}
        context.current[ovn_const.OVN_PORT_BINDING_PROFILE] = binding_profile
        self.assertRaises(n_exc.InvalidInput,
                          self.driver.create_port_precommit, context)

        binding_profile = {'tag': 1024, 'parent_name': 1024}
        context.current[ovn_const.OVN_PORT_BINDING_PROFILE] = binding_profile
        self.assertRaises(n_exc.InvalidInput,
                          self.driver.create_port_precommit, context)

        binding_profile = {'parent_name': 'test'}
        context.current[ovn_const.OVN_PORT_BINDING_PROFILE] = binding_profile
        self.assertRaises(n_exc.InvalidInput,
                          self.driver.create_port_precommit, context)

        binding_profile = {'tag': 'test'}
        context.current[ovn_const.OVN_PORT_BINDING_PROFILE] = binding_profile
        self.assertRaises(n_exc.InvalidInput,
                          self.driver.create_port_precommit, context)

    def test_create_port_security(self):
        self.skipTest("Fix these tests after we converted from ml2")
        context = mock.Mock()
        context.current = self._create_dummy_port()
        self.driver._ovn.create_lport = mock.Mock()
        self.driver.create_port_postcommit(context)
        self.assertTrue(self.driver._ovn.create_lport.called)
        called_args_dict = self.driver._ovn.create_lport.call_args_list[0][1]
        self.assertEqual(called_args_dict.get('port_security'),
                         [context.current['mac_address']])

        self.driver._ovn.set_lport = mock.Mock()
        self.driver.update_port_postcommit(context)
        self.assertTrue(self.driver._ovn.set_lport.called)
        called_args_dict = self.driver._ovn.set_lport.call_args_list[0][1]
        self.assertEqual(called_args_dict.get('port_security'),
                         [context.current['mac_address']])

    def test_create_port_with_disabled_security(self):
        self.skipTest("Fix these tests after we converted from ml2")
        context = mock.Mock()
        context.current = self._create_dummy_port()
        context.current['port_security_enabled'] = False

        self.driver._ovn.create_lport = mock.Mock()
        self.driver.create_port_postcommit(context)
        self.assertTrue(self.driver._ovn.create_lport.called)
        called_args_dict = self.driver._ovn.create_lport.call_args_list[0][1]
        self.assertEqual(called_args_dict.get('port_security'), [])

        self.driver._ovn.set_lport = mock.Mock()
        self.driver.update_port_postcommit(context)
        self.assertTrue(self.driver._ovn.set_lport.called)
        called_args_dict = self.driver._ovn.set_lport.call_args_list[0][1]
        self.assertEqual(called_args_dict.get('port_security'), [])

    def test_create_port_security_allowed_address_pairs(self):
        self.skipTest("Fix these tests after we converted from ml2")
        context = mock.Mock()
        context.current = self._create_dummy_port()
        context.current['allowed_address_pairs'] = [
            {"ip_address": "1.1.1.1", "mac_address": "22:22:22:22:22:22"}]

        self.driver._ovn.create_lport = mock.Mock()
        self.driver.create_port_postcommit(context)
        self.assertTrue(self.driver._ovn.create_lport.called)
        called_args_dict = self.driver._ovn.create_lport.call_args_list[0][1]
        self.assertEqual(tools.UnorderedList(
            called_args_dict.get('port_security')),
            tools.UnorderedList([context.current['mac_address'],
                                 "22:22:22:22:22:22"]))

        self.driver._ovn.set_lport = mock.Mock()
        self.driver.update_port_postcommit(context)
        self.assertTrue(self.driver._ovn.set_lport.called)
        called_args_dict = self.driver._ovn.set_lport.call_args_list[0][1]
        self.assertEqual(tools.UnorderedList(
            called_args_dict.get('port_security')),
            tools.UnorderedList([context.current['mac_address'],
                                 "22:22:22:22:22:22"]))

    def _create_dummy_network(self):
        return {'id': 'fakenetworkid123',
                'name': 'fakenet1'}

    def _create_dummy_port(self):
        return {'id': 'fakeportid123',
                'name': 'fakeport1',
                'network_id': 'fakenetworkid123',
                'mac_address': '00:00:00:00:00:01',
                'allowed_address_pairs': [],
                'port_security_enabled': True,
                'admin_state_up': True}

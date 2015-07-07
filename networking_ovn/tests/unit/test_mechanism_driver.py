# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import mock

from neutron.common import exceptions as n_exc
from neutron.tests import tools

from networking_ovn.common import constants as ovn_const
from networking_ovn.ml2 import mech_driver
from networking_ovn.tests import base


class TestOvnMechanismDriver(base.TestCase):

    def setUp(self):
        super(TestOvnMechanismDriver, self).setUp()
        self.driver = mech_driver.OVNMechDriver()
        self.driver._ovn = mock.Mock()

    def test_create_network(self):
        context = mock.Mock()
        context.current = self._create_dummy_network()
        self.driver.create_network_postcommit(context)

    def test_create_port(self):
        context = mock.Mock()
        context.current = self._create_dummy_port()
        self.driver.create_port_postcommit(context)

    def test_port_invalid_binding_profile(self):
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

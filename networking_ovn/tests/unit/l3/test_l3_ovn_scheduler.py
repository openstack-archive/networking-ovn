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

import random

import mock
from neutron.tests import base

from networking_ovn.common import constants as ovn_const
from networking_ovn.l3 import l3_ovn_scheduler


class FakeOVNGatewaySchedulerNbOvnIdl(object):
    def __init__(self, chassis_gateway_mapping, gateway):
        self.get_all_chassis_gateway_bindings = mock.Mock(
            return_value=chassis_gateway_mapping['Chassis_Bindings'])
        self.get_gateway_chassis_binding = mock.Mock(
            return_value=chassis_gateway_mapping['Gateways'].get(gateway,
                                                                 None))


class FakeOVNGatewaySchedulerSbOvnIdl(object):
    def __init__(self, chassis_gateway_mapping):
        self.get_all_chassis = mock.Mock(
            return_value=chassis_gateway_mapping['Chassis'])


class TestOVNGatewayScheduler(base.BaseTestCase):

    def setUp(self):
        super(TestOVNGatewayScheduler, self).setUp()

        # Overwritten by derived classes
        self.l3_scheduler = None

        # Used for unit tests
        self.new_gateway_name = 'lrp_new'
        self.fake_chassis_gateway_mappings = {
            'None': {'Chassis': [],
                     'Gateways': {
                         'g1': ovn_const.OVN_GATEWAY_INVALID_CHASSIS}},
            'Multiple1': {'Chassis': ['hv1', 'hv2'],
                          'Gateways': {'g1': 'hv1', 'g2': 'hv2', 'g3': 'hv1'}},
            'Multiple2': {'Chassis': ['hv1', 'hv2', 'hv3'],
                          'Gateways': {'g1': 'hv1', 'g2': 'hv1', 'g3': 'hv1'}},
            'Multiple3': {'Chassis': ['hv1', 'hv2', 'hv3'],
                          'Gateways': {'g1': 'hv3', 'g2': 'hv2', 'g3': 'hv2'}}
            }

        # Determine the chassis to gateway list bindings
        for details in self.fake_chassis_gateway_mappings.values():
            self.assertNotIn(self.new_gateway_name, details['Gateways'])
            details.setdefault('Chassis_Bindings', {})
            for chassis in details['Chassis']:
                details['Chassis_Bindings'].setdefault(chassis, [])
            for gateway, chassis in details['Gateways'].items():
                if chassis in details['Chassis_Bindings']:
                    details['Chassis_Bindings'][chassis].append(gateway)

    def select(self, chassis_gateway_mapping, gateway_name):
        nb_idl = FakeOVNGatewaySchedulerNbOvnIdl(chassis_gateway_mapping,
                                                 gateway_name)
        sb_idl = FakeOVNGatewaySchedulerSbOvnIdl(chassis_gateway_mapping)
        return self.l3_scheduler.select(nb_idl, sb_idl, gateway_name)


class OVNGatewayChanceScheduler(TestOVNGatewayScheduler):

    def setUp(self):
        super(OVNGatewayChanceScheduler, self).setUp()
        self.l3_scheduler = l3_ovn_scheduler.OVNGatewayChanceScheduler()

    def test_no_chassis_available_for_existing_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['None']
        gateway_name = random.choice(list(mapping['Gateways'].keys()))
        chassis = self.select(mapping, gateway_name)
        self.assertEqual(ovn_const.OVN_GATEWAY_INVALID_CHASSIS, chassis)

    def test_no_chassis_available_for_new_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['None']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name)
        self.assertEqual(ovn_const.OVN_GATEWAY_INVALID_CHASSIS, chassis)

    def test_random_chassis_available_for_new_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple1']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name)
        self.assertIn(chassis, mapping.get('Chassis'))

    def test_existing_chassis_available_for_existing_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple1']
        gateway_name = random.choice(list(mapping['Gateways'].keys()))
        chassis = self.select(mapping, gateway_name)
        self.assertEqual(mapping['Gateways'][gateway_name], chassis)


class OVNGatewayLeastLoadedScheduler(TestOVNGatewayScheduler):

    def setUp(self):
        super(OVNGatewayLeastLoadedScheduler, self).setUp()
        self.l3_scheduler = l3_ovn_scheduler.OVNGatewayLeastLoadedScheduler()

    def test_no_chassis_available_for_existing_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['None']
        gateway_name = random.choice(list(mapping['Gateways'].keys()))
        chassis = self.select(mapping, gateway_name)
        self.assertEqual(ovn_const.OVN_GATEWAY_INVALID_CHASSIS, chassis)

    def test_no_chassis_available_for_new_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['None']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name)
        self.assertEqual(ovn_const.OVN_GATEWAY_INVALID_CHASSIS, chassis)

    def test_least_loaded_chassis_available_for_new_gateway1(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple1']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name)
        self.assertIn(chassis, mapping.get('Chassis'))
        self.assertEqual('hv2', chassis)

    def test_least_loaded_chassis_available_for_new_gateway2(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple2']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name)
        self.assertNotEqual(chassis, 'hv1')
        self.assertIn(chassis, ['hv2', 'hv3'])

    def test_least_loaded_chassis_available_for_new_gateway3(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple3']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name)
        self.assertIn(chassis, mapping.get('Chassis'))
        self.assertEqual('hv1', chassis)

    def test_existing_chassis_available_for_existing_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple1']
        gateway_name = random.choice(list(mapping['Gateways'].keys()))
        chassis = self.select(mapping, gateway_name)
        self.assertEqual(mapping['Gateways'][gateway_name], chassis)

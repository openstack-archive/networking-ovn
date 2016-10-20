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
import random
import six

from neutron.tests import base

from networking_ovn.common import constants as ovn_const
from networking_ovn.l3 import l3_ovn_scheduler


class FakeOVNGatewaySchedulerNbOvnIdl(object):
    def __init__(self, chassis_router_mapping, router):
        self.get_all_chassis_router_bindings = mock.Mock(
            return_value=chassis_router_mapping['Chassis_Bindings'])
        self.get_router_chassis_binding = mock.Mock(
            return_value=chassis_router_mapping['Routers'].get(router, None))


class FakeOVNGatewaySchedulerSbOvnIdl(object):
    def __init__(self, chassis_router_mapping):
        self.get_all_chassis = mock.Mock(
            return_value=chassis_router_mapping['Chassis'])


class TestOVNGatewayScheduler(base.BaseTestCase):

    def setUp(self):
        super(TestOVNGatewayScheduler, self).setUp()

        # Overwritten by derived classes
        self.l3_scheduler = None

        # Used for unit tests
        self.new_router_name = 'router_new'
        self.fake_chassis_router_mappings = {
            'None': {'Chassis': [],
                     'Routers': {'r1': ovn_const.OVN_GATEWAY_INVALID_CHASSIS}},
            'Multiple1': {'Chassis': ['hv1', 'hv2'],
                          'Routers': {'r1': 'hv1', 'r2': 'hv2', 'r3': 'hv1'}},
            'Multiple2': {'Chassis': ['hv1', 'hv2', 'hv3'],
                          'Routers': {'r1': 'hv1', 'r2': 'hv1', 'r3': 'hv1'}},
            'Multiple3': {'Chassis': ['hv1', 'hv2', 'hv3'],
                          'Routers': {'r1': 'hv3', 'r2': 'hv2', 'r3': 'hv2'}}
            }

        # Determine the chassis to router list bindings
        for details in six.itervalues(self.fake_chassis_router_mappings):
            self.assertNotIn(self.new_router_name,
                             six.iterkeys(details['Routers']))
            details.setdefault('Chassis_Bindings', {})
            for chassis in details['Chassis']:
                details['Chassis_Bindings'].setdefault(chassis, [])
            for router, chassis in six.iteritems(details['Routers']):
                if chassis in six.iterkeys(details['Chassis_Bindings']):
                    details['Chassis_Bindings'][chassis].append(router)

    def select(self, chassis_router_mapping, router_name):
        nb_idl = FakeOVNGatewaySchedulerNbOvnIdl(chassis_router_mapping,
                                                 router_name)
        sb_idl = FakeOVNGatewaySchedulerSbOvnIdl(chassis_router_mapping)
        return self.l3_scheduler.select(nb_idl, sb_idl, router_name)


class OVNGatewayChanceScheduler(TestOVNGatewayScheduler):

    def setUp(self):
        super(OVNGatewayChanceScheduler, self).setUp()
        self.l3_scheduler = l3_ovn_scheduler.OVNGatewayChanceScheduler()

    def test_no_chassis_available_for_existing_router(self):
        mapping = self.fake_chassis_router_mappings['None']
        router_name = random.choice(list(mapping['Routers'].keys()))
        chassis = self.select(mapping, router_name)
        self.assertEqual(ovn_const.OVN_GATEWAY_INVALID_CHASSIS, chassis)

    def test_no_chassis_available_for_new_router(self):
        mapping = self.fake_chassis_router_mappings['None']
        router_name = self.new_router_name
        chassis = self.select(mapping, router_name)
        self.assertEqual(ovn_const.OVN_GATEWAY_INVALID_CHASSIS, chassis)

    def test_random_chassis_available_for_new_router(self):
        mapping = self.fake_chassis_router_mappings['Multiple1']
        router_name = self.new_router_name
        chassis = self.select(mapping, router_name)
        self.assertIn(chassis, mapping.get('Chassis'))

    def test_existing_chassis_available_for_existing_router(self):
        mapping = self.fake_chassis_router_mappings['Multiple1']
        router_name = random.choice(list(mapping['Routers'].keys()))
        chassis = self.select(mapping, router_name)
        self.assertEqual(mapping['Routers'][router_name], chassis)


class OVNGatewayLeastLoadedScheduler(TestOVNGatewayScheduler):

    def setUp(self):
        super(OVNGatewayLeastLoadedScheduler, self).setUp()
        self.l3_scheduler = l3_ovn_scheduler.OVNGatewayLeastLoadedScheduler()

    def test_no_chassis_available_for_existing_router(self):
        mapping = self.fake_chassis_router_mappings['None']
        router_name = random.choice(list(mapping['Routers'].keys()))
        chassis = self.select(mapping, router_name)
        self.assertEqual(ovn_const.OVN_GATEWAY_INVALID_CHASSIS, chassis)

    def test_no_chassis_available_for_new_router(self):
        mapping = self.fake_chassis_router_mappings['None']
        router_name = self.new_router_name
        chassis = self.select(mapping, router_name)
        self.assertEqual(ovn_const.OVN_GATEWAY_INVALID_CHASSIS, chassis)

    def test_least_loaded_chassis_available_for_new_router1(self):
        mapping = self.fake_chassis_router_mappings['Multiple1']
        router_name = self.new_router_name
        chassis = self.select(mapping, router_name)
        self.assertIn(chassis, mapping.get('Chassis'))
        self.assertEqual('hv2', chassis)

    def test_least_loaded_chassis_available_for_new_router2(self):
        mapping = self.fake_chassis_router_mappings['Multiple2']
        router_name = self.new_router_name
        chassis = self.select(mapping, router_name)
        self.assertNotEqual(chassis, 'hv1')
        self.assertIn(chassis, ['hv2', 'hv3'])

    def test_least_loaded_chassis_available_for_new_router3(self):
        mapping = self.fake_chassis_router_mappings['Multiple3']
        router_name = self.new_router_name
        chassis = self.select(mapping, router_name)
        self.assertIn(chassis, mapping.get('Chassis'))
        self.assertEqual('hv1', chassis)

    def test_existing_chassis_available_for_existing_router(self):
        mapping = self.fake_chassis_router_mappings['Multiple1']
        router_name = random.choice(list(mapping['Routers'].keys()))
        chassis = self.select(mapping, router_name)
        self.assertEqual(mapping['Routers'][router_name], chassis)

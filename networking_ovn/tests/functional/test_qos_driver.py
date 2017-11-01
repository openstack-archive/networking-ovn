# Copyright 2017 DtDream Technology Co.,Ltd.
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

from networking_ovn.tests.functional import base
from neutron.extensions import qos as qos_ext
from neutron.tests.unit.api import test_extensions
from ovsdbapp.backend.ovs_idl import idlutils


class QoSTestExtensionManager(object):
    def get_resources(self):
        return qos_ext.Qos.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestOVNQosDriver(base.TestOVNFunctionalBase):
    _extension_drivers = ['qos']

    def setUp(self):
        super(TestOVNQosDriver, self).setUp()
        qos_mgr = QoSTestExtensionManager()
        self.resource_prefix_map = {'policies': '/qos'}
        self.qos_api = test_extensions.setup_extensions_middleware(qos_mgr)

    def get_additional_service_plugins(self):
        p = super(TestOVNQosDriver, self).get_additional_service_plugins()
        p.update({'qos_plugin_name': 'qos'})
        return p

    def _test_qos_policy_create(self):
        data = {'policy': {'name': 'test-policy',
                           'tenant_id': self._tenant_id}}
        policy_req = self.new_create_request('policies', data, self.fmt)
        policy_res = policy_req.get_response(self.qos_api)
        policy = self.deserialize(self.fmt, policy_res)['policy']
        return policy['id']

    def _test_qos_policy_rule_create(self, policy_id, max_burst, max_bw):
        data = {'bandwidth_limit_rule': {'max_burst_kbps': max_burst,
                                         'max_kbps': max_bw,
                                         'tenant_id': self._tenant_id}}
        policy_rule_req = self.new_create_request(
            'policies', data, self.fmt, policy_id, 'bandwidth_limit_rules')
        policy_rule_res = policy_rule_req.get_response(self.qos_api)
        policy_rule = self.deserialize(self.fmt,
                                       policy_rule_res)['bandwidth_limit_rule']
        return policy_rule['id']

    def _test_qos_policy_rule_update(
            self, policy_id, rule_id, max_burst, max_bw):
        data = {'bandwidth_limit_rule': {'max_burst_kbps': max_burst,
                                         'max_kbps': max_bw}}
        policy_rule_req = self.new_update_request(
            'policies', data, policy_id, self.fmt,
            subresource='bandwidth_limit_rules' + '/' + rule_id)
        policy_rule_req.get_response(self.qos_api)

    def _test_qos_policy_rule_delete(
            self, policy_id, rule_id):
        policy_rule_req = self.new_delete_request(
            'policies', policy_id, self.fmt,
            subresource='bandwidth_limit_rules', sub_id=rule_id)
        policy_rule_req.get_response(self.qos_api)

    def _test_port_create(self, network_id, policy_id=None):
        data = {'port': {'network_id': network_id,
                         'tenant_id': self._tenant_id,
                         'device_owner': 'compute:None',
                         'qos_policy_id': policy_id}}
        port_req = self.new_create_request('ports', data, self.fmt)
        port_res = port_req.get_response(self.api)
        p1 = self.deserialize(self.fmt, port_res)['port']
        return p1['id']

    def _test_port_update(self, port_id, policy_id):
        data = {'port': {'qos_policy_id': policy_id}}
        port_req = self.new_update_request('ports', data, port_id, self.fmt)
        port_req.get_response(self.api)

    def _verify_qos_option_row_for_port(self, port_id,
                                        expected_lsp_qos_options):
        lsp = idlutils.row_by_value(self.nb_api.idl,
                                    'Logical_Switch_Port', 'name', port_id,
                                    None)

        observed_lsp_qos_options = {}
        if lsp.options:
            if 'qos_burst' in lsp.options:
                observed_lsp_qos_options['qos_burst'] = lsp.options.get(
                    'qos_burst')
            if 'qos_max_rate' in lsp.options:
                observed_lsp_qos_options['qos_max_rate'] = lsp.options.get(
                    'qos_max_rate')

        self.assertEqual(expected_lsp_qos_options, observed_lsp_qos_options)

    def test_port_qos_options_add_and_remove(self):
        expected_burst = 100
        expected_max_rate = 1
        network_id = self._make_network(self.fmt, 'n1', True)['network']['id']
        self._create_subnet(self.fmt, network_id, '10.0.0.0/24')
        port_id = self._test_port_create(network_id)
        policy_id = self._test_qos_policy_create()
        self._test_qos_policy_rule_create(
            policy_id, expected_burst, expected_max_rate)

        # port add QoS policy
        self._test_port_update(port_id, policy_id)
        expected_options = {
            'qos_burst': str(expected_burst * 1000),
            'qos_max_rate': str(expected_max_rate * 1000),
        }
        self._verify_qos_option_row_for_port(port_id, expected_options)

        # port remove QoS policy
        self._test_port_update(port_id, None)
        self._verify_qos_option_row_for_port(port_id, {})

    def test_port_qos_options_with_rule(self):
        expected_burst = 100
        expected_max_rate = 1
        network_id = self._make_network(self.fmt, 'n1', True)['network']['id']
        self._create_subnet(self.fmt, network_id, '10.0.0.0/24')
        policy_id = self._test_qos_policy_create()
        policy_rule_id = self._test_qos_policy_rule_create(
            policy_id, expected_burst, expected_max_rate)
        port_id = self._test_port_create(network_id, policy_id)

        # check qos options
        expected_options = {
            'qos_burst': str(expected_burst * 1000),
            'qos_max_rate': str(expected_max_rate * 1000),
        }
        self._verify_qos_option_row_for_port(port_id, expected_options)

        # update qos rule
        self._test_qos_policy_rule_update(
            policy_id, policy_rule_id,
            expected_burst * 2, expected_max_rate * 2)
        expected_options = {
            'qos_burst': str(expected_burst * 2 * 1000),
            'qos_max_rate': str(expected_max_rate * 2 * 1000),
        }
        self._verify_qos_option_row_for_port(port_id, expected_options)

        # delete qos rule
        self._test_qos_policy_rule_delete(policy_id, policy_rule_id)
        self._verify_qos_option_row_for_port(port_id, {})

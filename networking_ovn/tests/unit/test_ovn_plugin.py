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


import copy
import mock
from neutron_lib import exceptions as n_exc
from oslo_utils import uuidutils
import six
from webob import exc

from neutron import context
from neutron.core_extensions.qos import QosCoreResourceExtension
from neutron.db.qos import api as qos_api
from neutron.extensions import portbindings
from neutron.extensions import providernet
from neutron.objects.qos import policy as qos_policy
from neutron.objects.qos import rule as qos_rule
from neutron.services.qos.notification_drivers import manager as driver_mgr
from neutron.services.qos import qos_consts
from neutron.tests import tools
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit.db import test_allowedaddresspairs_db as test_aap
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_address_scope as test_as
from neutron.tests.unit.extensions import test_availability_zone as test_az
from neutron.tests.unit.extensions import test_extra_dhcp_opt as test_dhcpopts
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin
from neutron.tests.unit.extensions import test_portsecurity

from networking_ovn.common import acl as acl_utils
from networking_ovn.common import constants as ovn_const
from networking_ovn.ovsdb import commands as cmd
from networking_ovn.ovsdb import impl_idl_ovn

PLUGIN_NAME = ('networking_ovn.plugin.OVNPlugin')


class OVNPluginTestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        impl_idl_ovn.OvsdbOvnIdl = mock.Mock()
        super(OVNPluginTestCase, self).setUp(plugin=plugin,
                                             ext_mgr=ext_mgr,
                                             service_plugins=service_plugins)
        self.plugin._ovn = mock.MagicMock()
        patcher = mock.patch(
            'neutron.agent.ovsdb.native.idlutils.row_by_value',
            lambda *args, **kwargs: mock.MagicMock())
        patcher.start()

        def _fake(*args, **kwargs):
            return mock.MagicMock()

        self.plugin._ovn.transaction = _fake
        self.context = mock.Mock()
        self.port_create_status = 'DOWN'


class TestNetworksV2(test_plugin.TestNetworksV2, OVNPluginTestCase):

    def test_create_lswitch_exception(self):
        data = {'network': {'name': 'private',
                            'admin_state_up': True,
                            'shared': False,
                            'tenant_id': 'fake-id'}}
        self.plugin._ovn.create_lswitch = mock.MagicMock()
        self.plugin._ovn.create_lswitch.side_effect = RuntimeError('ovn')
        self.assertRaises(n_exc.ServiceUnavailable,
                          self.plugin.create_network,
                          context.get_admin_context(),
                          data)

    def test_delete_lswitch_exception(self):
        self.plugin._ovn.delete_lswitch = mock.MagicMock()
        self.plugin._ovn.delete_lswitch.side_effect = RuntimeError('ovn')
        res = self._create_network(self.fmt, 'net1', True)
        net = self.deserialize(self.fmt, res)
        req = self.new_delete_request('networks', net['network']['id'])
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, exc.HTTPNoContent.code)

    def test_create_provider_net(self):
        net_data = {'network': {'name': 'provider',
                                providernet.PHYSICAL_NETWORK: 'physnet1',
                                providernet.NETWORK_TYPE: 'flat',
                                providernet.SEGMENTATION_ID: 123,
                                'tenant_id': self._tenant_id}}
        network_req = self.new_create_request('networks', net_data, self.fmt)
        net = self.deserialize(self.fmt, network_req.get_response(self.api))
        for attr in providernet.ATTRIBUTES:
            self.assertEqual(net_data['network'][attr], net['network'][attr])


class TestPortsV2(test_plugin.TestPortsV2, OVNPluginTestCase,
                  test_bindings.PortBindingsTestCase,
                  test_bindings.PortBindingsHostTestCaseMixin,
                  test_bindings.PortBindingsVnicTestCaseMixin):

    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = True


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
        kwargs = {'mac_address': '00:00:00:00:00:01',
                  'fixed_ips': [{'ip_address': '10.0.0.2'},
                                {'ip_address': '10.0.0.4'}]}
        with self.network(set_context=True, tenant_id='test') as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               arg_list=('mac_address', 'fixed_ips'),
                               set_context=True, tenant_id='test',
                               **kwargs) as port:
                    self.assertTrue(
                        self.plugin._ovn.create_lport.called)
                    called_args_dict = (
                        (self.plugin._ovn.create_lport
                         ).call_args_list[0][1])
                    self.assertEqual(['00:00:00:00:00:01 10.0.0.2 10.0.0.4'],
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
                    self.assertEqual(['00:00:00:00:00:02 10.0.0.2 10.0.0.4'],
                                     called_args_dict.get('port_security'))

    def test_create_port_with_disabled_security(self):
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
        self.plugin._ovn.create_lport = mock.Mock()
        self.plugin._ovn.set_lport = mock.Mock()
        kwargs = {'allowed_address_pairs':
                  [{"ip_address": "1.1.1.1"},
                   {"ip_address": "2.2.2.2",
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
                        tools.UnorderedList(
                            ["22:22:22:22:22:22 2.2.2.2",
                             port['port']['mac_address'] + ' ' + '10.0.0.2'
                             + ' ' + '1.1.1.1']),
                        called_args_dict.get('port_security'))

                    old_mac = port['port']['mac_address']

                    # we are updating only the port mac address. So the
                    # mac address of the allowed address pair ip 1.1.1.1
                    # will have old mac address
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
                    self.assertEqual(tools.UnorderedList(
                        ["22:22:22:22:22:22 2.2.2.2",
                         "00:00:00:00:00:01 10.0.0.2",
                         old_mac + " 1.1.1.1"]),
                        called_args_dict.get('port_security'))


class TestQosOvnPlugin(OVNPluginTestCase):
    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        driver_mgr.QosServiceNotificationDriverManager = mock.Mock()
        super(TestQosOvnPlugin, self).setUp(
            plugin=plugin,
            ext_mgr=ext_mgr,
            service_plugins={"qos": "qos"})

        self.qos_policy_id1 = uuidutils.generate_uuid()
        self.tenant_id = "tenant_id"
        self.ctxt = context.Context("", self.tenant_id)
        self.policy1 = self._create_qos_policy(self.ctxt, self.qos_policy_id1)
        qos_policy.QosPolicy.get_object = mock.MagicMock(
            return_value=self.policy1)
        qos_api.create_policy_network_binding = mock.Mock()
        qos_api.delete_policy_network_binding = mock.Mock()
        qos_api.create_policy_port_binding = mock.Mock()
        qos_api.delete_policy_port_binding = mock.Mock()
        QosCoreResourceExtension.extract_fields = mock.MagicMock(
            side_effect=lambda resource_type, resource: {
                qos_consts.QOS_POLICY_ID: self.policy1.id})

        qos_rule.get_rules = mock.MagicMock(side_effect=self._rules_of_policy)

    def _rules_of_policy(self, context, policy_id):
        if policy_id == self.qos_policy_id1:
            return self.policy1.rules

        return []

    def _create_qos_bw_limit_rule(self, policy_id):
        ret = qos_rule.QosBandwidthLimitRule()
        ret.id = uuidutils.generate_uuid()
        ret.max_kbps = 50
        ret.max_burst_kbps = 500
        ret.obj_reset_changes()
        ret.qos_policy_id = policy_id
        return ret

    def _create_qos_policy(self, context, id):
        ret = qos_policy.QosPolicy()
        ret.id = id
        ret.rules = [self._create_qos_bw_limit_rule(id)]
        ret.name = "test-policy"
        ret._context = context
        return ret

    def _validate_port_create(self, options):
        self.assertTrue(
            self.plugin._ovn.create_lport.called)
        args, kwargs = self.plugin._ovn.create_lport.call_args
        self.assertIn("options", kwargs)
        unmatched = set(options.items()) ^ set(kwargs['options'].items())
        self.assertEqual(len(unmatched), 0)

    @mock.patch('neutron.objects.qos.policy.QosPolicy.get_network_policy')
    def test_qos_create_network(self, mock_get_nw_policy):
        mock_get_nw_policy.return_value = self.policy1

        data = {"network": {"name": "test-net",
                            "admin_state_up": True,
                            "tenant_id": self.tenant_id,
                            "qos_policy_id": self.qos_policy_id1}}
        req = self.new_create_request(
            "networks", data, self.fmt,
            context=self.ctxt)
        res = req.get_response(self.api)
        net1 = self.deserialize(self.fmt, res)
        self.assertIn('qos_policy_id', net1['network'])
        self.assertEqual(net1['network']['qos_policy_id'], self.qos_policy_id1)
        self.assertTrue(qos_api.create_policy_network_binding.called)

        with self.subnet(network=net1) as subnet1:
            with self.port(subnet=subnet1,
                           set_context=True,
                           device_owner="network:",
                           tenant_id=self.tenant_id):
                self._validate_port_create({})

            with self.port(subnet=subnet1,
                           set_context=True,
                           device_owner="compute:",
                           tenant_id=self.tenant_id):
                self._validate_port_create({'policing_rate': '50',
                                            'policing_burst': '500'})

        self.new_delete_request("networks", net1['network']['id'])

    @mock.patch('neutron.objects.qos.policy.QosPolicy.get_network_policy')
    def test_qos_create_port(self, mock_get_nw_policy):
        mock_get_nw_policy.return_value = self.policy1

        with self.network(set_context=True, tenant_id=self.tenant_id) as net1:
            with self.subnet(network=net1):
                data = {"port": {"network_id": net1['network']['id'],
                                 "qos_policy_id": self.qos_policy_id1,
                                 "tenant_id": self.tenant_id}}
                req = self.new_create_request(
                    "ports", data, self.fmt, context=self.ctxt)
                res = req.get_response(self.api)
                self.deserialize(self.fmt, res)
                self._validate_port_create({'policing_rate': '50',
                                            'policing_burst': '500'})


class TestOvnPluginACLs(OVNPluginTestCase):

    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(TestOvnPluginACLs, self).setUp(plugin=plugin,
                                             ext_mgr=ext_mgr,
                                             service_plugins=service_plugins)

        self.fake_port = {'id': 'fake_port_id1',
                          'network_id': 'network_id1',
                          'fixed_ips': [{'subnet_id': 'subnet_id1',
                                         'ip_address': '1.1.1.1'}]}
        self.fake_subnet = {'id': 'subnet_id1',
                            'ip_version': 4,
                            'cidr': '1.1.1.0/24'}

    def test_add_acl_dhcp(self):
        self.plugin._ovn.add_acl = mock.Mock()
        with mock.patch.object(self.plugin, 'get_subnet',
                               return_value=self.fake_subnet):
            subnet = acl_utils._get_subnet_from_cache(
                self.plugin, self.context, {}, 'subnet_id')
            acls = acl_utils.add_acl_dhcp(self.fake_port, subnet)

        expected_match_to_lport = (
            'outport == "%s" && ip4 && ip4.src == %s && udp && udp.src == 67 '
            '&& udp.dst == 68') % (self.fake_port['id'],
                                   self.fake_subnet['cidr'])
        acl_to_lport = {'action': 'allow', 'direction': 'to-lport',
                        'external_ids': {'neutron:lport': 'fake_port_id1'},
                        'log': False, 'lport': 'fake_port_id1',
                        'lswitch': 'neutron-network_id1',
                        'match': expected_match_to_lport, 'priority': 1002}
        expected_match_from_lport = (
            'inport == "%s" && ip4 && '
            '(ip4.dst == 255.255.255.255 || ip4.dst == %s) && '
            'udp && udp.src == 68 && udp.dst == 67'
        ) % (self.fake_port['id'], self.fake_subnet['cidr'])
        acl_from_lport = {'action': 'allow', 'direction': 'from-lport',
                          'external_ids': {'neutron:lport': 'fake_port_id1'},
                          'log': False, 'lport': 'fake_port_id1',
                          'lswitch': 'neutron-network_id1',
                          'match': expected_match_from_lport, 'priority': 1002}
        for acl in acls:
            if 'to-lport' in acl.values():
                self.assertEqual(acl_to_lport, acl)
            if 'from-lport' in acl.values():
                self.assertEqual(acl_from_lport, acl)

    def test_add_acls_no_sec_group(self):
        acls = acl_utils.add_acls(self.plugin, self.context,
                                  port={'security_groups': []},
                                  sg_cache={}, sg_ports_cache={},
                                  subnet_cache={})
        self.assertEqual(acls, [])

    def _test__add_sg_rule_acl_for_port(self, sg_rule, direction, match):
        port = {'id': 'port-id',
                'network_id': 'network-id'}
        self.plugin._ovn.add_acl = mock.Mock()
        acl = acl_utils._add_sg_rule_acl_for_port(self.plugin,
                                                  self.context,
                                                  port,
                                                  sg_rule,
                                                  sg_ports_cache={},
                                                  subnet_cache={})
        self.assertEqual(acl, {'lswitch': 'neutron-network-id',
                               'lport': 'port-id',
                               'priority': ovn_const.ACL_PRIORITY_ALLOW,
                               'action': ovn_const.ACL_ACTION_ALLOW_RELATED,
                               'log': False,
                               'direction': direction,
                               'match': match,
                               'external_ids': {'neutron:lport': 'port-id'}})

    def test__add_sg_rule_acl_for_port_remote_ip_prefix(self):
        sg_rule = {'direction': 'ingress',
                   'ethertype': 'IPv4',
                   'remote_group_id': None,
                   'remote_ip_prefix': '1.1.1.0/24',
                   'protocol': None}
        match = 'outport == "port-id" && ip4 && ip4.src == 1.1.1.0/24'
        self._test__add_sg_rule_acl_for_port(sg_rule,
                                             'to-lport',
                                             match)
        sg_rule['direction'] = 'egress'
        match = 'inport == "port-id" && ip4 && ip4.dst == 1.1.1.0/24'
        self._test__add_sg_rule_acl_for_port(sg_rule,
                                             'from-lport',
                                             match)

    def test__add_sg_rule_acl_for_port_remote_group(self):
        sg_rule = {'direction': 'ingress',
                   'ethertype': 'IPv4',
                   'remote_group_id': 'sg1',
                   'remote_ip_prefix': None,
                   'protocol': None}
        sg_ports = [{'security_group_id': 'sg1',
                     'port_id': 'port-id1'},
                    {'security_group_id': 'sg1',
                     'port_id': 'port-id2'}]
        port1 = {'id': 'port-id1',
                 'fixed_ips': [{'subnet_id': 'subnet-id',
                                'ip_address': '1.1.1.100'},
                               {'subnet_id': 'subnet-id',
                                'ip_address': '1.1.1.101'}]}
        port2 = {'id': 'port-id1',
                 'fixed_ips': [{'subnet_id': 'subnet-id',
                                'ip_address': '1.1.1.102'},
                               {'subnet_id': 'subnet-id-v6',
                                'ip_address': '2001:0db8::1:0:0:1'}]}
        ports = [port1, port2]

        subnet = {'id': 'subnet-id',
                  'ip_version': 4}
        subnet_v6 = {'id': 'subnet-id-v6',
                     'ip_version': 6}
        subnets = {'subnet-id': subnet,
                   'subnet-id-v6': subnet_v6}

        def _get_subnet(context, id):
            return subnets[id]

        with mock.patch('neutron.db.securitygroups_db.SecurityGroupDbMixin.'
                        '_get_port_security_group_bindings',
                        return_value=sg_ports), \
            mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.'
                       'get_ports', return_value=ports), \
            mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.'
                       'get_subnet', side_effect=_get_subnet):

            match = 'outport == "port-id" && ip4 && (ip4.src == 1.1.1.100' \
                    ' || ip4.src == 1.1.1.101' \
                    ' || ip4.src == 1.1.1.102)'

            self._test__add_sg_rule_acl_for_port(sg_rule,
                                                 'to-lport',
                                                 match)
            sg_rule['direction'] = 'egress'
            match = 'inport == "port-id" && ip4 && (ip4.dst == 1.1.1.100' \
                    ' || ip4.dst == 1.1.1.101' \
                    ' || ip4.dst == 1.1.1.102)'
            self._test__add_sg_rule_acl_for_port(sg_rule,
                                                 'from-lport',
                                                 match)

    def test__update_acls_compute_difference(self):
        lswitch_name = 'lswitch-1'
        port1 = {'id': 'port-id1',
                 'network_id': lswitch_name,
                 'fixed_ips': [{'subnet_id': 'subnet-id',
                                'ip_address': '1.1.1.101'},
                               {'subnet_id': 'subnet-id-v6',
                                'ip_address': '2001:0db8::1:0:0:1'}]}
        port2 = {'id': 'port-id2',
                 'network_id': lswitch_name,
                 'fixed_ips': [{'subnet_id': 'subnet-id',
                                'ip_address': '1.1.1.102'},
                               {'subnet_id': 'subnet-id-v6',
                                'ip_address': '2001:0db8::1:0:0:2'}]}
        ports = [port1, port2]
        # OLD ACLs, allow IPv4 communication
        aclport1_old1 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port1['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip4 && (ip.src == %s)' %
                         (port1['id'], port1['fixed_ips'][0]['ip_address'])}
        aclport1_old2 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port1['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip6 && (ip.src == %s)' %
                         (port1['id'], port1['fixed_ips'][1]['ip_address'])}
        aclport1_old3 = {'priority': 1002, 'direction': 'to-lport',
                         'lport': port1['id'], 'lswitch': lswitch_name,
                         'match': 'ip4 && (ip.src == %s)' %
                         (port2['fixed_ips'][0]['ip_address'])}
        port1_acls_old = [aclport1_old1, aclport1_old2, aclport1_old3]
        aclport2_old1 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port2['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip4 && (ip.src == %s)' %
                         (port2['id'], port2['fixed_ips'][0]['ip_address'])}
        aclport2_old2 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port2['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip6 && (ip.src == %s)' %
                         (port2['id'], port2['fixed_ips'][1]['ip_address'])}
        aclport2_old3 = {'priority': 1002, 'direction': 'to-lport',
                         'lport': port2['id'], 'lswitch': lswitch_name,
                         'match': 'ip4 && (ip.src == %s)' %
                         (port1['fixed_ips'][0]['ip_address'])}
        port2_acls_old = [aclport2_old1, aclport2_old2, aclport2_old3]
        acls_old_dict = {'%s' % (port1['id']): port1_acls_old,
                         '%s' % (port2['id']): port2_acls_old}
        acl_obj_dict = {str(aclport1_old1): 'row1',
                        str(aclport1_old2): 'row2',
                        str(aclport1_old3): 'row3',
                        str(aclport2_old1): 'row4',
                        str(aclport2_old2): 'row5',
                        str(aclport2_old3): 'row6'}
        # NEW ACLs, allow IPv6 communication
        aclport1_new1 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port1['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip4 && (ip.src == %s)' %
                         (port1['id'], port1['fixed_ips'][0]['ip_address'])}
        aclport1_new2 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port1['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip6 && (ip.src == %s)' %
                         (port1['id'], port1['fixed_ips'][1]['ip_address'])}
        aclport1_new3 = {'priority': 1002, 'direction': 'to-lport',
                         'lport': port1['id'], 'lswitch': lswitch_name,
                         'match': 'ip6 && (ip.src == %s)' %
                         (port2['fixed_ips'][1]['ip_address'])}
        port1_acls_new = [aclport1_new1, aclport1_new2, aclport1_new3]
        aclport2_new1 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port2['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip4 && (ip.src == %s)' %
                         (port2['id'], port2['fixed_ips'][0]['ip_address'])}
        aclport2_new2 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port2['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip6 && (ip.src == %s)' %
                         (port2['id'], port2['fixed_ips'][1]['ip_address'])}
        aclport2_new3 = {'priority': 1002, 'direction': 'to-lport',
                         'lport': port2['id'], 'lswitch': lswitch_name,
                         'match': 'ip6 && (ip.src == %s)' %
                         (port1['fixed_ips'][1]['ip_address'])}
        port2_acls_new = [aclport2_new1, aclport2_new2, aclport2_new3]
        acls_new_dict = {'%s' % (port1['id']): port1_acls_new,
                         '%s' % (port2['id']): port2_acls_new}

        acls_new_dict_copy = copy.deepcopy(acls_new_dict)

        # Invoke _compute_acl_differences
        update_cmd = cmd.UpdateACLsCommand(self.plugin._ovn,
                                           [lswitch_name],
                                           iter(ports),
                                           acls_new_dict
                                           )
        acl_dels, acl_adds =\
            update_cmd._compute_acl_differences(iter(ports),
                                                acls_old_dict,
                                                acls_new_dict,
                                                acl_obj_dict)
        # Sort the results for comparison
        for row in six.itervalues(acl_dels):
            row.sort()
        for row in six.itervalues(acl_adds):
            row.sort()
        # Expected Difference (Sorted)
        acl_del_exp = {lswitch_name: ['row3', 'row6']}
        acl_adds_exp = {lswitch_name:
                        [{'priority': 1002, 'direction': 'to-lport',
                          'match': 'ip6 && (ip.src == %s)' %
                          (port1['fixed_ips'][1]['ip_address'])},
                         {'priority': 1002, 'direction': 'to-lport',
                          'match': 'ip6 && (ip.src == %s)' %
                          (port2['fixed_ips'][1]['ip_address'])}]}
        self.assertEqual(acl_dels, acl_del_exp)
        self.assertEqual(acl_adds, acl_adds_exp)

        # make sure argument add_acl=False will take no affect in
        # need_compare=True scenario
        update_cmd_with_acl = cmd.UpdateACLsCommand(self.plugin._ovn,
                                                    [lswitch_name],
                                                    iter(ports),
                                                    acls_new_dict_copy,
                                                    need_compare=True,
                                                    is_add_acl=False)
        new_acl_dels, new_acl_adds =\
            update_cmd_with_acl._compute_acl_differences(iter(ports),
                                                         acls_old_dict,
                                                         acls_new_dict_copy,
                                                         acl_obj_dict)
        for row in six.itervalues(new_acl_dels):
            row.sort()
        for row in six.itervalues(new_acl_adds):
            row.sort()
        self.assertEqual(acl_dels, new_acl_dels)
        self.assertEqual(acl_adds, new_acl_adds)

    def test__get_update_data_without_compare(self):
        lswitch_name = 'lswitch-1'
        port1 = {'id': 'port-id1',
                 'network_id': lswitch_name,
                 'fixed_ips': mock.Mock()}
        port2 = {'id': 'port-id2',
                 'network_id': lswitch_name,
                 'fixed_ips': mock.Mock()}
        ports = [port1, port2]
        aclport1_new = {'priority': 1002, 'direction': 'to-lport',
                        'match': 'outport == %s && ip4 && icmp4' %
                        (port1['id'])}
        aclport2_new = {'priority': 1002, 'direction': 'to-lport',
                        'match': 'outport == %s && ip4 && icmp4' %
                        (port2['id'])}
        acls_new_dict = {'%s' % (port1['id']): aclport1_new,
                         '%s' % (port2['id']): aclport2_new}

        # test for creating new acls
        update_cmd_add_acl = cmd.UpdateACLsCommand(self.plugin._ovn,
                                                   [lswitch_name],
                                                   iter(ports),
                                                   acls_new_dict,
                                                   need_compare=False,
                                                   is_add_acl=True)
        lswitch_dict, acl_del_dict, acl_add_dict = \
            update_cmd_add_acl._get_update_data_without_compare()
        self.assertIn('neutron-lswitch-1', lswitch_dict)
        self.assertEqual({}, acl_del_dict)
        expected_acls = {'neutron-lswitch-1': [aclport1_new, aclport2_new]}
        self.assertEqual(expected_acls, acl_add_dict)

        # test for deleting existing acls
        acl1 = mock.Mock(
            match='outport == port-id1 && ip4 && icmp4')
        acl2 = mock.Mock(
            match='outport == port-id2 && ip4 && icmp4')
        acl3 = mock.Mock(
            match='outport == port-id1 && ip4 && (ip4.src == fake_ip)')
        lswitch_obj = mock.Mock(
            name='neutron-lswitch-1', acls=[acl1, acl2, acl3])
        with mock.patch('neutron.agent.ovsdb.native.idlutils.row_by_value',
                        return_value=lswitch_obj):
            update_cmd_del_acl = cmd.UpdateACLsCommand(self.plugin._ovn,
                                                       [lswitch_name],
                                                       iter(ports),
                                                       acls_new_dict,
                                                       need_compare=False,
                                                       is_add_acl=False)
            lswitch_dict, acl_del_dict, acl_add_dict = \
                update_cmd_del_acl._get_update_data_without_compare()
            self.assertIn('neutron-lswitch-1', lswitch_dict)
            expected_acls = {'neutron-lswitch-1': [acl1, acl2]}
            self.assertEqual(expected_acls, acl_del_dict)
            self.assertEqual({}, acl_add_dict)


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

        self.fake_router = {'id': 'router-id',
                            'name': 'router',
                            'admin_state_up': False,
                            'routes': [{'destination': '1.1.1.0/24',
                                        'nexthop': '2.2.2.3'}]}

    @mock.patch('neutron.db.l3_dvr_db.L3_NAT_with_dvr_db_mixin.'
                'add_router_interface')
    def test_add_router_interface(self, func):
        self.plugin._ovn.add_lrouter_port = mock.Mock()
        self.plugin._ovn.set_lrouter_port_in_lport = mock.Mock()

        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        with mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.'
                        'get_port', return_value=self.fake_router_port),\
            mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.'
                       'get_subnet', return_value=self.fake_subnet):
            self.plugin.add_router_interface(self.context, router_id,
                                             interface_info)

        self.plugin._ovn.add_lrouter_port.assert_called_once_with(
            lrouter='neutron-router-id',
            mac='aa:aa:aa:aa:aa:aa',
            name='lrp-router-port-id',
            network='10.0.0.100/24')
        self.plugin._ovn.set_lrouter_port_in_lport.assert_called_once_with(
            'router-port-id', 'lrp-router-port-id')

    @mock.patch('neutron.db.l3_dvr_db.L3_NAT_with_dvr_db_mixin.'
                'remove_router_interface')
    def test_remove_router_interface(self, func):
        self.plugin._ovn.delete_lrouter_port = mock.Mock()

        router_id = 'router-id'
        interface_info = {'port_id': 'router-port-id'}
        with mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.'
                        'get_port', return_value=self.fake_router_port),\
            mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.'
                       'get_ports', return_value=[self.fake_router_port]):
            self.plugin.remove_router_interface(
                self.context, router_id, interface_info)

        self.plugin._ovn.delete_lrouter_port.assert_called_once_with(
            'lrp-router-port-id', 'neutron-router-id', if_exists=False)

    @mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.update_router')
    def test_update_router_admin_state_no_change(self, func):
        router_id = 'router-id'
        update_data = {'router': {'admin_state_up': False}}
        with mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.'
                        'get_router', return_value=self.fake_router),\
            mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                       'update_router', return_value=self.fake_router):
            self.plugin.update_router(self.context, router_id, update_data)
        self.assertFalse(self.plugin._ovn.update_lrouter.called)

    @mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.update_router')
    def test_update_router_admin_state_change(self, func):
        router_id = 'router-id'
        update_data = {'router': {'admin_state_up': True}}
        with mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.'
                        'get_router', return_value=self.fake_router),\
            mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                       'update_router', return_value=self.fake_router):
            self.plugin.update_router(self.context, router_id, update_data)
        self.plugin._ovn.update_lrouter.assert_called_once_with(
            'neutron-router-id', enabled=True)

    @mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.update_router')
    def test_update_router_name_no_change(self, func):
        router_id = 'router-id'
        update_data = {'router': {'name': 'router'}}
        with mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.'
                        'get_router', return_value=self.fake_router),\
            mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                       'update_router', return_value=self.fake_router):
            self.plugin.update_router(self.context, router_id, update_data)
        self.assertFalse(self.plugin._ovn.update_lrouter.called)

    @mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.update_router')
    def test_update_router_name_change(self, func):
        router_id = 'router-id'
        update_data = {'router': {'name': 'test'}}
        with mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.'
                        'get_router', return_value=self.fake_router),\
            mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                       'update_router', return_value=self.fake_router):
            self.plugin.update_router(self.context, router_id, update_data)
        self.plugin._ovn.update_lrouter.assert_called_once_with(
            'neutron-router-id',
            external_ids={'neutron:router_name': 'test'})

    @mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.update_router')
    def test_update_router_static_route_no_change(self, func):
        router_id = 'router-id'
        update_data = {'router': {'routes': [{'destination': '1.1.1.0/24',
                                              'nexthop': '2.2.2.3'}]}}
        with mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.'
                        'get_router', return_value=self.fake_router),\
            mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                       'update_router', return_value=self.fake_router):
            self.plugin.update_router(self.context, router_id, update_data)
        self.assertFalse(self.plugin._ovn.add_static_route.called)
        self.assertFalse(self.plugin._ovn.delete_static_route.called)

    @mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.update_router')
    def test_update_router_static_route_change(self, func):
        router_id = 'router-id'
        update_data = {'router': {'routes': [{'destination': '2.2.2.0/24',
                                              'nexthop': '3.3.3.3'}]}}
        with mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.'
                        'get_router', return_value=self.fake_router),\
            mock.patch('neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.'
                       'update_router', return_value=self.fake_router):
            self.plugin.update_router(self.context, router_id, update_data)
        self.plugin._ovn.add_static_route.assert_called_once_with(
            'neutron-router-id',
            ip_prefix='2.2.2.0/24', nexthop='3.3.3.3')
        self.plugin._ovn.delete_static_route.assert_called_once_with(
            'neutron-router-id',
            ip_prefix='1.1.1.0/24', nexthop='2.2.2.3')


class TestL3NatTestCase(test_l3_plugin.L3NatDBIntTestCase,
                        OVNPluginTestCase):
    pass


class DHCPOptsTestCase(test_dhcpopts.TestExtraDhcpOpt, OVNPluginTestCase):

    def setUp(self, plugin=None):
        super(test_dhcpopts.ExtraDhcpOptDBTestCase, self).setUp(
            plugin=PLUGIN_NAME)


class TestAZNetworkTestCase(test_az.TestAZNetworkCase, OVNPluginTestCase):

    def setUp(self, plugin=None):
        ext_mgr = test_az.AZExtensionManager()
        super(test_az.TestAZNetworkCase, self).setUp(
            plugin=PLUGIN_NAME, ext_mgr=ext_mgr)


class TestOvnPortSecurity(test_portsecurity.TestPortSecurity,
                          OVNPluginTestCase):
    def setUp(self, plugin=PLUGIN_NAME):
        super(TestOvnPortSecurity, self).setUp(plugin=plugin)


class TestOvnAllowedAddressPairs(test_aap.TestAllowedAddressPairs,
                                 OVNPluginTestCase):
    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None):
        super(TestOvnAllowedAddressPairs, self).setUp(plugin=plugin,
                                                      ext_mgr=ext_mgr)


class TestOvnAddressScope(test_as.TestAddressScope,
                          OVNPluginTestCase):
    def setUp(self, plugin=None):
        ext_mgr = test_as.AddressScopeTestExtensionManager()
        super(test_as.TestAddressScope, self).setUp(
            plugin=PLUGIN_NAME, ext_mgr=ext_mgr)

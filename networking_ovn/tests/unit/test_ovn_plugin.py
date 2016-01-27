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
from oslo_config import cfg
from webob import exc

from neutron.common import exceptions as n_exc
from neutron import context
from neutron.extensions import portbindings
from neutron.tests import tools
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_extra_dhcp_opt as test_dhcpopts
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin

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

    def test__drop_all_ip_traffic_for_port(self):
        self.plugin._ovn.add_acl = mock.Mock()
        self.plugin._drop_all_ip_traffic_for_port(self.fake_port, mock.Mock())
        self.plugin._ovn.add_acl.assert_has_calls(
            [mock.call(action='drop', direction='from-lport',
                       external_ids={'neutron:lport': self.fake_port['id']},
                       log=False, lport=self.fake_port['id'],
                       lswitch='neutron-network_id1',
                       match='inport == "fake_port_id1" && ip', priority=1001),
             mock.call(action='drop', direction='to-lport',
                       external_ids={'neutron:lport': self.fake_port['id']},
                       log=False, lport=self.fake_port['id'],
                       lswitch='neutron-network_id1',
                       match='outport == "fake_port_id1" && ip',
                       priority=1001)])

    def test__add_acl_dhcp_no_cache(self):
        self.plugin._ovn.add_acl = mock.Mock()
        with mock.patch.object(self.plugin, 'get_subnet',
                               return_value=self.fake_subnet):
            self.plugin._add_acl_dhcp(self.context, self.fake_port,
                                      mock.Mock(), {})

        expected_match_to_lport = (
            'outport == "%s" && ip4 && ip4.src == %s && udp && udp.src == 67 '
            '&& udp.dst == 68') % (self.fake_port['id'],
                                   self.fake_subnet['cidr'])
        expected_match_from_lport = (
            'inport == "%s" && ip4 && '
            '(ip4.dst == 255.255.255.255 || ip4.dst == %s) && '
            'udp && udp.src == 68 && udp.dst == 67'
        ) % (self.fake_port['id'], self.fake_subnet['cidr'])
        self.plugin._ovn.add_acl.assert_has_calls(
            [mock.call(action='allow', direction='to-lport',
                       external_ids={'neutron:lport': 'fake_port_id1'},
                       log=False, lport='fake_port_id1',
                       lswitch='neutron-network_id1',
                       match=expected_match_to_lport, priority=1002),
             mock.call(action='allow', direction='from-lport',
                       external_ids={'neutron:lport': 'fake_port_id1'},
                       log=False, lport='fake_port_id1',
                       lswitch='neutron-network_id1',
                       match=expected_match_from_lport, priority=1002)])

    def test__add_acl_dhcp_cache(self):
        self.plugin._ovn.add_acl = mock.Mock()
        self.plugin._add_acl_dhcp(self.context, self.fake_port, mock.Mock(),
                                  {'subnet_id1': self.fake_subnet})
        expected_match_to_lport = (
            'outport == "%s" && ip4 && ip4.src == %s && udp && udp.src == 67 '
            '&& udp.dst == 68') % (self.fake_port['id'],
                                   self.fake_subnet['cidr'])
        expected_match_from_lport = (
            'inport == "%s" && ip4 && '
            '(ip4.dst == 255.255.255.255 || ip4.dst == %s) && '
            'udp && udp.src == 68 && udp.dst == 67'
        ) % (self.fake_port['id'], self.fake_subnet['cidr'])
        self.plugin._ovn.add_acl.assert_has_calls(
            [mock.call(action='allow', direction='to-lport',
                       external_ids={'neutron:lport': 'fake_port_id1'},
                       log=False, lport='fake_port_id1',
                       lswitch='neutron-network_id1',
                       match=expected_match_to_lport, priority=1002),
             mock.call(action='allow', direction='from-lport',
                       external_ids={'neutron:lport': 'fake_port_id1'},
                       log=False, lport='fake_port_id1',
                       lswitch='neutron-network_id1',
                       match=expected_match_from_lport, priority=1002)])

    def test__add_acls_no_sec_group(self):
        self.plugin._ovn.add_acl = mock.Mock()
        self.plugin._add_acls(
            self.context,
            port={'security_groups': []},
            txn=mock.Mock())
        self.plugin._ovn.add_acl.assert_not_called()

    def _test__add_sg_rule_acl_for_port(self, sg_rule, direction, match):
        port = {'id': 'port-id',
                'network_id': 'network-id'}
        self.plugin._ovn.add_acl = mock.Mock()
        self.plugin._add_sg_rule_acl_for_port(
            self.context,
            port,
            sg_rule,
            sg_ports_cache={},
            subnet_cache={})
        self.plugin._ovn.add_acl.assert_called_once_with(
            lswitch='neutron-network-id',
            lport='port-id',
            priority=ovn_const.ACL_PRIORITY_ALLOW,
            action=ovn_const.ACL_ACTION_ALLOW_RELATED,
            log=False,
            direction=direction,
            match=match,
            external_ids={'neutron:lport': 'port-id'})

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

    @mock.patch('neutron.db.l3_gwmode_db.L3_NAT_db_mixin.'
                'remove_router_interface')
    def test_remove_router_interface(self, func):
        self.plugin._ovn.delete_lrouter_port = mock.Mock()
        cfg.CONF.set_override('ovn_l3_mode', True, 'ovn')

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


class TestL3NatTestCase(test_l3_plugin.L3NatDBIntTestCase,
                        OVNPluginTestCase):
    pass


class DHCPOptsTestCase(test_dhcpopts.TestExtraDhcpOpt, OVNPluginTestCase):

    def setUp(self, plugin=None):
        super(test_dhcpopts.ExtraDhcpOptDBTestCase, self).setUp(
            plugin=PLUGIN_NAME)

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
from webob import exc

from neutron_lib import exceptions as n_exc

from neutron.callbacks import events
from neutron.callbacks import resources
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.ml2 import config
from neutron.tests import tools
from neutron.tests.unit.extensions import test_segment
from neutron.tests.unit.plugins.ml2 import test_ext_portsecurity
from neutron.tests.unit.plugins.ml2 import test_plugin

from networking_ovn.common import acl as ovn_acl
from networking_ovn.common import constants as ovn_const
from networking_ovn.ovsdb import impl_idl_ovn
from networking_ovn.tests.unit import fakes


class TestOVNMechanismDriver(test_plugin.Ml2PluginV2TestCase):

    _mechanism_drivers = ['logger', 'ovn']
    _extension_drivers = ['port_security']

    def setUp(self):
        impl_idl_ovn.OvsdbNbOvnIdl = fakes.FakeOvsdbNbOvnIdl()
        impl_idl_ovn.OvsdbSbOvnIdl = fakes.FakeOvsdbSbOvnIdl()
        config.cfg.CONF.set_override('extension_drivers',
                                     self._extension_drivers,
                                     group='ml2')
        config.cfg.CONF.set_override('tenant_network_types',
                                     ['geneve'],
                                     group='ml2')
        config.cfg.CONF.set_override('vni_ranges',
                                     ['1:65536'],
                                     group='ml2_type_geneve')
        super(TestOVNMechanismDriver, self).setUp()
        mm = manager.NeutronManager.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers['ovn'].obj
        self.mech_driver.initialize()
        self.mech_driver._nb_ovn = fakes.FakeOvsdbNbOvnIdl()
        self.mech_driver._sb_ovn = fakes.FakeOvsdbSbOvnIdl()

        self.fake_subnet = fakes.FakeSubnet.create_one_subnet().info()
        self.fake_port_no_sg = fakes.FakePort.create_one_port().info()

        self.fake_sg_rule = \
            fakes.FakeSecurityGroupRule.create_one_security_group_rule().info()
        self.fake_sg = fakes.FakeSecurityGroup.create_one_security_group(
            attrs={'security_group_rules': [self.fake_sg_rule]}
        ).info()
        self.fake_port_sg = fakes.FakePort.create_one_port(
            attrs={'security_groups': [self.fake_sg['id']],
                   'fixed_ips': [{'subnet_id': self.fake_subnet['id'],
                                  'ip_address': '10.10.10.20'}]}
        ).info()

        self.sg_cache = {self.fake_sg['id']: self.fake_sg}
        self.sg_ports_cache = {}
        self.subnet_cache = {self.fake_subnet['id']: self.fake_subnet}

    def test__process_sg_notifications_sg_update(self):
        with mock.patch(
            'networking_ovn.common.acl.update_acls_for_security_group'
        ) as ovn_acl_up:
            self.mech_driver._process_sg_notification(
                resources.SECURITY_GROUP, events.AFTER_UPDATE, {},
                security_group_id='sg_id')
            ovn_acl_up.assert_called_once_with(
                mock.ANY, mock.ANY, mock.ANY,
                'sg_id', is_add_acl=True, rule=None)

    def test__process_sg_notifications_sgr_create(self):
        with mock.patch(
            'networking_ovn.common.acl.update_acls_for_security_group'
        ) as ovn_acl_up:
            rule = {'security_group_id': 'sg_id'}
            self.mech_driver._process_sg_notification(
                resources.SECURITY_GROUP_RULE, events.AFTER_CREATE, {},
                security_group_rule=rule)
            ovn_acl_up.assert_called_once_with(
                mock.ANY, mock.ANY, mock.ANY,
                'sg_id', is_add_acl=True, rule=rule)

    def test_process_sg_notifications_sgr_delete(self):
        rule = {'security_group_id': 'sg_id'}
        with mock.patch(
            'networking_ovn.common.acl.update_acls_for_security_group'
        ) as ovn_acl_up:
            with mock.patch(
                'neutron.db.securitygroups_db.'
                'SecurityGroupDbMixin.get_security_group_rule',
                return_value=rule
            ):
                self.mech_driver._process_sg_notification(
                    resources.SECURITY_GROUP_RULE, events.BEFORE_DELETE, {},
                    security_group_rule=rule)
                ovn_acl_up.assert_called_once_with(
                    mock.ANY, mock.ANY, mock.ANY,
                    'sg_id', is_add_acl=False, rule=rule)

    def test_add_acls_no_sec_group(self):
        acls = ovn_acl.add_acls(self.mech_driver._plugin,
                                mock.Mock(),
                                self.fake_port_no_sg,
                                {}, {}, {})
        self.assertEqual([], acls)

    def test_add_acls_with_sec_group(self):
        expected_acls = []
        expected_acls += ovn_acl.drop_all_ip_traffic_for_port(
            self.fake_port_sg)
        expected_acls += ovn_acl.add_acl_dhcp(
            self.fake_port_sg, self.fake_subnet)
        sg_rule_acl = ovn_acl.add_sg_rule_acl_for_port(
            self.fake_port_sg, self.fake_sg_rule,
            'outport == "' + self.fake_port_sg['id'] + '" ' +
            '&& ip4 && ip4.src == 0.0.0.0/0 ' +
            '&& tcp && tcp.dst == 22')
        expected_acls.append(sg_rule_acl)

        # Test with caches
        acls = ovn_acl.add_acls(self.mech_driver._plugin,
                                mock.Mock(),
                                self.fake_port_sg,
                                self.sg_cache,
                                self.sg_ports_cache,
                                self.subnet_cache)
        self.assertEqual(expected_acls, acls)

        # Test without caches
        with mock.patch('neutron.db.db_base_plugin_v2.'
                        'NeutronDbPluginV2.get_subnet',
                        return_value=self.fake_subnet), \
            mock.patch('neutron.db.securitygroups_db.'
                       'SecurityGroupDbMixin.get_security_group',
                       return_value=self.fake_sg):

            acls = ovn_acl.add_acls(self.mech_driver._plugin,
                                    mock.Mock(),
                                    self.fake_port_sg,
                                    {}, {}, {})
            self.assertEqual(expected_acls, acls)

        # Test with security groups disabled
        with mock.patch('networking_ovn.common.acl.is_sg_enabled',
                        return_value=False):
            acls = ovn_acl.add_acls(self.mech_driver._plugin,
                                    mock.Mock(),
                                    self.fake_port_sg,
                                    self.sg_cache,
                                    self.sg_ports_cache,
                                    self.subnet_cache)
            self.assertEqual([], acls)

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
                        self.mech_driver._nb_ovn.create_lswitch_port.called)
                    called_args_dict = (
                        (self.mech_driver._nb_ovn.create_lswitch_port
                         ).call_args_list[0][1])
                    self.assertEqual(['00:00:00:00:00:01 10.0.0.2 10.0.0.4'],
                                     called_args_dict.get('port_security'))

                    data = {'port': {'mac_address': '00:00:00:00:00:02'}}
                    req = self.new_update_request(
                        'ports',
                        data, port['port']['id'])
                    req.get_response(self.api)
                    self.assertTrue(
                        self.mech_driver._nb_ovn.set_lswitch_port.called)
                    called_args_dict = (
                        (self.mech_driver._nb_ovn.set_lswitch_port
                         ).call_args_list[0][1])
                    self.assertEqual(['00:00:00:00:00:02 10.0.0.2 10.0.0.4'],
                                     called_args_dict.get('port_security'))

    def test_create_port_with_disabled_security(self):
        kwargs = {'port_security_enabled': False}
        with self.network(set_context=True, tenant_id='test') as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               arg_list=('port_security_enabled',),
                               set_context=True, tenant_id='test',
                               **kwargs) as port:
                    self.assertTrue(
                        self.mech_driver._nb_ovn.create_lswitch_port.called)
                    called_args_dict = (
                        (self.mech_driver._nb_ovn.create_lswitch_port
                         ).call_args_list[0][1])
                    self.assertEqual([],
                                     called_args_dict.get('port_security'))

                    data = {'port': {'mac_address': '00:00:00:00:00:01'}}
                    req = self.new_update_request(
                        'ports',
                        data, port['port']['id'])
                    req.get_response(self.api)
                    self.assertTrue(
                        self.mech_driver._nb_ovn.set_lswitch_port.called)
                    called_args_dict = (
                        (self.mech_driver._nb_ovn.set_lswitch_port
                         ).call_args_list[0][1])
                    self.assertEqual([],
                                     called_args_dict.get('port_security'))

    def test_create_port_security_allowed_address_pairs(self):
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
                    port_ip = port['port'].get('fixed_ips')[0]['ip_address']
                    self.assertTrue(
                        self.mech_driver._nb_ovn.create_lswitch_port.called)
                    called_args_dict = (
                        (self.mech_driver._nb_ovn.create_lswitch_port
                         ).call_args_list[0][1])
                    self.assertEqual(
                        tools.UnorderedList(
                            ["22:22:22:22:22:22 2.2.2.2",
                             port['port']['mac_address'] + ' ' + port_ip
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
                        self.mech_driver._nb_ovn.set_lswitch_port.called)
                    called_args_dict = (
                        (self.mech_driver._nb_ovn.set_lswitch_port
                         ).call_args_list[0][1])
                    self.assertEqual(tools.UnorderedList(
                        ["22:22:22:22:22:22 2.2.2.2",
                         "00:00:00:00:00:01 " + port_ip,
                         old_mac + " 1.1.1.1"]),
                        called_args_dict.get('port_security'))

    def _create_fake_network_context(self,
                                     network_type,
                                     physical_network=None,
                                     segmentation_id=None):
        network_attrs = {'provider:network_type': network_type,
                         'provider:physical_network': physical_network,
                         'provider:segmentation_id': segmentation_id}
        segment_attrs = {'network_type': network_type,
                         'physical_network': physical_network,
                         'segmentation_id': segmentation_id}
        fake_network = \
            fakes.FakeNetwork.create_one_network(attrs=network_attrs).info()
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        return fakes.FakeNetworkContext(fake_network, fake_segments)

    def test_create_network_precommit(self):
        # Test supported network types.
        fake_network_context = self._create_fake_network_context('local')
        self.mech_driver.create_network_precommit(fake_network_context)
        fake_network_context = self._create_fake_network_context(
            'flat', physical_network='physnet')
        self.mech_driver.create_network_precommit(fake_network_context)
        fake_network_context = self._create_fake_network_context(
            'geneve', segmentation_id=10)
        self.mech_driver.create_network_precommit(fake_network_context)
        fake_network_context = self._create_fake_network_context(
            'vlan', physical_network='physnet', segmentation_id=11)
        self.mech_driver.create_network_precommit(fake_network_context)

        # Test unsupported network types.
        fake_network_context = self._create_fake_network_context(
            'vxlan', segmentation_id=12)
        self.assertRaises(n_exc.InvalidInput,
                          self.mech_driver.create_network_precommit,
                          fake_network_context)
        fake_network_context = self._create_fake_network_context(
            'gre', segmentation_id=13)
        self.assertRaises(n_exc.InvalidInput,
                          self.mech_driver.create_network_precommit,
                          fake_network_context)

        # TODO(rtheis): Add support for multi-provider networks when
        # routed networks are supported.
        fake_network_context = self._create_fake_network_context('flat')
        fake_network_context.current['segments'] = \
            fake_network_context.network_segments
        self.assertRaises(n_exc.InvalidInput,
                          self.mech_driver.create_network_precommit,
                          fake_network_context)


class OVNMechanismDriverTestCase(test_plugin.Ml2PluginV2TestCase):
    _mechanism_drivers = ['logger', 'ovn']

    def setUp(self):
        config.cfg.CONF.set_override('tenant_network_types',
                                     ['geneve'],
                                     group='ml2')
        config.cfg.CONF.set_override('vni_ranges',
                                     ['1:65536'],
                                     group='ml2_type_geneve')
        super(OVNMechanismDriverTestCase, self).setUp()
        mm = manager.NeutronManager.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers['ovn'].obj
        self.mech_driver._nb_ovn = fakes.FakeOvsdbNbOvnIdl()
        self.mech_driver._sb_ovn = fakes.FakeOvsdbSbOvnIdl()
        self.mech_driver._insert_port_provisioning_block = mock.Mock()
        self.mech_driver.vif_type = portbindings.VIF_TYPE_OVS


class TestOVNMechansimDriverBasicGet(test_plugin.TestMl2BasicGet,
                                     OVNMechanismDriverTestCase):
    pass


class TestOVNMechansimDriverV2HTTPResponse(test_plugin.TestMl2V2HTTPResponse,
                                           OVNMechanismDriverTestCase):
    pass


class TestOVNMechansimDriverNetworksV2(test_plugin.TestMl2NetworksV2,
                                       OVNMechanismDriverTestCase):

    # TODO(rtheis): Add support for multi-provider networks when
    # routed networks are supported.
    def test_list_mpnetworks_with_segmentation_id(self):
        pass


class TestOVNMechansimDriverSubnetsV2(test_plugin.TestMl2SubnetsV2,
                                      OVNMechanismDriverTestCase):

    # NOTE(rtheis): Mock the OVN port update since it is getting subnet
    # information for ACL processing. This interferes with the update_port
    # mock already done by the test.
    def test_subnet_update_ipv4_and_ipv6_pd_v6stateless_subnets(self):
        with mock.patch.object(self.mech_driver, '_update_port_in_ovn'):
            super(TestOVNMechansimDriverSubnetsV2, self).\
                test_subnet_update_ipv4_and_ipv6_pd_v6stateless_subnets()

    # NOTE(rtheis): Mock the OVN port update since it is getting subnet
    # information for ACL processing. This interferes with the update_port
    # mock already done by the test.
    def test_subnet_update_ipv4_and_ipv6_pd_slaac_subnets(self):
        with mock.patch.object(self.mech_driver, '_update_port_in_ovn'):
            super(TestOVNMechansimDriverSubnetsV2, self).\
                test_subnet_update_ipv4_and_ipv6_pd_slaac_subnets()


class TestOVNMechansimDriverPortsV2(test_plugin.TestMl2PortsV2,
                                    OVNMechanismDriverTestCase):

    # NOTE(rtheis): Override this test to verify that updating
    # a port MAC fails when the port is bound.
    def test_update_port_mac(self):
        self.check_update_port_mac(
            host_arg={portbindings.HOST_ID: 'fake-host'},
            arg_list=(portbindings.HOST_ID,),
            expected_status=exc.HTTPConflict.code,
            expected_error='PortBound')


class TestOVNMechansimDriverAllowedAddressPairs(
        test_plugin.TestMl2AllowedAddressPairs,
        OVNMechanismDriverTestCase):
    pass


class TestOVNMechansimDriverPortSecurity(
        test_ext_portsecurity.PSExtDriverTestCase,
        OVNMechanismDriverTestCase):
    pass


class TestOVNMechansimDriverSegment(test_segment.HostSegmentMappingTestCase):
    _mechanism_drivers = ['logger', 'ovn']

    def setUp(self):
        super(TestOVNMechansimDriverSegment, self).setUp()
        mm = manager.NeutronManager.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers['ovn'].obj
        self.mech_driver._nb_ovn = fakes.FakeOvsdbNbOvnIdl()
        self.mech_driver._sb_ovn = fakes.FakeOvsdbSbOvnIdl()

    def _test_segment_host_mapping(self):
        host = 'hostname'
        with self.network() as network:
            network = network['network']
        segment1 = self._test_create_segment(
            network_id=network['id'], physical_network='phys_net1',
            segmentation_id=200, network_type='vlan')['segment']

        self._test_create_segment(
            network_id=network['id'],
            segmentation_id=200,
            network_type='vxlan')['segment']
        self.mech_driver.update_segment_host_mapping(host, ['phys_net1'])
        segments_host_db = self._get_segments_for_host(host)
        self.assertEqual({segment1['id']}, set(segments_host_db))
        return network['id'], host

    def test_update_segment_host_mapping(self):
        network_id, host = self._test_segment_host_mapping()

        # Update the mapping
        segment2 = self._test_create_segment(
            network_id=network_id, physical_network='phys_net2',
            segmentation_id=201, network_type='vlan')['segment']
        self.mech_driver.update_segment_host_mapping(host, ['phys_net2'])
        segments_host_db = self._get_segments_for_host(host)
        self.assertEqual({segment2['id']}, set(segments_host_db))

    def test_clear_segment_host_mapping(self):
        _, host = self._test_segment_host_mapping()

        # Clear the mapping
        self.mech_driver.update_segment_host_mapping(host, [])
        segments_host_db = self._get_segments_for_host(host)
        self.assertEqual({}, segments_host_db)

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

import copy
import datetime
import uuid

import mock
from neutron.common import utils as n_utils
from neutron.db import provisioning_blocks
from neutron.db import segments_db
from neutron.plugins.ml2.drivers import type_geneve  # noqa
from neutron.services.revisions import revision_plugin
from neutron.tests.unit.extensions import test_segment
from neutron.tests.unit.plugins.ml2 import test_ext_portsecurity
from neutron.tests.unit.plugins.ml2 import test_plugin
from neutron.tests.unit.plugins.ml2 import test_security_group
from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import extra_dhcp_opt as edo_ext
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.tests import tools
from neutron_lib.utils import net as n_net
from oslo_config import cfg
from oslo_db import exception as os_db_exc
from oslo_serialization import jsonutils
from oslo_utils import timeutils
from oslo_utils import uuidutils
from webob import exc

from networking_ovn.common import config as ovn_config
from networking_ovn.common import constants as ovn_const
from networking_ovn.common import ovn_client
from networking_ovn.common import utils as ovn_utils
from networking_ovn.db import revision as db_rev
from networking_ovn.ml2 import mech_driver
from networking_ovn.tests.unit import fakes

OVN_PROFILE = ovn_const.OVN_PORT_BINDING_PROFILE


class TestOVNMechanismDriver(test_plugin.Ml2PluginV2TestCase):

    _mechanism_drivers = ['logger', 'ovn']
    _extension_drivers = ['port_security', 'dns']

    def setUp(self):
        cfg.CONF.set_override('extension_drivers',
                              self._extension_drivers,
                              group='ml2')
        cfg.CONF.set_override('tenant_network_types',
                              ['geneve'],
                              group='ml2')
        cfg.CONF.set_override('vni_ranges',
                              ['1:65536'],
                              group='ml2_type_geneve')
        ovn_config.cfg.CONF.set_override('ovn_metadata_enabled',
                                         False,
                                         group='ovn')
        ovn_config.cfg.CONF.set_override('dns_servers', ['8.8.8.8'],
                                         group='ovn')
        super(TestOVNMechanismDriver, self).setUp()
        mm = directory.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers['ovn'].obj
        self.mech_driver._nb_ovn = fakes.FakeOvsdbNbOvnIdl()
        self.mech_driver._sb_ovn = fakes.FakeOvsdbSbOvnIdl()
        self.nb_ovn = self.mech_driver._nb_ovn
        self.sb_ovn = self.mech_driver._sb_ovn

        self.fake_subnet = fakes.FakeSubnet.create_one_subnet().info()

        self.fake_sg_rule = \
            fakes.FakeSecurityGroupRule.create_one_security_group_rule().info()
        self.fake_sg = fakes.FakeSecurityGroup.create_one_security_group(
            attrs={'security_group_rules': [self.fake_sg_rule]}
        ).info()

        self.sg_cache = {self.fake_sg['id']: self.fake_sg}
        self.subnet_cache = {self.fake_subnet['id']: self.fake_subnet}
        mock.patch(
            "networking_ovn.common.acl._acl_columns_name_severity_supported",
            return_value=True
        ).start()
        revision_plugin.RevisionPlugin()
        p = mock.patch.object(ovn_utils, 'get_revision_number', return_value=1)
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(db_rev, 'bump_revision')
        p.start()
        self.addCleanup(p.stop)

    @mock.patch.object(db_rev, 'bump_revision')
    def test__create_security_group(self, mock_bump):
        self.mech_driver._create_security_group(
            resources.SECURITY_GROUP, events.AFTER_CREATE, {},
            security_group=self.fake_sg)
        external_ids = {ovn_const.OVN_SG_EXT_ID_KEY: self.fake_sg['id']}
        pg_name = ovn_utils.ovn_port_group_name(self.fake_sg['id'])

        self.nb_ovn.pg_add.assert_called_once_with(
            name=pg_name, acls=[], external_ids=external_ids)

        mock_bump.assert_called_once_with(
            self.fake_sg, ovn_const.TYPE_SECURITY_GROUPS)

    @mock.patch.object(db_rev, 'delete_revision')
    def test__delete_security_group(self, mock_del_rev):
        self.mech_driver._delete_security_group(
            resources.SECURITY_GROUP, events.AFTER_CREATE, {},
            security_group_id=self.fake_sg['id'])
        pg_name = ovn_utils.ovn_port_group_name(self.fake_sg['id'])

        self.nb_ovn.pg_del.assert_called_once_with(name=pg_name)

        mock_del_rev.assert_called_once_with(
            self.fake_sg['id'], ovn_const.TYPE_SECURITY_GROUPS)

    @mock.patch.object(db_rev, 'bump_revision')
    def test__process_sg_rule_notifications_sgr_create(self, mock_bump):
        with mock.patch(
            'networking_ovn.common.acl.update_acls_for_security_group'
        ) as ovn_acl_up:
            rule = {'security_group_id': 'sg_id'}
            self.mech_driver._process_sg_rule_notification(
                resources.SECURITY_GROUP_RULE, events.AFTER_CREATE, {},
                security_group_rule=rule)
            ovn_acl_up.assert_called_once_with(
                mock.ANY, mock.ANY, mock.ANY,
                'sg_id', rule, is_add_acl=True)
            mock_bump.assert_called_once_with(
                rule, ovn_const.TYPE_SECURITY_GROUP_RULES)

    @mock.patch.object(db_rev, 'delete_revision')
    def test_process_sg_rule_notifications_sgr_delete(self, mock_delrev):
        rule = {'id': 'sgr_id', 'security_group_id': 'sg_id'}
        with mock.patch(
            'networking_ovn.common.acl.update_acls_for_security_group'
        ) as ovn_acl_up:
            with mock.patch(
                'neutron.db.securitygroups_db.'
                'SecurityGroupDbMixin.get_security_group_rule',
                return_value=rule
            ):
                self.mech_driver._process_sg_rule_notification(
                    resources.SECURITY_GROUP_RULE, events.BEFORE_DELETE, {},
                    security_group_rule=rule)
                ovn_acl_up.assert_called_once_with(
                    mock.ANY, mock.ANY, mock.ANY,
                    'sg_id', rule, is_add_acl=False)
                mock_delrev.assert_called_once_with(
                    rule['id'], ovn_const.TYPE_SECURITY_GROUP_RULES)

    def test_port_invalid_binding_profile(self):
        invalid_binding_profiles = [
            {'tag': 0,
             'parent_name': 'fakename'},
            {'tag': 1024},
            {'tag': 1024, 'parent_name': 1024},
            {'parent_name': 'test'},
            {'tag': 'test'},
            {'vtep-physical-switch': 'psw1'},
            {'vtep-logical-switch': 'lsw1'},
            {'vtep-physical-switch': 'psw1', 'vtep-logical-switch': 1234},
            {'vtep-physical-switch': 1234, 'vtep-logical-switch': 'lsw1'},
            {'vtep-physical-switch': 'psw1', 'vtep-logical-switch': 'lsw1',
             'tag': 1024},
            {'vtep-physical-switch': 'psw1', 'vtep-logical-switch': 'lsw1',
             'parent_name': 'fakename'},
            {'vtep-physical-switch': 'psw1', 'vtep-logical-switch': 'lsw1',
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

    def test__validate_ignored_port_update_from_fip_port(self):
        p = {'id': 'id', 'device_owner': 'test'}
        ori_p = {'id': 'id', 'device_owner': const.DEVICE_OWNER_FLOATINGIP}
        self.assertRaises(mech_driver.OVNPortUpdateError,
                          self.mech_driver._validate_ignored_port,
                          p, ori_p)

    def test__validate_ignored_port_update_to_fip_port(self):
        p = {'id': 'id', 'device_owner': const.DEVICE_OWNER_FLOATINGIP}
        ori_p = {'id': 'port-id', 'device_owner': 'test'}
        self.assertRaises(mech_driver.OVNPortUpdateError,
                          self.mech_driver._validate_ignored_port,
                          p, ori_p)

    def test__validate_port_extra_dhcp_opts(self):
        opt = {'opt_name': 'bootfile-name',
               'opt_value': 'homer_simpson.bin',
               'ip_version': 4}
        port = {edo_ext.EXTRADHCPOPTS: [opt], 'id': 'fake-port'}
        self.assertIsNone(
            self.mech_driver._validate_port_extra_dhcp_opts(port))

    @mock.patch.object(mech_driver.LOG, 'info')
    def test__validate_port_extra_dhcp_opts_invalid(self, mock_log):
        port_id = 'fake-port'
        opt = {'opt_name': 'not-valid',
               'opt_value': 'spongebob squarepants',
               'ip_version': 4}
        port = {edo_ext.EXTRADHCPOPTS: [opt], 'id': port_id}
        self.mech_driver._validate_port_extra_dhcp_opts(port)
        # Assert the log message contained the invalid DHCP options
        expected_call = mock.call(
            mock.ANY, {'port_id': port_id, 'ipv4_opts': 'not-valid',
                       'ipv6_opts': ''})
        mock_log.assert_has_calls([expected_call])

    @mock.patch.object(mech_driver.LOG, 'info')
    def test_create_port_invalid_extra_dhcp_opts(self, mock_log):
        extra_dhcp_opts = {
            'extra_dhcp_opts': [{'ip_version': 4, 'opt_name': 'banana',
                                 'opt_value': 'banana'},
                                {'ip_version': 6, 'opt_name': 'orange',
                                 'opt_value': 'orange'}]
        }
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port(self.fmt, n['network']['id'],
                                  arg_list=('extra_dhcp_opts',),
                                  **extra_dhcp_opts)
                port_id = self.deserialize(self.fmt, res)['port']['id']
                # Assert the log message contained the invalid DHCP options
                expected_call = mock.call(
                    mock.ANY, {'port_id': port_id, 'ipv4_opts': 'banana',
                               'ipv6_opts': 'orange'})
                mock_log.assert_has_calls([expected_call])

    @mock.patch.object(mech_driver.LOG, 'info')
    def test_update_port_invalid_extra_dhcp_opts(self, mock_log):
        data = {
            'port': {'extra_dhcp_opts': [{'ip_version': 4, 'opt_name': 'apple',
                                         'opt_value': 'apple'},
                                         {'ip_version': 6, 'opt_name': 'grape',
                                         'opt_value': 'grape'}]}}
        with self.network(set_context=True, tenant_id='test') as net:
            with self.subnet(network=net) as subnet:
                with self.port(subnet=subnet,
                               set_context=True, tenant_id='test') as port:
                    port_id = port['port']['id']
                    self._update('ports', port_id, data)

                    # Assert the log message contained the invalid DHCP options
                    expected_call = mock.call(
                        mock.ANY, {'port_id': port_id, 'ipv4_opts': 'apple',
                                   'ipv6_opts': 'grape'})
                    mock_log.assert_has_calls([expected_call])

    def test_create_and_update_ignored_fip_port(self):
        with self.network(set_context=True, tenant_id='test') as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               device_owner=const.DEVICE_OWNER_FLOATINGIP,
                               set_context=True, tenant_id='test') as port:
                    self.nb_ovn.create_lswitch_port.assert_not_called()
                    data = {'port': {'name': 'new'}}
                    req = self.new_update_request('ports', data,
                                                  port['port']['id'])
                    res = req.get_response(self.api)
                    self.assertEqual(exc.HTTPOk.code, res.status_int)
                    self.nb_ovn.set_lswitch_port.assert_not_called()

    def test_update_ignored_port_from_fip_device_owner(self):
        with self.network(set_context=True, tenant_id='test') as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               device_owner=const.DEVICE_OWNER_FLOATINGIP,
                               set_context=True, tenant_id='test') as port:
                    self.nb_ovn.create_lswitch_port.assert_not_called()
                    data = {'port': {'device_owner': 'test'}}
                    req = self.new_update_request('ports', data,
                                                  port['port']['id'])
                    res = req.get_response(self.api)
                    self.assertEqual(exc.HTTPBadRequest.code, res.status_int)
                    msg = jsonutils.loads(res.body)['NeutronError']['message']
                    expect_msg = ('Bad port request: Updating device_owner for'
                                  ' port %s owned by network:floatingip is'
                                  ' not supported.' % port['port']['id'])
                    self.assertEqual(msg, expect_msg)
                    self.nb_ovn.set_lswitch_port.assert_not_called()

    def test_update_ignored_port_to_fip_device_owner(self):
        with self.network(set_context=True, tenant_id='test') as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               device_owner='test',
                               set_context=True, tenant_id='test') as port:
                    self.assertEqual(
                        1, self.nb_ovn.create_lswitch_port.call_count)
                    data = {'port': {'device_owner':
                                     const.DEVICE_OWNER_FLOATINGIP}}
                    req = self.new_update_request('ports', data,
                                                  port['port']['id'])
                    res = req.get_response(self.api)
                    self.assertEqual(exc.HTTPBadRequest.code, res.status_int)
                    msg = jsonutils.loads(res.body)['NeutronError']['message']
                    expect_msg = ('Bad port request: Updating device_owner to'
                                  ' network:floatingip for port %s is'
                                  ' not supported.' % port['port']['id'])
                    self.assertEqual(msg, expect_msg)
                    self.nb_ovn.set_lswitch_port.assert_not_called()

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
                    self.assertTrue(self.nb_ovn.create_lswitch_port.called)
                    called_args_dict = (
                        (self.nb_ovn.create_lswitch_port
                         ).call_args_list[0][1])
                    self.assertEqual(['00:00:00:00:00:01 10.0.0.2 10.0.0.4'],
                                     called_args_dict.get('port_security'))

                    data = {'port': {'mac_address': '00:00:00:00:00:02'}}
                    req = self.new_update_request(
                        'ports',
                        data, port['port']['id'])
                    req.get_response(self.api)
                    self.assertTrue(self.nb_ovn.set_lswitch_port.called)
                    called_args_dict = (
                        (self.nb_ovn.set_lswitch_port
                         ).call_args_list[0][1])
                    self.assertEqual(['00:00:00:00:00:02 10.0.0.2 10.0.0.4'],
                                     called_args_dict.get('port_security'))

    def test_create_port_with_disabled_security(self):
        # NOTE(mjozefcz): Lets pretend this is nova port to not
        # be treated as VIP.
        kwargs = {'port_security_enabled': False,
                  'device_owner': 'compute:nova'}
        with self.network(set_context=True, tenant_id='test') as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               arg_list=('port_security_enabled',),
                               set_context=True, tenant_id='test',
                               **kwargs) as port:
                    self.assertTrue(self.nb_ovn.create_lswitch_port.called)
                    called_args_dict = (
                        (self.nb_ovn.create_lswitch_port
                         ).call_args_list[0][1])
                    self.assertEqual([],
                                     called_args_dict.get('port_security'))

                    self.assertEqual('unknown',
                                     called_args_dict.get('addresses')[1])
                    data = {'port': {'mac_address': '00:00:00:00:00:01'}}
                    req = self.new_update_request(
                        'ports',
                        data, port['port']['id'])
                    req.get_response(self.api)
                    self.assertTrue(self.nb_ovn.set_lswitch_port.called)
                    called_args_dict = (
                        (self.nb_ovn.set_lswitch_port
                         ).call_args_list[0][1])
                    self.assertEqual([],
                                     called_args_dict.get('port_security'))
                    self.assertEqual(2, len(called_args_dict.get('addresses')))
                    self.assertEqual('unknown',
                                     called_args_dict.get('addresses')[1])

                    # Enable port security
                    data = {'port': {'port_security_enabled': 'True'}}
                    req = self.new_update_request(
                        'ports',
                        data, port['port']['id'])
                    req.get_response(self.api)
                    called_args_dict = (
                        (self.nb_ovn.set_lswitch_port
                         ).call_args_list[1][1])
                    self.assertEqual(2,
                                     self.nb_ovn.set_lswitch_port.call_count)
                    self.assertEqual(1, len(called_args_dict.get('addresses')))
                    self.assertNotIn('unknown',
                                     called_args_dict.get('addresses'))

    def test_create_port_security_allowed_address_pairs(self):
        # NOTE(mjozefcz): Lets pretend this is nova port to not
        # be treated as VIP.
        kwargs = {'allowed_address_pairs':
                  [{"ip_address": "1.1.1.1"},
                   {"ip_address": "2.2.2.2",
                    "mac_address": "22:22:22:22:22:22"}],
                  'device_owner': 'compute:nova'}
        with self.network(set_context=True, tenant_id='test') as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               arg_list=('allowed_address_pairs',),
                               set_context=True, tenant_id='test',
                               **kwargs) as port:
                    port_ip = port['port'].get('fixed_ips')[0]['ip_address']
                    self.assertTrue(self.nb_ovn.create_lswitch_port.called)
                    called_args_dict = (
                        (self.nb_ovn.create_lswitch_port
                         ).call_args_list[0][1])
                    self.assertEqual(
                        tools.UnorderedList(
                            ["22:22:22:22:22:22 2.2.2.2",
                             port['port']['mac_address'] + ' ' + port_ip +
                             ' ' + '1.1.1.1']),
                        called_args_dict.get('port_security'))
                    self.assertEqual(
                        tools.UnorderedList(
                            ["22:22:22:22:22:22",
                             port['port']['mac_address'] + ' ' + port_ip]),
                        called_args_dict.get('addresses'))

                    old_mac = port['port']['mac_address']

                    # we are updating only the port mac address. So the
                    # mac address of the allowed address pair ip 1.1.1.1
                    # will have old mac address
                    data = {'port': {'mac_address': '00:00:00:00:00:01'}}
                    req = self.new_update_request(
                        'ports',
                        data, port['port']['id'])
                    req.get_response(self.api)
                    self.assertTrue(self.nb_ovn.set_lswitch_port.called)
                    called_args_dict = (
                        (self.nb_ovn.set_lswitch_port
                         ).call_args_list[0][1])
                    self.assertEqual(tools.UnorderedList(
                        ["22:22:22:22:22:22 2.2.2.2",
                         "00:00:00:00:00:01 " + port_ip,
                         old_mac + " 1.1.1.1"]),
                        called_args_dict.get('port_security'))
                    self.assertEqual(
                        tools.UnorderedList(
                            ["22:22:22:22:22:22",
                             "00:00:00:00:00:01 " + port_ip,
                             old_mac]),
                        called_args_dict.get('addresses'))

    def test_create_port_ovn_octavia_vip(self):
        with (self.network(set_context=True, tenant_id='test')) as net1, (
                self.subnet(network=net1)) as subnet1, (
                self.port(name=ovn_const.LB_VIP_PORT_PREFIX + 'foo',
                          subnet=subnet1, set_context=True, tenant_id='test')):

            self.assertTrue(self.nb_ovn.create_lswitch_port.called)
            called_args_dict = (
                self.nb_ovn.create_lswitch_port.call_args_list[0][1])
            self.assertEqual([],
                             called_args_dict.get('addresses'))

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

    def _create_fake_mp_network_context(self):
        network_type = 'flat'
        network_attrs = {'segments': []}
        fake_segments = []
        for physical_network in ['physnet1', 'physnet2']:
            network_attrs['segments'].append(
                {'provider:network_type': network_type,
                 'provider:physical_network': physical_network})
            segment_attrs = {'network_type': network_type,
                             'physical_network': physical_network}
            fake_segments.append(
                fakes.FakeSegment.create_one_segment(
                    attrs=segment_attrs).info())
        fake_network = \
            fakes.FakeNetwork.create_one_network(attrs=network_attrs).info()
        fake_network.pop('provider:network_type')
        fake_network.pop('provider:physical_network')
        fake_network.pop('provider:segmentation_id')
        return fakes.FakeNetworkContext(fake_network, fake_segments)

    def test_network_precommit(self):
        # Test supported network types.
        fake_network_context = self._create_fake_network_context('local')
        self.mech_driver.create_network_precommit(fake_network_context)
        fake_network_context = self._create_fake_network_context(
            'flat', physical_network='physnet')
        self.mech_driver.update_network_precommit(fake_network_context)
        fake_network_context = self._create_fake_network_context(
            'geneve', segmentation_id=10)
        self.mech_driver.create_network_precommit(fake_network_context)
        fake_network_context = self._create_fake_network_context(
            'vlan', physical_network='physnet', segmentation_id=11)
        self.mech_driver.update_network_precommit(fake_network_context)
        fake_mp_network_context = self._create_fake_mp_network_context()
        self.mech_driver.create_network_precommit(fake_mp_network_context)

        # Test unsupported network types.
        fake_network_context = self._create_fake_network_context(
            'vxlan', segmentation_id=12)
        self.assertRaises(n_exc.InvalidInput,
                          self.mech_driver.create_network_precommit,
                          fake_network_context)
        fake_network_context = self._create_fake_network_context(
            'gre', segmentation_id=13)
        self.assertRaises(n_exc.InvalidInput,
                          self.mech_driver.update_network_precommit,
                          fake_network_context)

    def _create_network_igmp_snoop(self, enabled):
        cfg.CONF.set_override('igmp_snooping_enable', enabled, group='OVS')
        nb_idl = self.mech_driver._ovn_client._nb_idl
        net = self._make_network(self.fmt, name='net1',
                                 admin_state_up=True)['network']
        value = 'true' if enabled else 'false'
        nb_idl.ls_add.assert_called_once_with(
            ovn_utils.ovn_name(net['id']), external_ids=mock.ANY,
            may_exist=True,
            other_config={ovn_const.MCAST_SNOOP: value,
                          ovn_const.MCAST_FLOOD_UNREGISTERED: value})

    def test_create_network_igmp_snoop_enabled(self):
        self._create_network_igmp_snoop(enabled=True)

    def test_create_network_igmp_snoop_disabled(self):
        self._create_network_igmp_snoop(enabled=False)

    def test_create_network_create_localnet_port_tunnel_network_type(self):
        nb_idl = self.mech_driver._ovn_client._nb_idl
        self._make_network(self.fmt, name='net1',
                           admin_state_up=True)['network']
        # net1 is not physical network
        nb_idl.create_lswitch_port.assert_not_called()

    def test_create_network_create_localnet_port_physical_network_type(self):
        nb_idl = self.mech_driver._ovn_client._nb_idl
        net_arg = {pnet.NETWORK_TYPE: 'vlan',
                   pnet.PHYSICAL_NETWORK: 'physnet1',
                   pnet.SEGMENTATION_ID: '2'}
        net = self._make_network(self.fmt, 'net1', True,
                                 arg_list=(pnet.NETWORK_TYPE,
                                           pnet.PHYSICAL_NETWORK,
                                           pnet.SEGMENTATION_ID,),
                                 **net_arg)['network']
        segments = segments_db.get_network_segments(
            self.context, net['id'])
        nb_idl.create_lswitch_port.assert_called_once_with(
            addresses=[ovn_const.UNKNOWN_ADDR],
            external_ids={},
            lport_name=ovn_utils.ovn_provnet_port_name(segments[0]['id']),
            lswitch_name=ovn_utils.ovn_name(net['id']),
            options={'network_name': 'physnet1'},
            tag=2,
            type='localnet')

    def test_create_port_without_security_groups(self):
        kwargs = {'security_groups': []}
        with self.network(set_context=True, tenant_id='test') as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               arg_list=('security_groups',),
                               set_context=True, tenant_id='test',
                               **kwargs):
                    self.assertEqual(
                        1, self.nb_ovn.create_lswitch_port.call_count)
                    self.assertFalse(self.nb_ovn.add_acl.called)

    def test_create_port_without_security_groups_no_ps(self):
        kwargs = {'security_groups': [], 'port_security_enabled': False}
        with self.network(set_context=True, tenant_id='test') as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               arg_list=('security_groups',
                                         'port_security_enabled'),
                               set_context=True, tenant_id='test',
                               **kwargs):
                    self.assertEqual(
                        1, self.nb_ovn.create_lswitch_port.call_count)
                    self.nb_ovn.add_acl.assert_not_called()

    def test_update_port_changed_security_groups(self):
        with self.network(set_context=True, tenant_id='test') as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               set_context=True, tenant_id='test') as port1:
                    sg_id = port1['port']['security_groups'][0]
                    fake_lsp = (
                        fakes.FakeOVNPort.from_neutron_port(
                            port1['port']))
                    self.nb_ovn.lookup.return_value = fake_lsp

                    # Remove the default security group.
                    self.nb_ovn.set_lswitch_port.reset_mock()
                    self.nb_ovn.update_acls.reset_mock()
                    data = {'port': {'security_groups': []}}
                    self._update('ports', port1['port']['id'], data)
                    self.assertEqual(
                        1, self.nb_ovn.set_lswitch_port.call_count)
                    self.assertFalse(self.nb_ovn.update_acls.called)
                    self.assertTrue(self.nb_ovn.pg_add_ports.called)

                    # Add the default security group.
                    self.nb_ovn.set_lswitch_port.reset_mock()
                    self.nb_ovn.update_acls.reset_mock()
                    fake_lsp.external_ids.pop(ovn_const.OVN_SG_IDS_EXT_ID_KEY)
                    data = {'port': {'security_groups': [sg_id]}}
                    self._update('ports', port1['port']['id'], data)
                    self.assertFalse(self.nb_ovn.update_acls.called)
                    self.assertTrue(self.nb_ovn.pg_add_ports.called)

    def test_update_port_unchanged_security_groups(self):
        with self.network(set_context=True, tenant_id='test') as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               set_context=True, tenant_id='test') as port1:
                    fake_lsp = (
                        fakes.FakeOVNPort.from_neutron_port(
                            port1['port']))
                    self.nb_ovn.lookup.return_value = fake_lsp

                    # Update the port name.
                    self.nb_ovn.set_lswitch_port.reset_mock()
                    self.nb_ovn.update_acls.reset_mock()
                    data = {'port': {'name': 'rtheis'}}
                    self._update('ports', port1['port']['id'], data)
                    self.assertEqual(
                        1, self.nb_ovn.set_lswitch_port.call_count)
                    self.nb_ovn.update_acls.assert_not_called()

                    # Update the port fixed IPs
                    self.nb_ovn.set_lswitch_port.reset_mock()
                    self.nb_ovn.update_acls.reset_mock()
                    data = {'port': {'fixed_ips': []}}
                    self._update('ports', port1['port']['id'], data)
                    self.assertEqual(
                        1, self.nb_ovn.set_lswitch_port.call_count)
                    self.assertFalse(self.nb_ovn.update_acls.called)

    def _test_update_port_vip(self, is_vip=True):
        kwargs = {}
        with (
            self.network(set_context=True, tenant_id='test')) as net1, (
            self.subnet(network=net1)) as subnet1, (
            self.port(subnet=subnet1, set_context=True,
                      tenant_id='test', **kwargs)) as port1:
            fake_lsp = (
                fakes.FakeOVNPort.from_neutron_port(
                    port1['port']))
            self.nb_ovn.lookup.return_value = fake_lsp
            self.nb_ovn.set_lswitch_port.reset_mock()
            if is_vip:
                data = {'port': {'name': ovn_const.LB_VIP_PORT_PREFIX + 'foo'}}
            else:
                data = {'port': {}}
            self._update('ports', port1['port']['id'], data)
            self.assertEqual(
                1, self.nb_ovn.set_lswitch_port.call_count)
            called_args_dict = (
                self.nb_ovn.set_lswitch_port.call_args_list[0][1])
            if is_vip:
                self.assertEqual([],
                                 called_args_dict.get('addresses'))
            else:
                self.assertNotEqual([],
                                    called_args_dict.get('addresses'))

    def test_update_port_not_vip_port(self):
        self._test_update_port_vip(is_vip=False)

    def test_update_port_vip_port(self):
        self._test_update_port_vip()

    def test_delete_port_without_security_groups(self):
        kwargs = {'security_groups': []}
        with self.network(set_context=True, tenant_id='test') as net1:
            with self.subnet(network=net1) as subnet1:
                with self.port(subnet=subnet1,
                               arg_list=('security_groups',),
                               set_context=True, tenant_id='test',
                               **kwargs) as port1:
                    fake_lsp = (
                        fakes.FakeOVNPort.from_neutron_port(
                            port1['port']))
                    self.nb_ovn.lookup.return_value = fake_lsp
                    self.nb_ovn.delete_lswitch_port.reset_mock()
                    self.nb_ovn.delete_acl.reset_mock()
                    self._delete('ports', port1['port']['id'])
                    self.assertEqual(
                        1, self.nb_ovn.delete_lswitch_port.call_count)

    @mock.patch.object(db_rev, 'delete_revision')
    @mock.patch.object(ovn_client.OVNClient, '_delete_port')
    def test_delete_port_exception_delete_revision(self, mock_del_port,
                                                   mock_del_rev):
        mock_del_port.side_effect = Exception('BoOoOoOoOmmmmm!!!')
        with self.network(set_context=True, tenant_id='test') as net:
            with self.subnet(network=net) as subnet:
                with self.port(subnet=subnet,
                               set_context=True, tenant_id='test') as port:
                    self._delete('ports', port['port']['id'])
                    # Assert that delete_revision wasn't invoked
                    mock_del_rev.assert_not_called()

    def _test_set_port_status_up(self, is_compute_port=False):
        port_device_owner = 'compute:nova' if is_compute_port else ''
        self.mech_driver._plugin.nova_notifier = mock.Mock()
        with self.network(set_context=True, tenant_id='test') as net1, \
                self.subnet(network=net1) as subnet1, \
                self.port(subnet=subnet1, set_context=True,
                          tenant_id='test',
                          device_owner=port_device_owner) as port1, \
                mock.patch('neutron.db.provisioning_blocks.'
                           'provisioning_complete') as pc, \
                mock.patch.object(self.mech_driver,
                                  '_update_dnat_entry_if_needed') as ude, \
                mock.patch.object(
                    self.mech_driver,
                    '_wait_for_metadata_provisioned_if_needed') as wmp, \
                mock.patch.object(self.mech_driver, '_should_notify_nova',
                                  return_value=is_compute_port):
            self.mech_driver.set_port_status_up(port1['port']['id'])
            pc.assert_called_once_with(
                mock.ANY,
                port1['port']['id'],
                resources.PORT,
                provisioning_blocks.L2_AGENT_ENTITY
            )
            ude.assert_called_once_with(port1['port']['id'])
            wmp.assert_called_once_with(port1['port']['id'])

            # If the port does NOT bellong to compute, do not notify Nova
            # about it's status changes
            if not is_compute_port:
                self.mech_driver._plugin.nova_notifier.\
                    notify_port_active_direct.assert_not_called()
            else:
                self.mech_driver._plugin.nova_notifier.\
                    notify_port_active_direct.assert_called_once_with(
                        mock.ANY)

    def test_set_port_status_up(self):
        self._test_set_port_status_up(is_compute_port=False)

    def test_set_compute_port_status_up(self):
        self._test_set_port_status_up(is_compute_port=True)

    def _test_set_port_status_down(self, is_compute_port=False):
        port_device_owner = 'compute:nova' if is_compute_port else ''
        self.mech_driver._plugin.nova_notifier = mock.Mock()
        with self.network(set_context=True, tenant_id='test') as net1, \
                self.subnet(network=net1) as subnet1, \
                self.port(subnet=subnet1, set_context=True,
                          tenant_id='test',
                          device_owner=port_device_owner) as port1, \
                mock.patch('neutron.db.provisioning_blocks.'
                           'add_provisioning_component') as apc, \
                mock.patch.object(self.mech_driver,
                                  '_update_dnat_entry_if_needed') as ude, \
                mock.patch.object(self.mech_driver, '_should_notify_nova',
                                  return_value=is_compute_port):
            self.mech_driver.set_port_status_down(port1['port']['id'])
            apc.assert_called_once_with(
                mock.ANY,
                port1['port']['id'],
                resources.PORT,
                provisioning_blocks.L2_AGENT_ENTITY
            )
            ude.assert_called_once_with(port1['port']['id'], False)

            # If the port does NOT bellong to compute, do not notify Nova
            # about it's status changes
            if not is_compute_port:
                self.mech_driver._plugin.nova_notifier.\
                    record_port_status_changed.assert_not_called()
                self.mech_driver._plugin.nova_notifier.\
                    send_port_status.assert_not_called()
            else:
                self.mech_driver._plugin.nova_notifier.\
                    record_port_status_changed.assert_called_once_with(
                        mock.ANY, const.PORT_STATUS_ACTIVE,
                        const.PORT_STATUS_DOWN, None)
                self.mech_driver._plugin.nova_notifier.\
                    send_port_status.assert_called_once_with(
                        None, None, mock.ANY)

    def test_set_port_status_down(self):
        self._test_set_port_status_down(is_compute_port=False)

    def test_set_compute_port_status_down(self):
        self._test_set_port_status_down(is_compute_port=True)

    def test_set_port_status_down_not_found(self):
        with mock.patch('neutron.db.provisioning_blocks.'
                        'add_provisioning_component') as apc, \
            mock.patch.object(self.mech_driver,
                              '_update_dnat_entry_if_needed'):
            self.mech_driver.set_port_status_down('foo')
            apc.assert_not_called()

    def test_set_port_status_concurrent_delete(self):
        exc = os_db_exc.DBReferenceError('', '', '', '')
        with self.network(set_context=True, tenant_id='test') as net1, \
                self.subnet(network=net1) as subnet1, \
                self.port(subnet=subnet1, set_context=True,
                          tenant_id='test') as port1, \
                mock.patch('neutron.db.provisioning_blocks.'
                           'add_provisioning_component',
                           side_effect=exc) as apc, \
                mock.patch.object(self.mech_driver,
                                  '_update_dnat_entry_if_needed') as ude:
            self.mech_driver.set_port_status_down(port1['port']['id'])
            apc.assert_called_once_with(
                mock.ANY,
                port1['port']['id'],
                resources.PORT,
                provisioning_blocks.L2_AGENT_ENTITY
            )
            ude.assert_called_once_with(port1['port']['id'], False)

    def _test__wait_for_metadata_provisioned_if_needed(self, enable_dhcp,
                                                       wait_expected):
        with self.network(set_context=True, tenant_id='test') as net1, \
                self.subnet(network=net1,
                            enable_dhcp=enable_dhcp) as subnet1, \
                self.port(subnet=subnet1, set_context=True,
                          tenant_id='test') as port1, \
                mock.patch.object(n_utils, 'wait_until_true') as wut, \
                mock.patch.object(ovn_config, 'is_ovn_metadata_enabled',
                                  return_value=True):
            self.mech_driver._wait_for_metadata_provisioned_if_needed(
                port1['port']['id'])
        if wait_expected:
            wut.assert_called_once()
        else:
            wut.assert_not_called()

    def test__wait_for_metadata_provisioned_if_needed(self):
        self._test__wait_for_metadata_provisioned_if_needed(
            enable_dhcp=True, wait_expected=True)

    def test__wait_for_metadata_provisioned_if_needed_not_needed(self):
        self._test__wait_for_metadata_provisioned_if_needed(
            enable_dhcp=False, wait_expected=False)

    def test_bind_port_unsupported_vnic_type(self):
        fake_port = fakes.FakePort.create_one_port(
            attrs={'binding:vnic_type': 'unknown'}).info()
        fake_port_context = fakes.FakePortContext(fake_port, 'host', [])
        self.mech_driver.bind_port(fake_port_context)
        self.sb_ovn.get_chassis_data_for_ml2_bind_port.assert_not_called()
        fake_port_context.set_binding.assert_not_called()

    def _test_bind_port_failed(self, fake_segments):
        fake_port = fakes.FakePort.create_one_port().info()
        fake_host = 'host'
        fake_port_context = fakes.FakePortContext(
            fake_port, fake_host, fake_segments)
        self.mech_driver.bind_port(fake_port_context)
        self.sb_ovn.get_chassis_data_for_ml2_bind_port.assert_called_once_with(
            fake_host)
        fake_port_context.set_binding.assert_not_called()

    def test_bind_port_host_not_found(self):
        self.sb_ovn.get_chassis_data_for_ml2_bind_port.side_effect = \
            RuntimeError
        self._test_bind_port_failed([])

    def test_bind_port_no_segments_to_bind(self):
        self._test_bind_port_failed([])

    def test_bind_port_physnet_not_found(self):
        segment_attrs = {'network_type': 'vlan',
                         'physical_network': 'unknown-physnet',
                         'segmentation_id': 23}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        self._test_bind_port_failed(fake_segments)

    def _test_bind_port(self, fake_segments):
        fake_port = fakes.FakePort.create_one_port().info()
        fake_host = 'host'
        fake_port_context = fakes.FakePortContext(
            fake_port, fake_host, fake_segments)
        self.mech_driver.bind_port(fake_port_context)
        self.sb_ovn.get_chassis_data_for_ml2_bind_port.assert_called_once_with(
            fake_host)
        fake_port_context.set_binding.assert_called_once_with(
            fake_segments[0]['id'],
            portbindings.VIF_TYPE_OVS,
            self.mech_driver.vif_details[portbindings.VIF_TYPE_OVS])

    def _test_bind_port_sriov(self, fake_segments):
        fake_port = fakes.FakePort.create_one_port(
            attrs={'binding:vnic_type': 'direct',
                   'binding:profile': {'capabilities': ['switchdev']}}).info()
        fake_host = 'host'
        fake_port_context = fakes.FakePortContext(
            fake_port, fake_host, fake_segments)
        self.mech_driver.bind_port(fake_port_context)
        self.sb_ovn.get_chassis_data_for_ml2_bind_port.assert_called_once_with(
            fake_host)
        fake_port_context.set_binding.assert_called_once_with(
            fake_segments[0]['id'],
            portbindings.VIF_TYPE_OVS,
            self.mech_driver.vif_details[portbindings.VIF_TYPE_OVS])

    def test_bind_port_geneve(self):
        segment_attrs = {'network_type': 'geneve',
                         'physical_network': None,
                         'segmentation_id': 1023}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        self._test_bind_port(fake_segments)

    def test_bind_sriov_port_geneve(self):
        """Test binding a SR-IOV port to a geneve segment."""
        segment_attrs = {'network_type': 'geneve',
                         'physical_network': None,
                         'segmentation_id': 1023}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        self._test_bind_port_sriov(fake_segments)

    def test_bind_port_vlan(self):
        segment_attrs = {'network_type': 'vlan',
                         'physical_network': 'fake-physnet',
                         'segmentation_id': 23}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        self._test_bind_port(fake_segments)

    def test_bind_port_flat(self):
        segment_attrs = {'network_type': 'flat',
                         'physical_network': 'fake-physnet',
                         'segmentation_id': None}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        self._test_bind_port(fake_segments)

    def test_bind_port_vxlan(self):
        segment_attrs = {'network_type': 'vxlan',
                         'physical_network': None,
                         'segmentation_id': 1024}
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        self._test_bind_port(fake_segments)

    def test__is_port_provisioning_required(self):
        fake_port = fakes.FakePort.create_one_port(
            attrs={'binding:vnic_type': 'normal',
                   'status': const.PORT_STATUS_DOWN}).info()
        fake_host = 'fake-physnet'

        # Test host not changed
        self.assertFalse(self.mech_driver._is_port_provisioning_required(
            fake_port, fake_host, fake_host))

        # Test invalid vnic type.
        fake_port['binding:vnic_type'] = 'unknown'
        self.assertFalse(self.mech_driver._is_port_provisioning_required(
            fake_port, fake_host, None))
        fake_port['binding:vnic_type'] = 'normal'

        # Test invalid status.
        fake_port['status'] = const.PORT_STATUS_ACTIVE
        self.assertFalse(self.mech_driver._is_port_provisioning_required(
            fake_port, fake_host, None))
        fake_port['status'] = const.PORT_STATUS_DOWN

        # Test no host.
        self.assertFalse(self.mech_driver._is_port_provisioning_required(
            fake_port, None, None))

        # Test invalid host.
        self.sb_ovn.chassis_exists.return_value = False
        self.assertFalse(self.mech_driver._is_port_provisioning_required(
            fake_port, fake_host, None))
        self.sb_ovn.chassis_exists.return_value = True

        # Test port provisioning required.
        self.assertTrue(self.mech_driver._is_port_provisioning_required(
            fake_port, fake_host, None))

    def _test_add_subnet_dhcp_options_in_ovn(self, subnet, ovn_dhcp_opts=None,
                                             call_get_dhcp_opts=True,
                                             call_add_dhcp_opts=True):
        subnet['id'] = 'fake_id'
        with mock.patch.object(self.mech_driver._ovn_client,
                               '_get_ovn_dhcp_options') as get_opts:
            self.mech_driver._ovn_client._add_subnet_dhcp_options(
                subnet, mock.ANY, ovn_dhcp_opts)
            self.assertEqual(call_get_dhcp_opts, get_opts.called)
            self.assertEqual(
                call_add_dhcp_opts,
                self.mech_driver._nb_ovn.add_dhcp_options.called)

    def test_add_subnet_dhcp_options_in_ovn(self):
        subnet = {'ip_version': const.IP_VERSION_4}
        self._test_add_subnet_dhcp_options_in_ovn(subnet)

    def test_add_subnet_dhcp_options_in_ovn_with_given_ovn_dhcp_opts(self):
        subnet = {'ip_version': const.IP_VERSION_4}
        self._test_add_subnet_dhcp_options_in_ovn(
            subnet, ovn_dhcp_opts={'foo': 'bar', 'external_ids': {}},
            call_get_dhcp_opts=False)

    def test_add_subnet_dhcp_options_in_ovn_with_slaac_v6_subnet(self):
        subnet = {'ip_version': const.IP_VERSION_6,
                  'ipv6_address_mode': const.IPV6_SLAAC}
        self._test_add_subnet_dhcp_options_in_ovn(
            subnet, call_get_dhcp_opts=False, call_add_dhcp_opts=False)

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_ports')
    @mock.patch('neutron_lib.utils.net.get_random_mac')
    def test_enable_subnet_dhcp_options_in_ovn_ipv4(self, grm, gps):
        grm.return_value = '01:02:03:04:05:06'
        gps.return_value = [
            {'id': 'port-id-1', 'device_owner': 'nova:compute'},
            {'id': 'port-id-2', 'device_owner': 'nova:compute',
             'extra_dhcp_opts': [
                 {'opt_value': '10.0.0.33', 'ip_version': 4,
                   'opt_name': 'router'}]},
            {'id': 'port-id-3', 'device_owner': 'nova:compute',
             'extra_dhcp_opts': [
                 {'opt_value': '1200', 'ip_version': 4,
                   'opt_name': 'mtu'}]},
            {'id': 'port-id-10', 'device_owner': 'network:foo'}]
        subnet = {'id': 'subnet-id', 'ip_version': 4, 'cidr': '10.0.0.0/24',
                  'network_id': 'network-id',
                  'gateway_ip': '10.0.0.1', 'enable_dhcp': True,
                  'dns_nameservers': [], 'host_routes': []}
        network = {'id': 'network-id', 'mtu': 1000}
        txn = self.mech_driver._nb_ovn.transaction().__enter__.return_value
        dhcp_option_command = mock.Mock()
        txn.add.return_value = dhcp_option_command

        self.mech_driver._ovn_client._enable_subnet_dhcp_options(
            subnet, network, txn)
        # Check adding DHCP_Options rows
        subnet_dhcp_options = {
            'external_ids': {'subnet_id': subnet['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'},
            'cidr': subnet['cidr'], 'options': {
                'router': subnet['gateway_ip'],
                'server_id': subnet['gateway_ip'],
                'server_mac': '01:02:03:04:05:06',
                'dns_server': '{8.8.8.8}',
                'lease_time': str(12 * 60 * 60),
                'mtu': str(1000)}}
        ports_dhcp_options = [{
            'external_ids': {'subnet_id': subnet['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
                             'port_id': 'port-id-2'},
            'cidr': subnet['cidr'], 'options': {
                'router': '10.0.0.33',
                'server_id': subnet['gateway_ip'],
                'dns_server': '{8.8.8.8}',
                'server_mac': '01:02:03:04:05:06',
                'lease_time': str(12 * 60 * 60),
                'mtu': str(1000)}}, {
            'external_ids': {'subnet_id': subnet['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
                             'port_id': 'port-id-3'},
            'cidr': subnet['cidr'], 'options': {
                'router': subnet['gateway_ip'],
                'server_id': subnet['gateway_ip'],
                'dns_server': '{8.8.8.8}',
                'server_mac': '01:02:03:04:05:06',
                'lease_time': str(12 * 60 * 60),
                'mtu': str(1200)}}]
        add_dhcp_calls = [mock.call('subnet-id', **subnet_dhcp_options)]
        add_dhcp_calls.extend([mock.call(
            'subnet-id', port_id=port_dhcp_options['external_ids']['port_id'],
            **port_dhcp_options) for port_dhcp_options in ports_dhcp_options])
        self.assertEqual(len(add_dhcp_calls),
                         self.mech_driver._nb_ovn.add_dhcp_options.call_count)
        self.mech_driver._nb_ovn.add_dhcp_options.assert_has_calls(
            add_dhcp_calls, any_order=True)

        # Check setting lport rows
        set_lsp_calls = [mock.call(lport_name='port-id-1',
                                   dhcpv4_options=dhcp_option_command),
                         mock.call(lport_name='port-id-2',
                                   dhcpv4_options=dhcp_option_command),
                         mock.call(lport_name='port-id-3',
                                   dhcpv4_options=dhcp_option_command)]
        self.assertEqual(len(set_lsp_calls),
                         self.mech_driver._nb_ovn.set_lswitch_port.call_count)
        self.mech_driver._nb_ovn.set_lswitch_port.assert_has_calls(
            set_lsp_calls, any_order=True)

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_ports')
    @mock.patch('neutron_lib.utils.net.get_random_mac')
    def test_enable_subnet_dhcp_options_in_ovn_ipv6(self, grm, gps):
        grm.return_value = '01:02:03:04:05:06'
        gps.return_value = [
            {'id': 'port-id-1', 'device_owner': 'nova:compute'},
            {'id': 'port-id-2', 'device_owner': 'nova:compute',
             'extra_dhcp_opts': [
                 {'opt_value': '11:22:33:44:55:66', 'ip_version': 6,
                   'opt_name': 'server-id'}]},
            {'id': 'port-id-3', 'device_owner': 'nova:compute',
             'extra_dhcp_opts': [
                 {'opt_value': '10::34', 'ip_version': 6,
                   'opt_name': 'dns-server'}]},
            {'id': 'port-id-10', 'device_owner': 'network:foo'}]
        subnet = {'id': 'subnet-id', 'ip_version': 6, 'cidr': '10::0/64',
                  'gateway_ip': '10::1', 'enable_dhcp': True,
                  'ipv6_address_mode': 'dhcpv6-stateless',
                  'dns_nameservers': [], 'host_routes': []}
        network = {'id': 'network-id', 'mtu': 1000}
        txn = self.mech_driver._nb_ovn.transaction().__enter__.return_value
        dhcp_option_command = mock.Mock()
        txn.add.return_value = dhcp_option_command

        self.mech_driver._ovn_client._enable_subnet_dhcp_options(
            subnet, network, txn)
        # Check adding DHCP_Options rows
        subnet_dhcp_options = {
            'external_ids': {'subnet_id': subnet['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'},
            'cidr': subnet['cidr'], 'options': {
                'dhcpv6_stateless': 'true',
                'server_id': '01:02:03:04:05:06'}}
        ports_dhcp_options = [{
            'external_ids': {'subnet_id': subnet['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
                             'port_id': 'port-id-2'},
            'cidr': subnet['cidr'], 'options': {
                'dhcpv6_stateless': 'true',
                'server_id': '11:22:33:44:55:66'}}, {
            'external_ids': {'subnet_id': subnet['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1',
                             'port_id': 'port-id-3'},
            'cidr': subnet['cidr'], 'options': {
                'dhcpv6_stateless': 'true',
                'server_id': '01:02:03:04:05:06',
                'dns_server': '10::34'}}]
        add_dhcp_calls = [mock.call('subnet-id', **subnet_dhcp_options)]
        add_dhcp_calls.extend([mock.call(
            'subnet-id', port_id=port_dhcp_options['external_ids']['port_id'],
            **port_dhcp_options) for port_dhcp_options in ports_dhcp_options])
        self.assertEqual(len(add_dhcp_calls),
                         self.mech_driver._nb_ovn.add_dhcp_options.call_count)
        self.mech_driver._nb_ovn.add_dhcp_options.assert_has_calls(
            add_dhcp_calls, any_order=True)

        # Check setting lport rows
        set_lsp_calls = [mock.call(lport_name='port-id-1',
                                   dhcpv6_options=dhcp_option_command),
                         mock.call(lport_name='port-id-2',
                                   dhcpv6_options=dhcp_option_command),
                         mock.call(lport_name='port-id-3',
                                   dhcpv6_options=dhcp_option_command)]
        self.assertEqual(len(set_lsp_calls),
                         self.mech_driver._nb_ovn.set_lswitch_port.call_count)
        self.mech_driver._nb_ovn.set_lswitch_port.assert_has_calls(
            set_lsp_calls, any_order=True)

    def test_enable_subnet_dhcp_options_in_ovn_ipv6_slaac(self):
        subnet = {'id': 'subnet-id', 'ip_version': 6, 'enable_dhcp': True,
                  'ipv6_address_mode': 'slaac'}
        network = {'id': 'network-id'}

        self.mech_driver._ovn_client._enable_subnet_dhcp_options(
            subnet, network, mock.Mock())
        self.mech_driver._nb_ovn.add_dhcp_options.assert_not_called()
        self.mech_driver._nb_ovn.set_lswitch_port.assert_not_called()

    def _test_remove_subnet_dhcp_options_in_ovn(self, ip_version):
        opts = {'subnet': {'uuid': 'subnet-uuid'},
                'ports': [{'uuid': 'port1-uuid'}]}
        self.mech_driver._nb_ovn.get_subnet_dhcp_options.return_value = opts
        self.mech_driver._ovn_client._remove_subnet_dhcp_options(
            'subnet-id', mock.Mock())

        # Check deleting DHCP_Options rows
        delete_dhcp_calls = [mock.call('subnet-uuid'), mock.call('port1-uuid')]
        self.assertEqual(
            len(delete_dhcp_calls),
            self.mech_driver._nb_ovn.delete_dhcp_options.call_count)
        self.mech_driver._nb_ovn.delete_dhcp_options.assert_has_calls(
            delete_dhcp_calls, any_order=True)

    def test_remove_subnet_dhcp_options_in_ovn_ipv4(self):
        self._test_remove_subnet_dhcp_options_in_ovn(4)

    def test_remove_subnet_dhcp_options_in_ovn_ipv6(self):
        self._test_remove_subnet_dhcp_options_in_ovn(6)

    def test_update_subnet_dhcp_options_in_ovn_ipv4(self):
        subnet = {'id': 'subnet-id', 'ip_version': 4, 'cidr': '10.0.0.0/24',
                  'network_id': 'network-id',
                  'gateway_ip': '10.0.0.1', 'enable_dhcp': True,
                  'dns_nameservers': [], 'host_routes': []}
        network = {'id': 'network-id', 'mtu': 1000}
        orignal_options = {'subnet': {
            'external_ids': {'subnet_id': subnet['id']},
            'cidr': subnet['cidr'], 'options': {
                'router': '10.0.0.2',
                'server_id': '10.0.0.2',
                'server_mac': '01:02:03:04:05:06',
                'dns_server': '{8.8.8.8}',
                'lease_time': str(12 * 60 * 60),
                'mtu': str(1000)}}, 'ports': []}
        self.mech_driver._nb_ovn.get_subnet_dhcp_options.return_value =\
            orignal_options

        self.mech_driver._ovn_client._update_subnet_dhcp_options(
            subnet, network, mock.Mock())
        new_options = {
            'external_ids': {'subnet_id': subnet['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'},
            'cidr': subnet['cidr'], 'options': {
                'router': subnet['gateway_ip'],
                'server_id': subnet['gateway_ip'],
                'dns_server': '{8.8.8.8}',
                'server_mac': '01:02:03:04:05:06',
                'lease_time': str(12 * 60 * 60),
                'mtu': str(1000)}}
        self.mech_driver._nb_ovn.add_dhcp_options.assert_called_once_with(
            subnet['id'], **new_options)

    def test_update_subnet_dhcp_options_in_ovn_ipv4_not_change(self):
        subnet = {'id': 'subnet-id', 'ip_version': 4, 'cidr': '10.0.0.0/24',
                  'network_id': 'network-id',
                  'gateway_ip': '10.0.0.1', 'enable_dhcp': True,
                  'dns_nameservers': [], 'host_routes': []}
        network = {'id': 'network-id', 'mtu': 1000}
        orignal_options = {'subnet': {
            'external_ids': {'subnet_id': subnet['id']},
            'cidr': subnet['cidr'], 'options': {
                'router': subnet['gateway_ip'],
                'server_id': subnet['gateway_ip'],
                'server_mac': '01:02:03:04:05:06',
                'dns_server': '{8.8.8.8}',
                'lease_time': str(12 * 60 * 60),
                'mtu': str(1000)}}, 'ports': []}
        self.mech_driver._nb_ovn.get_subnet_dhcp_options.return_value =\
            orignal_options

        self.mech_driver._ovn_client._update_subnet_dhcp_options(
            subnet, network, mock.Mock())
        self.mech_driver._nb_ovn.add_dhcp_options.assert_not_called()

    def test_update_subnet_dhcp_options_in_ovn_ipv6(self):
        subnet = {'id': 'subnet-id', 'ip_version': 6, 'cidr': '10::0/64',
                  'network_id': 'network-id',
                  'gateway_ip': '10::1', 'enable_dhcp': True,
                  'ipv6_address_mode': 'dhcpv6-stateless',
                  'dns_nameservers': ['10::3'], 'host_routes': []}
        network = {'id': 'network-id', 'mtu': 1000}
        orignal_options = {'subnet': {
            'external_ids': {'subnet_id': subnet['id']},
            'cidr': subnet['cidr'], 'options': {
                'dhcpv6_stateless': 'true',
                'server_id': '01:02:03:04:05:06'}}, 'ports': []}
        self.mech_driver._nb_ovn.get_subnet_dhcp_options.return_value =\
            orignal_options
        self.mech_driver._ovn_client._update_subnet_dhcp_options(
            subnet, network, mock.Mock())

        new_options = {
            'external_ids': {'subnet_id': subnet['id'],
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'},
            'cidr': subnet['cidr'], 'options': {
                'dhcpv6_stateless': 'true',
                'dns_server': '{10::3}',
                'server_id': '01:02:03:04:05:06'}}
        self.mech_driver._nb_ovn.add_dhcp_options.assert_called_once_with(
            subnet['id'], **new_options)

    def test_update_subnet_dhcp_options_in_ovn_ipv6_not_change(self):
        subnet = {'id': 'subnet-id', 'ip_version': 6, 'cidr': '10::0/64',
                  'gateway_ip': '10::1', 'enable_dhcp': True,
                  'ipv6_address_mode': 'dhcpv6-stateless',
                  'dns_nameservers': [], 'host_routes': []}
        network = {'id': 'network-id', 'mtu': 1000}
        orignal_options = {'subnet': {
            'external_ids': {'subnet_id': subnet['id']},
            'cidr': subnet['cidr'], 'options': {
                'dhcpv6_stateless': 'true',
                'server_id': '01:02:03:04:05:06'}}, 'ports': []}
        self.mech_driver._nb_ovn.get_subnet_dhcp_options.return_value =\
            orignal_options

        self.mech_driver._ovn_client._update_subnet_dhcp_options(
            subnet, network, mock.Mock())
        self.mech_driver._nb_ovn.add_dhcp_options.assert_not_called()

    def test_update_subnet_dhcp_options_in_ovn_ipv6_slaac(self):
        subnet = {'id': 'subnet-id', 'ip_version': 6, 'enable_dhcp': True,
                  'ipv6_address_mode': 'slaac'}
        network = {'id': 'network-id'}
        self.mech_driver._ovn_client._update_subnet_dhcp_options(
            subnet, network, mock.Mock())
        self.mech_driver._nb_ovn.get_subnet_dhcp_options.assert_not_called()
        self.mech_driver._nb_ovn.add_dhcp_options.assert_not_called()

    def test_update_subnet_postcommit_ovn_do_nothing(self):
        context = fakes.FakeSubnetContext(
            subnet={'enable_dhcp': False, 'ip_version': 4, 'network_id': 'id',
                    'id': 'subnet_id'},
            network={'id': 'id'})
        with mock.patch.object(
                self.mech_driver._ovn_client,
                '_enable_subnet_dhcp_options') as esd,\
                mock.patch.object(
                    self.mech_driver._ovn_client,
                    '_remove_subnet_dhcp_options') as dsd,\
                mock.patch.object(
                    self.mech_driver._ovn_client,
                    '_update_subnet_dhcp_options') as usd,\
                mock.patch.object(
                    self.mech_driver._ovn_client,
                    '_find_metadata_port') as fmd,\
                mock.patch.object(
                    self.mech_driver._ovn_client,
                    'update_metadata_port') as umd:
            self.mech_driver.update_subnet_postcommit(context)
            esd.assert_not_called()
            dsd.assert_not_called()
            usd.assert_not_called()
            fmd.assert_not_called()
            umd.assert_not_called()

    def test_update_subnet_postcommit_enable_dhcp(self):
        context = fakes.FakeSubnetContext(
            subnet={'enable_dhcp': True, 'ip_version': 4, 'network_id': 'id',
                    'id': 'subnet_id'},
            network={'id': 'id'})
        with mock.patch.object(
                self.mech_driver._ovn_client,
                '_enable_subnet_dhcp_options') as esd,\
                mock.patch.object(
                self.mech_driver._ovn_client,
                'update_metadata_port') as umd:
            self.mech_driver.update_subnet_postcommit(context)
            esd.assert_called_once_with(
                context.current, context.network.current, mock.ANY)
            umd.assert_called_once_with(mock.ANY, 'id')

    def test_update_subnet_postcommit_disable_dhcp(self):
        self.mech_driver._nb_ovn.get_subnet_dhcp_options.return_value = {
            'subnet': mock.sentinel.subnet, 'ports': []}
        context = fakes.FakeSubnetContext(
            subnet={'enable_dhcp': False, 'id': 'fake_id', 'ip_version': 4,
                    'network_id': 'id'},
            network={'id': 'id'})
        with mock.patch.object(
                self.mech_driver._ovn_client,
                '_remove_subnet_dhcp_options') as dsd,\
                mock.patch.object(
                self.mech_driver._ovn_client,
                'update_metadata_port') as umd:
            self.mech_driver.update_subnet_postcommit(context)
            dsd.assert_called_once_with(context.current['id'], mock.ANY)
            umd.assert_called_once_with(mock.ANY, 'id')

    def test_update_subnet_postcommit_update_dhcp(self):
        self.mech_driver._nb_ovn.get_subnet_dhcp_options.return_value = {
            'subnet': mock.sentinel.subnet, 'ports': []}
        context = fakes.FakeSubnetContext(
            subnet={'enable_dhcp': True, 'ip_version': 4, 'network_id': 'id',
                    'id': 'subnet_id'},
            network={'id': 'id'})
        with mock.patch.object(
                self.mech_driver._ovn_client,
                '_update_subnet_dhcp_options') as usd,\
                mock.patch.object(
                self.mech_driver._ovn_client,
                'update_metadata_port') as umd:
            self.mech_driver.update_subnet_postcommit(context)
            usd.assert_called_once_with(
                context.current, context.network.current, mock.ANY)
            umd.assert_called_once_with(mock.ANY, 'id')

    @mock.patch.object(provisioning_blocks, 'is_object_blocked')
    @mock.patch.object(provisioning_blocks, 'provisioning_complete')
    def test_notify_dhcp_updated(self, mock_prov_complete, mock_is_obj_block):
        port_id = 'fake-port-id'
        mock_is_obj_block.return_value = True
        self.mech_driver._notify_dhcp_updated(port_id)
        mock_prov_complete.assert_called_once_with(
            mock.ANY, port_id, resources.PORT,
            provisioning_blocks.DHCP_ENTITY)

        mock_is_obj_block.return_value = False
        mock_prov_complete.reset_mock()
        self.mech_driver._notify_dhcp_updated(port_id)
        mock_prov_complete.assert_not_called()

    @mock.patch.object(mech_driver.OVNMechanismDriver,
                       '_is_port_provisioning_required', lambda *_: True)
    @mock.patch.object(mech_driver.OVNMechanismDriver, '_notify_dhcp_updated')
    @mock.patch.object(ovn_client.OVNClient, 'create_port')
    def test_create_port_postcommit(self, mock_create_port, mock_notify_dhcp):
        fake_port = fakes.FakePort.create_one_port(
            attrs={'status': const.PORT_STATUS_DOWN}).info()
        fake_ctx = mock.Mock(current=fake_port)
        self.mech_driver.create_port_postcommit(fake_ctx)
        passed_fake_port = copy.deepcopy(fake_port)
        passed_fake_port['network'] = fake_ctx.network.current
        mock_create_port.assert_called_once_with(passed_fake_port)
        mock_notify_dhcp.assert_called_once_with(fake_port['id'])

    @mock.patch.object(mech_driver.OVNMechanismDriver,
                       '_is_port_provisioning_required', lambda *_: True)
    @mock.patch.object(mech_driver.OVNMechanismDriver, '_notify_dhcp_updated')
    @mock.patch.object(ovn_client.OVNClient, 'update_port')
    def test_update_port_postcommit(self, mock_update_port,
                                    mock_notify_dhcp):
        fake_port = fakes.FakePort.create_one_port(
            attrs={'status': const.PORT_STATUS_ACTIVE}).info()
        fake_ctx = mock.Mock(current=fake_port, original=fake_port)
        self.mech_driver.update_port_postcommit(fake_ctx)

        passed_fake_port = copy.deepcopy(fake_port)
        passed_fake_port['network'] = fake_ctx.network.current
        passed_fake_port_orig = copy.deepcopy(fake_ctx.original)
        passed_fake_port_orig['network'] = fake_ctx.network.current

        mock_update_port.assert_called_once_with(
            passed_fake_port, port_object=passed_fake_port_orig)
        mock_notify_dhcp.assert_called_once_with(fake_port['id'])

    @mock.patch.object(mech_driver.OVNMechanismDriver,
                       '_is_port_provisioning_required', lambda *_: True)
    @mock.patch.object(mech_driver.OVNMechanismDriver, '_notify_dhcp_updated')
    @mock.patch.object(ovn_client.OVNClient, 'update_port')
    @mock.patch.object(context, 'get_admin_context')
    def test_update_port_postcommit_live_migration(
            self, mock_admin_context, mock_update_port, mock_notify_dhcp):
        self.plugin.update_port_status = mock.Mock()
        foo_admin_context = mock.Mock()
        mock_admin_context.return_value = foo_admin_context
        fake_port = fakes.FakePort.create_one_port(
            attrs={
                'status': const.PORT_STATUS_DOWN,
                portbindings.PROFILE: {ovn_const.MIGRATING_ATTR: 'foo'},
                portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS}).info()
        fake_ctx = mock.Mock(current=fake_port, original=fake_port)

        self.mech_driver.update_port_postcommit(fake_ctx)

        mock_update_port.assert_not_called()
        mock_notify_dhcp.assert_not_called()
        self.plugin.update_port_status.assert_called_once_with(
            foo_admin_context, fake_port['id'], const.PORT_STATUS_ACTIVE)

    def _add_chassis_agent(self, nb_cfg, agent_type, updated_at=None):
        updated_at = updated_at or datetime.datetime.utcnow()
        chassis = mock.Mock()
        chassis.nb_cfg = nb_cfg
        chassis.uuid = uuid.uuid4()
        chassis.external_ids = {ovn_const.OVN_LIVENESS_CHECK_EXT_ID_KEY:
                                datetime.datetime.isoformat(updated_at)}
        if agent_type == ovn_const.OVN_METADATA_AGENT:
            chassis.external_ids.update({
                ovn_const.OVN_AGENT_METADATA_SB_CFG_KEY: nb_cfg,
                ovn_const.METADATA_LIVENESS_CHECK_EXT_ID_KEY:
                datetime.datetime.isoformat(updated_at)})

        return chassis

    def test_agent_alive_true(self):
        for agent_type in (ovn_const.OVN_CONTROLLER_AGENT,
                           ovn_const.OVN_METADATA_AGENT):
            self.mech_driver._nb_ovn.nb_global.nb_cfg = 5
            chassis = self._add_chassis_agent(5, agent_type)
            self.assertTrue(self.mech_driver.agent_alive(chassis, agent_type,
                                                         update_db=True))
        # Assert that each Chassis has been updated in the SB database
        self.assertEqual(2, self.sb_ovn.db_set.call_count)

    def test_agent_alive_true_one_diff(self):
        # Agent should be reported as alive when the nb_cfg delta is 1
        # even if the last update time was old enough.
        for agent_type in (ovn_const.OVN_CONTROLLER_AGENT,
                           ovn_const.OVN_METADATA_AGENT):
            self.mech_driver._nb_ovn.nb_global.nb_cfg = 5
            now = timeutils.utcnow()
            updated_at = now - datetime.timedelta(cfg.CONF.agent_down_time + 1)
            chassis = self._add_chassis_agent(4, agent_type, updated_at)
            self.assertTrue(self.mech_driver.agent_alive(chassis, agent_type,
                                                         update_db=True))

    def test_agent_alive_not_timed_out(self):
        for agent_type in (ovn_const.OVN_CONTROLLER_AGENT,
                           ovn_const.OVN_METADATA_AGENT):
            self.mech_driver._nb_ovn.nb_global.nb_cfg = 5
            chassis = self._add_chassis_agent(3, agent_type)
            self.assertTrue(self.mech_driver.agent_alive(
                chassis, agent_type, update_db=True),
                            "Agent type %s is not alive" % agent_type)

    def test_agent_alive_timed_out(self):
        for agent_type in (ovn_const.OVN_CONTROLLER_AGENT,
                           ovn_const.OVN_METADATA_AGENT):
            self.mech_driver._nb_ovn.nb_global.nb_cfg = 5
            now = timeutils.utcnow()
            updated_at = now - datetime.timedelta(cfg.CONF.agent_down_time + 1)
            chassis = self._add_chassis_agent(3, agent_type, updated_at)
            self.assertFalse(self.mech_driver.agent_alive(chassis, agent_type,
                                                          update_db=True))

    def test_agent_alive_true_skip_db_update(self):
        for agent_type in (ovn_const.OVN_CONTROLLER_AGENT,
                           ovn_const.OVN_METADATA_AGENT):
            self.mech_driver._nb_ovn.nb_global.nb_cfg = 5
            chassis = self._add_chassis_agent(5, agent_type)
            self.assertTrue(self.mech_driver.agent_alive(chassis, agent_type,
                                                         update_db=False))
            self.sb_ovn.db_set.assert_not_called()

    def _test__update_dnat_entry_if_needed(self, up=True):
        ovn_config.cfg.CONF.set_override(
            'enable_distributed_floating_ip', True, group='ovn')
        port_id = 'fake-port-id'
        fake_ext_mac_key = 'fake-ext-mac-key'
        fake_nat_uuid = uuidutils.generate_uuid()
        nat_row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'_uuid': fake_nat_uuid, 'external_ids': {
                ovn_const.OVN_FIP_EXT_MAC_KEY: fake_ext_mac_key}})

        fake_db_find = mock.Mock()
        fake_db_find.execute.return_value = [nat_row]
        self.nb_ovn.db_find.return_value = fake_db_find

        self.mech_driver._update_dnat_entry_if_needed(port_id, up=up)

        if up:
            # Assert that we are setting the external_mac in the NAT table
            self.nb_ovn.db_set.assert_called_once_with(
                'NAT', fake_nat_uuid, ('external_mac', fake_ext_mac_key))
        else:
            # Assert that we are cleaning the external_mac from the NAT table
            self.nb_ovn.db_clear.assert_called_once_with(
                'NAT', fake_nat_uuid, 'external_mac')

    def test__update_dnat_entry_if_needed_up(self):
        self._test__update_dnat_entry_if_needed()

    def test__update_dnat_entry_if_needed_down(self):
        self._test__update_dnat_entry_if_needed(up=False)

    def _test_update_network_fragmentation(self, new_mtu, expected_opts):
        network_attrs = {external_net.EXTERNAL: True}
        network = self._make_network(
            self.fmt, 'net1', True, arg_list=(external_net.EXTERNAL,),
            **network_attrs)

        with self.subnet(network=network) as subnet:
            with self.port(subnet=subnet,
                           device_owner=const.DEVICE_OWNER_ROUTER_GW) as port:
                # Let's update the MTU to something different
                network['network']['mtu'] = new_mtu
                fake_ctx = mock.Mock(current=network['network'])
                fake_ctx._plugin_context.session.is_active = False

                self.mech_driver.update_network_postcommit(fake_ctx)

                lrp_name = ovn_utils.ovn_lrouter_port_name(port['port']['id'])
                self.nb_ovn.update_lrouter_port.assert_called_once_with(
                    if_exists=True, name=lrp_name, options=expected_opts)

    def test_update_network_need_to_frag_enabled(self):
        ovn_config.cfg.CONF.set_override(
            'ovn_emit_need_to_frag', True, group='ovn')
        new_mtu = 1234
        expected_opts = {ovn_const.OVN_ROUTER_PORT_GW_MTU_OPTION:
                         str(new_mtu)}
        self._test_update_network_fragmentation(new_mtu, expected_opts)

    def test_update_network_need_to_frag_disabled(self):
        ovn_config.cfg.CONF.set_override(
            'ovn_emit_need_to_frag', False, group='ovn')
        new_mtu = 1234
        # Assert that the options column is empty (cleaning up an '
        # existing value if set before)
        expected_opts = {}
        self._test_update_network_fragmentation(new_mtu, expected_opts)

    def test_ping_chassis(self):
        self.nb_ovn.nb_global.external_ids = {}
        self.mech_driver.ping_chassis()
        self.nb_ovn.check_liveness.assert_called_once_with()

    def test_ping_chassis_interval_expired(self):
        timeout = 10
        ovn_config.cfg.CONF.set_override('agent_down_time', timeout)

        # Pretend the interval is already expired
        time = (timeutils.utcnow(with_timezone=True) -
                datetime.timedelta(seconds=timeout))
        self.nb_ovn.nb_global.external_ids = {
            ovn_const.OVN_LIVENESS_CHECK_EXT_ID_KEY: str(time)}

        update_db = self.mech_driver.ping_chassis()
        # Since the interval has expired, assert that the "check_liveness"
        # command has been invoked
        self.nb_ovn.check_liveness.assert_called_once_with()
        # Assert that ping_chassis returned True as it updated the db
        self.assertTrue(update_db)

    def test_ping_chassis_interval_not_expired(self):
        ovn_config.cfg.CONF.set_override('agent_down_time', 10)

        # Pretend the interval has NOT yet expired
        time = timeutils.utcnow(with_timezone=True)
        self.nb_ovn.nb_global.external_ids = {
            ovn_const.OVN_LIVENESS_CHECK_EXT_ID_KEY: str(time)}

        update_db = self.mech_driver.ping_chassis()
        # Assert that "check_liveness" wasn't invoked
        self.assertFalse(self.nb_ovn.check_liveness.called)
        # Assert that ping_chassis returned False as it didn't update the db
        self.assertFalse(update_db)

    def test_get_candidates_for_scheduling_availability_zones(self):
        ovn_client = self.mech_driver._ovn_client
        ch0 = fakes.FakeChassis.create(az_list=['az0', 'az1'],
                                       chassis_as_gw=True)
        ch1 = fakes.FakeChassis.create(az_list=['az3', 'az4'],
                                       chassis_as_gw=True)
        ch2 = fakes.FakeChassis.create(az_list=['az2'], chassis_as_gw=True)
        ch3 = fakes.FakeChassis.create(az_list=[], chassis_as_gw=True)
        ch4 = fakes.FakeChassis.create(az_list=['az0'], chassis_as_gw=True)
        ch5 = fakes.FakeChassis.create(az_list=['az2'], chassis_as_gw=False)

        # Fake ovsdbapp lookup
        def fake_lookup(table, chassis_name, default):
            for ch in [ch0, ch1, ch2, ch3, ch4, ch5]:
                if ch.name == chassis_name:
                    return ch
        ovn_client._sb_idl.lookup = fake_lookup

        # The target physnet and availability zones
        physnet = 'public'
        az_hints = ['az0', 'az2']

        cms = [ch0.name, ch1.name, ch2.name, ch3.name, ch4.name, ch5.name]
        ch_physnet = {ch0.name: [physnet], ch1.name: [physnet],
                      ch2.name: [physnet], ch3.name: [physnet],
                      ch4.name: ['another-physnet'],
                      ch5.name: ['yet-another-physnet']}

        candidates = ovn_client.get_candidates_for_scheduling(
            physnet, cms=cms, chassis_physnets=ch_physnet,
            availability_zone_hints=az_hints)

        # Only chassis ch0 and ch2 should match the availability zones
        # hints and physnet we passed to get_candidates_for_scheduling()
        expected_candidates = [ch0.name, ch2.name]
        self.assertEqual(sorted(expected_candidates), sorted(candidates))


class OVNMechanismDriverTestCase(test_plugin.Ml2PluginV2TestCase):
    _mechanism_drivers = ['logger', 'ovn']

    def setUp(self):
        cfg.CONF.set_override('tenant_network_types',
                              ['geneve'],
                              group='ml2')
        cfg.CONF.set_override('vni_ranges',
                              ['1:65536'],
                              group='ml2_type_geneve')
        ovn_config.cfg.CONF.set_override('dns_servers',
                                         ['8.8.8.8'],
                                         group='ovn')
        super(OVNMechanismDriverTestCase, self).setUp()
        # Make sure the node and target_node for the hash ring in the
        # mechanism driver matches
        node_uuid = uuidutils.generate_uuid()
        p = mock.patch('networking_ovn.common.hash_ring_manager.'
                       'HashRingManager.get_node', return_value=node_uuid)
        p.start()
        self.addCleanup(p.stop)
        self.driver.node_uuid = node_uuid
        self.driver.hash_ring_group = 'fake_hash_ring_group'

        mm = directory.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers['ovn'].obj
        nb_ovn = fakes.FakeOvsdbNbOvnIdl()
        sb_ovn = fakes.FakeOvsdbSbOvnIdl()
        self.mech_driver._nb_ovn = nb_ovn
        self.mech_driver._sb_ovn = sb_ovn
        self.mech_driver._insert_port_provisioning_block = mock.Mock()
        p = mock.patch.object(ovn_utils, 'get_revision_number', return_value=1)
        p.start()
        self.addCleanup(p.stop)


class TestOVNMechanismDriverBasicGet(test_plugin.TestMl2BasicGet,
                                     OVNMechanismDriverTestCase):
    pass


class TestOVNMechanismDriverV2HTTPResponse(test_plugin.TestMl2V2HTTPResponse,
                                           OVNMechanismDriverTestCase):
    pass


class TestOVNMechanismDriverNetworksV2(test_plugin.TestMl2NetworksV2,
                                       OVNMechanismDriverTestCase):

    def test__update_segmentation_id_ports_wrong_vif_type(self):
        """Skip the Update Segmentation ID tests

        Currently Segmentation ID cannot be updated till
        https://review.openstack.org/#/c/632984/ is merged
        to allow OVS Agents and thus OVN Mechanism Driver to allow
        updation of Segmentation IDs. Till then the test  needs to be skipped
        """
        pass

    def test__update_segmentation_id_ports(self):
        """Skip the Update Segmentation ID tests

        Currently Segmentation ID cannot be updated till
        https://review.openstack.org/#/c/632984/ is merged
        to allow OVS Agents and thus OVN Mechanism Driver to allow
        updation of Segmentation IDs. Till then the test  needs to be skipped
        """
        pass


class TestOVNMechanismDriverSubnetsV2(test_plugin.TestMl2SubnetsV2,
                                      OVNMechanismDriverTestCase):

    def setUp(self):
        # Disable metadata so that we don't interfere with existing tests
        # in Neutron tree. Doing this because some of the tests assume that
        # first IP address in a subnet will be available and this is not true
        # with metadata since it will book an IP address on each subnet.
        ovn_config.cfg.CONF.set_override('ovn_metadata_enabled',
                                         False,
                                         group='ovn')
        super(TestOVNMechanismDriverSubnetsV2, self).setUp()

    # NOTE(rtheis): Mock the OVN port update since it is getting subnet
    # information for ACL processing. This interferes with the update_port
    # mock already done by the test.
    def test_subnet_update_ipv4_and_ipv6_pd_v6stateless_subnets(self):
        with mock.patch.object(self.mech_driver._ovn_client, 'update_port'),\
                mock.patch.object(self.mech_driver._ovn_client,
                                  '_get_subnet_dhcp_options_for_port',
                                  return_value={}):
            super(TestOVNMechanismDriverSubnetsV2, self).\
                test_subnet_update_ipv4_and_ipv6_pd_v6stateless_subnets()

    # NOTE(rtheis): Mock the OVN port update since it is getting subnet
    # information for ACL processing. This interferes with the update_port
    # mock already done by the test.
    def test_subnet_update_ipv4_and_ipv6_pd_slaac_subnets(self):
        with mock.patch.object(self.mech_driver._ovn_client, 'update_port'),\
                mock.patch.object(self.mech_driver._ovn_client,
                                  '_get_subnet_dhcp_options_for_port',
                                  return_value={}):
            super(TestOVNMechanismDriverSubnetsV2, self).\
                test_subnet_update_ipv4_and_ipv6_pd_slaac_subnets()

    # NOTE(numans) Overriding the base test case here because the base test
    # case creates a network with vxlan type and OVN mech driver doesn't
    # support it.
    def test_create_subnet_check_mtu_in_mech_context(self):
        plugin = directory.get_plugin()
        plugin.mechanism_manager.create_subnet_precommit = mock.Mock()
        net_arg = {pnet.NETWORK_TYPE: 'geneve',
                   pnet.SEGMENTATION_ID: '1'}
        network = self._make_network(self.fmt, 'net1', True,
                                     arg_list=(pnet.NETWORK_TYPE,
                                               pnet.SEGMENTATION_ID,),
                                     **net_arg)
        with self.subnet(network=network):
            mock_subnet_pre = plugin.mechanism_manager.create_subnet_precommit
            observerd_mech_context = mock_subnet_pre.call_args_list[0][0][0]
            self.assertEqual(network['network']['mtu'],
                             observerd_mech_context.network.current['mtu'])


class TestOVNMechanismDriverPortsV2(test_plugin.TestMl2PortsV2,
                                    OVNMechanismDriverTestCase):

    def setUp(self):
        # Disable metadata so that we don't interfere with existing tests
        # in Neutron tree. Doing this because some of the tests assume that
        # first IP address in a subnet will be available and this is not true
        # with metadata since it will book an IP address on each subnet.
        ovn_config.cfg.CONF.set_override('ovn_metadata_enabled',
                                         False,
                                         group='ovn')
        super(TestOVNMechanismDriverPortsV2, self).setUp()

    # NOTE(rtheis): Override this test to verify that updating
    # a port MAC fails when the port is bound.
    def test_update_port_mac(self):
        self.check_update_port_mac(
            host_arg={portbindings.HOST_ID: 'fake-host'},
            arg_list=(portbindings.HOST_ID,),
            expected_status=exc.HTTPConflict.code,
            expected_error='PortBound')


class TestOVNMechanismDriverAllowedAddressPairs(
        test_plugin.TestMl2AllowedAddressPairs,
        OVNMechanismDriverTestCase):
    pass


class TestOVNMechanismDriverPortSecurity(
        test_ext_portsecurity.PSExtDriverTestCase,
        OVNMechanismDriverTestCase):
    pass


class TestOVNMechanismDriverSegment(test_segment.HostSegmentMappingTestCase):
    _mechanism_drivers = ['logger', 'ovn']

    def setUp(self):
        super(TestOVNMechanismDriverSegment, self).setUp()
        mm = directory.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers['ovn'].obj
        nb_ovn = fakes.FakeOvsdbNbOvnIdl()
        sb_ovn = fakes.FakeOvsdbSbOvnIdl()
        self.mech_driver._nb_ovn = nb_ovn
        self.mech_driver._sb_ovn = sb_ovn
        p = mock.patch.object(ovn_utils, 'get_revision_number', return_value=1)
        p.start()
        self.addCleanup(p.stop)
        self.context = context.get_admin_context()

    def _test_segment_host_mapping(self):
        # Disable the callback to update SegmentHostMapping by default, so
        # that update_segment_host_mapping is the only path to add the mapping
        registry.unsubscribe(
            self.mech_driver._add_segment_host_mapping_for_segment,
            resources.SEGMENT, events.AFTER_CREATE)
        host = 'hostname'
        with self.network() as network:
            network = network['network']
        segment1 = self._test_create_segment(
            network_id=network['id'], physical_network='phys_net1',
            segmentation_id=200, network_type='vlan')['segment']

        # As geneve networks mtu shouldn't be more than 1450, update it
        data = {'network': {'mtu': 1450}}
        req = self.new_update_request('networks', data, network['id'])
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertEqual(1450, res['network']['mtu'])

        self._test_create_segment(
            network_id=network['id'],
            segmentation_id=200,
            network_type='geneve')
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

    def test_update_segment_host_mapping_with_new_segment(self):
        hostname_with_physnets = {'hostname1': ['phys_net1', 'phys_net2'],
                                  'hostname2': ['phys_net1']}
        ovn_sb_api = self.mech_driver._sb_ovn
        ovn_sb_api.get_chassis_hostname_and_physnets.return_value = (
            hostname_with_physnets)
        self.mech_driver.subscribe()
        with self.network() as network:
            network_id = network['network']['id']
        segment = self._test_create_segment(
            network_id=network_id, physical_network='phys_net2',
            segmentation_id=201, network_type='vlan')['segment']
        segments_host_db1 = self._get_segments_for_host('hostname1')
        # A new SegmentHostMapping should be created for hostname1
        self.assertEqual({segment['id']}, set(segments_host_db1))

        segments_host_db2 = self._get_segments_for_host('hostname2')
        self.assertFalse(set(segments_host_db2))

    def test_create_segment_create_localnet_port(self):
        ovn_nb_api = self.mech_driver._nb_ovn
        with self.network() as network:
            net = network['network']
        new_segment = self._test_create_segment(
            network_id=net['id'], physical_network='phys_net1',
            segmentation_id=200, network_type='vlan')['segment']
        ovn_nb_api.create_lswitch_port.assert_called_once_with(
            addresses=[ovn_const.UNKNOWN_ADDR],
            external_ids={},
            lport_name=ovn_utils.ovn_provnet_port_name(new_segment['id']),
            lswitch_name=ovn_utils.ovn_name(net['id']),
            options={'network_name': 'phys_net1'},
            tag=200,
            type='localnet')
        ovn_nb_api.create_lswitch_port.reset_mock()
        new_segment = self._test_create_segment(
            network_id=net['id'], physical_network='phys_net2',
            segmentation_id=300, network_type='vlan')['segment']
        ovn_nb_api.create_lswitch_port.assert_called_once_with(
            addresses=[ovn_const.UNKNOWN_ADDR],
            external_ids={},
            lport_name=ovn_utils.ovn_provnet_port_name(new_segment['id']),
            lswitch_name=ovn_utils.ovn_name(net['id']),
            options={'network_name': 'phys_net2'},
            tag=300,
            type='localnet')
        segments = segments_db.get_network_segments(
            self.context, net['id'])
        self.assertEqual(len(segments), 3)

    def test_delete_segment_delete_localnet_port(self):
        ovn_nb_api = self.mech_driver._nb_ovn
        with self.network() as network:
            net = network['network']
        segment = self._test_create_segment(
            network_id=net['id'], physical_network='phys_net1',
            segmentation_id=200, network_type='vlan')['segment']
        self._delete('segments', segment['id'])
        ovn_nb_api.delete_lswitch_port.assert_called_once_with(
            lport_name=ovn_utils.ovn_provnet_port_name(segment['id']),
            lswitch_name=ovn_utils.ovn_name(net['id']))

    def test_delete_segment_delete_localnet_port_compat_name(self):
        ovn_nb_api = self.mech_driver._nb_ovn
        with self.network() as network:
            net = network['network']
        seg_1 = self._test_create_segment(
            network_id=net['id'], physical_network='phys_net1',
            segmentation_id=200, network_type='vlan')['segment']
        seg_2 = self._test_create_segment(
            network_id=net['id'], physical_network='phys_net2',
            segmentation_id=300, network_type='vlan')['segment']
        # Lets pretend that segment_1 is old and its localnet
        # port is based on neutron network id.
        ovn_nb_api.fake_ls_row.ports = [
            fakes.FakeOVNPort.create_one_port(
                attrs={
                    'options': {'network_name': 'phys_net1'},
                    'tag': 200,
                    'name': ovn_utils.ovn_provnet_port_name(net['id'])}),
            fakes.FakeOVNPort.create_one_port(
                attrs={
                    'options': {'network_name': 'phys_net2'},
                    'tag': 300,
                    'name': ovn_utils.ovn_provnet_port_name(seg_2['id'])})]
        self._delete('segments', seg_1['id'])
        ovn_nb_api.delete_lswitch_port.assert_called_once_with(
            lport_name=ovn_utils.ovn_provnet_port_name(net['id']),
            lswitch_name=ovn_utils.ovn_name(net['id']))
        ovn_nb_api.delete_lswitch_port.reset_mock()
        self._delete('segments', seg_2['id'])
        ovn_nb_api.delete_lswitch_port.assert_called_once_with(
            lport_name=ovn_utils.ovn_provnet_port_name(seg_2['id']),
            lswitch_name=ovn_utils.ovn_name(net['id']))

    def _test_segments_helper(self):
        ovn_config.cfg.CONF.set_override('ovn_metadata_enabled', True,
                                         group='ovn')

        # Create first segment and associate subnet to it.
        with self.network() as n:
            self.net = n
        self.seg_1 = self._test_create_segment(
            network_id=self.net['network']['id'], physical_network='phys_net1',
            segmentation_id=200, network_type='vlan')['segment']
        with self.subnet(network=self.net, cidr='10.0.1.0/24',
                         segment_id=self.seg_1['id']) as subnet:
            self.sub_1 = subnet

        # Create second segment and subnet linked to it
        self.seg_2 = self._test_create_segment(
            network_id=self.net['network']['id'], physical_network='phys_net2',
            segmentation_id=300, network_type='vlan')['segment']
        with self.subnet(network=self.net, cidr='10.0.2.0/24',
                         segment_id=self.seg_2['id']) as subnet:
            self.sub_2 = subnet

    def test_create_segments_subnet_metadata_ip_allocation(self):
        self._test_segments_helper()
        ovn_nb_api = self.mech_driver._nb_ovn

        # Assert that metadata address has been allocated from previously
        # created subnet.
        self.assertIn(
            '10.0.1.2',
            ovn_nb_api.set_lswitch_port.call_args_list[0][1]['addresses'][0])

        # Assert that the second subnet address also has been allocated for
        # metadata port.
        self.assertIn(
            '10.0.2.2',
            ovn_nb_api.set_lswitch_port.call_args_list[1][1]['addresses'][0])
        # Assert also that the first subnet address is in this update
        self.assertIn(
            '10.0.1.2',
            ovn_nb_api.set_lswitch_port.call_args_list[1][1]['addresses'][0])
        self.assertEqual(
            ovn_nb_api.set_lswitch_port.call_count, 2)

        # Make sure both updates where on same metadata port
        args_list = ovn_nb_api.set_lswitch_port.call_args_list
        self.assertEqual(
            'ovnmeta-%s' % self.net['network']['id'],
            args_list[1][1]['external_ids']['neutron:device_id'])
        self.assertEqual(
            args_list[1][1]['external_ids']['neutron:device_id'],
            args_list[0][1]['external_ids']['neutron:device_id'])
        self.assertEqual(
            args_list[1][1]['external_ids']['neutron:device_owner'],
            args_list[0][1]['external_ids']['neutron:device_owner'])
        self.assertEqual(
            const.DEVICE_OWNER_DHCP,
            args_list[1][1]['external_ids']['neutron:device_owner'])

    def test_create_segments_mixed_allocation_prohibited(self):
        self._test_segments_helper()

        # Try to create 'normal' port with ip address
        # allocations from multiple segments
        kwargs = {'fixed_ips': [{'ip_address': '10.0.1.100',
                                 'subnet_id': self.sub_1['subnet']['id']},
                                {'ip_address': '10.0.2.100',
                                 'subnet_id': self.sub_2['subnet']['id']}]}

        # Make sure that this allocation is prohibited.
        self._create_port(
            self.fmt, self.net['network']['id'],
            expected_res_status=400,
            arg_list=('fixed_ips',), **kwargs)

    def test_create_delete_segment_distributed_service_port_not_touched(self):
        self._test_segments_helper()
        ovn_nb_api = self.mech_driver._nb_ovn

        # Delete second subnet
        self._delete('subnets', self.sub_2['subnet']['id'])
        # Make sure that shared metadata port wasn't deleted.
        ovn_nb_api.delete_lswitch_port.assert_not_called()

        # Delete first subnet
        self._delete('subnets', self.sub_1['subnet']['id'])
        # Make sure that the metadata port wasn't deleted.
        ovn_nb_api.delete_lswitch_port.assert_not_called()

        # Delete both segments
        self._delete('segments', self.seg_2['id'])
        self._delete('segments', self.seg_1['id'])

        # Make sure that the metadata port wasn't deleted.
        deleted_ports = [
            port[1]['lport_name']
            for port in ovn_nb_api.delete_lswitch_port.call_args_list]
        self.assertNotIn(
            'ovnmeta-%s' % self.net['network']['id'],
            deleted_ports)
        self.assertEqual(
            2,
            ovn_nb_api.delete_lswitch_port.call_count)

        # Only on network deletion the metadata port is deleted.
        self._delete('networks', self.net['network']['id'])
        self.assertEqual(
            3,
            ovn_nb_api.delete_lswitch_port.call_count)


@mock.patch.object(n_net, 'get_random_mac', lambda *_: '01:02:03:04:05:06')
class TestOVNMechanismDriverDHCPOptions(OVNMechanismDriverTestCase):

    def _test_get_ovn_dhcp_options_helper(self, subnet, network,
                                          expected_dhcp_options,
                                          service_mac=None):
        dhcp_options = self.mech_driver._ovn_client._get_ovn_dhcp_options(
            subnet, network, service_mac)
        self.assertEqual(expected_dhcp_options, dhcp_options)

    def test_get_ovn_dhcp_options(self):
        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': '10.0.0.0/24',
                  'ip_version': 4,
                  'enable_dhcp': True,
                  'gateway_ip': '10.0.0.1',
                  'dns_nameservers': ['7.7.7.7', '8.8.8.8'],
                  'host_routes': [{'destination': '20.0.0.4',
                                   'nexthop': '10.0.0.100'}]}
        network = {'id': 'network-id', 'mtu': 1400}

        expected_dhcp_options = {'cidr': '10.0.0.0/24',
                                 'external_ids': {
                                     'subnet_id': 'foo-subnet',
                                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'}}
        expected_dhcp_options['options'] = {
            'server_id': subnet['gateway_ip'],
            'server_mac': '01:02:03:04:05:06',
            'lease_time': str(12 * 60 * 60),
            'mtu': '1400',
            'router': subnet['gateway_ip'],
            'dns_server': '{7.7.7.7, 8.8.8.8}',
            'classless_static_route':
            '{20.0.0.4,10.0.0.100, 0.0.0.0/0,10.0.0.1}'
        }

        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options)
        expected_dhcp_options['options']['server_mac'] = '11:22:33:44:55:66'
        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options,
                                               service_mac='11:22:33:44:55:66')

    def test_get_ovn_dhcp_options_dhcp_disabled(self):
        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': '10.0.0.0/24',
                  'ip_version': 4,
                  'enable_dhcp': False,
                  'gateway_ip': '10.0.0.1',
                  'dns_nameservers': ['7.7.7.7', '8.8.8.8'],
                  'host_routes': [{'destination': '20.0.0.4',
                                   'nexthop': '10.0.0.100'}]}
        network = {'id': 'network-id', 'mtu': 1400}

        expected_dhcp_options = {'cidr': '10.0.0.0/24',
                                 'external_ids': {
                                     'subnet_id': 'foo-subnet',
                                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'},
                                 'options': {}}

        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options)

    def test_get_ovn_dhcp_options_no_gw_ip(self):
        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': '10.0.0.0/24',
                  'ip_version': 4,
                  'enable_dhcp': True,
                  'gateway_ip': None,
                  'dns_nameservers': ['7.7.7.7', '8.8.8.8'],
                  'host_routes': [{'destination': '20.0.0.4',
                                   'nexthop': '10.0.0.100'}]}
        network = {'id': 'network-id', 'mtu': 1400}

        expected_dhcp_options = {'cidr': '10.0.0.0/24',
                                 'external_ids': {
                                     'subnet_id': 'foo-subnet',
                                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'},
                                 'options': {}}

        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options)

    def test_get_ovn_dhcp_options_no_gw_ip_but_metadata_ip(self):
        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': '10.0.0.0/24',
                  'ip_version': 4,
                  'enable_dhcp': True,
                  'dns_nameservers': [],
                  'host_routes': [],
                  'gateway_ip': None}
        network = {'id': 'network-id', 'mtu': 1400}

        expected_dhcp_options = {
            'cidr': '10.0.0.0/24',
            'external_ids': {'subnet_id': 'foo-subnet',
                             ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'},
            'options': {'server_id': '10.0.0.2',
                        'server_mac': '01:02:03:04:05:06',
                        'dns_server': '{8.8.8.8}',
                        'lease_time': str(12 * 60 * 60),
                        'mtu': '1400',
                        'classless_static_route':
                            '{169.254.169.254/32,10.0.0.2}'}}

        with mock.patch.object(self.mech_driver._ovn_client,
                               '_find_metadata_port_ip',
                               return_value='10.0.0.2'):
            self._test_get_ovn_dhcp_options_helper(subnet, network,
                                                   expected_dhcp_options)

    def test_get_ovn_dhcp_options_with_global_options(self):
        ovn_config.cfg.CONF.set_override('ovn_dhcp4_global_options',
                                         'ntp_server:8.8.8.8,'
                                         'mtu:9000,'
                                         'wpad:',
                                         group='ovn')

        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': '10.0.0.0/24',
                  'ip_version': 4,
                  'enable_dhcp': True,
                  'gateway_ip': '10.0.0.1',
                  'dns_nameservers': ['7.7.7.7', '8.8.8.8'],
                  'host_routes': [{'destination': '20.0.0.4',
                                   'nexthop': '10.0.0.100'}]}
        network = {'id': 'network-id', 'mtu': 1400}

        expected_dhcp_options = {'cidr': '10.0.0.0/24',
                                 'external_ids': {
                                     'subnet_id': 'foo-subnet',
                                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'}}
        expected_dhcp_options['options'] = {
            'server_id': subnet['gateway_ip'],
            'server_mac': '01:02:03:04:05:06',
            'lease_time': str(12 * 60 * 60),
            'mtu': '1400',
            'router': subnet['gateway_ip'],
            'ntp_server': '8.8.8.8',
            'dns_server': '{7.7.7.7, 8.8.8.8}',
            'classless_static_route':
            '{20.0.0.4,10.0.0.100, 0.0.0.0/0,10.0.0.1}'
        }

        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options)
        expected_dhcp_options['options']['server_mac'] = '11:22:33:44:55:66'
        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options,
                                               service_mac='11:22:33:44:55:66')

    def test_get_ovn_dhcp_options_with_global_options_ipv6(self):
        ovn_config.cfg.CONF.set_override('ovn_dhcp6_global_options',
                                         'ntp_server:8.8.8.8,'
                                         'server_id:01:02:03:04:05:04,'
                                         'wpad:',
                                         group='ovn')

        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': 'ae70::/24',
                  'ip_version': 6,
                  'enable_dhcp': True,
                  'dns_nameservers': ['7.7.7.7', '8.8.8.8']}
        network = {'id': 'network-id', 'mtu': 1400}

        ext_ids = {'subnet_id': 'foo-subnet',
                   ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'}
        expected_dhcp_options = {
            'cidr': 'ae70::/24', 'external_ids': ext_ids,
            'options': {'server_id': '01:02:03:04:05:06',
                        'ntp_server': '8.8.8.8',
                        'dns_server': '{7.7.7.7, 8.8.8.8}'}}

        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options)
        expected_dhcp_options['options']['server_id'] = '11:22:33:44:55:66'
        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options,
                                               service_mac='11:22:33:44:55:66')

    def test_get_ovn_dhcp_options_ipv6_subnet(self):
        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': 'ae70::/24',
                  'ip_version': 6,
                  'enable_dhcp': True,
                  'dns_nameservers': ['7.7.7.7', '8.8.8.8']}
        network = {'id': 'network-id', 'mtu': 1400}

        ext_ids = {'subnet_id': 'foo-subnet',
                   ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'}
        expected_dhcp_options = {
            'cidr': 'ae70::/24', 'external_ids': ext_ids,
            'options': {'server_id': '01:02:03:04:05:06',
                        'dns_server': '{7.7.7.7, 8.8.8.8}'}}

        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options)
        expected_dhcp_options['options']['server_id'] = '11:22:33:44:55:66'
        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options,
                                               service_mac='11:22:33:44:55:66')

    def test_get_ovn_dhcp_options_dhcpv6_stateless_subnet(self):
        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': 'ae70::/24',
                  'ip_version': 6,
                  'enable_dhcp': True,
                  'dns_nameservers': ['7.7.7.7', '8.8.8.8'],
                  'ipv6_address_mode': const.DHCPV6_STATELESS}
        network = {'id': 'network-id', 'mtu': 1400}

        ext_ids = {'subnet_id': 'foo-subnet',
                   ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'}
        expected_dhcp_options = {
            'cidr': 'ae70::/24', 'external_ids': ext_ids,
            'options': {'server_id': '01:02:03:04:05:06',
                        'dns_server': '{7.7.7.7, 8.8.8.8}',
                        'dhcpv6_stateless': 'true'}}

        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options)
        expected_dhcp_options['options']['server_id'] = '11:22:33:44:55:66'
        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options,
                                               service_mac='11:22:33:44:55:66')

    def test_get_ovn_dhcp_options_metadata_route(self):
        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': '10.0.0.0/24',
                  'ip_version': 4,
                  'enable_dhcp': True,
                  'gateway_ip': '10.0.0.1',
                  'dns_nameservers': ['7.7.7.7', '8.8.8.8'],
                  'host_routes': []}
        network = {'id': 'network-id', 'mtu': 1400}

        expected_dhcp_options = {'cidr': '10.0.0.0/24',
                                 'external_ids': {
                                     'subnet_id': 'foo-subnet',
                                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'}}
        expected_dhcp_options['options'] = {
            'server_id': subnet['gateway_ip'],
            'server_mac': '01:02:03:04:05:06',
            'lease_time': str(12 * 60 * 60),
            'mtu': '1400',
            'router': subnet['gateway_ip'],
            'dns_server': '{7.7.7.7, 8.8.8.8}',
            'classless_static_route':
            '{169.254.169.254/32,10.0.0.2, 0.0.0.0/0,10.0.0.1}'
        }

        with mock.patch.object(self.mech_driver._ovn_client,
                               '_find_metadata_port_ip',
                               return_value='10.0.0.2'):
            self._test_get_ovn_dhcp_options_helper(subnet, network,
                                                   expected_dhcp_options)

    def test_get_ovn_dhcp_options_domain_name(self):
        cfg.CONF.set_override('dns_domain', 'foo.com')
        subnet = {'id': 'foo-subnet', 'network_id': 'network-id',
                  'cidr': '10.0.0.0/24',
                  'ip_version': 4,
                  'enable_dhcp': True,
                  'gateway_ip': '10.0.0.1',
                  'dns_nameservers': ['7.7.7.7', '8.8.8.8'],
                  'host_routes': [{'destination': '20.0.0.4',
                                   'nexthop': '10.0.0.100'}]}
        network = {'id': 'network-id', 'mtu': 1400}

        expected_dhcp_options = {'cidr': '10.0.0.0/24',
                                 'external_ids': {
                                     'subnet_id': 'foo-subnet',
                                     ovn_const.OVN_REV_NUM_EXT_ID_KEY: '1'}}
        expected_dhcp_options['options'] = {
            'server_id': subnet['gateway_ip'],
            'server_mac': '01:02:03:04:05:06',
            'lease_time': str(12 * 60 * 60),
            'mtu': '1400',
            'router': subnet['gateway_ip'],
            'domain_name': '"foo.com"',
            'dns_server': '{7.7.7.7, 8.8.8.8}',
            'classless_static_route':
            '{20.0.0.4,10.0.0.100, 0.0.0.0/0,10.0.0.1}'
        }

        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options)
        expected_dhcp_options['options']['server_mac'] = '11:22:33:44:55:66'
        self._test_get_ovn_dhcp_options_helper(subnet, network,
                                               expected_dhcp_options,
                                               service_mac='11:22:33:44:55:66')

    def _test__get_port_dhcp_options_port_dhcp_opts_set(self, ip_version=4):
        if ip_version == 4:
            ip_address = '10.0.0.11'
        else:
            ip_address = 'aef0::4'

        port = {
            'id': 'foo-port',
            'device_owner': 'compute:None',
            'fixed_ips': [{'subnet_id': 'foo-subnet',
                           'ip_address': ip_address}]}
        if ip_version == 4:
            port['extra_dhcp_opts'] = [
                {'ip_version': 4, 'opt_name': 'mtu', 'opt_value': '1200'},
                {'ip_version': 4, 'opt_name': 'ntp-server',
                 'opt_value': '8.8.8.8'}]
        else:
            port['extra_dhcp_opts'] = [
                {'ip_version': 6, 'opt_name': 'domain-search',
                 'opt_value': 'foo-domain'},
                {'ip_version': 4, 'opt_name': 'dns-server',
                 'opt_value': '7.7.7.7'}]

        self.mech_driver._ovn_client._get_subnet_dhcp_options_for_port = (
            mock.Mock(
                return_value=({
                    'cidr': '10.0.0.0/24' if ip_version == 4 else 'aef0::/64',
                    'external_ids': {'subnet_id': 'foo-subnet'},
                    'options': (ip_version == 4) and {
                        'router': '10.0.0.1', 'mtu': '1400'} or {
                        'server_id': '01:02:03:04:05:06'},
                    'uuid': 'foo-uuid'})))

        if ip_version == 4:
            expected_dhcp_options = {
                'cidr': '10.0.0.0/24',
                'external_ids': {'subnet_id': 'foo-subnet',
                                 'port_id': 'foo-port'},
                'options': {'router': '10.0.0.1', 'mtu': '1200',
                            'ntp_server': '8.8.8.8'}}
        else:
            expected_dhcp_options = {
                'cidr': 'aef0::/64',
                'external_ids': {'subnet_id': 'foo-subnet',
                                 'port_id': 'foo-port'},
                'options': {'server_id': '01:02:03:04:05:06',
                            'domain_search': 'foo-domain'}}

        self.mech_driver._nb_ovn.add_dhcp_options.return_value = 'foo-val'
        dhcp_options = self.mech_driver._ovn_client._get_port_dhcp_options(
            port, ip_version)
        self.assertEqual({'cmd': 'foo-val'}, dhcp_options)
        self.mech_driver._nb_ovn.add_dhcp_options.assert_called_once_with(
            'foo-subnet', port_id='foo-port', **expected_dhcp_options)

    def test__get_port_dhcp_options_port_dhcp_opts_set_v4(self):
        self._test__get_port_dhcp_options_port_dhcp_opts_set(ip_version=4)

    def test__get_port_dhcp_options_port_dhcp_opts_set_v6(self):
        self._test__get_port_dhcp_options_port_dhcp_opts_set(ip_version=6)

    def _test__get_port_dhcp_options_port_dhcp_opts_not_set(self,
                                                            ip_version=4):
        if ip_version == 4:
            port = {'id': 'foo-port',
                    'device_owner': 'compute:None',
                    'fixed_ips': [{'subnet_id': 'foo-subnet',
                                   'ip_address': '10.0.0.11'}]}
        else:
            port = {'id': 'foo-port',
                    'device_owner': 'compute:None',
                    'fixed_ips': [{'subnet_id': 'foo-subnet',
                                   'ip_address': 'aef0::4'}]}

        if ip_version == 4:
            expected_dhcp_opts = {
                'cidr': '10.0.0.0/24',
                'external_ids': {'subnet_id': 'foo-subnet'},
                'options': {'router': '10.0.0.1', 'mtu': '1400'}}
        else:
            expected_dhcp_opts = {
                'cidr': 'aef0::/64',
                'external_ids': {'subnet_id': 'foo-subnet'},
                'options': {'server_id': '01:02:03:04:05:06'}}

        self.mech_driver._ovn_client._get_subnet_dhcp_options_for_port = (
            mock.Mock(return_value=expected_dhcp_opts))

        self.assertEqual(
            expected_dhcp_opts,
            self.mech_driver._ovn_client._get_port_dhcp_options(
                port, ip_version=ip_version))

        # Since the port has no extra DHCPv4/v6 options defined, no new
        # DHCP_Options row should be created and logical switch port DHCPv4/v6
        # options should point to the subnet DHCPv4/v6 options.
        self.mech_driver._nb_ovn.add_dhcp_options.assert_not_called()

    def test__get_port_dhcp_options_port_dhcp_opts_not_set_v4(self):
        self._test__get_port_dhcp_options_port_dhcp_opts_not_set(ip_version=4)

    def test__get_port_dhcp_options_port_dhcp_opts_not_set_v6(self):
        self._test__get_port_dhcp_options_port_dhcp_opts_not_set(ip_version=6)

    def _test__get_port_dhcp_options_port_dhcp_disabled(self, ip_version=4):
        port = {
            'id': 'foo-port',
            'device_owner': 'compute:None',
            'fixed_ips': [{'subnet_id': 'foo-subnet',
                           'ip_address': '10.0.0.11'},
                          {'subnet_id': 'foo-subnet-v6',
                           'ip_address': 'aef0::11'}],
            'extra_dhcp_opts': [{'ip_version': 4, 'opt_name': 'dhcp_disabled',
                                 'opt_value': 'False'},
                                {'ip_version': 6, 'opt_name': 'dhcp_disabled',
                                 'opt_value': 'False'}]
            }

        subnet_dhcp_opts = mock.Mock()
        self.mech_driver._ovn_client._get_subnet_dhcp_options_for_port = (
            mock.Mock(return_value=subnet_dhcp_opts))

        # No dhcp_disabled set to true, subnet dhcp options will be get for
        # this port. Since it doesn't have any other extra dhcp options, but
        # dhcp_disabled, no port dhcp options will be created.
        self.assertEqual(
            subnet_dhcp_opts,
            self.mech_driver._ovn_client._get_port_dhcp_options(
                port, ip_version))
        self.assertEqual(
            1,
            self.mech_driver._ovn_client._get_subnet_dhcp_options_for_port.
            call_count)
        self.mech_driver._nb_ovn.add_dhcp_options.assert_not_called()

        # Set dhcp_disabled with ip_version specified by this test case to
        # true, no dhcp options will be get since it's dhcp_disabled now for
        # ip_version be tested.
        opt_index = 0 if ip_version == 4 else 1
        port['extra_dhcp_opts'][opt_index]['opt_value'] = 'True'
        self.mech_driver._ovn_client._get_subnet_dhcp_options_for_port.\
            reset_mock()
        self.assertIsNone(
            self.mech_driver._ovn_client._get_port_dhcp_options(
                port, ip_version))
        self.assertEqual(
            0,
            self.mech_driver._ovn_client._get_subnet_dhcp_options_for_port.
            call_count)
        self.mech_driver._nb_ovn.add_dhcp_options.assert_not_called()

        # Set dhcp_disabled with ip_version specified by this test case to
        # false, and set dhcp_disabled with ip_version not in test to true.
        # Subnet dhcp options will be get, since dhcp_disabled with ip_version
        # not in test should not affect.
        opt_index_1 = 1 if ip_version == 4 else 0
        port['extra_dhcp_opts'][opt_index]['opt_value'] = 'False'
        port['extra_dhcp_opts'][opt_index_1]['opt_value'] = 'True'
        self.assertEqual(
            subnet_dhcp_opts,
            self.mech_driver._ovn_client._get_port_dhcp_options(
                port, ip_version))
        self.assertEqual(
            1,
            self.mech_driver._ovn_client._get_subnet_dhcp_options_for_port.
            call_count)
        self.mech_driver._nb_ovn.add_dhcp_options.assert_not_called()

    def test__get_port_dhcp_options_port_dhcp_disabled_v4(self):
        self._test__get_port_dhcp_options_port_dhcp_disabled(ip_version=4)

    def test__get_port_dhcp_options_port_dhcp_disabled_v6(self):
        self._test__get_port_dhcp_options_port_dhcp_disabled(ip_version=6)

    def test__get_port_dhcp_options_port_with_invalid_device_owner(self):
        port = {
            'id': 'foo-port',
            'device_owner': 'neutron:router_interface',
            'fixed_ips': ['fake']
        }

        self.assertIsNone(
            self.mech_driver._ovn_client._get_port_dhcp_options(
                port, mock.ANY))

    def _test__get_subnet_dhcp_options_for_port(self, ip_version=4,
                                                enable_dhcp=True):
        port = {'fixed_ips': [
            {'ip_address': '10.0.0.4',
             'subnet_id': 'v4_snet_id_1' if enable_dhcp else 'v4_snet_id_2'},
            {'ip_address': '2001:dba::4',
             'subnet_id': 'v6_snet_id_1' if enable_dhcp else 'v6_snet_id_2'},
            {'ip_address': '2001:dbb::4', 'subnet_id': 'v6_snet_id_3'}]}

        def fake(subnets):
            fake_rows = {
                'v4_snet_id_1': 'foo',
                'v6_snet_id_1': {'options': {}},
                'v6_snet_id_3': {'options': {
                    ovn_const.DHCPV6_STATELESS_OPT: 'true'}}}
            return [fake_rows[row] for row in fake_rows if row in subnets]

        self.mech_driver._nb_ovn.get_subnets_dhcp_options.side_effect = fake

        if ip_version == 4:
            expected_opts = 'foo' if enable_dhcp else None
        else:
            expected_opts = {
                'options': {} if enable_dhcp else {
                    ovn_const.DHCPV6_STATELESS_OPT: 'true'}}

        self.assertEqual(
            expected_opts,
            self.mech_driver._ovn_client._get_subnet_dhcp_options_for_port(
                port, ip_version))

    def test__get_subnet_dhcp_options_for_port_v4(self):
        self._test__get_subnet_dhcp_options_for_port()

    def test__get_subnet_dhcp_options_for_port_v4_dhcp_disabled(self):
        self._test__get_subnet_dhcp_options_for_port(enable_dhcp=False)

    def test__get_subnet_dhcp_options_for_port_v6(self):
        self._test__get_subnet_dhcp_options_for_port(ip_version=6)

    def test__get_subnet_dhcp_options_for_port_v6_dhcp_disabled(self):
        self._test__get_subnet_dhcp_options_for_port(ip_version=6,
                                                     enable_dhcp=False)


class TestOVNMechanismDriverSecurityGroup(
        test_security_group.Ml2SecurityGroupsTestCase):
    # This set of test cases is supplement to test_acl.py, the purpose is to
    # test acl methods invoking. Content correctness of args of acl methods
    # is mainly guaranteed by acl_test.py.

    def setUp(self):
        cfg.CONF.set_override('mechanism_drivers',
                              ['logger', 'ovn'],
                              'ml2')
        cfg.CONF.set_override('dns_servers', ['8.8.8.8'], group='ovn')
        super(TestOVNMechanismDriverSecurityGroup, self).setUp()
        mm = directory.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers['ovn'].obj
        nb_ovn = fakes.FakeOvsdbNbOvnIdl()
        sb_ovn = fakes.FakeOvsdbSbOvnIdl()
        self.mech_driver._nb_ovn = nb_ovn
        self.mech_driver._sb_ovn = sb_ovn
        self.ctx = context.get_admin_context()
        revision_plugin.RevisionPlugin()

    def _delete_default_sg_rules(self, security_group_id):
        res = self._list(
            'security-group-rules',
            query_params='security_group_id=%s' % security_group_id)
        for r in res['security_group_rules']:
            self._delete('security-group-rules', r['id'])

    def _create_sg(self, sg_name):
        sg = self._make_security_group(self.fmt, sg_name, '')
        return sg['security_group']

    def _create_empty_sg(self, sg_name):
        sg = self._create_sg(sg_name)
        self._delete_default_sg_rules(sg['id'])
        return sg

    def _create_sg_rule(self, sg_id, direction, proto,
                        port_range_min=None, port_range_max=None,
                        remote_ip_prefix=None, remote_group_id=None,
                        ethertype=const.IPv4):
        r = self._build_security_group_rule(sg_id, direction, proto,
                                            port_range_min=port_range_min,
                                            port_range_max=port_range_max,
                                            remote_ip_prefix=remote_ip_prefix,
                                            remote_group_id=remote_group_id,
                                            ethertype=ethertype)
        res = self._create_security_group_rule(self.fmt, r)
        rule = self.deserialize(self.fmt, res)
        return rule['security_group_rule']

    def _delete_sg_rule(self, rule_id):
        self._delete('security-group-rules', rule_id)

    def test_create_security_group(self):
        sg = self._create_sg('sg')

        expected_pg_name = ovn_utils.ovn_port_group_name(sg['id'])
        expected_pg_add_calls = [
            mock.call(acls=[],
                      external_ids={'neutron:security_group_id': sg['id']},
                      name=expected_pg_name),
        ]
        self.mech_driver._nb_ovn.pg_add.assert_has_calls(
            expected_pg_add_calls)

    def test_delete_security_group(self):
        sg = self._create_sg('sg')
        self._delete('security-groups', sg['id'])

        expected_pg_name = ovn_utils.ovn_port_group_name(sg['id'])
        expected_pg_del_calls = [
            mock.call(name=expected_pg_name),
        ]
        self.mech_driver._nb_ovn.pg_del.assert_has_calls(
            expected_pg_del_calls)

    def test_create_port(self):
        with self.network() as n, self.subnet(n):
            sg = self._create_empty_sg('sg')
            self._make_port(self.fmt, n['network']['id'],
                            security_groups=[sg['id']])

            # Assert the port has been added to the right security groups
            expected_pg_name = ovn_utils.ovn_port_group_name(sg['id'])
            expected_pg_add_ports_calls = [
                mock.call('neutron_pg_drop', mock.ANY),
                mock.call(expected_pg_name, mock.ANY)
            ]
            self.mech_driver._nb_ovn.pg_add_ports.assert_has_calls(
                expected_pg_add_ports_calls)

            # Assert add_acl() is not used anymore
            self.assertFalse(self.mech_driver._nb_ovn.add_acl.called)

    def test_create_port_with_sg_default_rules(self):
        with self.network() as n, self.subnet(n):
            self.mech_driver._nb_ovn.pg_acl_add.reset_mock()
            sg = self._create_sg('sg')
            self._make_port(self.fmt, n['network']['id'],
                            security_groups=[sg['id']])
            # egress traffic for ipv4 and ipv6 is allowed by default
            self.assertEqual(
                2, self.mech_driver._nb_ovn.pg_acl_add.call_count)

    def test_create_port_with_empty_sg(self):
        with self.network() as n, self.subnet(n):
            self.mech_driver._nb_ovn.pg_acl_add.reset_mock()
            sg = self._create_empty_sg('sg')
            # Implicit egress rules for ipv4 and ipv6
            self.assertEqual(2, self.mech_driver._nb_ovn.pg_acl_add.call_count)
            self.mech_driver._nb_ovn.pg_acl_add.reset_mock()
            self.mech_driver._nb_ovn.pg_add.reset_mock()
            self.mech_driver._nb_ovn.pg_add_ports.reset_mock()

            self._make_port(self.fmt, n['network']['id'],
                            security_groups=[sg['id']])
            self.assertFalse(self.mech_driver._nb_ovn.pg_acl_add.called)
            self.assertFalse(self.mech_driver._nb_ovn.pg_add.called)
            self.assertEqual(1, self.mech_driver._nb_ovn.pg_add_ports.called)

    def test_create_port_with_multi_sgs_duplicate_rules(self):
        with self.network() as n, self.subnet(n):
            self.mech_driver._nb_ovn.pg_add.reset_mock()
            sg1 = self._create_empty_sg('sg1')
            sg2 = self._create_empty_sg('sg2')
            self.assertEqual(
                2, self.mech_driver._nb_ovn.pg_add.call_count)

            self.mech_driver._nb_ovn.pg_acl_add.reset_mock()
            self._create_sg_rule(sg1['id'], 'ingress', const.PROTO_NAME_TCP,
                                 port_range_min=22, port_range_max=23,
                                 remote_ip_prefix='20.0.0.0/24')
            self._create_sg_rule(sg2['id'], 'ingress', const.PROTO_NAME_TCP,
                                 port_range_min=22, port_range_max=23,
                                 remote_ip_prefix='20.0.0.0/24')
            self.assertEqual(
                2, self.mech_driver._nb_ovn.pg_acl_add.call_count)

            self._make_port(self.fmt, n['network']['id'],
                            security_groups=[sg1['id'], sg2['id']])
            # Default drop group, two security groups
            self.assertEqual(
                3, self.mech_driver._nb_ovn.pg_add_ports.call_count)

    @mock.patch('networking_ovn.common.ovn_client.'
                'OVNClient.is_external_ports_supported', lambda *_: True)
    def _test_create_port_with_vnic_type(self, vnic_type):
        fake_grp = 'fake-default-ha-group-uuid'
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={'uuid': fake_grp})
        self.mech_driver._nb_ovn.ha_chassis_group_get.return_value.\
            execute.return_value = row

        with self.network() as n, self.subnet(n):
            self._create_port(
                self.fmt, n['network']['id'],
                arg_list=(portbindings.VNIC_TYPE,),
                **{portbindings.VNIC_TYPE: vnic_type})

            # Assert create_lswitch_port was called with the relevant
            # parameters
            _, kwargs = self.mech_driver._nb_ovn.create_lswitch_port.call_args
            self.assertEqual(
                1, self.mech_driver._nb_ovn.create_lswitch_port.call_count)
            self.assertEqual(ovn_const.LSP_TYPE_EXTERNAL, kwargs['type'])
            self.assertEqual(fake_grp, kwargs['ha_chassis_group'])

    def test_create_port_with_vnic_direct(self):
        self._test_create_port_with_vnic_type(portbindings.VNIC_DIRECT)

    def test_create_port_with_vnic_direct_physical(self):
        self._test_create_port_with_vnic_type(
            portbindings.VNIC_DIRECT_PHYSICAL)

    def test_create_port_with_vnic_macvtap(self):
        self._test_create_port_with_vnic_type(
            portbindings.VNIC_MACVTAP)

    def test_update_port_with_sgs(self):
        with self.network() as n, self.subnet(n):
            sg1 = self._create_empty_sg('sg1')
            self._create_sg_rule(sg1['id'], 'ingress', const.PROTO_NAME_TCP,
                                 ethertype=const.IPv6)

            p = self._make_port(self.fmt, n['network']['id'],
                                security_groups=[sg1['id']])['port']

            sg2 = self._create_empty_sg('sg2')
            self._create_sg_rule(sg2['id'], 'egress', const.PROTO_NAME_UDP,
                                 remote_ip_prefix='30.0.0.0/24')
            data = {'port': {'security_groups': [sg1['id'], sg2['id']]}}

            self.mech_driver._nb_ovn.pg_add_ports.reset_mock()
            req = self.new_update_request('ports', data, p['id'])
            req.get_response(self.api)

            self.assertEqual(
                1, self.mech_driver._nb_ovn.pg_add_ports.call_count)

    def test_update_sg_change_rule(self):
        with self.network() as n, self.subnet(n):
            sg = self._create_empty_sg('sg')

            self._make_port(self.fmt, n['network']['id'],
                            security_groups=[sg['id']])

            self.mech_driver._nb_ovn.pg_acl_add.reset_mock()
            sg_r = self._create_sg_rule(sg['id'], 'ingress',
                                        const.PROTO_NAME_UDP,
                                        ethertype=const.IPv6)
            self.assertEqual(
                1, self.mech_driver._nb_ovn.pg_acl_add.call_count)

            self.mech_driver._nb_ovn.pg_acl_del.reset_mock()
            self._delete_sg_rule(sg_r['id'])
            self.assertEqual(
                1, self.mech_driver._nb_ovn.pg_acl_del.call_count)

    def test_update_sg_duplicate_rule(self):
        with self.network() as n, self.subnet(n):
            sg1 = self._create_empty_sg('sg1')
            sg2 = self._create_empty_sg('sg2')
            self._create_sg_rule(sg1['id'], 'ingress',
                                 const.PROTO_NAME_UDP,
                                 port_range_min=22, port_range_max=23)
            self._make_port(self.fmt, n['network']['id'],
                            security_groups=[sg1['id'], sg2['id']])
            # One default drop rule, two SGs
            self.assertEqual(
                3, self.mech_driver._nb_ovn.pg_add_ports.call_count)

            self.mech_driver._nb_ovn.pg_acl_add.reset_mock()
            # Add a new duplicate rule to sg2. It's expected to be added.
            sg2_r = self._create_sg_rule(sg2['id'], 'ingress',
                                         const.PROTO_NAME_UDP,
                                         port_range_min=22, port_range_max=23)
            self.assertEqual(
                1, self.mech_driver._nb_ovn.pg_acl_add.call_count)

            self.mech_driver._nb_ovn.pg_acl_del.reset_mock()
            # Delete the duplicate rule. It's expected to be deleted.
            self._delete_sg_rule(sg2_r['id'])
            self.assertEqual(
                1, self.mech_driver._nb_ovn.pg_acl_del.call_count)

    def test_update_sg_duplicate_rule_multi_ports(self):
        with self.network() as n, self.subnet(n):
            sg1 = self._create_empty_sg('sg1')
            sg2 = self._create_empty_sg('sg2')
            sg3 = self._create_empty_sg('sg3')

            self.mech_driver._nb_ovn.pg_acl_add.reset_mock()
            self._create_sg_rule(sg1['id'], 'ingress',
                                 const.PROTO_NAME_UDP,
                                 remote_group_id=sg3['id'])
            self._create_sg_rule(sg2['id'], 'egress', const.PROTO_NAME_TCP,
                                 port_range_min=60, port_range_max=70)

            self._make_port(self.fmt, n['network']['id'],
                            security_groups=[sg1['id'], sg2['id']])
            self._make_port(self.fmt, n['network']['id'],
                            security_groups=[sg1['id'], sg2['id']])
            self._make_port(self.fmt, n['network']['id'],
                            security_groups=[sg2['id'], sg3['id']])

            # No matter how many ports are there, there are two rules only
            self.assertEqual(
                2, self.mech_driver._nb_ovn.pg_acl_add.call_count)

            # Add a rule to sg1 duplicate with sg2. It's expected to be added.
            self.mech_driver._nb_ovn.pg_acl_add.reset_mock()
            sg1_r = self._create_sg_rule(sg1['id'], 'egress',
                                         const.PROTO_NAME_TCP,
                                         port_range_min=60, port_range_max=70)
            self.assertEqual(1, self.mech_driver._nb_ovn.pg_acl_add.call_count)

            # Add a rule to sg2 duplicate with sg1 but not duplicate with sg3.
            # It's expected to be added as well.
            self.mech_driver._nb_ovn.pg_acl_add.reset_mock()
            sg2_r = self._create_sg_rule(sg2['id'], 'ingress',
                                         const.PROTO_NAME_UDP,
                                         remote_group_id=sg3['id'])
            self.assertEqual(
                1, self.mech_driver._nb_ovn.pg_acl_add.call_count)

            # Delete the duplicate rule in sg1. It's expected to be deleted.
            self.mech_driver._nb_ovn.pg_acl_del.reset_mock()
            self._delete_sg_rule(sg1_r['id'])
            self.assertEqual(
                1, self.mech_driver._nb_ovn.pg_acl_del.call_count)

            # Delete the duplicate rule in sg2. It's expected to be deleted.
            self.mech_driver._nb_ovn.pg_acl_del.reset_mock()
            self._delete_sg_rule(sg2_r['id'])
            self.assertEqual(
                1, self.mech_driver._nb_ovn.pg_acl_del.call_count)

    def test_delete_port_with_security_groups_port_doesnt_remove_pg(self):
        with self.network(set_context=True, tenant_id='test') as net1:
            with self.subnet(network=net1):
                sg = self._create_sg('sg')
                port = self._make_port(
                    self.fmt, net1['network']['id'],
                    security_groups=[sg['id']])['port']
                fake_lsp = fakes.FakeOVNPort.from_neutron_port(port)
                self.mech_driver._nb_ovn.lookup.return_value = fake_lsp
                self.mech_driver._nb_ovn.delete_lswitch_port.reset_mock()
                self.mech_driver._nb_ovn.delete_acl.reset_mock()
                self._delete('ports', port['id'])
                self.assertEqual(
                    1, self.mech_driver._nb_ovn.delete_lswitch_port.call_count)
                self.assertFalse(self.mech_driver._nb_ovn.pg_del.called)
                self.assertFalse(self.mech_driver._nb_ovn.delete_acl.called)


class TestOVNMechanismDriverMetadataPort(test_plugin.Ml2PluginV2TestCase):

    _mechanism_drivers = ['logger', 'ovn']

    def setUp(self):
        super(TestOVNMechanismDriverMetadataPort, self).setUp()
        mm = directory.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers['ovn'].obj
        self.mech_driver._nb_ovn = fakes.FakeOvsdbNbOvnIdl()
        self.mech_driver._sb_ovn = fakes.FakeOvsdbSbOvnIdl()
        self.nb_ovn = self.mech_driver._nb_ovn
        self.sb_ovn = self.mech_driver._sb_ovn
        self.ctx = context.get_admin_context()
        ovn_config.cfg.CONF.set_override('ovn_metadata_enabled',
                                         True,
                                         group='ovn')
        p = mock.patch.object(ovn_utils, 'get_revision_number', return_value=1)
        p.start()
        self.addCleanup(p.stop)

    def _create_fake_dhcp_port(self, device_id):
        return {'network_id': 'fake', 'device_owner': const.DEVICE_OWNER_DHCP,
                'device_id': device_id}

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_ports')
    def test__find_metadata_port(self, mock_get_ports):
        ports = [
            self._create_fake_dhcp_port('dhcp-0'),
            self._create_fake_dhcp_port('dhcp-1'),
            self._create_fake_dhcp_port(const.DEVICE_ID_RESERVED_DHCP_PORT),
            self._create_fake_dhcp_port('ovnmeta-0')]
        mock_get_ports.return_value = ports

        md_port = self.mech_driver._ovn_client._find_metadata_port(
            self.ctx, 'fake-net-id')
        self.assertEqual('ovnmeta-0', md_port['device_id'])

    def test_metadata_port_on_network_create(self):
        """Check metadata port create.

        Check that a localport is created when a neutron network is
        created.
        """
        with self.network():
            self.assertEqual(1, self.nb_ovn.create_lswitch_port.call_count)
            args, kwargs = self.nb_ovn.create_lswitch_port.call_args
            self.assertEqual('localport', kwargs['type'])

    def test_metadata_port_not_created_if_exists(self):
        """Check that metadata port is not created if it already exists.

        In the event of a sync, it might happen that a metadata port exists
        already. When we are creating the logical switch in OVN we don't want
        this port to be created again.
        """
        with mock.patch.object(
            self.mech_driver._ovn_client, '_find_metadata_port',
                return_value={'port': {'id': 'metadata_port1'}}):
            with self.network():
                self.assertEqual(0, self.nb_ovn.create_lswitch_port.call_count)

    def test_metadata_ip_on_subnet_create(self):
        """Check metadata port update.

        Check that the metadata port is updated with a new IP address when a
        subnet is created.
        """
        with self.network(set_context=True, tenant_id='test') as net1:
            with self.subnet(network=net1, cidr='10.0.0.0/24') as subnet1:
                # Create a network:dhcp owner port just as how Neutron DHCP
                # agent would do.
                with self.port(subnet=subnet1,
                               device_owner=const.DEVICE_OWNER_DHCP,
                               device_id='dhcpxxxx',
                               set_context=True, tenant_id='test'):
                    with self.subnet(network=net1, cidr='20.0.0.0/24'):
                        self.assertEqual(
                            2, self.nb_ovn.set_lswitch_port.call_count)
                        args, kwargs = self.nb_ovn.set_lswitch_port.call_args
                        self.assertEqual('localport', kwargs['type'])
                        self.assertEqual('10.0.0.2/24 20.0.0.2/24',
                                         kwargs['external_ids'].get(
                                             ovn_const.OVN_CIDRS_EXT_ID_KEY,
                                             ''))

    def test_metadata_port_on_network_delete(self):
        """Check metadata port delete.

        Check that the metadata port is deleted when a network is deleted.
        """
        net = self._make_network(self.fmt, name="net1", admin_state_up=True)
        network_id = net['network']['id']
        req = self.new_delete_request('networks', network_id)
        res = req.get_response(self.api)
        self.assertEqual(exc.HTTPNoContent.code,
                         res.status_int)
        self.assertEqual(1, self.nb_ovn.delete_lswitch_port.call_count)


class TestOVNParentTagPortBinding(OVNMechanismDriverTestCase):
    def test_create_port_with_invalid_parent(self):
        binding = {OVN_PROFILE: {"parent_name": 'invalid', 'tag': 1}}
        with self.network() as n:
            with self.subnet(n):
                self._create_port(
                    self.fmt, n['network']['id'],
                    expected_res_status=404,
                    arg_list=(OVN_PROFILE,),
                    **binding)

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    def test_create_port_with_parent_and_tag(self, mock_get_port):
        binding = {OVN_PROFILE: {"parent_name": '', 'tag': 1}}
        with self.network() as n:
            with self.subnet(n) as s:
                with self.port(s) as p:
                    binding[OVN_PROFILE]['parent_name'] = p['port']['id']
                    res = self._create_port(self.fmt, n['network']['id'],
                                            arg_list=(OVN_PROFILE,),
                                            **binding)
                    port = self.deserialize(self.fmt, res)
                    self.assertEqual(port['port'][OVN_PROFILE],
                                     binding[OVN_PROFILE])
                    mock_get_port.assert_called_with(mock.ANY, p['port']['id'])

    def test_create_port_with_invalid_tag(self):
        binding = {OVN_PROFILE: {"parent_name": '', 'tag': 'a'}}
        with self.network() as n:
            with self.subnet(n) as s:
                with self.port(s) as p:
                    binding[OVN_PROFILE]['parent_name'] = p['port']['id']
                    self._create_port(self.fmt, n['network']['id'],
                                      arg_list=(OVN_PROFILE,),
                                      expected_res_status=400,
                                      **binding)


class TestOVNVtepPortBinding(OVNMechanismDriverTestCase):

    def test_create_port_with_vtep_options(self):
        binding = {OVN_PROFILE: {"vtep-physical-switch": 'psw1',
                   "vtep-logical-switch": 'lsw1'}}
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port(self.fmt, n['network']['id'],
                                        arg_list=(OVN_PROFILE,),
                                        **binding)
                port = self.deserialize(self.fmt, res)
                self.assertEqual(binding[OVN_PROFILE],
                                 port['port'][OVN_PROFILE])

    def test_create_port_with_only_vtep_physical_switch(self):
        binding = {OVN_PROFILE: {"vtep-physical-switch": 'psw'}}
        with self.network() as n:
            with self.subnet(n):
                self._create_port(self.fmt, n['network']['id'],
                                  arg_list=(OVN_PROFILE,),
                                  expected_res_status=400,
                                  **binding)

    def test_create_port_with_only_vtep_logical_switch(self):
        binding = {OVN_PROFILE: {"vtep-logical-switch": 'lsw1'}}
        with self.network() as n:
            with self.subnet(n):
                self._create_port(self.fmt, n['network']['id'],
                                  arg_list=(OVN_PROFILE,),
                                  expected_res_status=400,
                                  **binding)

    def test_create_port_with_invalid_vtep_logical_switch(self):
        binding = {OVN_PROFILE: {"vtep-logical-switch": 1234,
                                 "vtep-physical-switch": "psw1"}}
        with self.network() as n:
            with self.subnet(n):
                self._create_port(self.fmt, n['network']['id'],
                                  arg_list=(OVN_PROFILE,),
                                  expected_res_status=400,
                                  **binding)

    def test_create_port_with_vtep_options_and_parent_name_tag(self):
        binding = {OVN_PROFILE: {"vtep-logical-switch": "lsw1",
                                 "vtep-physical-switch": "psw1",
                                 "parent_name": "pname", "tag": 22}}
        with self.network() as n:
            with self.subnet(n):
                self._create_port(self.fmt, n['network']['id'],
                                  arg_list=(OVN_PROFILE,),
                                  expected_res_status=400,
                                  **binding)

    def test_create_port_with_vtep_options_and_check_vtep_keys(self):
        port = {
            'id': 'foo-port',
            'device_owner': 'compute:None',
            'fixed_ips': [{'subnet_id': 'foo-subnet',
                           'ip_address': '10.0.0.11'}],
            OVN_PROFILE: {"vtep-logical-switch": "lsw1",
                          "vtep-physical-switch": "psw1"}
        }
        ovn_port_info = (
            self.mech_driver._ovn_client._get_port_options(port))
        self.assertEqual(port[OVN_PROFILE]["vtep-physical-switch"],
                         ovn_port_info.options["vtep-physical-switch"])
        self.assertEqual(port[OVN_PROFILE]["vtep-logical-switch"],
                         ovn_port_info.options["vtep-logical-switch"])


@mock.patch('networking_ovn.common.ovn_client.OVNClient'
            '._is_virtual_port_supported', lambda *args: True)
class TestOVNVVirtualPort(OVNMechanismDriverTestCase):

    def setUp(self):
        super(TestOVNVVirtualPort, self).setUp()
        self.context = context.get_admin_context()
        self.nb_idl = self.mech_driver._ovn_client._nb_idl
        self.net = self._make_network(
            self.fmt, name='net1', admin_state_up=True)['network']
        self.subnet = self._make_subnet(
            self.fmt, {'network': self.net},
            '10.0.0.1', '10.0.0.0/24')['subnet']

    @mock.patch('networking_ovn.common.ovn_client.OVNClient.'
                'get_virtual_port_parents')
    def test_create_port_with_virtual_type_and_options(self, mock_get_parents):
        fake_parents = ['parent-0', 'parent-1']
        mock_get_parents.return_value = fake_parents
        port = {'id': 'virt-port',
                'mac_address': '00:00:00:00:00:00',
                'device_owner': '',
                'network_id': self.net['id'],
                'fixed_ips': [{'subnet_id': self.subnet['id'],
                               'ip_address': '10.0.0.55'}]}
        port_info = self.mech_driver._ovn_client._get_port_options(
            port)
        self.assertEqual(ovn_const.LSP_TYPE_VIRTUAL, port_info.type)
        self.assertEqual(
            '10.0.0.55',
            port_info.options[ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY])
        self.assertIn(
            'parent-0',
            port_info.options[
                ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY])
        self.assertIn(
            'parent-1',
            port_info.options[
                ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY])

    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_ports')
    def _test_set_unset_virtual_port_type(self, mock_get_ports, unset=False):
        cmd = self.nb_idl.set_lswitch_port_to_virtual_type
        if unset:
            cmd = self.nb_idl.unset_lswitch_port_to_virtual_type

        fake_txn = mock.Mock()
        parent_port = {'id': 'parent-port', 'network_id': 'fake-network'}
        port = {'id': 'virt-port'}
        mock_get_ports.return_value = [port]
        self.mech_driver._ovn_client._set_unset_virtual_port_type(
            self.context, fake_txn, parent_port, ['10.0.0.55'], unset=unset)

        args = {'lport_name': 'virt-port',
                'virtual_parent': 'parent-port',
                'if_exists': True}
        if not unset:
            args['vip'] = '10.0.0.55'

        cmd.assert_called_once_with(**args)

    def test__set_unset_virtual_port_type_set(self):
        self._test_set_unset_virtual_port_type(unset=False)

    def test__set_unset_virtual_port_type_unset(self):
        self._test_set_unset_virtual_port_type(unset=True)

    def test_delete_virtual_port_parent(self):
        self.nb_idl.ls_get.return_value.execute.return_value = (
            fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={'ports': []}))
        virt_port = self._make_port(self.fmt, self.net['id'])['port']
        virt_ip = virt_port['fixed_ips'][0]['ip_address']
        parent = self._make_port(
            self.fmt, self.net['id'],
            allowed_address_pairs=[{'ip_address': virt_ip}])['port']
        fake_row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': virt_port['id'],
                   'type': ovn_const.LSP_TYPE_VIRTUAL,
                   'options': {ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY:
                               parent['id']}})
        self.nb_idl.ls_get.return_value.execute.return_value = (
            mock.Mock(ports=[fake_row]))

        self.mech_driver._ovn_client.delete_port(parent['id'])
        self.nb_idl.unset_lswitch_port_to_virtual_type.assert_called_once_with(
            virt_port['id'], parent['id'], if_exists=True)


class TestOVNAvailabilityZone(OVNMechanismDriverTestCase):

    def setUp(self):
        super(TestOVNAvailabilityZone, self).setUp()
        self.context = context.get_admin_context()
        self.sb_idl = self.mech_driver._ovn_client._sb_idl

    def test_list_availability_zones(self):
        ch0 = fakes.FakeChassis.create(az_list=['az0', 'az1'],
                                       chassis_as_gw=True)
        ch1 = fakes.FakeChassis.create(az_list=[], chassis_as_gw=False)
        ch2 = fakes.FakeChassis.create(az_list=['az2'], chassis_as_gw=True)
        ch3 = fakes.FakeChassis.create(az_list=[], chassis_as_gw=True)
        self.sb_idl.chassis_list.return_value.execute.return_value = [
            ch0, ch1, ch2, ch3]

        azs = self.mech_driver.list_availability_zones(self.context)
        expected_azs = {'az0': {'name': 'az0', 'resource': 'router',
                                'state': 'available', 'tenant_id': mock.ANY},
                        'az1': {'name': 'az1', 'resource': 'router',
                                'state': 'available', 'tenant_id': mock.ANY},
                        'az2': {'name': 'az2', 'resource': 'router',
                                'state': 'available', 'tenant_id': mock.ANY}}
        self.assertEqual(expected_azs, azs)

    def test_list_availability_zones_no_azs(self):
        ch0 = fakes.FakeChassis.create(az_list=[], chassis_as_gw=True)
        ch1 = fakes.FakeChassis.create(az_list=[], chassis_as_gw=True)
        self.sb_idl.chassis_list.return_value.execute.return_value = [
            ch0, ch1]

        azs = self.mech_driver.list_availability_zones(mock.Mock())
        self.assertEqual({}, azs)

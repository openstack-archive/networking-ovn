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
import os

import mock
from neutron.tests import base
from neutronclient.common import exceptions as n_exc
from octavia_lib.api.drivers import data_models
from octavia_lib.api.drivers import driver_lib
from octavia_lib.api.drivers import exceptions
from octavia_lib.common import constants
from oslo_utils import uuidutils
from ovs.db import idl as ovs_idl
from ovsdbapp.backend.ovs_idl import idlutils

from networking_ovn.common import constants as ovn_const
from networking_ovn.octavia import ovn_driver
from networking_ovn.tests.unit import fakes

basedir = os.path.dirname(os.path.abspath(__file__))
schema_files = {
    'OVN_Northbound': os.path.join(basedir.replace('octavia', 'ovsdb'),
                                   'schemas', 'ovn-nb.ovsschema')}


# TODO(mjozefcz): Move it to unittest fakes.
class MockedLB(data_models.LoadBalancer):
    def __init__(self, *args, **kwargs):
        self.external_ids = kwargs.pop('ext_ids')
        self.uuid = kwargs.pop('uuid')
        super(MockedLB, self).__init__(*args, **kwargs)

    def __hash__(self):
        # Required for Python3, not for Python2
        return self.__sizeof__()


class TestOvnNbIdlForLb(base.BaseTestCase):
    def setUp(self):
        super(TestOvnNbIdlForLb, self).setUp()
        self.mock_gsh = mock.patch.object(
            idlutils, 'get_schema_helper',
            side_effect=lambda x, y: ovs_idl.SchemaHelper(
                location=schema_files['OVN_Northbound'])).start()
        self.idl = ovn_driver.OvnNbIdlForLb()

    def test__get_ovsdb_helper(self):
        self.mock_gsh.reset_mock()
        self.idl._get_ovsdb_helper('foo')
        self.mock_gsh.assert_called_once_with('foo', 'OVN_Northbound')

    def test_start(self):
        with mock.patch('ovsdbapp.backend.ovs_idl.connection.Connection',
                        side_effect=lambda x, timeout: mock.Mock()):
            idl1 = ovn_driver.OvnNbIdlForLb()
            ret1 = idl1.start()
            id1 = id(ret1.ovsdb_connection)
            idl2 = ovn_driver.OvnNbIdlForLb()
            ret2 = idl2.start()
            id2 = id(ret2.ovsdb_connection)
            self.assertNotEqual(id1, id2)

    @mock.patch('ovsdbapp.backend.ovs_idl.connection.Connection')
    def test_stop(self, mock_conn):
        mock_conn.stop.return_value = False
        with (
            mock.patch.object(
                self.idl.notify_handler, 'shutdown')) as mock_notify, (
                mock.patch.object(self.idl, 'close')) as mock_close:
            self.idl.start()
            self.idl.stop()
        mock_notify.assert_called_once_with()
        mock_close.assert_called_once_with()

    def test_setlock(self):
        with mock.patch.object(ovn_driver.OvnNbIdlForLb,
                               'set_lock') as set_lock:
            self.idl = ovn_driver.OvnNbIdlForLb(event_lock_name='foo')
        set_lock.assert_called_once_with('foo')


class TestOvnOctaviaBase(base.BaseTestCase):

    def setUp(self):
        super(TestOvnOctaviaBase, self).setUp()
        self.listener_id = uuidutils.generate_uuid()
        self.loadbalancer_id = uuidutils.generate_uuid()
        self.pool_id = uuidutils.generate_uuid()
        self.member_id = uuidutils.generate_uuid()
        self.member_subnet_id = uuidutils.generate_uuid()
        self.member_port = "1010"
        self.member_pool_id = self.pool_id
        self.member_address = "192.168.2.149"
        self.port1_id = uuidutils.generate_uuid()
        self.port2_id = uuidutils.generate_uuid()
        self.project_id = uuidutils.generate_uuid()
        self.vip_network_id = uuidutils.generate_uuid()
        self.vip_port_id = uuidutils.generate_uuid()
        self.vip_subnet_id = uuidutils.generate_uuid()
        mock.patch("networking_ovn.common.utils.get_ovsdb_connection").start()
        mock.patch(
            "networking_ovn.octavia.ovn_driver.OvnNbIdlForLb").start()
        self.member_address = "192.168.2.149"
        self.vip_address = '192.148.210.109'
        self.vip_dict = {'vip_network_id': uuidutils.generate_uuid(),
                         'vip_subnet_id': uuidutils.generate_uuid()}
        self.vip_output = {'vip_network_id': self.vip_dict['vip_network_id'],
                           'vip_subnet_id': self.vip_dict['vip_subnet_id']}
        mock.patch(
            'ovsdbapp.backend.ovs_idl.idlutils.get_schema_helper').start()
        try:
            mock.patch.object(
                driver_lib.DriverLibrary, '_check_for_socket_ready').start()
        except AttributeError:
            # Backward compatiblity with octavia-lib < 1.3.1
            pass


class TestOvnProviderDriver(TestOvnOctaviaBase):

    def setUp(self):
        super(TestOvnProviderDriver, self).setUp()
        self.driver = ovn_driver.OvnProviderDriver()
        add_req_thread = mock.patch.object(ovn_driver.OvnProviderHelper,
                                           'add_request')
        self.member_line = (
            'member_%s_%s:%s_%s' %
            (self.member_id, self.member_address,
             self.member_port, self.member_subnet_id))
        self.ovn_lb = mock.MagicMock()
        self.ovn_lb.name = 'foo_ovn_lb'
        self.ovn_lb.external_ids = {
            ovn_const.LB_EXT_IDS_VIP_KEY: '10.22.33.4',
            'pool_%s' % self.pool_id: self.member_line,
            'listener_%s' % self.listener_id: '80:pool_%s' % self.pool_id}
        self.mock_add_request = add_req_thread.start()
        self.project_id = uuidutils.generate_uuid()

        self.fail_member = data_models.Member(
            address='198.51.100.4',
            admin_state_up=True,
            member_id=self.member_id,
            monitor_address="100.200.200.100",
            monitor_port=66,
            name='Amazin',
            pool_id=self.pool_id,
            protocol_port=99,
            subnet_id=self.member_subnet_id,
            weight=55)
        self.ref_member = data_models.Member(
            address='198.52.100.4',
            admin_state_up=True,
            member_id=self.member_id,
            monitor_address=data_models.Unset,
            monitor_port=data_models.Unset,
            name='Amazing',
            pool_id=self.pool_id,
            protocol_port=99,
            subnet_id=self.member_subnet_id,
            weight=55)
        self.update_member = data_models.Member(
            address='198.53.100.4',
            admin_state_up=False,
            member_id=self.member_id,
            monitor_address=data_models.Unset,
            monitor_port=data_models.Unset,
            name='Amazin',
            pool_id=self.pool_id,
            protocol_port=99,
            subnet_id=self.member_subnet_id,
            weight=55)
        self.ref_update_pool = data_models.Pool(
            admin_state_up=False,
            description='pool',
            name='Peter',
            lb_algorithm=constants.LB_ALGORITHM_SOURCE_IP_PORT,
            loadbalancer_id=self.loadbalancer_id,
            listener_id=self.listener_id,
            members=[self.ref_member],
            pool_id=self.pool_id,
            protocol='TCP',
            session_persistence={'type': 'fix'})
        self.ref_pool = data_models.Pool(
            admin_state_up=True,
            description='pool',
            name='Peter',
            lb_algorithm=constants.LB_ALGORITHM_SOURCE_IP_PORT,
            loadbalancer_id=self.loadbalancer_id,
            listener_id=self.listener_id,
            members=[self.ref_member],
            pool_id=self.pool_id,
            protocol='TCP',
            session_persistence={'type': 'fix'})
        self.ref_http_pool = data_models.Pool(
            admin_state_up=True,
            description='pool',
            lb_algorithm=constants.LB_ALGORITHM_SOURCE_IP_PORT,
            loadbalancer_id=self.loadbalancer_id,
            listener_id=self.listener_id,
            members=[self.ref_member],
            name='Groot',
            pool_id=self.pool_id,
            protocol='HTTP',
            session_persistence={'type': 'fix'})
        self.ref_lc_pool = data_models.Pool(
            admin_state_up=True,
            description='pool',
            lb_algorithm=constants.LB_ALGORITHM_LEAST_CONNECTIONS,
            loadbalancer_id=self.loadbalancer_id,
            listener_id=self.listener_id,
            members=[self.ref_member],
            name='Groot',
            pool_id=self.pool_id,
            protocol='HTTP',
            session_persistence={'type': 'fix'})
        self.ref_listener = data_models.Listener(
            admin_state_up=False,
            connection_limit=5,
            default_pool=self.ref_pool,
            default_pool_id=self.pool_id,
            listener_id=self.listener_id,
            loadbalancer_id=self.loadbalancer_id,
            name='listener',
            protocol='TCP',
            protocol_port=42)
        self.ref_listener_udp = data_models.Listener(
            admin_state_up=False,
            connection_limit=5,
            default_pool=self.ref_pool,
            default_pool_id=self.pool_id,
            listener_id=self.listener_id,
            loadbalancer_id=self.loadbalancer_id,
            name='listener',
            protocol='UDP',
            protocol_port=42)
        self.fail_listener = data_models.Listener(
            admin_state_up=False,
            connection_limit=5,
            default_pool=self.ref_pool,
            default_pool_id=self.pool_id,
            listener_id=self.listener_id,
            loadbalancer_id=self.loadbalancer_id,
            name='listener',
            protocol='http',
            protocol_port=42)
        self.ref_lb0 = data_models.LoadBalancer(
            admin_state_up=False,
            listeners=[self.ref_listener],
            loadbalancer_id=self.loadbalancer_id,
            name='favorite_lb0',
            project_id=self.project_id,
            vip_address=self.vip_address,
            vip_network_id=self.vip_network_id)
        self.ref_lb1 = data_models.LoadBalancer(
            admin_state_up=True,
            listeners=[self.ref_listener],
            loadbalancer_id=self.loadbalancer_id,
            name='favorite_lb1',
            project_id=self.project_id,
            vip_address=self.vip_address,
            vip_network_id=self.vip_network_id)
        mock.patch.object(
            ovn_driver.OvnProviderHelper, '_find_ovn_lbs',
            side_effect=lambda x, protocol=None:
                self.ovn_lb if protocol else [self.ovn_lb]).start()
        self.mock_find_lb_pool_key = mock.patch.object(
            ovn_driver.OvnProviderHelper,
            '_find_ovn_lb_with_pool_key',
            return_value=self.ovn_lb).start()

    def test__ip_version_differs(self):
        self.assertFalse(self.driver._ip_version_differs(self.ref_member))
        self.ref_member.address = 'fc00::1'
        self.assertTrue(self.driver._ip_version_differs(self.ref_member))

    def test__ip_version_differs_pool_disabled(self):
        self.mock_find_lb_pool_key.side_effect = [None, self.ovn_lb]
        self.driver._ip_version_differs(self.ref_member)
        self.mock_find_lb_pool_key.assert_has_calls([
            mock.call('pool_%s' % self.pool_id),
            mock.call('pool_%s:D' % self.pool_id)])

    def test_member_create(self):
        info = {'id': self.ref_member.member_id,
                'address': self.ref_member.address,
                'protocol_port': self.ref_member.protocol_port,
                'pool_id': self.ref_member.pool_id,
                'subnet_id': self.ref_member.subnet_id,
                'admin_state_up': self.ref_member.admin_state_up}
        expected_dict = {'type': ovn_driver.REQ_TYPE_MEMBER_CREATE,
                         'info': info}
        info_dvr = {
            'id': self.ref_member.member_id,
            'address': self.ref_member.address,
            'pool_id': self.ref_member.pool_id,
            'subnet_id': self.ref_member.subnet_id,
            'action': ovn_driver.REQ_INFO_MEMBER_ADDED}
        expected_dict_dvr = {
            'type': ovn_driver.REQ_TYPE_HANDLE_MEMBER_DVR,
            'info': info_dvr}
        self.driver.member_create(self.ref_member)
        expected = [
            mock.call(expected_dict),
            mock.call(expected_dict_dvr)]
        self.mock_add_request.assert_has_calls(expected)

    def test_member_create_failure(self):
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_create, self.fail_member)

    def test_member_create_different_ip_version(self):
        self.ref_member.address = 'fc00::1'
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_create, self.ref_member)

    def test_member_create_different_ip_version_lb_disable(self):
        self.driver._ovn_helper._find_ovn_lb_with_pool_key.side_effect = [
            None, self.ovn_lb]
        self.ref_member.address = 'fc00::1'
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_create, self.ref_member)
        self.driver._ovn_helper._find_ovn_lb_with_pool_key.assert_has_calls(
            [mock.call('pool_%s' % self.pool_id),
             mock.call('pool_%s%s' % (self.pool_id, ':D'))])

    def test_member_create_no_subnet_provided(self):
        self.ref_member.subnet_id = data_models.UnsetType()
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_create, self.ref_member)
        self.ref_member.subnet_id = None
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_create, self.ref_member)

    def test_member_create_monitor_opts(self):
        self.ref_member.monitor_address = '172.20.20.1'
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_create, self.ref_member)
        self.ref_member.monitor_port = '80'
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_create, self.ref_member)

    def test_member_create_no_set_admin_state_up(self):
        self.ref_member.admin_state_up = data_models.UnsetType()
        info = {'id': self.ref_member.member_id,
                'address': self.ref_member.address,
                'protocol_port': self.ref_member.protocol_port,
                'pool_id': self.ref_member.pool_id,
                'subnet_id': self.ref_member.subnet_id,
                'admin_state_up': True}
        expected_dict = {'type': ovn_driver.REQ_TYPE_MEMBER_CREATE,
                         'info': info}
        expected_dict_dvr = {'type': ovn_driver.REQ_TYPE_HANDLE_MEMBER_DVR,
                             'info': mock.ANY}
        expected = [
            mock.call(expected_dict),
            mock.call(expected_dict_dvr)]
        self.driver.member_create(self.ref_member)
        self.mock_add_request.assert_has_calls(expected)

    def test_member_update(self):
        info = {'id': self.update_member.member_id,
                'address': self.ref_member.address,
                'protocol_port': self.ref_member.protocol_port,
                'pool_id': self.ref_member.pool_id,
                'admin_state_up': self.update_member.admin_state_up,
                'subnet_id': self.ref_member.subnet_id}
        expected_dict = {'type': ovn_driver.REQ_TYPE_MEMBER_UPDATE,
                         'info': info}
        self.driver.member_update(self.ref_member, self.update_member)
        self.mock_add_request.assert_called_once_with(expected_dict)

    @mock.patch.object(ovn_driver.OvnProviderDriver, '_ip_version_differs')
    def test_member_update_no_ip_addr(self, mock_ip_differs):
        self.update_member.address = None
        self.driver.member_update(self.ref_member, self.update_member)
        mock_ip_differs.assert_not_called()

    def test_member_batch_update(self):
        self.driver.member_batch_update([self.ref_member, self.update_member])
        self.assertEqual(self.mock_add_request.call_count, 3)

    def test_member_batch_update_no_members(self):
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_batch_update, [])

    def test_member_batch_update_missing_pool(self):
        delattr(self.ref_member, 'pool_id')
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_batch_update, [self.ref_member])

    def test_member_batch_update_skipped_monitor(self):
        self.ref_member.monitor_address = '10.11.1.1'
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_batch_update,
                          [self.ref_member])

    def test_member_batch_update_skipped_mixed_ip(self):
        self.ref_member.address = 'fc00::1'
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_batch_update,
                          [self.ref_member])

    def test_member_batch_update_unset_admin_state_up(self):
        self.ref_member.admin_state_up = data_models.UnsetType()
        self.driver.member_batch_update([self.ref_member])
        self.assertEqual(self.mock_add_request.call_count, 2)

    def test_member_batch_update_missing_subnet_id(self):
        self.ref_member.subnet_id = None
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_batch_update, [self.ref_member])

    def test_member_update_failure(self):
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_update, self.ref_member,
                          self.fail_member)

    def test_member_update_different_ip_version(self):
        self.ref_member.address = 'fc00::1'
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_update, self.ref_member,
                          self.ref_member)

    def test_member_delete(self):
        info = {'id': self.ref_member.member_id,
                'address': self.ref_member.address,
                'protocol_port': self.ref_member.protocol_port,
                'pool_id': self.ref_member.pool_id,
                'subnet_id': self.ref_member.subnet_id}
        expected_dict = {'type': ovn_driver.REQ_TYPE_MEMBER_DELETE,
                         'info': info}
        info_dvr = {
            'id': self.ref_member.member_id,
            'address': self.ref_member.address,
            'pool_id': self.ref_member.pool_id,
            'subnet_id': self.ref_member.subnet_id,
            'action': ovn_driver.REQ_INFO_MEMBER_DELETED}
        expected_dict_dvr = {
            'type': ovn_driver.REQ_TYPE_HANDLE_MEMBER_DVR,
            'info': info_dvr}
        self.driver.member_delete(self.ref_member)
        expected = [
            mock.call(expected_dict),
            mock.call(expected_dict_dvr)]
        self.mock_add_request.assert_has_calls(expected)

    def test_listener_create(self):
        info = {'id': self.ref_listener.listener_id,
                'protocol': self.ref_listener.protocol,
                'protocol_port': self.ref_listener.protocol_port,
                'default_pool_id': self.ref_listener.default_pool_id,
                'admin_state_up': self.ref_listener.admin_state_up,
                'loadbalancer_id': self.ref_listener.loadbalancer_id}
        expected_dict = {'type': ovn_driver.REQ_TYPE_LISTENER_CREATE,
                         'info': info}
        self.driver.listener_create(self.ref_listener)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_listener_create_unset_admin_state_up(self):
        self.ref_listener.admin_state_up = data_models.UnsetType()
        info = {'id': self.ref_listener.listener_id,
                'protocol': self.ref_listener.protocol,
                'protocol_port': self.ref_listener.protocol_port,
                'default_pool_id': self.ref_listener.default_pool_id,
                'admin_state_up': True,
                'loadbalancer_id': self.ref_listener.loadbalancer_id}
        expected_dict = {'type': ovn_driver.REQ_TYPE_LISTENER_CREATE,
                         'info': info}
        self.driver.listener_create(self.ref_listener)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_listener_create_unsupported_protocol(self):
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.listener_create, self.fail_listener)

    def test_listener_create_multiple_protocols(self):
        self.ovn_lb.protocol = ['tcp']
        info = {'id': self.ref_listener.listener_id,
                'protocol': self.ref_listener.protocol,
                'protocol_port': self.ref_listener.protocol_port,
                'default_pool_id': self.ref_listener.default_pool_id,
                'admin_state_up': self.ref_listener.admin_state_up,
                'loadbalancer_id': self.ref_listener.loadbalancer_id}
        expected_dict = {'type': ovn_driver.REQ_TYPE_LISTENER_CREATE,
                         'info': info}
        self.driver.listener_create(self.ref_listener)
        self.mock_add_request.assert_called_once_with(expected_dict)
        self.ovn_lb.protocol = ['UDP']
        info['protocol'] = 'UDP'
        expected_dict = {'type': ovn_driver.REQ_TYPE_LISTENER_CREATE,
                         'info': info}
        self.driver.listener_create(self.ref_listener)

    def test_listener_update(self):
        info = {'id': self.ref_listener.listener_id,
                'protocol_port': self.ref_listener.protocol_port,
                'protocol': self.ref_pool.protocol,
                'admin_state_up': self.ref_listener.admin_state_up,
                'loadbalancer_id': self.ref_listener.loadbalancer_id}
        if self.ref_listener.default_pool_id:
            info['default_pool_id'] = self.ref_listener.default_pool_id
        expected_dict = {'type': ovn_driver.REQ_TYPE_LISTENER_UPDATE,
                         'info': info}
        self.driver.listener_update(self.ref_listener, self.ref_listener)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_listener_delete(self):
        info = {'id': self.ref_listener.listener_id,
                'protocol_port': self.ref_listener.protocol_port,
                'protocol': self.ref_pool.protocol,
                'loadbalancer_id': self.ref_listener.loadbalancer_id}
        expected_dict = {'type': ovn_driver.REQ_TYPE_LISTENER_DELETE,
                         'info': info}
        self.driver.listener_delete(self.ref_listener)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_loadbalancer_create(self):
        info = {'id': self.ref_lb0.loadbalancer_id,
                'vip_address': self.ref_lb0.vip_address,
                'vip_network_id': self.ref_lb0.vip_network_id,
                'admin_state_up': self.ref_lb0.admin_state_up}
        expected_dict = {'type': ovn_driver.REQ_TYPE_LB_CREATE,
                         'info': info}
        self.driver.loadbalancer_create(self.ref_lb0)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_loadbalancer_create_unset_admin_state_up(self):
        self.ref_lb0.admin_state_up = data_models.UnsetType()
        info = {'id': self.ref_lb0.loadbalancer_id,
                'vip_address': self.ref_lb0.vip_address,
                'vip_network_id': self.ref_lb0.vip_network_id,
                'admin_state_up': True}
        expected_dict = {'type': ovn_driver.REQ_TYPE_LB_CREATE,
                         'info': info}
        self.driver.loadbalancer_create(self.ref_lb0)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_loadbalancer_update(self):
        info = {'id': self.ref_lb1.loadbalancer_id,
                'admin_state_up': self.ref_lb1.admin_state_up}
        expected_dict = {'type': ovn_driver.REQ_TYPE_LB_UPDATE,
                         'info': info}
        self.driver.loadbalancer_update(self.ref_lb0, self.ref_lb1)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_loadbalancer_delete(self):
        info = {'id': self.ref_lb0.loadbalancer_id,
                'cascade': False}
        expected_dict = {'type': ovn_driver.REQ_TYPE_LB_DELETE,
                         'info': info}
        self.driver.loadbalancer_delete(self.ref_lb1)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_loadbalancer_failover(self):
        info = {'id': self.ref_lb0.loadbalancer_id}
        expected_dict = {'type': ovn_driver.REQ_TYPE_LB_FAILOVER,
                         'info': info}
        self.driver.loadbalancer_failover(info['id'])
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_pool_create_unsupported_protocol(self):
        self.ref_pool.protocol = 'HTTP'
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.pool_create, self.ref_pool)

    def test_pool_create_leastcount_algo(self):
        self.ref_pool.lb_algorithm = constants.LB_ALGORITHM_LEAST_CONNECTIONS
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.pool_create, self.ref_pool)

    def test_pool_create(self):
        info = {'id': self.ref_pool.pool_id,
                'loadbalancer_id': self.ref_pool.loadbalancer_id,
                'listener_id': self.ref_pool.listener_id,
                'protocol': self.ref_pool.protocol,
                'admin_state_up': self.ref_pool.admin_state_up}
        expected_dict = {'type': ovn_driver.REQ_TYPE_POOL_CREATE,
                         'info': info}
        self.driver.pool_create(self.ref_pool)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_pool_create_unset_admin_state_up(self):
        self.ref_pool.admin_state_up = data_models.UnsetType()
        info = {'id': self.ref_pool.pool_id,
                'loadbalancer_id': self.ref_pool.loadbalancer_id,
                'protocol': self.ref_pool.protocol,
                'listener_id': self.ref_pool.listener_id,
                'admin_state_up': True}
        expected_dict = {'type': ovn_driver.REQ_TYPE_POOL_CREATE,
                         'info': info}
        self.driver.pool_create(self.ref_pool)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_pool_delete(self):
        # Pretent we don't have members
        self.ref_pool.members = []
        info = {'id': self.ref_pool.pool_id,
                'protocol': self.ref_pool.protocol,
                'loadbalancer_id': self.ref_pool.loadbalancer_id}
        expected = {'type': ovn_driver.REQ_TYPE_POOL_DELETE,
                    'info': info}
        self.driver.pool_delete(self.ref_pool)
        self.mock_add_request.assert_called_once_with(expected)

    def test_pool_delete_with_members(self):
        info = {'id': self.ref_pool.pool_id,
                'protocol': self.ref_pool.protocol,
                'loadbalancer_id': self.ref_pool.loadbalancer_id}
        expected = {'type': ovn_driver.REQ_TYPE_POOL_DELETE,
                    'info': info}
        info_member = {'id': self.ref_member.member_id,
                       'pool_id': self.ref_member.pool_id,
                       'subnet_id': self.ref_member.subnet_id,
                       'protocol_port': self.ref_member.protocol_port,
                       'address': self.ref_member.address}
        expected_members = {
            'type': ovn_driver.REQ_TYPE_MEMBER_DELETE,
            'info': info_member}
        expected_members_dvr = {
            'type': ovn_driver.REQ_TYPE_HANDLE_MEMBER_DVR,
            'info': mock.ANY}
        calls = [mock.call(expected_members),
                 mock.call(expected_members_dvr),
                 mock.call(expected)]
        self.driver.pool_delete(self.ref_pool)
        self.mock_add_request.assert_has_calls(calls)

    def test_pool_update(self):
        info = {'id': self.ref_update_pool.pool_id,
                'loadbalancer_id': self.ref_update_pool.loadbalancer_id,
                'protocol': self.ref_pool.protocol,
                'admin_state_up': self.ref_update_pool.admin_state_up}
        expected_dict = {'type': ovn_driver.REQ_TYPE_POOL_UPDATE,
                         'info': info}
        self.driver.pool_update(self.ref_pool, self.ref_update_pool)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_create_vip_port(self):
        with mock.patch.object(ovn_driver, 'get_network_driver'):
            port_dict = self.driver.create_vip_port(self.loadbalancer_id,
                                                    self.project_id,
                                                    self.vip_dict)
            self.assertIsNotNone(port_dict.pop('vip_address', None))
            self.assertIsNotNone(port_dict.pop('vip_port_id', None))
            # The network_driver function is mocked, therefore the
            # created port vip_address and vip_port_id are also mocked.
            # Check if it exists and move on.
            # The finally output is include vip_address, vip_port_id,
            # vip_network_id and vip_subnet_id.
            for key, value in port_dict.items():
                self.assertEqual(value, self.vip_output[key])

    def test_create_vip_port_exception(self):
        with mock.patch.object(ovn_driver, 'get_network_driver',
                               side_effect=[RuntimeError]):
            self.assertRaises(
                exceptions.DriverError,
                self.driver.create_vip_port,
                self.loadbalancer_id,
                self.project_id,
                self.vip_dict)


class TestOvnProviderHelper(TestOvnOctaviaBase):

    def setUp(self):
        super(TestOvnProviderHelper, self).setUp()
        self.helper = ovn_driver.OvnProviderHelper()
        mock.patch.object(self.helper, '_update_status_to_octavia').start()
        self.listener = {'id': self.listener_id,
                         'loadbalancer_id': self.loadbalancer_id,
                         'protocol': "TCP",
                         'protocol_port': 80,
                         'default_pool_id': self.pool_id,
                         'admin_state_up': False}
        self.lb = {'id': self.loadbalancer_id,
                   'vip_address': self.vip_address,
                   'cascade': False,
                   'vip_network_id': self.vip_network_id,
                   'admin_state_up': False}
        self.ports = {'ports': [{
            'fixed_ips': [{'ip_address': self.vip_address}],
            'network_id': self.vip_network_id,
            'id': self.port1_id}]}
        self.pool = {'id': self.pool_id,
                     'loadbalancer_id': self.loadbalancer_id,
                     'listener_id': self.listener_id,
                     'protocol': "TCP",
                     'admin_state_up': False}
        self.member = {'id': self.member_id,
                       'address': self.member_address,
                       'protocol_port': self.member_port,
                       'subnet_id': self.member_subnet_id,
                       'pool_id': self.member_pool_id,
                       'admin_state_up': True}
        self.ovn_nbdb_api = mock.patch.object(self.helper, 'ovn_nbdb_api')
        self.ovn_nbdb_api.start()
        add_req_thread = mock.patch.object(ovn_driver.OvnProviderHelper,
                                           'add_request')
        self.mock_add_request = add_req_thread.start()
        self.ovn_lb = mock.MagicMock()
        self.ovn_lb.protocol = ['tcp']
        self.ovn_lb.uuid = uuidutils.generate_uuid()
        self.member_line = (
            'member_%s_%s:%s_%s' %
            (self.member_id, self.member_address,
             self.member_port, self.member_subnet_id))
        self.ovn_lb.external_ids = {
            ovn_const.LB_EXT_IDS_VIP_KEY: '10.22.33.4',
            ovn_const.LB_EXT_IDS_VIP_FIP_KEY: '123.123.123.123',
            ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: 'foo_port',
            'enabled': True,
            'pool_%s' % self.pool_id: self.member_line,
            'listener_%s' % self.listener_id: '80:pool_%s' % self.pool_id}
        self.helper.ovn_nbdb_api.db_find.return_value.\
            execute.return_value = [self.ovn_lb]
        self.helper.ovn_nbdb_api.db_list_rows.return_value.\
            execute.return_value = [self.ovn_lb]
        self.mock_find_lb_pool_key = mock.patch.object(
            self.helper,
            '_find_ovn_lb_with_pool_key',
            return_value=self.ovn_lb).start()

        self.mock_find_ovn_lbs = mock.patch.object(
            ovn_driver.OvnProviderHelper, '_find_ovn_lbs',
            side_effect=lambda x, protocol=None:
                self.ovn_lb if protocol else [self.ovn_lb])
        self.mock_find_ovn_lbs.start()

        mock.patch.object(self.helper,
                          '_get_pool_listeners',
                          return_value=[]).start()
        self._update_lb_to_ls_association = mock.patch.object(
            self.helper,
            '_update_lb_to_ls_association',
            return_value=[])
        self._update_lb_to_ls_association.start()
        self._update_lb_to_lr_association = mock.patch.object(
            self.helper,
            '_update_lb_to_lr_association',
            return_value=[])
        self._update_lb_to_lr_association.start()

        # NOTE(mjozefcz): Create foo router and network.
        net_id = uuidutils.generate_uuid()
        router_id = uuidutils.generate_uuid()
        self.ref_lb1 = MockedLB(
            uuid=uuidutils.generate_uuid(),
            admin_state_up=True,
            listeners=[],
            loadbalancer_id=self.loadbalancer_id,
            name='favorite_lb1',
            project_id=self.project_id,
            vip_address=self.vip_address,
            vip_network_id=self.vip_network_id,
            ext_ids={
                ovn_const.LB_EXT_IDS_LR_REF_KEY: "neutron-%s" % net_id,
                ovn_const.LB_EXT_IDS_LS_REFS_KEY:
                    '{\"neutron-%s\": 1}' % net_id})
        self.ref_lb2 = MockedLB(
            uuid=uuidutils.generate_uuid(),
            admin_state_up=True,
            listeners=[],
            loadbalancer_id=self.loadbalancer_id,
            name='favorite_lb2',
            project_id=self.project_id,
            vip_address=self.vip_address,
            vip_network_id=self.vip_network_id,
            ext_ids={
                ovn_const.LB_EXT_IDS_LR_REF_KEY: "neutron-%s" % net_id,
                ovn_const.LB_EXT_IDS_LS_REFS_KEY:
                    '{\"neutron-%s\": 1}' % net_id})
        # TODO(mjozefcz): Consider using FakeOVNRouter.
        self.router = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'load_balancer': [self.ref_lb1],
                   'name': 'neutron-%s' % router_id,
                   'ports': []})
        # TODO(mjozefcz): Consider using FakeOVNSwitch.
        self.network = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'load_balancer': [self.ref_lb2],
                   'name': 'neutron-%s' % net_id,
                   'ports': [],
                   'uuid': net_id})
        self.mock_get_nw = mock.patch.object(
            self.helper, "_get_nw_router_info_on_interface_event",
            return_value=(self.router, self.network))
        self.mock_get_nw.start()
        (self.helper.ovn_nbdb_api.ls_get.return_value.
            execute.return_value) = self.network

    def test__is_lb_empty(self):
        f = self.helper._is_lb_empty
        self.assertFalse(f(self.ovn_lb.external_ids))
        self.ovn_lb.external_ids.pop('listener_%s' % self.listener_id)
        self.assertFalse(f(self.ovn_lb.external_ids))
        self.ovn_lb.external_ids.pop('pool_%s' % self.pool_id)
        self.assertTrue(f(self.ovn_lb.external_ids))

    def test__delete_disabled_from_status(self):
        f = self.helper._delete_disabled_from_status
        status = {
            'pools': [
                {'id': 'f:D', 'provisioning_status': 'ACTIVE',
                 'operating_status': 'ONLINE'}],
            'members': [
                {'id': 'foo:D',
                 'provisioning_status': 'ACTIVE'}]}
        expected = {
            'pools': [
                {'id': 'f', 'provisioning_status': 'ACTIVE',
                 'operating_status': 'ONLINE'}],
            'members': [
                {'id': 'foo',
                 'provisioning_status': 'ACTIVE'}]}
        self.assertEqual(f(status), expected)
        self.assertEqual(f(expected), expected)
        status = {}
        self.assertEqual(f(status), {})

    def test__find_ovn_lbs(self):
        self.mock_find_ovn_lbs.stop()
        f = self.helper._find_ovn_lbs
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [self.ovn_lb]

        # Without protocol specified return a list
        found = f(self.ovn_lb.id)
        self.assertListEqual(found, [self.ovn_lb])
        self.helper.ovn_nbdb_api.db_find_rows.assert_called_once_with(
            'Load_Balancer', ('name', '=', self.ovn_lb.id))
        self.helper.ovn_nbdb_api.db_find_rows.reset_mock()

        # With protocol specified return an instance
        found = f(self.ovn_lb.id, protocol='tcp')
        self.assertEqual(found, self.ovn_lb)
        self.helper.ovn_nbdb_api.db_find_rows.reset_mock()

        # LB with given protocol not found
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = []
        self.assertRaises(
            idlutils.RowNotFound,
            f,
            self.ovn_lb.id,
            protocol='UDP')

        # Multiple protocols
        udp_lb = copy.copy(self.ovn_lb)
        udp_lb.protocol = ['udp']
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [self.ovn_lb, udp_lb]
        found = f(self.ovn_lb.id)
        self.assertListEqual(found, [self.ovn_lb, udp_lb])

    def test__get_or_create_ovn_lb_no_lb_found(self):
        self.mock_find_ovn_lbs.stop()
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = []
        self.assertRaises(
            idlutils.RowNotFound,
            self.helper._get_or_create_ovn_lb,
            self.ovn_lb.name,
            protocol='TCP',
            admin_state_up='True')

    @mock.patch.object(ovn_driver.OvnProviderHelper, 'lb_create')
    def test__get_or_create_ovn_lb_required_proto_not_found(self, lbc):
        udp_lb = copy.copy(self.ovn_lb)
        udp_lb.protocol = ['udp']
        self.mock_find_ovn_lbs.stop()
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.side_effect = [[udp_lb], [self.ovn_lb]]
        self.helper._get_or_create_ovn_lb(
            self.ovn_lb.name,
            protocol='TCP',
            admin_state_up='True')
        expected_lb_info = {
            'id': self.ovn_lb.name,
            'protocol': 'tcp',
            'vip_address': udp_lb.external_ids.get(
                ovn_const.LB_EXT_IDS_VIP_KEY),
            'vip_port_id':
                udp_lb.external_ids.get(
                    ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY),
            ovn_const.LB_EXT_IDS_LR_REF_KEY:
                udp_lb.external_ids.get(
                    ovn_const.LB_EXT_IDS_LR_REF_KEY),
            ovn_const.LB_EXT_IDS_LS_REFS_KEY:
                udp_lb.external_ids.get(
                    ovn_const.LB_EXT_IDS_LS_REFS_KEY),
            'admin_state_up': 'True',
            ovn_const.LB_EXT_IDS_VIP_FIP_KEY:
                udp_lb.external_ids.get(
                    ovn_const.LB_EXT_IDS_VIP_FIP_KEY)}
        lbc.assert_called_once_with(expected_lb_info, protocol='tcp')

    def test__get_or_create_ovn_lb_found(self):
        self.mock_find_ovn_lbs.stop()
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [self.ovn_lb]
        found = self.helper._get_or_create_ovn_lb(
            self.ovn_lb.name,
            protocol='TCP',
            admin_state_up='True')
        self.assertEqual(found, self.ovn_lb)

    def test__get_or_create_ovn_lb_lb_without_protocol(self):
        self.mock_find_ovn_lbs.stop()
        self.ovn_lb.protocol = []
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [self.ovn_lb]
        found = self.helper._get_or_create_ovn_lb(
            self.ovn_lb.name,
            protocol='TCP',
            admin_state_up='True')
        self.assertEqual(found, self.ovn_lb)
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid, ('protocol', 'tcp'))

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_lb_create_disabled(self, net_dr):
        self.lb['admin_state_up'] = False
        net_dr.return_value.neutron_client.list_ports.return_value = (
            self.ports)
        status = self.helper.lb_create(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)
        self.helper.ovn_nbdb_api.db_create.assert_called_once_with(
            'Load_Balancer', external_ids={
                ovn_const.LB_EXT_IDS_VIP_KEY: mock.ANY,
                ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: mock.ANY,
                'enabled': 'False'},
            name=mock.ANY,
            protocol=None)

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_lb_create_enabled(self, net_dr):
        self.lb['admin_state_up'] = True
        net_dr.return_value.neutron_client.list_ports.return_value = (
            self.ports)
        status = self.helper.lb_create(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ONLINE)
        self.helper.ovn_nbdb_api.db_create.assert_called_once_with(
            'Load_Balancer', external_ids={
                ovn_const.LB_EXT_IDS_VIP_KEY: mock.ANY,
                ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: mock.ANY,
                'enabled': 'True'},
            name=mock.ANY,
            protocol=None)

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_lb_create_on_multi_protocol(self, net_dr):
        """This test situation when new protocol is added

           to the same loadbalancer and we need to add
           additional OVN lb with the same name.
        """
        self.lb['admin_state_up'] = True
        self.lb['protocol'] = 'UDP'
        self.lb[ovn_const.LB_EXT_IDS_LR_REF_KEY] = 'foo'
        self.lb[ovn_const.LB_EXT_IDS_LS_REFS_KEY] = "{\"neutron-foo\": 1}"
        net_dr.return_value.neutron_client.list_ports.return_value = (
            self.ports)
        status = self.helper.lb_create(self.lb, protocol='UDP')
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ONLINE)
        self.helper.ovn_nbdb_api.db_create.assert_called_once_with(
            'Load_Balancer', external_ids={
                ovn_const.LB_EXT_IDS_VIP_KEY: mock.ANY,
                ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: mock.ANY,
                ovn_const.LB_EXT_IDS_LR_REF_KEY: 'foo',
                'enabled': 'True'},
            name=mock.ANY,
            protocol='udp')
        self.helper._update_lb_to_ls_association.assert_has_calls([
            mock.call(self.ovn_lb, associate=True,
                      network_id=self.lb['vip_network_id']),
            mock.call(self.ovn_lb, associate=True, network_id='foo')])

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    @mock.patch.object(ovn_driver.OvnProviderHelper, 'delete_vip_port')
    def test_lb_create_exception(self, del_port, net_dr):
        self.helper._find_ovn_lbs.side_effect = [RuntimeError]
        net_dr.return_value.neutron_client.list_ports.return_value = (
            self.ports)
        status = self.helper.lb_create(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ERROR)
        del_port.assert_called_once_with(self.ports.get('ports')[0]['id'])

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    @mock.patch.object(ovn_driver.OvnProviderHelper, 'delete_vip_port')
    def test_lb_delete(self, del_port, net_dr):
        net_dr.return_value.neutron_client.delete_port.return_value = None
        status = self.helper.lb_delete(self.ovn_lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)
        self.helper.ovn_nbdb_api.lb_del.assert_called_once_with(
            self.ovn_lb.uuid)
        del_port.assert_called_once_with('foo_port')

    @mock.patch.object(ovn_driver.OvnProviderHelper, 'delete_vip_port')
    def test_lb_delete_row_not_found(self, del_port):
        self.helper._find_ovn_lbs.side_effect = [idlutils.RowNotFound]
        status = self.helper.lb_delete(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)
        self.helper.ovn_nbdb_api.lb_del.assert_not_called()
        del_port.assert_not_called()

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    @mock.patch.object(ovn_driver.OvnProviderHelper, 'delete_vip_port')
    def test_lb_delete_exception(self, del_port, net_dr):
        self.helper.ovn_nbdb_api.lb_del.side_effect = [RuntimeError]
        status = self.helper.lb_delete(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ERROR)
        self.helper.ovn_nbdb_api.lb_del.assert_called_once_with(
            self.ovn_lb.uuid)
        del_port.assert_called_once_with('foo_port')

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    @mock.patch.object(ovn_driver.OvnProviderHelper, 'delete_vip_port')
    def test_lb_delete_port_not_found(self, del_port, net_dr):
        net_dr.return_value.neutron_client.delete_port.side_effect = (
            [n_exc.PortNotFoundClient])
        status = self.helper.lb_delete(self.ovn_lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)
        self.helper.ovn_nbdb_api.lb_del.assert_called_once_with(
            self.ovn_lb.uuid)
        del_port.assert_called_once_with('foo_port')

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_lb_delete_cascade(self, net_dr):
        net_dr.return_value.neutron_client.delete_port.return_value = None
        self.lb['cascade'] = True
        status = self.helper.lb_delete(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.DELETED)
        self.helper.ovn_nbdb_api.lb_del.assert_called_once_with(
            self.ovn_lb.uuid)

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_lb_delete_ls_lr(self, net_dr):
        self.ovn_lb.external_ids.update({
            ovn_const.LB_EXT_IDS_LR_REF_KEY: self.router.name,
            ovn_const.LB_EXT_IDS_LS_REFS_KEY:
                '{\"neutron-%s\": 1}' % self.network.uuid})
        net_dr.return_value.neutron_client.delete_port.return_value = None
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network
        (self.helper.ovn_nbdb_api.tables['Logical_Router'].rows.
            values.return_value) = [self.router]
        self.helper.lb_delete(self.ovn_lb)
        self.helper.ovn_nbdb_api.ls_lb_del.assert_called_once_with(
            self.network.uuid, self.ovn_lb.uuid)
        self.helper.ovn_nbdb_api.lr_lb_del.assert_called_once_with(
            self.router.uuid, self.ovn_lb.uuid)

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_lb_delete_multiple_protocols(self, net_dr):
        net_dr.return_value.neutron_client.delete_port.return_value = None
        self.mock_find_ovn_lbs.stop()
        udp_lb = copy.copy(self.ovn_lb)
        udp_lb.protocol = ['udp']
        udp_lb.uuid = 'foo_uuid'
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [self.ovn_lb, udp_lb]
        self.helper.lb_delete(self.lb)
        self.helper.ovn_nbdb_api.lb_del.assert_has_calls([
            mock.call(self.ovn_lb.uuid),
            mock.call(udp_lb.uuid)])

    def test_lb_failover(self):
        status = self.helper.lb_failover(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_refresh_lb_vips')
    def test_lb_update_disabled(self, refresh_vips):
        self.lb['admin_state_up'] = False
        status = self.helper.lb_update(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)
        refresh_vips.assert_called_once_with(
            self.ovn_lb.uuid, self.ovn_lb.external_ids)
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            ('external_ids', {'enabled': 'False'}))

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_refresh_lb_vips')
    def test_lb_update_enabled(self, refresh_vips):
        # Change the mock, its enabled by default.
        self.ovn_lb.external_ids.update({'enabled': False})
        self.lb['admin_state_up'] = True
        status = self.helper.lb_update(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ONLINE)
        refresh_vips.assert_called_once_with(
            self.ovn_lb.uuid, self.ovn_lb.external_ids)
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            ('external_ids', {'enabled': 'True'}))

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_refresh_lb_vips')
    def test_lb_update_enabled_multiple_protocols(self, refresh_vips):
        self.mock_find_ovn_lbs.stop()
        self.ovn_lb.external_ids.update({'enabled': 'False'})
        udp_lb = copy.deepcopy(self.ovn_lb)
        udp_lb.protocol = ['udp']
        udp_lb.uuid = 'foo_uuid'
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [self.ovn_lb, udp_lb]
        self.lb['admin_state_up'] = True
        status = self.helper.lb_update(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ONLINE)
        refresh_vips.assert_has_calls([
            mock.call(self.ovn_lb.uuid, self.ovn_lb.external_ids),
            mock.ANY,
            mock.ANY,
            mock.call(udp_lb.uuid, udp_lb.external_ids),
            ], any_order=False)
        self.helper.ovn_nbdb_api.db_set.assert_has_calls([
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('external_ids', {'enabled': 'True'})),
            mock.call('Load_Balancer', udp_lb.uuid,
                      ('external_ids', {'enabled': 'True'}))])

    def test_lb_update_exception(self):
        self.helper._find_ovn_lbs.side_effect = [RuntimeError]
        status = self.helper.lb_update(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ERROR)

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_refresh_lb_vips')
    def test_listener_create_disabled(self, refresh_vips):
        self.ovn_lb.external_ids.pop('listener_%s' % self.listener_id)
        status = self.helper.listener_create(self.listener)
        # Set expected as disabled
        self.ovn_lb.external_ids.update({
            'listener_%s:D' % self.listener_id: '80:pool_%s' % self.pool_id})
        refresh_vips.assert_called_once_with(
            self.ovn_lb.uuid, self.ovn_lb.external_ids)
        expected_calls = [
            mock.call(
                'Load_Balancer', self.ovn_lb.uuid,
                ('external_ids', {
                    'listener_%s:D' % self.listener_id:
                        '80:pool_%s' % self.pool_id})),
            mock.call('Load_Balancer', self.ovn_lb.uuid, ('protocol', 'tcp'))]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(expected_calls)
        self.assertEqual(
            len(expected_calls),
            self.helper.ovn_nbdb_api.db_set.call_count)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.OFFLINE)

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_refresh_lb_vips')
    def test_listener_create_enabled(self, refresh_vips):
        self.listener['admin_state_up'] = True
        status = self.helper.listener_create(self.listener)
        refresh_vips.assert_called_once_with(
            self.ovn_lb.uuid, self.ovn_lb.external_ids)
        expected_calls = [
            mock.call(
                'Load_Balancer', self.ovn_lb.uuid,
                ('external_ids', {
                    'listener_%s' % self.listener_id:
                        '80:pool_%s' % self.pool_id}))]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(expected_calls)
        self.assertEqual(
            len(expected_calls),
            self.helper.ovn_nbdb_api.db_set.call_count)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ONLINE)

    def test_listener_create_no_default_pool(self):
        self.listener['admin_state_up'] = True
        self.listener.pop('default_pool_id')
        self.helper.listener_create(self.listener)
        expected_calls = [
            mock.call('Load_Balancer', self.ovn_lb.uuid, ('external_ids', {
                'listener_%s' % self.listener_id: '80:'})),
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('vips', {}))]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(
            expected_calls)
        self.assertEqual(
            len(expected_calls),
            self.helper.ovn_nbdb_api.db_set.call_count)

    def test_listener_create_exception(self):
        self.helper.ovn_nbdb_api.db_set.side_effect = [RuntimeError]
        status = self.helper.listener_create(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ERROR)

    def test_listener_update(self):
        status = self.helper.listener_update(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.OFFLINE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.listener['admin_state_up'] = True
        status = self.helper.listener_update(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ONLINE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)

    def test_listener_update_row_not_found(self):
        self.helper._find_ovn_lbs.side_effect = [idlutils.RowNotFound]
        status = self.helper.listener_update(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ERROR)
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_refresh_lb_vips')
    def test_listener_update_exception(self, refresh_vips):
        refresh_vips.side_effect = [RuntimeError]
        status = self.helper.listener_update(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ERROR)

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_refresh_lb_vips')
    def test_listener_update_listener_enabled(self, refresh_vips):
        self.listener['admin_state_up'] = True
        # Update the listener port.
        self.listener.update({'protocol_port': 123})
        status = self.helper.listener_update(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ONLINE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            ('external_ids', {
                'listener_%s' % self.listener_id:
                '123:pool_%s' % self.pool_id}))
        # Update expected listener, because it was updated.
        self.ovn_lb.external_ids.pop('listener_%s' % self.listener_id)
        self.ovn_lb.external_ids.update(
            {'listener_%s' % self.listener_id: '123:pool_%s' % self.pool_id})
        refresh_vips.assert_called_once_with(
            self.ovn_lb.uuid, self.ovn_lb.external_ids)

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_refresh_lb_vips')
    def test_listener_update_listener_disabled(self, refresh_vips):
        self.listener['admin_state_up'] = False
        status = self.helper.listener_update(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.OFFLINE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid, 'external_ids',
            'listener_%s' % self.listener_id)
        # It gets disabled, so update the key
        self.ovn_lb.external_ids.pop('listener_%s' % self.listener_id)
        self.ovn_lb.external_ids.update(
            {'listener_%s:D' % self.listener_id: '80:pool_%s' % self.pool_id})
        refresh_vips.assert_called_once_with(
            self.ovn_lb.uuid, self.ovn_lb.external_ids)

    def test_listener_delete_no_external_id(self):
        self.ovn_lb.external_ids.pop('listener_%s' % self.listener_id)
        status = self.helper.listener_delete(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.OFFLINE)
        self.helper.ovn_nbdb_api.db_remove.assert_not_called()

    def test_listener_delete_row_not_found(self):
        self.helper._find_ovn_lbs.side_effect = [idlutils.RowNotFound]
        status = self.helper.listener_delete(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.OFFLINE)

    def test_listener_delete_exception(self):
        self.helper.ovn_nbdb_api.db_remove.side_effect = [RuntimeError]
        status = self.helper.listener_delete(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ERROR)

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_refresh_lb_vips')
    def test_listener_delete_external_id(self, refresh_vips):
        status = self.helper.listener_delete(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.OFFLINE)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'listener_%s' % self.listener_id)
        self.ovn_lb.external_ids.pop('listener_%s' % self.listener_id)
        refresh_vips.assert_called_once_with(
            self.ovn_lb.uuid, self.ovn_lb.external_ids)

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_is_lb_empty')
    def test_listener_delete_ovn_lb_not_empty(self, lb_empty):
        lb_empty.return_value = False
        self.helper.listener_delete(self.listener)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'listener_%s' % self.listener_id)
        self.helper.ovn_nbdb_api.lb_del.assert_not_called()

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_is_lb_empty')
    def test_listener_delete_ovn_lb_empty_octavia_lb_empty(self, lb_empty):
        """That test situation when the OVN and Octavia LBs are empty.

           That test situation when both OVN and Octavia LBs are empty,
           but we cannot remove OVN LB row.
        """
        lb_empty.return_value = True
        self.helper.listener_delete(self.listener)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'listener_%s' % self.listener_id)
        self.helper.ovn_nbdb_api.lb_del.assert_not_called()
        # Assert that protocol has been set to [].
        self.helper.ovn_nbdb_api.db_set.assert_has_calls([
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('protocol', []))])

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_is_lb_empty')
    def test_listener_delete_ovn_lb_empty_octavia_lb_not_empty(self, lb_empty):
        """We test if we can remove one LB with not used protocol"""
        ovn_lb_udp = copy.copy(self.ovn_lb)
        ovn_lb_udp.protocol = ['udp']
        self.mock_find_ovn_lbs.stop()
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.side_effect = [[self.ovn_lb], [self.ovn_lb, ovn_lb_udp]]
        lb_empty.return_value = True
        self.helper.listener_delete(self.listener)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'listener_%s' % self.listener_id)
        self.helper.ovn_nbdb_api.lb_del.assert_called_once_with(
            self.ovn_lb.uuid)
        # Validate that the vips column hasn't been touched, because
        # in previous command we remove the LB, so there is no need
        # to update it.
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    def test_pool_create(self):
        status = self.helper.pool_create(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.OFFLINE)
        self.pool['admin_state_up'] = True
        # Pool Operating status shouldnt change if member isnt present.
        status = self.helper.pool_create(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.OFFLINE)

    def test_pool_create_exception(self):
        self.helper.ovn_nbdb_api.db_set.side_effect = [RuntimeError]
        status = self.helper.pool_update(self.pool)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ERROR)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)

    def test_pool_update(self):
        status = self.helper.pool_update(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.OFFLINE)
        self.pool['admin_state_up'] = True
        status = self.helper.pool_update(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.ONLINE)

    def test_pool_update_exception(self):
        self.helper._get_pool_listeners.side_effect = [RuntimeError]
        status = self.helper.pool_update(self.pool)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ERROR)

    def test_pool_update_unset_admin_state_up(self):
        self.pool.pop('admin_state_up')
        status = self.helper.pool_update(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)

    def test_pool_update_pool_disabled_change_to_up(self):
        self.pool.update({'admin_state_up': True})
        disabled_p_key = self.helper._get_pool_key(self.pool_id,
                                                   is_enabled=False)
        p_key = self.helper._get_pool_key(self.pool_id)
        self.ovn_lb.external_ids.update({
            disabled_p_key: self.member_line})
        self.ovn_lb.external_ids.pop(p_key)
        status = self.helper.pool_update(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.ONLINE)
        expected_calls = [
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('external_ids',
                          {'pool_%s' % self.pool_id: self.member_line})),
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('vips', {'10.22.33.4:80': '192.168.2.149:1010',
                                '123.123.123.123:80': '192.168.2.149:1010'}))]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(
            expected_calls)

    def test_pool_update_pool_up_change_to_disabled(self):
        self.pool.update({'admin_state_up': False})
        status = self.helper.pool_update(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['operating_status'],
                         constants.OFFLINE)
        expected_calls = [
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('external_ids',
                          {'pool_%s:D' % self.pool_id: self.member_line})),
            mock.call('Load_Balancer', self.ovn_lb.uuid, ('vips', {}))]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(
            expected_calls)

    def test_pool_update_listeners(self):
        self.helper._get_pool_listeners.return_value = ['listener1']
        status = self.helper.pool_update(self.pool)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)

    def test_pool_delete(self):
        status = self.helper.pool_delete(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.DELETED)
        self.helper.ovn_nbdb_api.db_clear.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid, 'vips')
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'pool_%s' % self.pool_id)
        expected_calls = [
            mock.call('Load_Balancer', self.ovn_lb.uuid, ('vips', {})),
            mock.call(
                'Load_Balancer', self.ovn_lb.uuid,
                ('external_ids', {
                    ovn_const.LB_EXT_IDS_VIP_KEY: '10.22.33.4',
                    ovn_const.LB_EXT_IDS_VIP_FIP_KEY: '123.123.123.123',
                    ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: 'foo_port',
                    'enabled': True,
                    'listener_%s' % self.listener_id: '80:'}))]
        self.assertEqual(self.helper.ovn_nbdb_api.db_set.call_count,
                         len(expected_calls))
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(
            expected_calls)

    def test_pool_delete_row_not_found(self):
        self.helper._find_ovn_lbs.side_effect = [idlutils.RowNotFound]
        status = self.helper.pool_delete(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.DELETED)
        self.helper.ovn_nbdb_api.db_remove.assert_not_called()
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    def test_pool_delete_exception(self):
        self.helper.ovn_nbdb_api.db_set.side_effect = [RuntimeError]
        status = self.helper.pool_delete(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ERROR)

    def test_pool_delete_associated_listeners(self):
        self.helper._get_pool_listeners.return_value = ['listener1']
        status = self.helper.pool_delete(self.pool)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.helper.ovn_nbdb_api.db_set.assert_called_with(
            'Load_Balancer', self.ovn_lb.uuid,
            ('external_ids', {
                'enabled': True,
                'listener_%s' % self.listener_id: '80:',
                ovn_const.LB_EXT_IDS_VIP_KEY: '10.22.33.4',
                ovn_const.LB_EXT_IDS_VIP_FIP_KEY: '123.123.123.123',
                ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: 'foo_port'}))

    def test_pool_delete_pool_disabled(self):
        disabled_p_key = self.helper._get_pool_key(self.pool_id,
                                                   is_enabled=False)
        p_key = self.helper._get_pool_key(self.pool_id)
        self.ovn_lb.external_ids.update({
            disabled_p_key: self.member_line})
        self.ovn_lb.external_ids.pop(p_key)
        status = self.helper.pool_delete(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.DELETED)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'pool_%s:D' % self.pool_id)

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_is_lb_empty')
    def test_pool_delete_ovn_lb_not_empty(self, lb_empty):
        lb_empty.return_value = False
        self.helper.pool_delete(self.pool)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'pool_%s' % self.pool_id)
        self.helper.ovn_nbdb_api.lb_del.assert_not_called()

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_is_lb_empty')
    def test_pool_delete_ovn_lb_empty_lb_empty(self, lb_empty):
        lb_empty.return_value = True
        self.helper.pool_delete(self.pool)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'pool_%s' % self.pool_id)
        self.helper.ovn_nbdb_api.lb_del.assert_not_called()
        # Assert that protocol has been set to [].
        self.helper.ovn_nbdb_api.db_set.assert_called_with(
            'Load_Balancer', self.ovn_lb.uuid,
            ('protocol', []))

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_is_lb_empty')
    def test_pool_delete_ovn_lb_empty_lb_not_empty(self, lb_empty):
        ovn_lb_udp = copy.copy(self.ovn_lb)
        self.mock_find_ovn_lbs.stop()
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.side_effect = [[self.ovn_lb], [self.ovn_lb, ovn_lb_udp]]
        lb_empty.return_value = True
        self.helper.pool_delete(self.pool)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ovn_lb.uuid,
            'external_ids', 'pool_%s' % self.pool_id)
        self.helper.ovn_nbdb_api.lb_del.assert_called_once_with(
            self.ovn_lb.uuid)

    def test_member_create(self):
        self.ovn_lb.external_ids = mock.MagicMock()
        status = self.helper.member_create(self.member)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.member['admin_state_up'] = False
        status = self.helper.member_create(self.member)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.ACTIVE)

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_add_member')
    def test_member_create_exception(self, mock_add_member):
        mock_add_member.side_effect = [RuntimeError]
        status = self.helper.member_create(self.member)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ERROR)

    def test_member_create_lb_disabled(self):
        self.helper._find_ovn_lb_with_pool_key.side_effect = [
            None, self.ovn_lb]
        self.helper.member_create(self.member)
        self.helper._find_ovn_lb_with_pool_key.assert_has_calls(
            [mock.call('pool_%s' % self.pool_id),
             mock.call('pool_%s%s' % (self.pool_id, ':D'))])

    def test_member_create_listener(self):
        self.ovn_lb.external_ids = mock.MagicMock()
        self.helper._get_pool_listeners.return_value = ['listener1']
        status = self.helper.member_create(self.member)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['id'],
                         'listener1')

    def test_member_create_already_exists(self):
        self.helper.member_create(self.member)
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    def test_member_create_already_exists_backward_compat(self):
        old_member_line = ('member_%s_%s:%s' %
                           (self.member_id, self.member_address,
                            self.member_port))
        self.ovn_lb.external_ids.update(
            {'pool_%s' % self.pool_id: old_member_line})
        self.helper.member_create(self.member)
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    def test_member_create_first_member_in_pool(self):
        self.ovn_lb.external_ids.update({
            'pool_' + self.pool_id: ''})
        self.helper.member_create(self.member)
        expected_calls = [
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('external_ids',
                       {'pool_%s' % self.pool_id: self.member_line})),
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('vips', {
                          '10.22.33.4:80': '192.168.2.149:1010',
                          '123.123.123.123:80': '192.168.2.149:1010'}))]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(
            expected_calls)

    def test_member_create_second_member_in_pool(self):
        member2_id = uuidutils.generate_uuid()
        member2_subnet_id = uuidutils.generate_uuid()
        member2_port = "1010"
        member2_address = "192.168.2.150"
        member2_line = ('member_%s_%s:%s_%s' %
                        (member2_id, member2_address,
                         member2_port, member2_subnet_id))
        self.ovn_lb.external_ids.update(
            {'pool_%s' % self.pool_id: member2_line})
        self.helper.member_create(self.member)
        all_member_line = (
            '%s,member_%s_%s:%s_%s' %
            (member2_line, self.member_id,
             self.member_address, self.member_port,
             self.member_subnet_id))
        # We have two members now.
        expected_calls = [
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('external_ids', {
                          'pool_%s' % self.pool_id: all_member_line})),
            mock.call(
                'Load_Balancer', self.ovn_lb.uuid,
                ('vips', {
                    '10.22.33.4:80':
                        '192.168.2.150:1010,192.168.2.149:1010',
                    '123.123.123.123:80':
                        '192.168.2.150:1010,192.168.2.149:1010'}))]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(
            expected_calls)

    def test_member_update(self):
        self.ovn_lb.external_ids = mock.MagicMock()
        status = self.helper.member_update(self.member)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['operating_status'],
                         constants.ONLINE)
        self.member['admin_state_up'] = False
        status = self.helper.member_update(self.member)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['operating_status'],
                         constants.OFFLINE)

    def test_member_update_disabled_lb(self):
        self.helper._find_ovn_lb_with_pool_key.side_effect = [
            None, self.ovn_lb]
        self.helper.member_update(self.member)
        self.helper._find_ovn_lb_with_pool_key.assert_has_calls(
            [mock.call('pool_%s' % self.pool_id),
             mock.call('pool_%s%s' % (self.pool_id, ':D'))])

    def test_member_update_pool_listeners(self):
        self.ovn_lb.external_ids = mock.MagicMock()
        self.helper._get_pool_listeners.return_value = ['listener1']
        status = self.helper.member_update(self.member)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['id'],
                         'listener1')

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_update_member')
    def test_member_update_exception(self, mock_update_member):
        mock_update_member.side_effect = [RuntimeError]
        status = self.helper.member_update(self.member)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)

    def test_member_update_new_member_line(self):
        old_member_line = (
            'member_%s_%s:%s' %
            (self.member_id, self.member_address,
             self.member_port))
        new_member_line = (
            'member_%s_%s:%s_%s' %
            (self.member_id, self.member_address,
             self.member_port, self.member_subnet_id))
        self.ovn_lb.external_ids.update(
            {'pool_%s' % self.pool_id: old_member_line})
        self.helper.member_update(self.member)
        expected_calls = [
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('external_ids', {
                          'pool_%s' % self.pool_id: new_member_line}))]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(
            expected_calls)

    def test_member_update_new_port(self):
        new_port = 11
        member_line = ('member_%s_%s:%s_%s' %
                       (self.member_id, self.member_address,
                        new_port, self.member_subnet_id))
        self.ovn_lb.external_ids.update(
            {'pool_%s' % self.pool_id: member_line})
        self.helper.member_update(self.member)
        new_member_line = (
            'member_%s_%s:%s_%s' %
            (self.member_id, self.member_address,
             self.member_port, self.member_subnet_id))
        expected_calls = [
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('external_ids', {
                          'pool_%s' % self.pool_id: new_member_line})),
            mock.call('Load_Balancer', self.ovn_lb.uuid, ('vips', {
                '10.22.33.4:80': '192.168.2.149:1010',
                '123.123.123.123:80': '192.168.2.149:1010'}))]
        self.helper.ovn_nbdb_api.db_set.assert_has_calls(
            expected_calls)

    @mock.patch('networking_ovn.octavia.ovn_driver.OvnProviderHelper.'
                '_refresh_lb_vips')
    def test_member_delete(self, mock_vip_command):
        status = self.helper.member_delete(self.member)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.DELETED)

    def test_member_delete_one_left(self):
        member2_id = uuidutils.generate_uuid()
        member2_port = "1010"
        member2_address = "192.168.2.150"
        member_line = (
            'member_%s_%s:%s,member_%s_%s:%s' %
            (self.member_id, self.member_address, self.member_port,
             member2_id, member2_address, member2_port))
        self.ovn_lb.external_ids.update({
            'pool_' + self.pool_id: member_line})
        status = self.helper.member_delete(self.member)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)

    def test_member_delete_backward_compat(self):
        old_member_line = ('member_%s_%s:%s' %
                           (self.member_id, self.member_address,
                            self.member_port))
        self.ovn_lb.external_ids.update(
            {'pool_%s' % self.pool_id: old_member_line})
        self.helper.member_delete(self.member)
        expected_calls = [
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('external_ids', {'pool_%s' % self.pool_id: ''})),
            mock.call('Load_Balancer', self.ovn_lb.uuid,
                      ('vips', {}))]
        self.helper.ovn_nbdb_api.db_set.has_calls(expected_calls)

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_remove_member')
    def test_member_delete_exception(self, mock_remove_member):
        mock_remove_member.side_effect = [RuntimeError]
        status = self.helper.member_delete(self.member)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)

    def test_member_delete_disabled_lb(self):
        self.helper._find_ovn_lb_with_pool_key.side_effect = [
            None, self.ovn_lb]
        self.helper.member_delete(self.member)
        self.helper._find_ovn_lb_with_pool_key.assert_has_calls(
            [mock.call('pool_%s' % self.pool_id),
             mock.call('pool_%s%s' % (self.pool_id, ':D'))])

    def test_member_delete_pool_listeners(self):
        self.ovn_lb.external_ids.update({
            'pool_' + self.pool_id: 'member_' + self.member_id + '_' +
            self.member_address + ':' + self.member_port})
        self.helper._get_pool_listeners.return_value = ['listener1']
        status = self.helper.member_delete(self.member)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['id'],
                         'listener1')

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_logical_router_port_event_create(self, net_dr):
        self.router_port_event = ovn_driver.LogicalRouterPortEvent(
            self.helper)
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'gateway_chassis': []})
        self.router_port_event.run('create', row, mock.ANY)
        expected = {
            'info':
                {'router': self.router,
                 'network': self.network},
            'type': 'lb_create_lrp_assoc'}
        self.mock_add_request.assert_called_once_with(expected)

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_logical_router_port_event_delete(self, net_dr):
        self.router_port_event = ovn_driver.LogicalRouterPortEvent(
            self.helper)
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'gateway_chassis': []})
        self.router_port_event.run('delete', row, mock.ANY)
        expected = {
            'info':
                {'router': self.router,
                 'network': self.network},
            'type': 'lb_delete_lrp_assoc'}
        self.mock_add_request.assert_called_once_with(expected)

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_logical_router_port_event_gw_port(self, net_dr):
        self.router_port_event = ovn_driver.LogicalRouterPortEvent(
            self.helper)
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'gateway_chassis': ['temp-gateway-chassis']})
        self.router_port_event.run(mock.ANY, row, mock.ANY)
        self.mock_add_request.assert_not_called()

    def test__get_nw_router_info_on_interface_event(self):
        self.mock_get_nw.stop()
        lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'router1',
                    ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: 'network1'}
            })
        self.helper._get_nw_router_info_on_interface_event(lrp)
        expected_calls = [
            mock.call.lookup('Logical_Router', 'neutron-router1'),
            mock.call.lookup('Logical_Switch', 'network1')]
        self.helper.ovn_nbdb_api.assert_has_calls(expected_calls)

    def test__get_nw_router_info_on_interface_event_not_found(self):
        self.mock_get_nw.stop()
        self.helper.ovn_nbdb_api.lookup.side_effect = [idlutils.RowNotFound]
        lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'router1'}
            })
        self.assertRaises(
            idlutils.RowNotFound,
            self.helper._get_nw_router_info_on_interface_event,
            lrp)

    def test_lb_delete_lrp_assoc_handler(self):
        lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        self.helper.lb_delete_lrp_assoc_handler(lrp)
        expected = {
            'info':
                {'router': self.router,
                 'network': self.network},
            'type': 'lb_delete_lrp_assoc'}
        self.mock_add_request.assert_called_once_with(expected)

    def test_lb_delete_lrp_assoc_handler_info_not_found(self):
        self.mock_get_nw.stop()
        self.helper.ovn_nbdb_api.lookup.side_effect = [idlutils.RowNotFound]
        lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'router1'}
            })
        self.helper.lb_delete_lrp_assoc_handler(lrp)
        self.mock_add_request.assert_not_called()

    @mock.patch.object(ovn_driver.OvnProviderHelper,
                       '_execute_commands')
    def test_lb_delete_lrp_assoc_no_net_lb_no_r_lb(self, mock_execute):
        info = {
            'network': self.network,
            'router': self.router,
        }
        self.network.load_balancer = []
        self.router.load_balancer = []
        self.helper.lb_delete_lrp_assoc(info)
        self.helper._update_lb_to_lr_association.assert_not_called()
        mock_execute.assert_not_called()

    @mock.patch.object(ovn_driver.OvnProviderHelper,
                       '_execute_commands')
    def test_lb_delete_lrp_assoc_no_net_lb_r_lb(self, mock_execute):
        info = {
            'network': self.network,
            'router': self.router,
        }
        self.network.load_balancer = []
        self.helper.lb_delete_lrp_assoc(info)
        expected = [
            self.helper.ovn_nbdb_api.ls_lb_del(
                self.network.uuid,
                self.router.load_balancer[0].uuid
            ),
        ]
        self.helper._update_lb_to_lr_association.assert_not_called()
        mock_execute.assert_called_once_with(expected)

    @mock.patch.object(ovn_driver.OvnProviderHelper,
                       '_execute_commands')
    def test_lb_delete_lrp_assoc_net_lb_no_r_lb(self, mock_execute):
        info = {
            'network': self.network,
            'router': self.router,
        }
        self.router.load_balancer = []
        self.helper.lb_delete_lrp_assoc(info)
        mock_execute.assert_not_called()
        self.helper._update_lb_to_lr_association.assert_called_once_with(
            self.network.load_balancer[0], self.router, delete=True
        )

    @mock.patch.object(ovn_driver.OvnProviderHelper,
                       '_execute_commands')
    def test_lb_delete_lrp_assoc(self, mock_execute):
        info = {
            'network': self.network,
            'router': self.router,
        }
        self.helper.lb_delete_lrp_assoc(info)
        self.helper._update_lb_to_lr_association.assert_called_once_with(
            self.network.load_balancer[0], self.router, delete=True
        )
        expected = [
            self.helper.ovn_nbdb_api.ls_lb_del(
                self.network.uuid,
                self.router.load_balancer[0].uuid
            ),
        ]
        mock_execute.assert_called_once_with(expected)

    def test_lb_create_lrp_assoc_handler(self):
        lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        self.helper.lb_create_lrp_assoc_handler(lrp)
        expected = {
            'info':
                {'router': self.router,
                 'network': self.network},
            'type': 'lb_create_lrp_assoc'}
        self.mock_add_request.assert_called_once_with(expected)

    def test_lb_create_lrp_assoc_handler_row_not_found(self):
        self.mock_get_nw.stop()
        self.helper.ovn_nbdb_api.lookup.side_effect = [idlutils.RowNotFound]
        lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'router1'}
            })
        self.helper.lb_create_lrp_assoc_handler(lrp)
        self.mock_add_request.assert_not_called()

    @mock.patch.object(ovn_driver.OvnProviderHelper,
                       '_execute_commands')
    def test_lb_create_lrp_assoc(self, mock_execute):
        info = {
            'network': self.network,
            'router': self.router,
        }
        self.helper.lb_create_lrp_assoc(info)
        self.helper._update_lb_to_lr_association.assert_called_once_with(
            self.network.load_balancer[0], self.router
        )
        expected = [
            self.helper.ovn_nbdb_api.ls_lb_add(
                self.network.uuid,
                self.router.load_balancer[0].uuid
            ),
        ]
        mock_execute.assert_called_once_with(expected)

    @mock.patch.object(ovn_driver.OvnProviderHelper,
                       '_execute_commands')
    def test_lb_create_lrp_assoc_uniq_lb(self, mock_execute):
        info = {
            'network': self.network,
            'router': self.router,
        }
        # Make it already uniq.
        self.network.load_balancer = self.router.load_balancer
        self.helper.lb_create_lrp_assoc(info)
        self.helper._update_lb_to_lr_association.assert_not_called()
        mock_execute.assert_not_called()

    def test__find_lb_in_ls(self):
        net_lb = self.helper._find_lb_in_ls(self.network)
        for lb in self.network.load_balancer:
            self.assertIn(lb, net_lb)

    def test__find_lb_in_ls_wrong_ref(self):
        # lets break external_ids refs
        self.network.load_balancer[0].external_ids.update({
            ovn_const.LB_EXT_IDS_LS_REFS_KEY: 'foo'})
        net_lb = self.helper._find_lb_in_ls(self.network)
        for lb in self.network.load_balancer:
            self.assertNotIn(lb, net_lb)

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test__find_ls_for_lr(self, net_dr):
        fake_subnet1 = fakes.FakeSubnet.create_one_subnet()
        fake_subnet1.network_id = 'foo1'
        fake_subnet2 = fakes.FakeSubnet.create_one_subnet()
        fake_subnet2.network_id = 'foo2'
        net_dr.return_value.get_subnet.side_effect = [
            fake_subnet1, fake_subnet2]
        p1 = fakes.FakeOVNPort.create_one_port(attrs={
            'gateway_chassis': [],
            'external_ids': {
                ovn_const.OVN_SUBNET_EXT_IDS_KEY:
                '%s %s' % (fake_subnet1.id,
                           fake_subnet2.id)}})
        self.router.ports.append(p1)
        res = self.helper._find_ls_for_lr(self.router)
        self.assertListEqual(['neutron-foo1', 'neutron-foo2'],
                             res)

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test__find_ls_for_lr_subnet_not_found(self, net_dr):
        fake_subnet1 = fakes.FakeSubnet.create_one_subnet()
        fake_subnet1.network_id = 'foo1'
        fake_subnet2 = fakes.FakeSubnet.create_one_subnet()
        fake_subnet2.network_id = 'foo2'
        net_dr.return_value.get_subnet.side_effect = [
            fake_subnet1, n_exc.NotFound]
        p1 = fakes.FakeOVNPort.create_one_port(attrs={
            'gateway_chassis': [],
            'external_ids': {
                ovn_const.OVN_SUBNET_EXT_IDS_KEY:
                '%s %s' % (fake_subnet1.id,
                           fake_subnet2.id)}})
        self.router.ports.append(p1)
        res = self.helper._find_ls_for_lr(self.router)
        self.assertListEqual(['neutron-foo1'], res)

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test__find_ls_for_lr_gw_port(self, net_dr):
        p1 = fakes.FakeOVNPort.create_one_port(attrs={
            'gateway_chassis': ['foo-gw-chassis'],
            'external_ids': {
                ovn_const.OVN_SUBNET_EXT_IDS_KEY: self.member_subnet_id}})
        self.router.ports.append(p1)
        result = self.helper._find_ls_for_lr(self.router)
        self.assertListEqual([], result)

    @mock.patch.object(
        ovn_driver.OvnProviderHelper, '_del_lb_to_lr_association')
    @mock.patch.object(
        ovn_driver.OvnProviderHelper, '_add_lb_to_lr_association')
    def test__update_lb_to_lr_association(self, add, delete):
        self._update_lb_to_lr_association.stop()
        self.helper._update_lb_to_lr_association(self.ref_lb1, self.router)
        lr_ref = self.ref_lb1.external_ids.get(
            ovn_const.LB_EXT_IDS_LR_REF_KEY)
        add.assert_called_once_with(self.ref_lb1, self.router, lr_ref)
        delete.assert_not_called()

    @mock.patch.object(
        ovn_driver.OvnProviderHelper, '_del_lb_to_lr_association')
    @mock.patch.object(
        ovn_driver.OvnProviderHelper, '_add_lb_to_lr_association')
    def test__update_lb_to_lr_association_delete(self, add, delete):
        self._update_lb_to_lr_association.stop()
        self.helper._update_lb_to_lr_association(
            self.ref_lb1, self.router, delete=True)
        lr_ref = self.ref_lb1.external_ids.get(
            ovn_const.LB_EXT_IDS_LR_REF_KEY)
        add.assert_not_called()
        delete.assert_called_once_with(self.ref_lb1, self.router, lr_ref)

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test__del_lb_to_lr_association(self, net_dr):
        lr_ref = self.ref_lb1.external_ids.get(
            ovn_const.LB_EXT_IDS_LR_REF_KEY)
        upd_lr_ref = '%s,%s' % (lr_ref, self.router.name)
        self.helper._del_lb_to_lr_association(
            self.ref_lb1, self.router, upd_lr_ref)
        expected_calls = [
            mock.call.db_set(
                'Load_Balancer', self.ref_lb1.uuid,
                (('external_ids',
                  {ovn_const.LB_EXT_IDS_LR_REF_KEY: lr_ref}))),
            mock.call.lr_lb_del(
                self.router.uuid, self.ref_lb1.uuid,
                if_exists=True)]
        self.helper.ovn_nbdb_api.assert_has_calls(
            expected_calls)
        self.helper.ovn_nbdb_api.db_remove.assert_not_called()

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test__del_lb_to_lr_association_no_lr_ref(self, net_dr):
        lr_ref = ''
        self.helper._del_lb_to_lr_association(
            self.ref_lb1, self.router, lr_ref)
        self.helper.ovn_nbdb_api.db_set.assert_not_called()
        self.helper.ovn_nbdb_api.db_remove.assert_not_called()
        self.helper.ovn_nbdb_api.lr_lb_del.assert_not_called()

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test__del_lb_to_lr_association_lr_ref_empty_after(self, net_dr):
        lr_ref = self.router.name
        self.helper._del_lb_to_lr_association(
            self.ref_lb1, self.router, lr_ref)
        self.helper.ovn_nbdb_api.db_remove.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid, 'external_ids',
            ovn_const.LB_EXT_IDS_LR_REF_KEY)
        self.helper.ovn_nbdb_api.lr_lb_del.assert_called_once_with(
            self.router.uuid, self.ref_lb1.uuid, if_exists=True)
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_find_ls_for_lr')
    def test__del_lb_to_lr_association_from_ls(self, f_ls):
        # This test if LB is deleted from Logical_Router_Port
        # Logical_Switch.
        f_ls.return_value = ['neutron-xyz', 'neutron-qwr']
        self.helper._del_lb_to_lr_association(self.ref_lb1, self.router, '')
        self.helper.ovn_nbdb_api.ls_lb_del.assert_has_calls([
            (mock.call('neutron-xyz', self.ref_lb1.uuid, if_exists=True)),
            (mock.call('neutron-qwr', self.ref_lb1.uuid, if_exists=True))])

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_find_ls_for_lr')
    def test__add_lb_to_lr_association(self, f_ls):
        lr_ref = 'foo'
        f_ls.return_value = ['neutron-xyz', 'neutron-qwr']
        self.helper._add_lb_to_lr_association(
            self.ref_lb1, self.router, lr_ref)
        self.helper.ovn_nbdb_api.lr_lb_add.assert_called_once_with(
            self.router.uuid, self.ref_lb1.uuid, may_exist=True)
        self.helper.ovn_nbdb_api.ls_lb_add.assert_has_calls([
            (mock.call('neutron-xyz', self.ref_lb1.uuid, may_exist=True)),
            (mock.call('neutron-qwr', self.ref_lb1.uuid, may_exist=True))])
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid,
            ('external_ids', {'lr_ref': 'foo,%s' % self.router.name}))

    def test__find_lr_of_ls(self):
        lsp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'router1'},
                'type': 'router',
                'options': {
                    'router-port': 'lrp-foo-name'}
            })
        lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'name': 'lrp-foo-name'
            })
        lr = fakes.FakeOVNRouter.create_one_router(
            attrs={
                'name': 'router1',
                'ports': [lrp]})
        ls = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ports': [lsp]})

        (self.helper.ovn_nbdb_api.tables['Logical_Router'].rows.
            values.return_value) = [lr]
        returned_lr = self.helper._find_lr_of_ls(ls)
        self.assertEqual(lr, returned_lr)

    def test__find_lr_of_ls_no_lrp(self):
        ls = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ports': []})
        returned_lr = self.helper._find_lr_of_ls(ls)
        (self.helper.ovn_nbdb_api.tables['Logical_Router'].rows.
            values.assert_not_called())
        self.assertIsNone(returned_lr)

    def test__update_lb_to_ls_association_empty_network_and_subnet(self):
        self._update_lb_to_ls_association.stop()
        returned_commands = self.helper._update_lb_to_ls_association(
            self.ref_lb1, associate=True)
        self.assertListEqual(returned_commands, [])

    def test__update_lb_to_ls_association_network(self):
        self._update_lb_to_ls_association.stop()

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid, associate=True)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            self.network.name)
        ls_refs = {'ls_refs': '{"%s": 2}' % self.network.name}
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid, ('external_ids', ls_refs))

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test__update_lb_to_ls_association_subnet(self, net_dr):
        self._update_lb_to_ls_association.stop()
        subnet = fakes.FakeSubnet.create_one_subnet(
            attrs={'id': 'foo_subnet_id',
                   'name': 'foo_subnet_name',
                   'network_id': 'foo_network_id'})
        net_dr.return_value.get_subnet.return_value = subnet

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, subnet_id=subnet.id, associate=True)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            'neutron-foo_network_id')

    def test__update_lb_to_ls_association_empty_ls_refs(self):
        self._update_lb_to_ls_association.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network
        self.ref_lb1.external_ids.pop('ls_refs')

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid)

        self.helper.ovn_nbdb_api.ls_lb_add.assert_called_once_with(
            self.network.uuid, self.ref_lb1.uuid, may_exist=True)
        ls_refs = {'ls_refs': '{"%s": 1}' % self.network.name}
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid, ('external_ids', ls_refs))

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test__update_lb_to_ls_association_no_ls(self, net_dr):
        self._update_lb_to_ls_association.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            side_effect) = [idlutils.RowNotFound]

        returned_commands = self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            self.network.name)
        self.assertListEqual([], returned_commands)

    def test__update_lb_to_ls_association_network_disassociate(self):
        self._update_lb_to_ls_association.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid, associate=False)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            self.network.name)
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid,
            ('external_ids', {'ls_refs': '{}'}))
        self.helper.ovn_nbdb_api.ls_lb_del.assert_called_once_with(
            self.network.uuid, self.ref_lb1.uuid, if_exists=True)

    def test__update_lb_to_ls_association_network_dis_ls_not_found(self):
        self._update_lb_to_ls_association.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            side_effect) = [idlutils.RowNotFound]

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid, associate=False)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            self.network.name)
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid,
            ('external_ids', {'ls_refs': '{}'}))
        self.helper.ovn_nbdb_api.ls_lb_del.assert_not_called()

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test__update_lb_to_ls_association_network_dis_net_not_found(self, gn):
        gn.return_value.get_subnet.side_effect = n_exc.NotFound
        self._update_lb_to_ls_association.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network
        self.helper._update_lb_to_ls_association(
            self.ref_lb1, subnet_id='foo', associate=False)
        self.helper.ovn_nbdb_api.ls_get.assert_not_called()
        self.helper.ovn_nbdb_api.db_set.assert_not_called()
        self.helper.ovn_nbdb_api.ls_lb_del.assert_not_called()

    def test__update_lb_to_ls_association_disassoc_ls_not_in_ls_refs(self):
        self._update_lb_to_ls_association.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network
        self.ref_lb1.external_ids.pop('ls_refs')

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid, associate=False)

        self.helper.ovn_nbdb_api.ls_lb_del.assert_not_called()
        self.helper.ovn_nbdb_api.db_set.assert_not_called()

    def test__update_lb_to_ls_association_disassoc_multiple_refs(self):
        self._update_lb_to_ls_association.stop()
        (self.helper.ovn_nbdb_api.ls_get.return_value.execute.
            return_value) = self.network
        # multiple refs
        ls_refs = {'ls_refs': '{"%s": 2}' % self.network.name}
        self.ref_lb1.external_ids.update(ls_refs)

        self.helper._update_lb_to_ls_association(
            self.ref_lb1, network_id=self.network.uuid, associate=False)

        self.helper.ovn_nbdb_api.ls_get.assert_called_once_with(
            self.network.name)
        exp_ls_refs = {'ls_refs': '{"%s": 1}' % self.network.name}
        self.helper.ovn_nbdb_api.db_set.assert_called_once_with(
            'Load_Balancer', self.ref_lb1.uuid, ('external_ids', exp_ls_refs))

    def test_logical_switch_port_update_event_vip_port(self):
        self.switch_port_event = ovn_driver.LogicalSwitchPortUpdateEvent(
            self.helper)
        port_name = '%s%s' % (ovn_const.LB_VIP_PORT_PREFIX, 'foo')
        attrs = {
            'external_ids':
            {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port_name,
             ovn_const.OVN_PORT_FIP_EXT_ID_KEY: '10.0.0.1'}}
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs=attrs)
        self.switch_port_event.run(mock.ANY, row, mock.ANY)
        expected_call = {
            'info':
                {'action': 'associate',
                 'vip_fip': '10.0.0.1',
                 'ovn_lb': self.ovn_lb},
            'type': 'handle_vip_fip'}
        self.mock_add_request.assert_called_once_with(expected_call)

    def test_logical_switch_port_update_event_missing_port_name(self):
        self.switch_port_event = ovn_driver.LogicalSwitchPortUpdateEvent(
            self.helper)
        attrs = {'external_ids': {}}
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs=attrs)
        self.switch_port_event.run(mock.ANY, row, mock.ANY)
        self.mock_add_request.assert_not_called()

    def test_logical_switch_port_update_event_empty_fip(self):
        self.switch_port_event = ovn_driver.LogicalSwitchPortUpdateEvent(
            self.helper)
        port_name = '%s%s' % (ovn_const.LB_VIP_PORT_PREFIX, 'foo')
        attrs = {'external_ids':
                 {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port_name}}
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs=attrs)
        self.switch_port_event.run(mock.ANY, row, mock.ANY)
        expected_call = {
            'info':
                {'action': 'disassociate',
                 'vip_fip': None,
                 'ovn_lb': self.ovn_lb},
            'type': 'handle_vip_fip'}
        self.mock_add_request.assert_called_once_with(expected_call)

    def test_logical_switch_port_update_event_not_vip_port(self):
        self.switch_port_event = ovn_driver.LogicalSwitchPortUpdateEvent(
            self.helper)
        port_name = 'foo'
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids':
                   {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port_name}})
        self.switch_port_event.run(mock.ANY, row, mock.ANY)
        self.mock_add_request.assert_not_called()

    @mock.patch('networking_ovn.octavia.ovn_driver.OvnProviderHelper.'
                '_find_ovn_lbs')
    def test_vip_port_update_handler_lb_not_found(self, lb):
        lb.side_effect = [idlutils.RowNotFound]
        self.switch_port_event = ovn_driver.LogicalSwitchPortUpdateEvent(
            self.helper)
        port_name = '%s%s' % (ovn_const.LB_VIP_PORT_PREFIX, 'foo')
        attrs = {'external_ids':
                 {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port_name}}
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs=attrs)
        self.switch_port_event.run(mock.ANY, row, mock.ANY)
        self.mock_add_request.assert_not_called()

    @mock.patch('networking_ovn.octavia.ovn_driver.OvnProviderHelper.'
                '_find_ovn_lbs')
    def test_vip_port_update_handler_multiple_lbs(self, lb):
        lb1 = mock.MagicMock()
        lb2 = mock.MagicMock()
        lb.return_value = [lb1, lb2]
        self.switch_port_event = ovn_driver.LogicalSwitchPortUpdateEvent(
            self.helper)
        port_name = '%s%s' % (ovn_const.LB_VIP_PORT_PREFIX, 'foo')
        attrs = {'external_ids':
                 {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port_name}}
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs=attrs)
        self.switch_port_event.run(mock.ANY, row, mock.ANY)

        def expected_call(lb):
            return {'type': 'handle_vip_fip',
                    'info':
                        {'action': mock.ANY,
                         'vip_fip': None,
                         'ovn_lb': lb}}

        self.mock_add_request.assert_has_calls([
            mock.call(expected_call(lb1)),
            mock.call(expected_call(lb2))])

    @mock.patch('networking_ovn.octavia.ovn_driver.OvnProviderHelper.'
                '_find_ovn_lbs')
    def test_handle_vip_fip_disassociate(self, flb):
        lb = mock.MagicMock()
        fip_info = {
            'action': 'disassociate',
            'vip_fip': None,
            'ovn_lb': lb}
        flb.return_value = lb
        self.helper.handle_vip_fip(fip_info)
        calls = [
            mock.call.db_remove(
                'Load_Balancer', lb.uuid, 'external_ids', 'neutron:vip_fip'),
            mock.call.db_clear('Load_Balancer', lb.uuid, 'vips'),
            mock.call.db_set('Load_Balancer', lb.uuid, ('vips', {}))]
        self.helper.ovn_nbdb_api.assert_has_calls(calls)

    @mock.patch('networking_ovn.octavia.ovn_driver.OvnProviderHelper.'
                '_find_ovn_lbs')
    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_handle_vip_fip_associate(self, net_dr, fb):
        lb = mock.MagicMock()
        fip_info = {
            'action': 'associate',
            'vip_fip': '10.0.0.123',
            'ovn_lb': lb}
        members = 'member_%s_%s:%s' % (self.member_id,
                                       self.member_address,
                                       self.member_port)
        external_ids = {
            'listener_foo': '80:pool_%s' % self.pool_id,
            'pool_%s' % self.pool_id: members,
            'neutron:vip': '172.26.21.20'}

        lb.external_ids = external_ids
        fb.return_value = lb

        self.helper.handle_vip_fip(fip_info)
        calls = [
            mock.call.db_set(
                'Load_Balancer', lb.uuid,
                ('external_ids', {'neutron:vip_fip': '10.0.0.123'})),
            mock.call.db_clear('Load_Balancer', lb.uuid, 'vips'),
            mock.call.db_set(
                'Load_Balancer', lb.uuid,
                ('vips', {'10.0.0.123:80': '192.168.2.149:1010',
                          '172.26.21.20:80': '192.168.2.149:1010'}))]
        self.helper.ovn_nbdb_api.assert_has_calls(calls)

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_handle_member_dvr_lb_has_no_fip(self, net_dr):
        lb = mock.MagicMock()
        info = {
            'id': self.member_id,
            'pool_id': self.pool_id,
            'action': ovn_driver.REQ_INFO_MEMBER_ADDED}
        external_ids = {
            'neutron:vip_fip': ''}
        lb.external_ids = external_ids
        self.mock_find_lb_pool_key.return_value = lb
        self.helper.handle_member_dvr(info)
        net_dr.assert_not_called()
        self.helper.ovn_nbdb_api.db_clear.assert_not_called()

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_handle_member_dvr_lb_fip_no_ls_ports(self, net_dr):
        lb = mock.MagicMock()
        info = {
            'id': self.member_id,
            'subnet_id': self.member_subnet_id,
            'pool_id': self.pool_id,
            'action': ovn_driver.REQ_INFO_MEMBER_ADDED}
        external_ids = {
            'neutron:vip_fip': '11.11.11.11'}
        lb.external_ids = external_ids
        self.mock_find_lb_pool_key.return_value = lb
        fake_ls = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {},
                'ports': {}})
        self.helper.ovn_nbdb_api.lookup.return_value = fake_ls
        self.helper.handle_member_dvr(info)
        self.helper.ovn_nbdb_api.db_clear.assert_not_called()

    def _test_handle_member_dvr_lb_fip(
            self, net_dr, action=ovn_driver.REQ_INFO_MEMBER_ADDED):
        lb = mock.MagicMock()
        fake_port = fakes.FakePort.create_one_port(
            attrs={'allowed_address_pairs': ''})
        info = {
            'id': self.member_id,
            'address': fake_port['fixed_ips'][0]['ip_address'],
            'pool_id': self.pool_id,
            'subnet_id': fake_port['fixed_ips'][0]['subnet_id'],
            'action': action}
        member_subnet = fakes.FakeSubnet.create_one_subnet()
        member_subnet.id = self.member_subnet_id
        member_subnet.network_id = 'foo'
        net_dr.return_value.get_subnet.return_value = member_subnet
        fake_lsp = fakes.FakeOVNPort.from_neutron_port(
            fake_port)
        fake_ls = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ids': {},
                'name': 'foo',
                'ports': [fake_lsp]})
        self.helper.ovn_nbdb_api.lookup.return_value = fake_ls
        fake_nat = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'external_ip': '22.22.22.22',
                'external_ids': {
                    ovn_const.OVN_FIP_EXT_ID_KEY: 'fip_id'}})
        fip_info = {
            'floatingip': {
                'description': 'bar'}}
        net_dr.return_value.neutron_client.show_floatingip.return_value = (
            fip_info)
        self.helper.ovn_nbdb_api.db_find_rows.return_value.\
            execute.return_value = [fake_nat]
        external_ids = {
            ovn_const.LB_EXT_IDS_VIP_FIP_KEY: '11.11.11.11'}
        lb.external_ids = external_ids
        self.mock_find_lb_pool_key.return_value = lb
        self.helper.handle_member_dvr(info)

        if action == ovn_driver.REQ_INFO_MEMBER_ADDED:
            calls = [
                mock.call.lookup('Logical_Switch', 'neutron-foo'),
                mock.call.db_find_rows('NAT', ('external_ids', '=', {
                    ovn_const.OVN_FIP_PORT_EXT_ID_KEY: fake_lsp.name})),
                mock.ANY,
                mock.call.db_clear('NAT', fake_nat.uuid, 'external_mac'),
                mock.ANY,
                mock.call.db_clear('NAT', fake_nat.uuid, 'logical_port'),
                mock.ANY]
            self.helper.ovn_nbdb_api.assert_has_calls(calls)
        else:
            (net_dr.return_value.neutron_client.show_floatingip.
             assert_called_once_with('fip_id'))
            (net_dr.return_value.neutron_client.update_floatingip.
             assert_called_once_with('fip_id', {
                 'floatingip': {'description': 'bar'}}))
            self.helper.ovn_nbdb_api.db_clear.assert_not_called()

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_handle_member_dvr_lb_fip_member_added(self, net_dr):
        self._test_handle_member_dvr_lb_fip(net_dr)

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_handle_member_dvr_lb_fip_member_deleted(self, net_dr):
        self._test_handle_member_dvr_lb_fip(
            net_dr, action=ovn_driver.REQ_INFO_MEMBER_DELETED)

    @mock.patch.object(ovn_driver, 'atexit')
    def test_ovsdb_connections(self, mock_atexit):
        ovn_driver.OvnProviderHelper.ovn_nbdb_api = None
        ovn_driver.OvnProviderHelper.ovn_nbdb_api_for_events = None
        prov_helper1 = ovn_driver.OvnProviderHelper()
        prov_helper2 = ovn_driver.OvnProviderHelper()
        # One connection for API requests
        self.assertIs(prov_helper1.ovn_nbdb_api,
                      prov_helper2.ovn_nbdb_api)
        # One connection to handle events
        self.assertIs(prov_helper1.ovn_nbdb_api_for_events,
                      prov_helper2.ovn_nbdb_api_for_events)
        prov_helper2.shutdown()
        prov_helper1.shutdown()
        # Assert at_exit calls
        mock_atexit.assert_has_calls([
            mock.call.register(prov_helper1.shutdown),
            mock.call.register(prov_helper2.shutdown)])

    def test_create_vip_port_vip_selected(self):
        expected_dict = {
            'port': {'name': '%s%s' % (ovn_const.LB_VIP_PORT_PREFIX,
                                       self.loadbalancer_id),
                     'fixed_ips': [{'subnet_id':
                                    self.vip_dict['vip_subnet_id'],
                                    'ip_address':'10.1.10.1'}],
                     'network_id': self.vip_dict['vip_network_id'],
                     'admin_state_up': True,
                     'project_id': self.project_id}}
        with mock.patch.object(ovn_driver, 'get_network_driver') as gn:
            self.vip_dict['vip_address'] = '10.1.10.1'
            self.helper.create_vip_port(self.project_id,
                                        self.loadbalancer_id,
                                        self.vip_dict)
            expected_call = [
                mock.call().neutron_client.create_port(expected_dict)]
            gn.assert_has_calls(expected_call)

    def test_create_vip_port_vip_not_selected(self):
        expected_dict = {
            'port': {'name': '%s%s' % (ovn_const.LB_VIP_PORT_PREFIX,
                                       self.loadbalancer_id),
                     'fixed_ips': [{'subnet_id':
                                    self.vip_dict['vip_subnet_id']}],
                     'network_id': self.vip_dict['vip_network_id'],
                     'admin_state_up': True,
                     'project_id': self.project_id}}
        with mock.patch.object(ovn_driver, 'get_network_driver') as gn:
            self.helper.create_vip_port(self.project_id,
                                        self.loadbalancer_id,
                                        self.vip_dict)
            expected_call = [
                mock.call().neutron_client.create_port(expected_dict)]
            gn.assert_has_calls(expected_call)

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_create_vip_port_vip_selected_already_exist(self, net_dr):
        net_dr.return_value.neutron_client.create_port.side_effect = [
            n_exc.IpAddressAlreadyAllocatedClient]
        net_dr.return_value.neutron_client.list_ports.return_value = {
            'ports': [
                {'name': 'ovn-lb-vip-' + self.loadbalancer_id,
                 'id': self.loadbalancer_id}]}
        self.vip_dict['vip_address'] = '10.1.10.1'
        ret = self.helper.create_vip_port(
            self.project_id,
            self.loadbalancer_id,
            self.vip_dict)
        expected = {
            'port': {
                'name': '%s%s' % (ovn_const.LB_VIP_PORT_PREFIX,
                                  self.loadbalancer_id),
                'id': self.loadbalancer_id}}
        self.assertDictEqual(expected, ret)
        expected_call = [
            mock.call().neutron_client.list_ports(
                network_id='%s' % self.vip_dict['vip_network_id'],
                name='%s%s' % (ovn_const.LB_VIP_PORT_PREFIX,
                               self.loadbalancer_id))]
        net_dr.assert_has_calls(expected_call)

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_create_vip_port_vip_selected_other_allocation_exist(self, net_dr):
        net_dr.return_value.neutron_client.create_port.side_effect = [
            n_exc.IpAddressAlreadyAllocatedClient]
        net_dr.return_value.neutron_client.list_ports.return_value = {
            'ports': []}
        self.vip_dict['vip_address'] = '10.1.10.1'
        ret = self.helper.create_vip_port(
            self.project_id,
            self.loadbalancer_id,
            self.vip_dict)
        self.assertIsNone(ret)
        expected_call = [
            mock.call().neutron_client.list_ports(
                network_id='%s' % self.vip_dict['vip_network_id'],
                name='%s%s' % (ovn_const.LB_VIP_PORT_PREFIX,
                               self.loadbalancer_id))]
        net_dr.assert_has_calls(expected_call)
        self.helper._update_status_to_octavia.assert_called_once_with(
            {'loadbalancers':
                [{'id': self.loadbalancer_id,
                  'provisioning_status': 'ERROR',
                  'operating_status': 'ERROR'}]})

    def test_get_pool_member_id(self):
        ret = self.helper.get_pool_member_id(
            self.pool_id, mem_addr_port='192.168.2.149:1010')
        self.assertEqual(self.member_id, ret)

    def test__get_existing_pool_members(self):
        ret = self.helper._get_existing_pool_members(self.pool_id)
        self.assertEqual(ret, self.member_line)

    def test__frame_lb_vips(self):
        ret = self.helper._frame_vip_ips(self.ovn_lb.external_ids)
        expected = {'10.22.33.4:80': '192.168.2.149:1010',
                    '123.123.123.123:80': '192.168.2.149:1010'}
        self.assertEqual(expected, ret)

    def test__frame_lb_vips_ipv6(self):
        self.member_address = '2001:db8::1'
        self.member_line = (
            'member_%s_%s:%s_%s' %
            (self.member_id, self.member_address,
             self.member_port, self.member_subnet_id))
        self.ovn_lb.external_ids = {
            ovn_const.LB_EXT_IDS_VIP_KEY: 'fc00::',
            ovn_const.LB_EXT_IDS_VIP_FIP_KEY: '2002::',
            'pool_%s' % self.pool_id: self.member_line,
            'listener_%s' % self.listener_id: '80:pool_%s' % self.pool_id}
        ret = self.helper._frame_vip_ips(self.ovn_lb.external_ids)
        expected = {'[2002::]:80': '[2001:db8::1]:1010',
                    '[fc00::]:80': '[2001:db8::1]:1010'}
        self.assertEqual(expected, ret)

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
import os

import mock
from neutron.tests import base
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
        self.member_id = uuidutils.generate_uuid()
        self.member_subnet_id = uuidutils.generate_uuid()
        self.pool_id = uuidutils.generate_uuid()
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
        self.member_port = "1010"
        self.member_pool_id = self.pool_id
        self.member_subnet_id = uuidutils.generate_uuid()
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
        self.ovn_lb = mock.MagicMock()
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
            lb_algorithm=constants.LB_ALGORITHM_ROUND_ROBIN,
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
            lb_algorithm=constants.LB_ALGORITHM_ROUND_ROBIN,
            loadbalancer_id=self.loadbalancer_id,
            listener_id=self.listener_id,
            members=[self.ref_member],
            pool_id=self.pool_id,
            protocol='TCP',
            session_persistence={'type': 'fix'})
        self.ref_http_pool = data_models.Pool(
            admin_state_up=True,
            description='pool',
            lb_algorithm=constants.LB_ALGORITHM_ROUND_ROBIN,
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
        mock.patch.object(ovn_driver.OvnProviderHelper, '_find_ovn_lb',
                          return_value=self.ovn_lb).start()
        mock.patch.object(
            ovn_driver.OvnProviderHelper, 'get_member_info',
            return_value=[
                (self.ref_member.member_id, "198.52.100.4:99"),
                (self.fail_member.member_id, "198.51.100.4:99")]).start()
        mock.patch.object(ovn_driver.OvnProviderHelper,
                          '_find_ovn_lb_with_pool_key',
                          return_value=self.ovn_lb).start()

    def test_member_create(self):
        info = {'id': self.ref_member.member_id,
                'address': self.ref_member.address,
                'protocol_port': self.ref_member.protocol_port,
                'pool_id': self.ref_member.pool_id,
                'subnet_id': self.ref_member.subnet_id,
                'admin_state_up': self.ref_member.admin_state_up}
        expected_dict = {'type': ovn_driver.REQ_TYPE_MEMBER_CREATE,
                         'info': info}
        self.driver.member_create(self.ref_member)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_member_create_failure(self):
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_create, self.fail_member)

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

    def test_member_update_batch(self):
        self.driver.member_batch_update([self.ref_member, self.update_member])
        self.assertEqual(self.mock_add_request.call_count, 3)

    def test_member_update_failure(self):
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.member_update, self.ref_member,
                          self.fail_member)

    def test_member_delete(self):
        info = {'id': self.ref_member.member_id,
                'address': self.ref_member.address,
                'protocol_port': self.ref_member.protocol_port,
                'pool_id': self.ref_member.pool_id,
                'subnet_id': self.ref_member.subnet_id}
        expected_dict = {'type': ovn_driver.REQ_TYPE_MEMBER_DELETE,
                         'info': info}
        self.driver.member_delete(self.ref_member)
        self.mock_add_request.assert_called_once_with(expected_dict)

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

    def test_listener_update(self):
        info = {'id': self.ref_listener.listener_id,
                'protocol_port': self.ref_listener.protocol_port,
                'admin_state_up': self.ref_listener.admin_state_up,
                'loadbalancer_id': self.ref_listener.loadbalancer_id}
        if self.ref_listener.default_pool_id:
            info['default_pool_id'] = self.ref_listener.default_pool_id
        expected_dict = {'type': ovn_driver.REQ_TYPE_LISTENER_UPDATE,
                         'info': info}
        self.driver.listener_update(self.ref_listener, self.ref_listener)
        self.mock_add_request.assert_called_once_with(expected_dict)

    @mock.patch.object(ovn_driver.OvnProviderHelper, '_is_listener_in_lb',
                       return_value=True)
    def test_listener_failure(self, mock_listener):
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.listener_create, self.fail_listener)
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.listener_update, self.ref_listener,
                          self.fail_listener)
        self.ovn_lb.protocol = ['TCP']
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.listener_create,
                          self.ref_listener_udp)

    def test_listener_delete(self):
        info = {'id': self.ref_listener.listener_id,
                'protocol_port': self.ref_listener.protocol_port,
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

    def test_pool_create_http(self):
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.pool_create, self.ref_http_pool)

    def test_pool_create_leastcount_algo(self):
        self.assertRaises(exceptions.UnsupportedOptionError,
                          self.driver.pool_create, self.ref_lc_pool)

    def test_pool_create_tcp(self):
        info = {'id': self.ref_pool.pool_id,
                'loadbalancer_id': self.ref_pool.loadbalancer_id,
                'listener_id': self.ref_pool.listener_id,
                'admin_state_up': self.ref_pool.admin_state_up}
        expected_dict = {'type': ovn_driver.REQ_TYPE_POOL_CREATE,
                         'info': info}
        self.driver.pool_create(self.ref_pool)
        self.mock_add_request.assert_called_once_with(expected_dict)

    def test_pool_delete(self):
        # Pretent we don't have members
        self.ref_pool.members = []
        info = {'id': self.ref_pool.pool_id,
                'loadbalancer_id': self.ref_pool.loadbalancer_id}
        expected = {'type': ovn_driver.REQ_TYPE_POOL_DELETE,
                    'info': info}
        self.driver.pool_delete(self.ref_pool)
        self.mock_add_request.assert_called_once_with(expected)

    def test_pool_delete_with_members(self):
        info = {'id': self.ref_pool.pool_id,
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
        calls = [mock.call(expected_members),
                 mock.call(expected)]
        self.driver.pool_delete(self.ref_pool)
        self.mock_add_request.assert_has_calls(calls)

    def test_pool_update(self):
        info = {'id': self.ref_update_pool.pool_id,
                'loadbalancer_id': self.ref_update_pool.loadbalancer_id,
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
            'id': self.port1_id}]}
        self.pool = {'id': self.pool_id,
                     'loadbalancer_id': self.loadbalancer_id,
                     'listener_id': self.listener_id,
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
        self.logical_sw = self.helper.ovn_nbdb_api.ls_get.return_value
        self.logical_sw.execute.return_value.ports = []
        self.ovn_lb = mock.MagicMock()
        self.ovn_lb.uuid = uuidutils.generate_uuid()
        self.ovn_lb.external_ids.get.return_value = {}
        self.helper.ovn_nbdb_api.db_find.return_value.\
            execute.return_value = [self.ovn_lb]
        self.helper.ovn_nbdb_api.db_list_rows.return_value.\
            execute.return_value = [self.ovn_lb]
        mock.patch.object(self.helper,
                          '_find_ovn_lb_with_pool_key',
                          return_value=self.ovn_lb).start()
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
                ovn_driver.LB_EXT_IDS_LR_REF_KEY: "neutron-%s" % net_id,
                ovn_driver.LB_EXT_IDS_LS_REFS_KEY:
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
                ovn_driver.LB_EXT_IDS_LR_REF_KEY: "neutron-%s" % net_id,
                ovn_driver.LB_EXT_IDS_LS_REFS_KEY:
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
                   'uuid': net_id})
        self.mock_get_nw = mock.patch.object(
            self.helper, "_get_nw_router_info_on_interface_event",
            return_value=(self.router, self.network))
        self.mock_get_nw.start()

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_lb_create(self, net_dr):
        net_dr.return_value.neutron_client.list_ports.return_value = (
            self.ports)
        status = self.helper.lb_create(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)
        self.lb['admin_state_up'] = True
        status = self.helper.lb_create(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ONLINE)

    @mock.patch('networking_ovn.octavia.ovn_driver.OvnProviderHelper.'
                '_find_ovn_lb')
    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_lb_delete(self, net_dr, lb):
        net_dr.return_value.neutron_client.delete_port.return_value = None
        lb.return_value.external_ids.get.return_value = {}
        status = self.helper.lb_delete(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)

    @mock.patch('networking_ovn.octavia.ovn_driver.OvnProviderHelper.'
                '_find_ovn_lb')
    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_lb_cascade_delete(self, net_dr, lb):
        net_dr.return_value.neutron_client.delete_port.return_value = None
        lb.return_value.external_ids.get.return_value = {}
        self.lb['cascade'] = True
        status = self.helper.lb_delete(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)

    def test_lb_update(self):
        status = self.helper.lb_update(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.OFFLINE)
        self.lb['admin_state_up'] = True
        status = self.helper.lb_update(self.lb)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['loadbalancers'][0]['operating_status'],
                         constants.ONLINE)

    def test_listener_update(self):
        status = self.helper.listener_update(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'], [])
        self.listener['admin_state_up'] = True
        status = self.helper.listener_update(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'], [])

    def test_listener_create(self):
        status = self.helper.listener_create(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.OFFLINE)
        self.listener['admin_state_up'] = True
        status = self.helper.listener_create(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.ONLINE)
        mock.patch.object(self.helper, "_is_listener_in_lb",
                          return_value=True).start()
        status = self.helper.listener_create(self.listener)

    def test_listener_delete(self):
        status = self.helper.listener_delete(self.listener)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['listeners'][0]['provisioning_status'],
                         constants.DELETED)
        self.assertEqual(status['listeners'][0]['operating_status'],
                         constants.OFFLINE)

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
                         constants.OFFLINE)

    def test_pool_delete(self):
        status = self.helper.pool_delete(self.pool)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.DELETED)

    def test_member_create(self):
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

    def test_member_update(self):
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

    @mock.patch('networking_ovn.octavia.ovn_driver.OvnProviderHelper.'
                '_refresh_lb_vips')
    def test_member_delete(self, mock_vip_command):
        self.ovn_lb.external_ids = {
            'pool_' + self.pool_id: 'member_' + self.member_id + '_' +
            self.member_address + ':' + self.member_port}
        status = self.helper.member_delete(self.member)
        self.assertEqual(status['loadbalancers'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['pools'][0]['provisioning_status'],
                         constants.ACTIVE)
        self.assertEqual(status['members'][0]['provisioning_status'],
                         constants.DELETED)

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
            ovn_driver.LB_EXT_IDS_LS_REFS_KEY: 'foo'})
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
            ovn_driver.LB_EXT_IDS_LR_REF_KEY)
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
            ovn_driver.LB_EXT_IDS_LR_REF_KEY)
        add.assert_not_called()
        delete.assert_called_once_with(self.ref_lb1, self.router, lr_ref)

    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test__del_lb_to_lr_association(self, net_dr):
        lr_ref = self.ref_lb1.external_ids.get(
            ovn_driver.LB_EXT_IDS_LR_REF_KEY)
        upd_lr_ref = '%s,%s' % (lr_ref, self.router.name)
        self.helper._del_lb_to_lr_association(
            self.ref_lb1, self.router, upd_lr_ref)
        expected_calls = [
            mock.call.db_set(
                'Load_Balancer', self.ref_lb1.uuid,
                (('external_ids',
                  {ovn_driver.LB_EXT_IDS_LR_REF_KEY: lr_ref}))),
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
            ovn_driver.LB_EXT_IDS_LR_REF_KEY)
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
            return_value) = None

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
                 'lb_id': 'foo'},
            'type': 'handle_vip_fip'}
        self.mock_add_request.assert_called_once_with(expected_call)

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
                 'lb_id': 'foo'},
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
                '_find_ovn_lb')
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
                '_find_ovn_lb')
    def test_handle_vip_fip_disassociate(self, flb):
        fip_info = {
            'action': 'disassociate',
            'vip_fip': None,
            'lb_id': 'foo'}
        lb = mock.MagicMock()
        flb.return_value = lb
        self.helper.handle_vip_fip(fip_info)
        calls = [
            mock.call.db_remove(
                'Load_Balancer', lb.uuid, 'external_ids', 'neutron:vip_fip'),
            mock.call.db_clear('Load_Balancer', lb.uuid, 'vips'),
            mock.call.db_set('Load_Balancer', lb.uuid, ('vips', {}))]
        self.helper.ovn_nbdb_api.assert_has_calls(calls)

    @mock.patch('networking_ovn.octavia.ovn_driver.OvnProviderHelper.'
                '_find_ovn_lb')
    @mock.patch('networking_ovn.octavia.ovn_driver.get_network_driver')
    def test_handle_vip_fip_associate(self, net_dr, fb):
        fip_info = {
            'action': 'associate',
            'vip_fip': '10.0.0.123',
            'lb_id': 'foo'}
        members = 'member_%s_%s:%s' % (self.member_id,
                                       self.member_address,
                                       self.member_port)
        external_ids = {
            'listener_foo': '80:pool_%s' % self.pool_id,
            'pool_%s' % self.pool_id: members,
            'neutron:vip': '172.26.21.20'}

        lb = mock.MagicMock()
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

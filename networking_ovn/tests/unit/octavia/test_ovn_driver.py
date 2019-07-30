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
import collections

import mock
from neutron.tests import base
from octavia_lib.api.drivers import data_models
from octavia_lib.api.drivers import exceptions
from octavia_lib.common import constants
from oslo_utils import uuidutils

from networking_ovn.octavia import ovn_driver


class MockedLB(data_models.LoadBalancer):
    def __init__(self, *args, **kwargs):
        self.external_ids = kwargs.pop('ext_ids')
        self.uuid = kwargs.pop('uuid')
        super(MockedLB, self).__init__(*args, **kwargs)

    def __hash__(self):
        # Required for Python3, not for Python2
        return self.__sizeof__()


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
        self.member_address = "192.168.2.149"
        self.vip_address = '192.148.210.109'
        self.member_port = "1010"
        self.member_pool_id = self.pool_id
        self.member_subnet_id = uuidutils.generate_uuid()
        mock.patch(
            'ovsdbapp.backend.ovs_idl.idlutils.get_schema_helper').start()


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
        self.vip_dict = {'vip_network_id': uuidutils.generate_uuid(),
                         'vip_subnet_id': uuidutils.generate_uuid()}
        self.vip_output = {'vip_network_id': self.vip_dict['vip_network_id'],
                           'vip_subnet_id': self.vip_dict['vip_subnet_id']}

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
            for key, value in self.vip_output.items():
                self.assertEqual(value, port_dict[key])
            self.vip_dict['vip_address'] = '10.1.10.1'
            port_dict = self.driver.create_vip_port(self.loadbalancer_id,
                                                    self.project_id,
                                                    self.vip_dict)
            # The network_driver function is mocked, therefore the
            # created port vip_address is also mocked. Check if it exists
            # and move on.
            self.assertIsNotNone(port_dict.pop('vip_address', None))
            for key, value in self.vip_output.items():
                self.assertEqual(value, port_dict[key])


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
        mock.patch.object(self.helper, 'ovn_nbdb_api').start()
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
        ref_lb1 = MockedLB(
            uuid=uuidutils.generate_uuid(),
            admin_state_up=True,
            listeners=[],
            loadbalancer_id=self.loadbalancer_id,
            name='favorite_lb1',
            project_id=self.project_id,
            vip_address=self.vip_address,
            vip_network_id=self.vip_network_id,
            ext_ids={ovn_driver.LB_EXT_IDS_LR_REF_KEY: '1'})
        ref_lb2 = MockedLB(
            uuid=uuidutils.generate_uuid(),
            admin_state_up=True,
            listeners=[],
            loadbalancer_id=self.loadbalancer_id,
            name='favorite_lb2',
            project_id=self.project_id,
            vip_address=self.vip_address,
            vip_network_id=self.vip_network_id,
            ext_ids={ovn_driver.LB_EXT_IDS_LR_REF_KEY: '1'})
        loadbalancer = collections.namedtuple("LoadBalancer",
                                              "load_balancer name uuid")
        mock.patch.object(self.helper,
                          '_find_ovn_lb_with_pool_key',
                          return_value=self.ovn_lb).start()
        mock.patch.object(self.helper,
                          '_get_pool_listeners',
                          return_value=[]).start()
        mock.patch.object(self.helper,
                          '_update_lb_to_ls_association',
                          return_value=[]).start()
        mock.patch.object(self.helper,
                          '_update_lb_to_lr_association',
                          return_value=[]).start()
        self.router = loadbalancer(load_balancer=[ref_lb1], name='router_lb',
                                   uuid=uuidutils.generate_uuid())
        self.network = loadbalancer(load_balancer=[ref_lb2], name='network_lb',
                                    uuid=uuidutils.generate_uuid())

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
                         constants.ONLINE)

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

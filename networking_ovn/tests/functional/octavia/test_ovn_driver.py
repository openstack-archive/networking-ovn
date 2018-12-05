# Copyright 2018 Red Hat, Inc.
# All Rights Reserved.
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

import mock

from neutron.common import utils as n_utils
from octavia_lib.api.drivers import data_models as octavia_data_model
from octavia_lib.api.drivers import exceptions as o_exceptions
from octavia_lib.common import constants as o_constants
from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from networking_ovn.octavia import ovn_driver
from networking_ovn.tests.functional import base


class TestOctaviaOvnProviderDriver(base.TestOVNFunctionalBase):

    def setUp(self):
        super(TestOctaviaOvnProviderDriver, self).setUp()
        # ovn_driver.OvnProviderHelper.ovn_nbdb_api is a class variable.
        # Set it to None, so that when a worker starts the 2nd test we don't
        # use the old object.
        ovn_driver.OvnProviderHelper.ovn_nbdb_api = None
        self.ovn_driver = ovn_driver.OvnProviderDriver()
        self.ovn_driver._ovn_helper._octavia_driver_lib = mock.MagicMock()
        self._o_driver_lib = self.ovn_driver._ovn_helper._octavia_driver_lib
        self._o_driver_lib.update_loadbalancer_status = mock.Mock()
        self.fake_network_driver = mock.MagicMock()
        ovn_driver.get_network_driver = mock.MagicMock()
        ovn_driver.get_network_driver.return_value = self.fake_network_driver
        self.fake_network_driver.get_subnet = self._mock_get_subnet
        self.fake_network_driver.neutron_client.list_ports = (
            self._mock_list_ports)
        self._local_net_cache = {}
        self._local_port_cache = {'ports': []}

    def _mock_get_subnet(self, subnet_id):
        m_subnet = mock.MagicMock()
        m_subnet.network_id = self._local_net_cache[subnet_id]
        return m_subnet

    def _mock_list_ports(self, **kwargs):
        return self._local_port_cache

    def _create_lb_model(self, vip=None, vip_network_id=None,
                         admin_state_up=True):
        lb = octavia_data_model.LoadBalancer()
        lb.loadbalancer_id = uuidutils.generate_uuid()

        if vip:
            lb.vip_address = vip
        else:
            lb.vip_address = '10.0.0.4'

        if vip_network_id:
            lb.vip_network_id = vip_network_id
        lb.admin_state_up = admin_state_up
        return lb

    def _create_pool_model(self, loadbalancer_id, pool_name, protocol=None,
                           admin_state_up=True, listener_id=None):
        m_pool = octavia_data_model.Pool()
        if protocol:
            m_pool.protocol = protocol
        else:
            m_pool.protocol = o_constants.PROTOCOL_TCP
        m_pool.name = pool_name
        m_pool.pool_id = uuidutils.generate_uuid()
        m_pool.loadbalancer_id = loadbalancer_id
        m_pool.members = []
        m_pool.admin_state_up = admin_state_up
        if listener_id:
            m_pool.listener_id = listener_id
        return m_pool

    def _create_member_model(self, pool_id, subnet_id, address,
                             protocol_port=None, admin_state_up=True):
        m_member = octavia_data_model.Member()
        if protocol_port:
            m_member.protocol_port = protocol_port
        else:
            m_member.protocol_port = 80

        m_member.member_id = uuidutils.generate_uuid()
        m_member.pool_id = pool_id
        if subnet_id:
            m_member.subnet_id = subnet_id
        m_member.address = address
        m_member.admin_state_up = admin_state_up
        return m_member

    def _create_listener_model(self, loadbalancer_id, pool_id=None,
                               protocol_port=80, protocol=None,
                               admin_state_up=True):
        m_listener = octavia_data_model.Listener()
        if protocol:
            m_listener.protocol = protocol
        else:
            m_listener.protocol = o_constants.PROTOCOL_TCP

        m_listener.listener_id = uuidutils.generate_uuid()
        m_listener.loadbalancer_id = loadbalancer_id
        if pool_id:
            m_listener.default_pool_id = pool_id
        m_listener.protocol_port = protocol_port
        m_listener.admin_state_up = admin_state_up
        return m_listener

    def _get_loadbalancers(self):
        lbs = []
        for lb in self.nb_api.tables['Load_Balancer'].rows.values():
            external_ids = dict(lb.external_ids)
            ls_refs = external_ids.get(ovn_driver.LB_EXT_IDS_LS_REFS_KEY)
            if ls_refs:
                external_ids[
                    ovn_driver.LB_EXT_IDS_LS_REFS_KEY] = jsonutils.loads(
                        ls_refs)
            lbs.append({'name': lb.name, 'protocol': lb.protocol,
                        'vips': lb.vips, 'external_ids': external_ids})

        return lbs

    def _get_loadbalancer_id(self, lb_name):
        for lb in self.nb_api.tables['Load_Balancer'].rows.values():
            if lb.name == lb_name:
                return lb.uuid

    def _validate_loadbalancers(self, expected_lbs):
        observed_lbs = self._get_loadbalancers()
        self.assertItemsEqual(expected_lbs, observed_lbs)

    def _is_lb_associated_to_ls(self, lb_name, ls_name):
        lb_uuid = self._get_loadbalancer_id(lb_name)
        for ls in self.nb_api.tables['Logical_Switch'].rows.values():
            if ls.name == ls_name:
                ls_lbs = [lb.uuid for lb in ls.load_balancer]
                return lb_uuid in ls_lbs

        return False

    def _create_router(self, name, gw_info=None):
        router = {'router':
                  {'name': name,
                   'admin_state_up': True,
                   'tenant_id': self._tenant_id}}
        if gw_info:
            router['router']['external_gateway_info'] = gw_info
        router = self.l3_plugin.create_router(self.context, router)
        return router['id']

    def _create_net(self, name, cidr, router_id=None):
        n1 = self._make_network(self.fmt, name, True)
        res = self._create_subnet(self.fmt, n1['network']['id'],
                                  cidr)
        subnet = self.deserialize(self.fmt, res)['subnet']
        self._local_net_cache[subnet['id']] = n1['network']['id']

        port = self._make_port(self.fmt, n1['network']['id'])
        if router_id:
            self.l3_plugin.add_router_interface(
                self.context, router_id, {'subnet_id': subnet['id']})
        self._local_port_cache['ports'].append(port['port'])
        vip_port_address = port['port']['fixed_ips'][0]['ip_address']
        return (n1['network']['id'], subnet['id'], vip_port_address,
                port['port']['id'])

    def _update_ls_refs(self, lb_data, net_id, add_ref=True):
        if not net_id.startswith("neutron-"):
            net_id = "neutron-" + net_id

        if add_ref:
            if net_id in lb_data[ovn_driver.LB_EXT_IDS_LS_REFS_KEY]:
                ref_ct = lb_data[
                    ovn_driver.LB_EXT_IDS_LS_REFS_KEY][net_id] + 1
                lb_data[ovn_driver.LB_EXT_IDS_LS_REFS_KEY][net_id] = ref_ct
            else:
                lb_data[ovn_driver.LB_EXT_IDS_LS_REFS_KEY][net_id] = 1
        else:
            ref_ct = lb_data[ovn_driver.LB_EXT_IDS_LS_REFS_KEY][net_id] - 1
            if ref_ct > 0:
                lb_data[ovn_driver.LB_EXT_IDS_LS_REFS_KEY][net_id] = ref_ct
            else:
                del lb_data[ovn_driver.LB_EXT_IDS_LS_REFS_KEY][net_id]

    def _wait_for_status_and_validate(self, lb_data, expected_status,
                                      check_call=True):
        call_count = len(expected_status)
        expected_calls = [mock.call(status) for status in expected_status]
        update_loadbalancer_status = (
            self._o_driver_lib.update_loadbalancer_status)
        n_utils.wait_until_true(
            lambda: update_loadbalancer_status.call_count == call_count,
            timeout=10)
        if check_call:
            try:
                self._o_driver_lib.update_loadbalancer_status.assert_has_calls(
                    expected_calls, any_order=True)
            except Exception:
                raise Exception(
                    self._o_driver_lib.update_loadbalancer_status.mock_calls)
        expected_lbs = self._make_expected_lbs(lb_data)
        self._validate_loadbalancers(expected_lbs)

    def _create_load_balancer_and_validate(self, lb_info,
                                           admin_state_up=True):
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        lb_data = {}
        router_id = self._create_router("r1")
        lb_data[ovn_driver.LB_EXT_IDS_LR_REF_KEY] = router_id
        net_info = self._create_net(lb_info['vip_network'], lb_info['cidr'],
                                    router_id=router_id)
        lb_data['vip_net_info'] = net_info
        lb_data['model'] = self._create_lb_model(vip=net_info[2],
                                                 vip_network_id=net_info[0],
                                                 admin_state_up=admin_state_up)
        lb_data[ovn_driver.LB_EXT_IDS_LS_REFS_KEY] = {}
        lb_data['listeners'] = []
        lb_data['pools'] = []
        self._update_ls_refs(lb_data, net_info[0])

        self.ovn_driver.loadbalancer_create(lb_data['model'])
        if lb_data['model'].admin_state_up:
            expected_status = {
                'loadbalancers': [{"id": lb_data['model'].loadbalancer_id,
                                   "provisioning_status": "ACTIVE",
                                   "operating_status": o_constants.ONLINE}]
            }
        else:
            expected_status = {
                'loadbalancers': [{"id": lb_data['model'].loadbalancer_id,
                                   "provisioning_status": "ACTIVE",
                                   "operating_status": o_constants.OFFLINE}]
            }
        self._wait_for_status_and_validate(lb_data, [expected_status])
        self.assertTrue(
            self._is_lb_associated_to_ls(lb_data['model'].loadbalancer_id,
                                         'neutron-' + net_info[0]))
        return lb_data

    def _update_load_balancer_and_validate(self, lb_data,
                                           admin_state_up=None):
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        if admin_state_up is not None:
            lb_data['model'].admin_state_up = admin_state_up
        self.ovn_driver.loadbalancer_update(
            lb_data['model'], lb_data['model'])

        if lb_data['model'].admin_state_up:
            expected_status = {
                'loadbalancers': [{"id": lb_data['model'].loadbalancer_id,
                                   "provisioning_status": "ACTIVE",
                                   "operating_status": o_constants.ONLINE}]
            }
        else:
            expected_status = {
                'loadbalancers': [{"id": lb_data['model'].loadbalancer_id,
                                   "provisioning_status": "ACTIVE",
                                   "operating_status": o_constants.OFFLINE}]
            }

        self._wait_for_status_and_validate(lb_data, [expected_status])

    def _delete_load_balancer_and_validate(self, lb_data, cascade=False):
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        self.ovn_driver.loadbalancer_delete(lb_data['model'], cascade)
        expected_status = {
            'loadbalancers': [{"id": lb_data['model'].loadbalancer_id,
                               "provisioning_status": "DELETED",
                               "operating_status": "OFFLINE"}]
        }
        if cascade:
            expected_status['pools'] = []
            expected_status['members'] = []
            expected_status['listeners'] = []
            for pool in lb_data['pools']:
                expected_status['pools'].append({
                    'id': pool.pool_id,
                    'provisioning_status': 'DELETED'})
                for member in pool.members:
                    expected_status['members'].append({
                        "id": member.member_id,
                        "provisioning_status": "DELETED"})
            for listener in lb_data['listeners']:
                expected_status['listeners'].append({
                    "id": listener.listener_id,
                    "provisioning_status": "DELETED",
                    "operating_status": "OFFLINE"})
            expected_status = {
                key: value for key, value in expected_status.items() if value}

        lb = lb_data['model']
        del lb_data['model']
        self._wait_for_status_and_validate(lb_data, [expected_status])
        self._validate_loadbalancers([])
        vip_net_id = lb_data['vip_net_info'][0]
        self.assertFalse(
            self._is_lb_associated_to_ls(lb.loadbalancer_id,
                                         'neutron-' + vip_net_id))

    def _make_expected_lbs(self, lb_data):
        if not lb_data or not lb_data.get('model'):
            return []

        vip_net_info = lb_data['vip_net_info']
        external_ids = {ovn_driver.LB_EXT_IDS_LS_REFS_KEY: {},
                        'neutron:vip': lb_data['model'].vip_address,
                        'neutron:vip_port_id': vip_net_info[3],
                        'enabled': str(lb_data['model'].admin_state_up)}

        pool_info = {}
        for p in lb_data.get('pools', []):
            p_members = ""
            for m in p.members:
                if not m.admin_state_up:
                    continue
                m_info = 'member_' + m.member_id + '_' + m.address
                m_info += ":" + str(m.protocol_port)
                if p_members:
                    p_members += "," + m_info
                else:
                    p_members = m_info
            pool_key = 'pool_' + p.pool_id
            if not p.admin_state_up:
                pool_key += ':D'
            external_ids[pool_key] = p_members
            pool_info[p.pool_id] = p_members

        for net_id, ref_ct in lb_data[
            ovn_driver.LB_EXT_IDS_LS_REFS_KEY].items():
            external_ids[ovn_driver.LB_EXT_IDS_LS_REFS_KEY][net_id] = ref_ct

        if lb_data.get(ovn_driver.LB_EXT_IDS_LR_REF_KEY):
            external_ids[
                ovn_driver.LB_EXT_IDS_LR_REF_KEY] = 'neutron-' + lb_data[
                    ovn_driver.LB_EXT_IDS_LR_REF_KEY]

        expected_vips = {}
        expected_protocol = ['tcp']
        for l in lb_data['listeners']:
            listener_k = 'listener_' + str(l.listener_id)
            if lb_data['model'].admin_state_up and l.admin_state_up:
                vip_k = lb_data['model'].vip_address + ":" + str(
                    l.protocol_port)
                if not isinstance(l.default_pool_id,
                                  octavia_data_model.UnsetType) and pool_info[
                                      l.default_pool_id]:
                    expected_vips[vip_k] = self._extract_member_info(
                        pool_info[l.default_pool_id])
            else:
                listener_k += ':D'
            external_ids[listener_k] = str(l.protocol_port) + ":"
            if not isinstance(l.default_pool_id,
                              octavia_data_model.UnsetType):
                external_ids[listener_k] += 'pool_' + (l.default_pool_id)
            elif lb_data.get('pools', []):
                external_ids[listener_k] += 'pool_' + lb_data[
                    'pools'][0].pool_id

        expected_lbs = [{'name': lb_data['model'].loadbalancer_id,
                         'protocol': expected_protocol,
                         'vips': expected_vips,
                         'external_ids': external_ids}]
        return expected_lbs

    def _extract_member_info(self, member):
        mem_info = ''
        if member:
            for item in member.split(','):
                mem_info += item.split('_')[2] + ","
        return mem_info[:-1]

    def _create_pool_and_validate(self, lb_data, pool_name,
                                  listener_id=None):
        lb_pools = lb_data['pools']
        m_pool = self._create_pool_model(lb_data['model'].loadbalancer_id,
                                         pool_name,
                                         listener_id=listener_id)
        lb_pools.append(m_pool)
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        self.ovn_driver.pool_create(m_pool)
        expected_status = {
            'pools': [{'id': m_pool.pool_id,
                       'provisioning_status': 'ACTIVE',
                       'operating_status': o_constants.ONLINE}],
            'loadbalancers': [{'id': m_pool.loadbalancer_id,
                               'provisioning_status': 'ACTIVE'}]
        }
        if listener_id:
            expected_status['listeners'] = [
                {'id': listener_id,
                 'provisioning_status': 'ACTIVE'}]

        self._wait_for_status_and_validate(lb_data, [expected_status])

        expected_lbs = self._make_expected_lbs(lb_data)
        self._validate_loadbalancers(expected_lbs)

    def _update_pool_and_validate(self, lb_data, pool_name,
                                  admin_state_up=None):
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        m_pool = self._get_pool_from_lb_data(lb_data, pool_name=pool_name)
        old_admin_state_up = m_pool.admin_state_up
        operating_status = 'ONLINE'
        if admin_state_up is not None:
            m_pool.admin_state_up = admin_state_up
            if not admin_state_up:
                operating_status = 'OFFLINE'

        pool_listeners = self._get_pool_listeners(lb_data, m_pool.pool_id)
        expected_listener_status = [
            {'id': l.listener_id, 'provisioning_status': 'ACTIVE'}
            for l in pool_listeners]
        self.ovn_driver.pool_update(m_pool, m_pool)
        expected_status = {
            'pools': [{'id': m_pool.pool_id,
                       'provisioning_status': 'ACTIVE',
                       'operating_status': operating_status}],
            'loadbalancers': [{'id': m_pool.loadbalancer_id,
                               'provisioning_status': 'ACTIVE'}],
            'listeners': expected_listener_status
        }

        if old_admin_state_up != m_pool.admin_state_up:
            if m_pool.admin_state_up:
                oper_status = o_constants.ONLINE
            else:
                oper_status = o_constants.OFFLINE
            expected_status['pools'][0]['operating_status'] = oper_status
        self._wait_for_status_and_validate(lb_data, [expected_status])

    def _delete_pool_and_validate(self, lb_data, pool_name,
                                  listener_id=None):
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        p = self._get_pool_from_lb_data(lb_data, pool_name=pool_name)
        self.ovn_driver.pool_delete(p)
        lb_data['pools'].remove(p)
        expected_status = []
        # When a pool is deleted and if it has any members, there are
        # expected to be deleted.
        for m in p.members:
            expected_status.append(
                {'pools': [{"id": p.pool_id,
                            "provisioning_status": "ACTIVE"}],
                 'members': [{"id": m.member_id,
                              "provisioning_status": "DELETED"}],
                 'loadbalancers': [{"id": p.loadbalancer_id,
                                    "provisioning_status": "ACTIVE"}],
                 'listeners': []})
            self._update_ls_refs(
                lb_data, self._local_net_cache[m.subnet_id], add_ref=False)

        pool_dict = {
            'pools': [{'id': p.pool_id,
                       'provisioning_status': 'DELETED'}],
            'loadbalancers': [{'id': p.loadbalancer_id,
                               'provisioning_status': 'ACTIVE'}]
        }
        if listener_id:
            pool_dict['listeners'] = [{'id': listener_id,
                                       'provisioning_status': 'ACTIVE'}]
        expected_status.append(pool_dict)
        self._wait_for_status_and_validate(lb_data, expected_status)

    def _get_pool_from_lb_data(self, lb_data, pool_id=None,
                               pool_name=None):
        for p in lb_data['pools']:
            if pool_id and p.pool_id == pool_id:
                return p

            if pool_name and p.name == pool_name:
                return p

    def _get_listener_from_lb_data(self, lb_data, protocol_port):
        for l in lb_data['listeners']:
            if l.protocol_port == protocol_port:
                return l

    def _get_pool_listeners(self, lb_data, pool_id):
        listeners = []
        for l in lb_data['listeners']:
            if l.default_pool_id == pool_id:
                listeners.append(l)

        return listeners

    def _create_member_and_validate(self, lb_data, pool_id, subnet_id,
                                    network_id, address):
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        pool = self._get_pool_from_lb_data(lb_data, pool_id=pool_id)

        m_member = self._create_member_model(pool.pool_id, subnet_id, address)
        pool.members.append(m_member)

        self.ovn_driver.member_create(m_member)
        self._update_ls_refs(lb_data, network_id)
        pool_listeners = self._get_pool_listeners(lb_data, pool_id)

        expected_listener_status = [
            {'id': l.listener_id, 'provisioning_status': 'ACTIVE'}
            for l in pool_listeners]

        expected_status = {
            'pools': [{'id': pool.pool_id,
                       'provisioning_status': 'ACTIVE'}],
            'members': [{"id": m_member.member_id,
                         "provisioning_status": "ACTIVE"}],
            'loadbalancers': [{'id': pool.loadbalancer_id,
                               'provisioning_status': 'ACTIVE'}],
            'listeners': expected_listener_status
        }
        self._wait_for_status_and_validate(lb_data, [expected_status])

    def _get_pool_member(self, pool, member_address):
        for m in pool.members:
            if m.address == member_address:
                return m

    def _update_member_and_validate(self, lb_data, pool_id, member_address):
        pool = self._get_pool_from_lb_data(lb_data, pool_id=pool_id)

        member = self._get_pool_member(pool, member_address)
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        self.ovn_driver.member_update(member, member)
        expected_status = {
            'pools': [{'id': pool.pool_id,
                       'provisioning_status': 'ACTIVE'}],
            'members': [{"id": member.member_id,
                         'provisioning_status': 'ACTIVE',
                         'operating_status': 'ONLINE'}],
            'loadbalancers': [{'id': pool.loadbalancer_id,
                               'provisioning_status': 'ACTIVE'}],
            'listeners': []
        }
        self._wait_for_status_and_validate(lb_data, [expected_status])

    def _update_members_in_batch_and_validate(self, lb_data, pool_id,
                                              members):
        pool = self._get_pool_from_lb_data(lb_data, pool_id=pool_id)
        expected_status = []
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        self.ovn_driver.member_batch_update(members)
        for member in members:
            expected_status.append(
                {'pools': [{'id': pool.pool_id,
                           'provisioning_status': 'ACTIVE'}],
                 'members': [{'id': member.member_id,
                              'provisioning_status': 'ACTIVE',
                              'operating_status': 'ONLINE'}],
                 'loadbalancers': [{'id': pool.loadbalancer_id,
                                   'provisioning_status': 'ACTIVE'}],
                 'listeners': []})
        for m in pool.members:
            found = False
            for member in members:
                if member.member_id == m.member_id:
                    found = True
                    break
            if not found:
                expected_status.append(
                    {'pools': [{'id': pool.pool_id,
                                'provisioning_status': 'ACTIVE'}],
                     'members': [{'id': m.member_id,
                                  'provisioning_status': 'DELETED'}],
                     'loadbalancers': [{'id': pool.loadbalancer_id,
                                        'provisioning_status': 'ACTIVE'}],
                     'listeners': []})
        self._wait_for_status_and_validate(lb_data, expected_status,
                                           check_call=False)

    def _delete_member_and_validate(self, lb_data, pool_id, network_id,
                                    member_address):
        pool = self._get_pool_from_lb_data(lb_data, pool_id=pool_id)
        member = self._get_pool_member(pool, member_address)
        pool.members.remove(member)
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        self.ovn_driver.member_delete(member)
        expected_status = {
            'pools': [{"id": pool.pool_id,
                       "provisioning_status": "ACTIVE"}],
            'members': [{"id": member.member_id,
                         "provisioning_status": "DELETED"}],
            'loadbalancers': [{"id": pool.loadbalancer_id,
                               "provisioning_status": "ACTIVE"}],
            'listeners': []}

        self._update_ls_refs(lb_data, network_id, add_ref=False)
        self._wait_for_status_and_validate(lb_data, [expected_status])

    def _create_listener_and_validate(self, lb_data, pool_id=None,
                                      protocol_port=80,
                                      admin_state_up=True, protocol='TCP'):
        if pool_id:
            pool = self._get_pool_from_lb_data(lb_data, pool_id=pool_id)
            loadbalancer_id = pool.loadbalancer_id
            pool_id = pool.pool_id
        else:
            loadbalancer_id = lb_data['model'].loadbalancer_id
            pool_id = None
        m_listener = self._create_listener_model(loadbalancer_id,
                                                 pool_id, protocol_port,
                                                 protocol=protocol,
                                                 admin_state_up=admin_state_up)
        lb_data['listeners'].append(m_listener)

        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        self.ovn_driver.listener_create(m_listener)
        expected_status = {
            'listeners': [{'id': m_listener.listener_id,
                           'provisioning_status': 'ACTIVE',
                           'operating_status': 'ONLINE'}],
            'loadbalancers': [{'id': m_listener.loadbalancer_id,
                               'provisioning_status': "ACTIVE"}]}

        self._wait_for_status_and_validate(lb_data, [expected_status])

    def _update_listener_and_validate(self, lb_data, protocol_port,
                                      admin_state_up=None, protocol='TCP'):
        m_listener = self._get_listener_from_lb_data(lb_data, protocol_port)
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        old_admin_state_up = m_listener.admin_state_up
        operating_status = 'ONLINE'
        if admin_state_up is not None:
            m_listener.admin_state_up = admin_state_up
            if not admin_state_up:
                operating_status = 'OFFLINE'
        m_listener.protocol = protocol

        self.ovn_driver.listener_update(m_listener, m_listener)
        pool_status = [{'id': m_listener.default_pool_id,
                        'provisioning_status': 'ACTIVE'}]
        expected_status = {
            'listeners': [{'id': m_listener.listener_id,
                           'provisioning_status': 'ACTIVE',
                           'operating_status': operating_status}],
            'loadbalancers': [{"id": m_listener.loadbalancer_id,
                               "provisioning_status": "ACTIVE"}],
            'pools': pool_status}

        if old_admin_state_up != m_listener.admin_state_up:
            if m_listener.admin_state_up:
                oper_status = o_constants.ONLINE
            else:
                oper_status = o_constants.OFFLINE
            expected_status['listeners'][0]['operating_status'] = oper_status

        self._wait_for_status_and_validate(lb_data, [expected_status])

    def _delete_listener_and_validate(self, lb_data, protocol_port=80):
        m_listener = self._get_listener_from_lb_data(lb_data, protocol_port)
        lb_data['listeners'].remove(m_listener)
        self._o_driver_lib.update_loadbalancer_status.reset_mock()
        self.ovn_driver.listener_delete(m_listener)
        expected_status = {
            'listeners': [{"id": m_listener.listener_id,
                           "provisioning_status": "DELETED",
                           "operating_status": "OFFLINE"}],
            'loadbalancers': [{"id": m_listener.loadbalancer_id,
                               "provisioning_status": "ACTIVE"}]}

        self._wait_for_status_and_validate(lb_data, [expected_status])

    def test_loadbalancer(self):
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'})
        self._update_load_balancer_and_validate(lb_data, admin_state_up=False)
        self._update_load_balancer_and_validate(lb_data, admin_state_up=True)
        self._delete_load_balancer_and_validate(lb_data)
        # create load balance with admin state down
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'}, admin_state_up=False)
        self._delete_load_balancer_and_validate(lb_data)

    def test_pool(self):
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'})
        self._create_pool_and_validate(lb_data, "p1")
        self._update_pool_and_validate(lb_data, "p1")
        self._update_pool_and_validate(lb_data, "p1", admin_state_up=True)
        self._update_pool_and_validate(lb_data, "p1", admin_state_up=False)
        self._update_pool_and_validate(lb_data, "p1", admin_state_up=True)
        self._create_pool_and_validate(lb_data, "p2")
        self._delete_pool_and_validate(lb_data, "p2")
        self._delete_pool_and_validate(lb_data, "p1")
        self._delete_load_balancer_and_validate(lb_data)

    def test_member(self):
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'})
        self._create_pool_and_validate(lb_data, "p1")
        pool_id = lb_data['pools'][0].pool_id
        self._create_member_and_validate(
            lb_data, pool_id, lb_data['vip_net_info'][1],
            lb_data['vip_net_info'][0], '10.0.0.10')
        self._update_member_and_validate(lb_data, pool_id, "10.0.0.10")

        self._create_member_and_validate(
            lb_data, pool_id, lb_data['vip_net_info'][1],
            lb_data['vip_net_info'][0], '10.0.0.11')

        # Disable loadbalancer
        self._update_load_balancer_and_validate(lb_data,
                                                admin_state_up=False)

        # Enable loadbalancer back
        self._update_load_balancer_and_validate(lb_data,
                                                admin_state_up=True)
        self._delete_member_and_validate(lb_data, pool_id,
                                         lb_data['vip_net_info'][0],
                                         '10.0.0.10')
        self._delete_member_and_validate(lb_data, pool_id,
                                         lb_data['vip_net_info'][0],
                                         '10.0.0.11')
        self._create_member_and_validate(
            lb_data, pool_id, lb_data['vip_net_info'][1],
            lb_data['vip_net_info'][0], '10.0.0.10')

        net20_info = self._create_net('net20', '20.0.0.0/24')
        net20 = net20_info[0]
        subnet20 = net20_info[1]
        self._create_member_and_validate(lb_data, pool_id, subnet20, net20,
                                         '20.0.0.4')
        self._create_member_and_validate(lb_data, pool_id, subnet20, net20,
                                         '20.0.0.6')
        net30_info = self._create_net('net30', '30.0.0.0/24')
        net30 = net30_info[0]
        subnet30 = net30_info[1]
        self._create_member_and_validate(lb_data, pool_id, subnet30, net30,
                                         '30.0.0.6')
        self._delete_member_and_validate(lb_data, pool_id, net20, '20.0.0.6')

        # Test creating Member without subnet
        m_member = self._create_member_model(pool_id,
                                             None,
                                             '30.0.0.7', 80)
        self.assertRaises(o_exceptions.UnsupportedOptionError,
                          self.ovn_driver.member_create, m_member)

        # Deleting the pool should also delete the members.
        self._delete_pool_and_validate(lb_data, "p1")
        self._delete_load_balancer_and_validate(lb_data)

    def test_listener(self):
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'})
        self._create_pool_and_validate(lb_data, "p1")
        pool_id = lb_data['pools'][0].pool_id
        self._create_member_and_validate(
            lb_data, pool_id, lb_data['vip_net_info'][1],
            lb_data['vip_net_info'][0], '10.0.0.10')

        net_info = self._create_net('net1', '20.0.0.0/24')
        self._create_member_and_validate(lb_data, pool_id,
                                         net_info[1], net_info[0], '20.0.0.4')
        self._create_listener_and_validate(lb_data, pool_id, 80)
        self._update_listener_and_validate(lb_data, 80)
        self._update_listener_and_validate(lb_data, 80, admin_state_up=True)
        self._update_listener_and_validate(lb_data, 80, admin_state_up=False)
        self._update_listener_and_validate(lb_data, 80, admin_state_up=True)
        self._create_listener_and_validate(lb_data, pool_id, 82)

        self._delete_listener_and_validate(lb_data, 82)
        self._delete_listener_and_validate(lb_data, 80)

    def _test_cascade_delete(self, pool=True, listener=True, member=True):
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'})
        if pool:
            self._create_pool_and_validate(lb_data, "p1")
            pool_id = lb_data['pools'][0].pool_id
            if member:
                self._create_member_and_validate(
                    lb_data, pool_id, lb_data['vip_net_info'][1],
                    lb_data['vip_net_info'][0], '10.0.0.10')
            if listener:
                self._create_listener_and_validate(lb_data, pool_id, 80)

        self._delete_load_balancer_and_validate(lb_data, cascade=True)

    def test_lb_listener_pools_cascade(self):
        self._test_cascade_delete(member=False)

    def test_lb_pool_cascade(self):
        self._test_cascade_delete(member=False, listener=False)

    def test_cascade_delete(self):
        self._test_cascade_delete()

    def test_for_unsupported_options(self):
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'})

        m_pool = self._create_pool_model(lb_data['model'].loadbalancer_id,
                                         'lb1')
        m_pool.protocol = o_constants.PROTOCOL_HTTP
        self.assertRaises(o_exceptions.UnsupportedOptionError,
                          self.ovn_driver.pool_create, m_pool)

        m_listener = self._create_listener_model(
            lb_data['model'].loadbalancer_id, m_pool.pool_id, 80)
        m_listener.protocol = o_constants.PROTOCOL_HTTP
        self.assertRaises(o_exceptions.UnsupportedOptionError,
                          self.ovn_driver.listener_create, m_listener)
        self._create_listener_and_validate(lb_data)
        self.assertRaises(o_exceptions.UnsupportedOptionError,
                          self._create_listener_and_validate,
                          lb_data, protocol_port=80, protocol='UDP')
        self.assertRaises(o_exceptions.UnsupportedOptionError,
                          self._update_listener_and_validate,
                          lb_data, protocol_port=80, protocol='UDP')

    def test_lb_listener_pool_workflow(self):
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'})
        self._create_listener_and_validate(lb_data)
        self._create_pool_and_validate(lb_data, "p1",
                                       lb_data['listeners'][0].listener_id)
        self._delete_pool_and_validate(lb_data, "p1",
                                       lb_data['listeners'][0].listener_id)
        self._delete_listener_and_validate(lb_data)
        self._delete_load_balancer_and_validate(lb_data)

    def test_lb_member_batch_update(self):
        # Create a LoadBalancer
        lb_data = self._create_load_balancer_and_validate(
            {'vip_network': 'vip_network',
             'cidr': '10.0.0.0/24'})
        # Create a pool
        self._create_pool_and_validate(lb_data, "p1")
        pool_id = lb_data['pools'][0].pool_id
        # Create Member-1 and associate it with lb_data
        self._create_member_and_validate(
            lb_data, pool_id, lb_data['vip_net_info'][1],
            lb_data['vip_net_info'][0], '10.0.0.10')
        # Create Member-2
        m_member = self._create_member_model(pool_id,
                                             lb_data['vip_net_info'][1],
                                             '10.0.0.12')
        # Update ovn's Logical switch reference
        self._update_ls_refs(lb_data, lb_data['vip_net_info'][0])
        lb_data['pools'][0].members.append(m_member)
        # Add a new member to the LB
        members = [m_member] + [lb_data['pools'][0].members[0]]
        self._update_members_in_batch_and_validate(lb_data, pool_id, members)
        # Deleting one member, while keeping the other member available
        self._update_members_in_batch_and_validate(lb_data, pool_id,
                                                   [m_member])

# Copyright 2016 Red Hat, Inc.
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

from networking_ovn.common import utils
from networking_ovn.tests.functional import base
from oslo_config import cfg
from oslo_utils import uuidutils


class TestPortBinding(base.TestOVNFunctionalBase):

    def setUp(self):
        super(TestPortBinding, self).setUp()
        self.ovs_host = 'ovs-host'
        self.dpdk_host = 'dpdk-host'
        self.invalid_dpdk_host = 'invalid-host'
        self.vhu_mode = 'server'
        self.add_fake_chassis(self.ovs_host)
        self.add_fake_chassis(
            self.dpdk_host,
            external_ids={'datapath-type': 'netdev',
                          'iface-types': 'dummy,dummy-internal,dpdkvhostuser'})

        self.add_fake_chassis(
            self.invalid_dpdk_host,
            external_ids={'datapath-type': 'netdev',
                          'iface-types': 'dummy,dummy-internal,geneve,vxlan'})
        self.n1 = self._make_network(self.fmt, 'n1', True)
        res = self._create_subnet(self.fmt, self.n1['network']['id'],
                                  '10.0.0.0/24')
        self.deserialize(self.fmt, res)

    def _create_or_update_port(self, port_id=None, hostname=None):

        if port_id is None:
            port_data = {
                'port': {'network_id': self.n1['network']['id'],
                         'tenant_id': self._tenant_id}}

            if hostname:
                port_data['port']['device_id'] = uuidutils.generate_uuid()
                port_data['port']['device_owner'] = 'compute:None'
                port_data['port']['binding:host_id'] = hostname

            port_req = self.new_create_request('ports', port_data, self.fmt)
            port_res = port_req.get_response(self.api)
            p = self.deserialize(self.fmt, port_res)
            port_id = p['port']['id']
        else:
            port_data = {
                'port': {'device_id': uuidutils.generate_uuid(),
                         'device_owner': 'compute:None',
                         'binding:host_id': hostname}}
            port_req = self.new_update_request('ports', port_data, port_id,
                                               self.fmt)
            port_res = port_req.get_response(self.api)
            self.deserialize(self.fmt, port_res)

        return port_id

    def _verify_vif_details(self, port_id, expected_host_name,
                            expected_vif_type, expected_vif_details):
        port_req = self.new_show_request('ports', port_id)
        port_res = port_req.get_response(self.api)
        p = self.deserialize(self.fmt, port_res)
        self.assertEqual(expected_host_name, p['port']['binding:host_id'])
        self.assertEqual(expected_vif_type, p['port']['binding:vif_type'])
        self.assertEqual(expected_vif_details,
                         p['port']['binding:vif_details'])

    def test_port_binding_create_port(self):
        port_id = self._create_or_update_port(hostname=self.ovs_host)
        self._verify_vif_details(port_id, self.ovs_host, 'ovs',
                                 {'port_filter': True})

        port_id = self._create_or_update_port(hostname=self.dpdk_host)
        expected_vif_details = {'port_filter': False,
                                'vhostuser_mode': self.vhu_mode,
                                'vhostuser_ovs_plug': True}
        expected_vif_details['vhostuser_socket'] = (
            utils.ovn_vhu_sockpath(cfg.CONF.ovn.vhost_sock_dir, port_id))
        self._verify_vif_details(port_id, self.dpdk_host, 'vhostuser',
                                 expected_vif_details)

        port_id = self._create_or_update_port(hostname=self.invalid_dpdk_host)
        self._verify_vif_details(port_id, self.invalid_dpdk_host, 'ovs',
                                 {'port_filter': True})

    def test_port_binding_update_port(self):
        port_id = self._create_or_update_port()
        self._verify_vif_details(port_id, '', 'unbound', {})
        port_id = self._create_or_update_port(port_id=port_id,
                                              hostname=self.ovs_host)
        self._verify_vif_details(port_id, self.ovs_host, 'ovs',
                                 {'port_filter': True})

        port_id = self._create_or_update_port(port_id=port_id,
                                              hostname=self.dpdk_host)
        expected_vif_details = {'port_filter': False,
                                'vhostuser_mode': self.vhu_mode,
                                'vhostuser_ovs_plug': True}
        expected_vif_details['vhostuser_socket'] = (
            utils.ovn_vhu_sockpath(cfg.CONF.ovn.vhost_sock_dir, port_id))
        self._verify_vif_details(port_id, self.dpdk_host, 'vhostuser',
                                 expected_vif_details)

        port_id = self._create_or_update_port(port_id=port_id,
                                              hostname=self.invalid_dpdk_host)
        self._verify_vif_details(port_id, self.invalid_dpdk_host, 'ovs',
                                 {'port_filter': True})


class TestPortBindingOverTcp(TestPortBinding):
    def get_ovsdb_server_protocol(self):
        return 'tcp'


class TestPortBindingOverSsl(TestPortBinding):
    def get_ovsdb_server_protocol(self):
        return 'ssl'

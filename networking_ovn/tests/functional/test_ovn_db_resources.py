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


import mock

from networking_ovn.tests.functional import base
from neutron.agent.ovsdb.native import idlutils
from neutron.common import utils as n_utils


class TestNBDbResources(base.TestOVNFunctionalBase):

    def setUp(self):
        super(TestNBDbResources, self).setUp()
        self.fake_api = mock.MagicMock()
        self.fake_api.idl = self.monitor_nb_db_idl
        self.fake_api._tables = self.monitor_nb_db_idl.tables
        self.orig_get_random_mac = n_utils.get_random_mac
        n_utils.get_random_mac = mock.Mock()
        n_utils.get_random_mac.return_value = '01:02:03:04:05:06'

    def tearDown(self):
        super(TestNBDbResources, self).tearDown()
        # This is required, else other tests run by the same worker
        # would fail.
        n_utils.get_random_mac = self.orig_get_random_mac

    def _verify_dhcp_option_rows(self, expected_dhcp_options_rows):
        observed_dhcp_options_rows = []
        for row in self.monitor_nb_db_idl.tables['DHCP_Options'].rows.values():
            observed_dhcp_options_rows.append({
                'cidr': row.cidr, 'external_ids': row.external_ids,
                'options': row.options})

        self.assertItemsEqual(expected_dhcp_options_rows,
                              observed_dhcp_options_rows)

    def _verify_dhcp_option_row_for_port(self, port_id,
                                         expected_lsp_dhcp_options):
        lsp = idlutils.row_by_value(self.monitor_nb_db_idl,
                                    'Logical_Switch_Port', 'name', port_id,
                                    None)

        if lsp.dhcpv4_options:
            observed_lsp_dhcp_options = {
                'cidr': lsp.dhcpv4_options[0].cidr,
                'external_ids': lsp.dhcpv4_options[0].external_ids,
                'options': lsp.dhcpv4_options[0].options}
        else:
            observed_lsp_dhcp_options = {}

        self.assertEqual(expected_lsp_dhcp_options, observed_lsp_dhcp_options)

    def test_dhcp_options(self):
        """Test for DHCP_Options table rows

        When a new subnet is created, a new row has to be created in the
        DHCP_Options table for this subnet with the dhcp options stored
        in the DHCP_Options.options column.
        When ports are created for this subnet (with IPv4 address set and
        DHCP enabled in the subnet), the
        Logical_Switch_Port.dhcpv4_options column should refer to the
        appropriate row of DHCP_Options.

        In cases where a port has extra DHCPv4 options defined, a new row
        in the DHCP_Options table should be created for this port and
        Logical_Switch_Port.dhcpv4_options colimn should refer to this row.

        In order to map the DHCP_Options row to the subnet (and to a port),
        subnet_id is stored in DHCP_Options.external_ids column.
        For DHCP_Options row which belongs to a port, port_id is also stored
        in the DHCP_Options.external_ids along with the subnet_id.
        """

        n1 = self._make_network(self.fmt, 'n1', True)
        created_subnets = {}
        expected_dhcp_options_rows = []

        for cidr in ['10.0.0.0/24', '20.0.0.0/24', '30.0.0.0/24',
                     '40.0.0.0/24']:
            res = self._create_subnet(self.fmt, n1['network']['id'], cidr)
            subnet = self.deserialize(self.fmt, res)
            created_subnets[cidr] = subnet
            expected_dhcp_options_rows.append({
                'cidr': cidr,
                'external_ids': {'subnet_id': subnet['subnet']['id']},
                'options': {'server_id': cidr.replace('0/24', '1'),
                            'server_mac': '01:02:03:04:05:06',
                            'lease_time': str(12 * 60 * 60),
                            'mtu': str(n1['network']['mtu']),
                            'router': subnet['subnet']['gateway_ip']}})

        for (cidr, enable_dhcp, gateway_ip) in [
                ('50.0.0.0/24', False, '50.0.0.1'),
                ('60.0.0.0/24', True, None)]:
            res = self._create_subnet(self.fmt, n1['network']['id'], cidr,
                                      enable_dhcp=enable_dhcp,
                                      gateway_ip=gateway_ip)
            subnet = self.deserialize(self.fmt, res)
            created_subnets[cidr] = subnet
            if enable_dhcp:
                expected_dhcp_options_rows.append({
                    'cidr': cidr,
                    'external_ids': {'subnet_id': subnet['subnet']['id']},
                    'options': {}})

        # create a subnet with dns nameservers and host routes
        n2 = self._make_network(self.fmt, 'n2', True)
        res = self._create_subnet(
            self.fmt, n2['network']['id'], '10.0.0.0/24',
            dns_nameservers=['7.7.7.7', '8.8.8.8'],
            host_routes=[{'destination': '40.0.0.0/24',
                          'nexthop': '10.0.0.4'},
                         {'destination': '30.0.0.0/24',
                          'nexthop': '10.0.0.8'}])

        subnet = self.deserialize(self.fmt, res)
        static_routes = ('{40.0.0.0/24,10.0.0.4, 30.0.0.0/24,'
                         '10.0.0.8, 0.0.0.0/0,10.0.0.1}')
        expected_dhcp_options_rows.append({
            'cidr': '10.0.0.0/24',
            'external_ids': {'subnet_id': subnet['subnet']['id']},
            'options': {'server_id': '10.0.0.1',
                        'server_mac': '01:02:03:04:05:06',
                        'lease_time': str(12 * 60 * 60),
                        'mtu': str(n2['network']['mtu']),
                        'router': subnet['subnet']['gateway_ip'],
                        'dns_server': '{7.7.7.7, 8.8.8.8}',
                        'classless_static_route': static_routes}})

        # Verify that DHCP_Options rows are created for these subnets or not
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)

        n_utils.get_random_mac = self.orig_get_random_mac

        # Create a port and verify if Logical_Switch_Port.dhcpv4_options
        # is properly set or not
        subnet = created_subnets['40.0.0.0/24']
        p = self._make_port(self.fmt, n1['network']['id'],
                            fixed_ips=[{'subnet_id': subnet['subnet']['id']}])

        self._verify_dhcp_option_row_for_port(p['port']['id'],
                                              expected_dhcp_options_rows[3])

        # create a port with dhcp disabled subnet
        subnet = created_subnets['50.0.0.0/24']

        p = self._make_port(self.fmt, n1['network']['id'],
                            fixed_ips=[{'subnet_id': subnet['subnet']['id']}])

        self._verify_dhcp_option_row_for_port(p['port']['id'], {})

        # Delete the first subnet created
        subnet = created_subnets['10.0.0.0/24']
        req = self.new_delete_request('subnets', subnet['subnet']['id'])
        req.get_response(self.api)

        # Verify that DHCP_Options rows is deleted or not
        del expected_dhcp_options_rows[0]
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)

    def test_port_dhcp_options(self):
        n1 = self._make_network(self.fmt, 'n1', True)
        res = self._create_subnet(self.fmt, n1['network']['id'], '10.0.0.0/24')
        subnet = self.deserialize(self.fmt, res)

        n_utils.get_random_mac = self.orig_get_random_mac
        expected_dhcp_options_rows = [{
            'cidr': '10.0.0.0/24',
            'external_ids': {'subnet_id': subnet['subnet']['id']},
            'options': {'server_id': '10.0.0.1',
                        'server_mac': '01:02:03:04:05:06',
                        'lease_time': str(12 * 60 * 60),
                        'mtu': str(n1['network']['mtu']),
                        'router': subnet['subnet']['gateway_ip']}}]

        data = {
            'port': {'network_id': n1['network']['id'],
                     'tenant_id': self._tenant_id,
                     'extra_dhcp_opts': [{'ip_version': 4, 'opt_name': 'mtu',
                                          'opt_value': '1100'},
                                         {'ip_version': 4,
                                          'opt_name': 'ntp-server',
                                          'opt_value': '8.8.8.8'}]}}
        port_req = self.new_create_request('ports', data, self.fmt)
        port_res = port_req.get_response(self.api)
        p1 = self.deserialize(self.fmt, port_res)

        expected_dhcp_options_rows.append({
            'cidr': '10.0.0.0/24',
            'external_ids': {'subnet_id': subnet['subnet']['id'],
                             'port_id': p1['port']['id']},
            'options': {'server_id': '10.0.0.1',
                        'server_mac': '01:02:03:04:05:06',
                        'lease_time': str(12 * 60 * 60),
                        'mtu': '1100',
                        'router': subnet['subnet']['gateway_ip'],
                        'ntp_server': '8.8.8.8'}})

        data = {
            'port': {'network_id': n1['network']['id'],
                     'tenant_id': self._tenant_id,
                     'extra_dhcp_opts': [{'ip_version': 4,
                                          'opt_name': 'ip-forward-enable',
                                          'opt_value': '1'},
                                         {'ip_version': 4,
                                          'opt_name': 'tftp-server',
                                          'opt_value': '10.0.0.100'},
                                         {'ip_version': 4,
                                          'opt_name': 'dns-server',
                                          'opt_value': '20.20.20.20'}]}}

        port_req = self.new_create_request('ports', data, self.fmt)
        port_res = port_req.get_response(self.api)
        p2 = self.deserialize(self.fmt, port_res)

        expected_dhcp_options_rows.append({
            'cidr': '10.0.0.0/24',
            'external_ids': {'subnet_id': subnet['subnet']['id'],
                             'port_id': p2['port']['id']},
            'options': {'server_id': '10.0.0.1',
                        'server_mac': '01:02:03:04:05:06',
                        'lease_time': str(12 * 60 * 60),
                        'mtu': str(n1['network']['mtu']),
                        'router': subnet['subnet']['gateway_ip'],
                        'ip_forward_enable': '1',
                        'tftp_server': '10.0.0.100',
                        'dns_server': '20.20.20.20'}})

        self._verify_dhcp_option_rows(expected_dhcp_options_rows)

        self._verify_dhcp_option_row_for_port(p1['port']['id'],
                                              expected_dhcp_options_rows[1])
        self._verify_dhcp_option_row_for_port(p2['port']['id'],
                                              expected_dhcp_options_rows[2])

        # Update the subnet with dns_server. It should get propagated
        # to the DHCP options of the p1. Note that it should not get
        # propagate to DHCP options of port p2 because, it has overridden
        # dns-server in the Extra DHCP options.
        n_utils.get_random_mac = mock.Mock()
        n_utils.get_random_mac.return_value = '01:02:03:04:05:06'
        data = {'subnet': {'dns_nameservers': ['7.7.7.7', '8.8.8.8']}}
        req = self.new_update_request('subnets', data, subnet['subnet']['id'])
        req.get_response(self.api)

        for i in [0, 1]:
            expected_dhcp_options_rows[i]['options']['dns_server'] = (
                '{7.7.7.7, 8.8.8.8}')

        self._verify_dhcp_option_rows(expected_dhcp_options_rows)

        # Update the port p2 by removing dns-server and tfp-server in the
        # extra DHCP options. dns-server option from the subnet DHCP options
        # should be updated in the p2 DHCP options
        data = {'port': {'extra_dhcp_opts': [{'ip_version': 4,
                                              'opt_name': 'ip-forward-enable',
                                              'opt_value': '0'},
                                             {'ip_version': 4,
                                              'opt_name': 'tftp-server',
                                              'opt_value': None},
                                             {'ip_version': 4,
                                              'opt_name': 'dns-server',
                                              'opt_value': None}]}}
        port_req = self.new_update_request('ports', data, p2['port']['id'])
        port_req.get_response(self.api)
        expected_dhcp_options_rows[2]['options']['dns_server'] = (
            '{7.7.7.7, 8.8.8.8}')
        expected_dhcp_options_rows[2]['options']['ip_forward_enable'] = '0'

        del expected_dhcp_options_rows[2]['options']['tftp_server']
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)

        # Disable dhcp in p2
        data = {'port': {'extra_dhcp_opts': [{'ip_version': 4,
                                              'opt_name': 'dhcp_disabled',
                                              'opt_value': 'true'}]}}
        port_req = self.new_update_request('ports', data, p2['port']['id'])
        port_req.get_response(self.api)

        del expected_dhcp_options_rows[2]
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)

        # delete port p1.
        port_req = self.new_delete_request('ports', p1['port']['id'])
        port_req.get_response(self.api)

        del expected_dhcp_options_rows[1]
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)

    def test_port_dhcp_opts_add_and_remove_extra_dhcp_opts(self):
        """Orphaned DHCP_Options row.

        In this test case a port is created with extra DHCP options.
        Since it has extra DHCP options a new row in the DHCP_Options is
        created for this port.
        Next the port is updated to delete the extra DHCP options.
        After the update, the Logical_Switch_Port.dhcpv4_options for this port
        should refer to the subnet DHCP_Options and the DHCP_Options row
        created for this port earlier should be deleted.
        """
        n1 = self._make_network(self.fmt, 'n1', True)
        res = self._create_subnet(self.fmt, n1['network']['id'], '10.0.0.0/24')
        subnet = self.deserialize(self.fmt, res)

        n_utils.get_random_mac = self.orig_get_random_mac
        expected_dhcp_options_rows = [{
            'cidr': '10.0.0.0/24',
            'external_ids': {'subnet_id': subnet['subnet']['id']},
            'options': {'server_id': '10.0.0.1',
                        'server_mac': '01:02:03:04:05:06',
                        'lease_time': str(12 * 60 * 60),
                        'mtu': str(n1['network']['mtu']),
                        'router': subnet['subnet']['gateway_ip']}}]

        data = {
            'port': {'network_id': n1['network']['id'],
                     'tenant_id': self._tenant_id,
                     'extra_dhcp_opts': [{'ip_version': 4, 'opt_name': 'mtu',
                                          'opt_value': '1100'},
                                         {'ip_version': 4,
                                          'opt_name': 'ntp-server',
                                          'opt_value': '8.8.8.8'}]}}
        port_req = self.new_create_request('ports', data, self.fmt)
        port_res = port_req.get_response(self.api)
        p1 = self.deserialize(self.fmt, port_res)

        expected_dhcp_options_rows.append({
            'cidr': '10.0.0.0/24',
            'external_ids': {'subnet_id': subnet['subnet']['id'],
                             'port_id': p1['port']['id']},
            'options': {'server_id': '10.0.0.1',
                        'server_mac': '01:02:03:04:05:06',
                        'lease_time': str(12 * 60 * 60),
                        'mtu': '1100',
                        'router': subnet['subnet']['gateway_ip'],
                        'ntp_server': '8.8.8.8'}})

        self._verify_dhcp_option_rows(expected_dhcp_options_rows)
        # The Logical_Switch_Port.dhcpv4_options should refer to the
        # the port DHCP options.
        self._verify_dhcp_option_row_for_port(p1['port']['id'],
                                              expected_dhcp_options_rows[1])

        # Now update the port to delete the extra DHCP options
        data = {'port': {'extra_dhcp_opts': [{'ip_version': 4,
                                              'opt_name': 'mtu',
                                              'opt_value': None},
                                             {'ip_version': 4,
                                              'opt_name': 'ntp-server',
                                              'opt_value': None}]}}
        port_req = self.new_update_request('ports', data, p1['port']['id'])
        port_req.get_response(self.api)

        # DHCP_Options row created for the port earlier should have been
        # deleted.
        del expected_dhcp_options_rows[1]
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)
        # The Logical_Switch_Port.dhcpv4_options for this port should refer to
        # the subnet DHCP options.
        self._verify_dhcp_option_row_for_port(p1['port']['id'],
                                              expected_dhcp_options_rows[0])

        # update the port again with extra DHCP options.
        data = {'port': {'extra_dhcp_opts': [{'ip_version': 4,
                                              'opt_name': 'mtu',
                                              'opt_value': '1200'},
                                             {'ip_version': 4,
                                              'opt_name': 'tftp-server',
                                              'opt_value': '8.8.8.8'}]}}

        port_req = self.new_update_request('ports', data, p1['port']['id'])
        port_req.get_response(self.api)

        expected_dhcp_options_rows.append({
            'cidr': '10.0.0.0/24',
            'external_ids': {'subnet_id': subnet['subnet']['id'],
                             'port_id': p1['port']['id']},
            'options': {'server_id': '10.0.0.1',
                        'server_mac': '01:02:03:04:05:06',
                        'lease_time': str(12 * 60 * 60),
                        'mtu': '1200',
                        'router': subnet['subnet']['gateway_ip'],
                        'tftp_server': '8.8.8.8'}})
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)
        self._verify_dhcp_option_row_for_port(p1['port']['id'],
                                              expected_dhcp_options_rows[1])

        # Disable dhcp for this port. The DHCP_Options row created for this
        # port should be get deleted.
        data = {'port': {'extra_dhcp_opts': [{'ip_version': 4,
                                              'opt_name': 'dhcp_disabled',
                                              'opt_value': 'true'}]}}
        port_req = self.new_update_request('ports', data, p1['port']['id'])
        port_req.get_response(self.api)

        del expected_dhcp_options_rows[1]
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)
        # The Logical_Switch_Port.dhcpv4_options for this port should be
        # empty.
        self._verify_dhcp_option_row_for_port(p1['port']['id'], {})

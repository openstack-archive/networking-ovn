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

from networking_ovn.common import constants as ovn_const
from networking_ovn.common import utils as ovn_utils
from networking_ovn.l3 import l3_ovn_scheduler as l3_sched
from networking_ovn.tests.functional import base

from neutron.common import utils as n_utils
from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib import constants as n_consts
from neutron_lib.plugins import directory
from ovsdbapp.backend.ovs_idl import idlutils


class TestRouter(base.TestOVNFunctionalBase):
    def setUp(self):
        super(TestRouter, self).setUp(ovn_worker=True)
        self.chassis1 = self.add_fake_chassis(
            'ovs-host1', physical_nets=['physnet1', 'physnet3'])
        self.chassis2 = self.add_fake_chassis(
            'ovs-host2', physical_nets=['physnet2', 'physnet3'])

    def _create_router(self, name, gw_info=None):
        router = {'router':
                  {'name': name,
                   'admin_state_up': True,
                   'tenant_id': self._tenant_id}}
        if gw_info:
            router['router']['external_gateway_info'] = gw_info
        return self.l3_plugin.create_router(self.context, router)

    def _create_ext_network(self, name, net_type, physnet, seg,
                            gateway, cidr):
        arg_list = (pnet.NETWORK_TYPE, external_net.EXTERNAL,)
        net_arg = {pnet.NETWORK_TYPE: net_type,
                   external_net.EXTERNAL: True}
        if seg:
            arg_list = arg_list + (pnet.SEGMENTATION_ID,)
            net_arg[pnet.SEGMENTATION_ID] = seg
        if physnet:
            arg_list = arg_list + (pnet.PHYSICAL_NETWORK,)
            net_arg[pnet.PHYSICAL_NETWORK] = physnet
        network = self._make_network(self.fmt, name, True,
                                     arg_list=arg_list, **net_arg)
        self._make_subnet(self.fmt, network, gateway, cidr, ip_version=4)
        return network

    def _set_redirect_chassis_to_invalid_chassis(self, ovn_client):
        with ovn_client._nb_idl.transaction(check_error=True) as txn:
            for lrp in self.nb_api.tables[
                    'Logical_Router_Port'].rows.values():
                txn.add(ovn_client._nb_idl.update_lrouter_port(
                    lrp.name,
                    gateway_chassis=[ovn_const.OVN_GATEWAY_INVALID_CHASSIS]))

    def test_gateway_chassis_on_router_gateway_port(self):
        ext2 = self._create_ext_network(
            'ext2', 'flat', 'physnet3', None, "20.0.0.1", "20.0.0.0/24")
        gw_info = {'network_id': ext2['network']['id']}
        self._create_router('router1', gw_info=gw_info)
        expected = [row.name for row in
                    self.sb_api.tables['Chassis'].rows.values()]
        for row in self.nb_api.tables[
                'Logical_Router_Port'].rows.values():
            if self._l3_ha_supported():
                chassis = [gwc.chassis_name for gwc in row.gateway_chassis]
                self.assertItemsEqual(expected, chassis)
            else:
                rc = row.options.get(ovn_const.OVN_GATEWAY_CHASSIS_KEY)
                self.assertIn(rc, expected)

    def _check_gateway_chassis_candidates(self, candidates):
        # In this test, fake_select() is called once from _create_router()
        # and later from schedule_unhosted_gateways()
        ovn_client = self.l3_plugin._ovn_client
        ext1 = self._create_ext_network(
            'ext1', 'vlan', 'physnet1', 1, "10.0.0.1", "10.0.0.0/24")
        # mock select function and check if it is called with expected
        # candidates.

        def fake_select(*args, **kwargs):
            self.assertItemsEqual(candidates, kwargs['candidates'])
            # We are not interested in further processing, let us return
            # INVALID_CHASSIS to avoid erros
            return [ovn_const.OVN_GATEWAY_INVALID_CHASSIS]

        with mock.patch.object(ovn_client._ovn_scheduler, 'select',
                               side_effect=fake_select) as client_select,\
            mock.patch.object(self.l3_plugin.scheduler, 'select',
                              side_effect=fake_select) as plugin_select:
            gw_info = {'network_id': ext1['network']['id']}
            self._create_router('router1', gw_info=gw_info)
            self.assertFalse(plugin_select.called)
            self.assertTrue(client_select.called)
            client_select.reset_mock()
            plugin_select.reset_mock()

            # set redirect-chassis to neutron-ovn-invalid-chassis, so
            # that schedule_unhosted_gateways will try to schedule it
            self._set_redirect_chassis_to_invalid_chassis(ovn_client)
            self.l3_plugin.schedule_unhosted_gateways()
            self.assertFalse(client_select.called)
            self.assertTrue(plugin_select.called)

    def test_gateway_chassis_with_cms_and_bridge_mappings(self):
        # Both chassis1 and chassis3 are having proper bridge mappings,
        # but only chassis3 is having enable-chassis-as-gw.
        # Test if chassis3 is selected as candidate or not.
        self.chassis3 = self.add_fake_chassis(
            'ovs-host3', physical_nets=['physnet1'],
            external_ids={'ovn-cms-options': 'enable-chassis-as-gw'})
        self._check_gateway_chassis_candidates([self.chassis3])

    def test_gateway_chassis_with_cms_and_no_bridge_mappings(self):
        # chassis1 is having proper bridge mappings.
        # chassis3 is having enable-chassis-as-gw, but no bridge mappings.
        # Test if chassis1 is selected as candidate or not.
        self.chassis3 = self.add_fake_chassis(
            'ovs-host3',
            external_ids={'ovn-cms-options': 'enable-chassis-as-gw'})
        self._check_gateway_chassis_candidates([self.chassis1])

    def test_gateway_chassis_with_bridge_mappings_and_no_cms(self):
        # chassis1 is configured with proper bridge mappings,
        # but none of the chassis having enable-chassis-as-gw.
        # Test if chassis1 is selected as candidate or not.
        self._check_gateway_chassis_candidates([self.chassis1])

    def _l3_ha_supported(self):
        # If the Gateway_Chassis table exists in SB database, then it
        # means that L3 HA is supported.
        return self.nb_api.tables.get('Gateway_Chassis')

    def test_gateway_chassis_least_loaded_scheduler(self):
        # This test will create 4 routers each with its own gateway.
        # Using the least loaded policy for scheduling gateway ports, we
        # expect that they are equally distributed across the two available
        # chassis.
        ovn_client = self.l3_plugin._ovn_client
        ovn_client._ovn_scheduler = l3_sched.OVNGatewayLeastLoadedScheduler()
        ext1 = self._create_ext_network(
            'ext1', 'flat', 'physnet3', None, "20.0.0.1", "20.0.0.0/24")
        gw_info = {'network_id': ext1['network']['id']}

        # Create 4 routers with a gateway. Since we're using physnet3, the
        # chassis candidates will be chassis1 and chassis2.
        for i in range(1, 5):
            self._create_router('router%d' % i, gw_info=gw_info)

        # At this point we expect two gateways to be present in chassis1
        # and two in chassis2. If schema supports L3 HA, we expect each
        # chassis to host 2 priority 2 gateways and 2 priority 1 ones.
        if self._l3_ha_supported():
            # Each chassis contains a dict of (priority, # of ports hosted).
            # {1: 2, 2: 2} means that this chassis hosts 2 ports of prio 1
            # and two ports of prio 2.
            expected = {self.chassis1: {1: 2, 2: 2},
                        self.chassis2: {1: 2, 2: 2}}
        else:
            # For non L3 HA, each chassis should contain two gateway ports.
            expected = {self.chassis1: 2,
                        self.chassis2: 2}
        sched_info = {}
        for row in self.nb_api.tables[
                'Logical_Router_Port'].rows.values():
            if self._l3_ha_supported():
                for gwc in row.gateway_chassis:
                    chassis = sched_info.setdefault(gwc.chassis_name, {})
                    chassis[gwc.priority] = chassis.get(gwc.priority, 0) + 1
            else:
                rc = row.options.get(ovn_const.OVN_GATEWAY_CHASSIS_KEY)
                sched_info[rc] = sched_info.get(rc, 0) + 1
        self.assertEqual(expected, sched_info)

    def test_gateway_chassis_with_bridge_mappings(self):
        ovn_client = self.l3_plugin._ovn_client
        # Create external networks with vlan, flat and geneve network types
        ext1 = self._create_ext_network(
            'ext1', 'vlan', 'physnet1', 1, "10.0.0.1", "10.0.0.0/24")
        ext2 = self._create_ext_network(
            'ext2', 'flat', 'physnet3', None, "20.0.0.1", "20.0.0.0/24")
        ext3 = self._create_ext_network(
            'ext3', 'geneve', None, 10, "30.0.0.1", "30.0.0.0/24")
        # mock select function and check if it is called with expected
        # candidates.
        self.candidates = []

        def fake_select(*args, **kwargs):
            self.assertItemsEqual(self.candidates, kwargs['candidates'])
            # We are not interested in further processing, let us return
            # INVALID_CHASSIS to avoid erros
            return [ovn_const.OVN_GATEWAY_INVALID_CHASSIS]

        with mock.patch.object(ovn_client._ovn_scheduler, 'select',
                               side_effect=fake_select) as client_select,\
            mock.patch.object(self.l3_plugin.scheduler, 'select',
                              side_effect=fake_select) as plugin_select:
            self.candidates = [self.chassis1]
            gw_info = {'network_id': ext1['network']['id']}
            router1 = self._create_router('router1', gw_info=gw_info)

            # set redirect-chassis to neutron-ovn-invalid-chassis, so
            # that schedule_unhosted_gateways will try to schedule it
            self._set_redirect_chassis_to_invalid_chassis(ovn_client)
            self.l3_plugin.schedule_unhosted_gateways()

            self.candidates = [self.chassis1, self.chassis2]
            gw_info = {'network_id': ext2['network']['id']}
            self.l3_plugin.update_router(
                self.context, router1['id'],
                {'router': {l3_apidef.EXTERNAL_GW_INFO: gw_info}})
            self._set_redirect_chassis_to_invalid_chassis(ovn_client)
            self.l3_plugin.schedule_unhosted_gateways()

            self.candidates = []
            gw_info = {'network_id': ext3['network']['id']}
            self.l3_plugin.update_router(
                self.context, router1['id'],
                {'router': {l3_apidef.EXTERNAL_GW_INFO: gw_info}})
            self._set_redirect_chassis_to_invalid_chassis(ovn_client)
            self.l3_plugin.schedule_unhosted_gateways()

            # We can't test call_count for these mocks, as we have enabled
            # ovn_worker which will trigger chassis events and eventually
            # calling schedule_unhosted_gateways
            self.assertTrue(client_select.called)
            self.assertTrue(plugin_select.called)

    def test_router_gateway_port_binding_host_id(self):
        # Test setting chassis on chassisredirect port in Port_Binding table,
        # will update host_id of corresponding router gateway port
        # with this chassis.
        chassis = idlutils.row_by_value(self.sb_api.idl, 'Chassis',
                                        'name', self.chassis1)
        host_id = chassis.hostname
        ext = self._create_ext_network(
            'ext1', 'vlan', 'physnet1', 1, "10.0.0.1", "10.0.0.0/24")
        gw_info = {'network_id': ext['network']['id']}
        router = self._create_router('router1', gw_info=gw_info)
        core_plugin = directory.get_plugin()
        gw_port_id = router.get('gw_port_id')

        # Set chassis on chassisredirect port in Port_Binding table
        logical_port = 'cr-lrp-%s' % gw_port_id
        self.sb_api.lsp_bind(logical_port, self.chassis1,
                             may_exist=True).execute(check_error=True)

        def check_port_binding_host_id(port_id):
            port = core_plugin.get_ports(
                self.context, filters={'id': [port_id]})[0]
            return port[portbindings.HOST_ID] == host_id

        # Test if router gateway port updated with this chassis
        n_utils.wait_until_true(lambda: check_port_binding_host_id(
            gw_port_id))

    def _validate_router_ipv6_ra_configs(self, lrp_name, expected_ra_confs):
        lrp = idlutils.row_by_value(self.nb_api.idl,
                                    'Logical_Router_Port', 'name', lrp_name)
        self.assertEqual(expected_ra_confs, lrp.ipv6_ra_configs)

    def _test_router_port_ipv6_ra_configs_helper(
            self, cidr='aef0::/64', ip_version=6,
            address_mode=n_consts.IPV6_SLAAC,):
        router1 = self._create_router('router1')
        n1 = self._make_network(self.fmt, 'n1', True)
        if ip_version == 6:
            kwargs = {'ip_version': 6, 'cidr': 'aef0::/64',
                      'ipv6_address_mode': address_mode,
                      'ipv6_ra_mode': address_mode}
        else:
            kwargs = {'ip_version': 4, 'cidr': '10.0.0.0/24'}

        res = self._create_subnet(self.fmt, n1['network']['id'],
                                  **kwargs)

        n1_s1 = self.deserialize(self.fmt, res)
        n1_s1_id = n1_s1['subnet']['id']
        router_iface_info = self.l3_plugin.add_router_interface(
            self.context, router1['id'], {'subnet_id': n1_s1_id})

        lrp_name = ovn_utils.ovn_lrouter_port_name(
            router_iface_info['port_id'])
        if ip_version == 6:
            expected_ra_configs = {
                'address_mode': ovn_utils.get_ovn_ipv6_address_mode(
                    address_mode),
                'send_periodic': 'true',
                'mtu': '1450'}
        else:
            expected_ra_configs = {}
        self._validate_router_ipv6_ra_configs(lrp_name, expected_ra_configs)

    def test_router_port_ipv6_ra_configs_addr_mode_slaac(self):
        self._test_router_port_ipv6_ra_configs_helper()

    def test_router_port_ipv6_ra_configs_addr_mode_dhcpv6_stateful(self):
        self._test_router_port_ipv6_ra_configs_helper(
            address_mode=n_consts.DHCPV6_STATEFUL)

    def test_router_port_ipv6_ra_configs_addr_mode_dhcpv6_stateless(self):
        self._test_router_port_ipv6_ra_configs_helper(
            address_mode=n_consts.DHCPV6_STATELESS)

    def test_router_port_ipv6_ra_configs_ipv4(self):
        self._test_router_port_ipv6_ra_configs_helper(
            ip_version=4)

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

from neutron.agent.ovsdb.native import idlutils

from networking_ovn.common import constants as ovn_const
from networking_ovn.ovsdb import commands
from networking_ovn.tests import base
from networking_ovn.tests.unit import fakes


class TestBaseCommandHelpers(base.TestCase):
    def setUp(self):
        super(TestBaseCommandHelpers, self).setUp()
        self.column = 'ovn'
        self.new_value = '1'
        self.old_value = '2'

    def _get_fake_row_mutate(self):
        return fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={self.column: []},
            methods={'addvalue': None, 'delvalue': None})

    def _get_fake_row_no_mutate(self, column_value=None):
        column_value = column_value or []
        return fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={self.column: column_value})

    def test__addvalue_to_list_mutate(self):
        fake_row_mutate = self._get_fake_row_mutate()
        commands._addvalue_to_list(
            fake_row_mutate, self.column, self.new_value)
        fake_row_mutate.addvalue.assert_called_once_with(
            self.column, self.new_value)
        fake_row_mutate.verify.assert_not_called()

    def _test__addvalue_to_list_no_mutate(self, fake_row):
        commands._addvalue_to_list(fake_row, self.column, self.new_value)
        fake_row.verify.assert_called_once_with(self.column)
        self.assertEqual([self.new_value], fake_row.ovn)

    def test__addvalue_to_list_new_no_mutate(self):
        fake_row_new = self._get_fake_row_no_mutate()
        self._test__addvalue_to_list_no_mutate(fake_row_new)

    def test__addvalue_to_list_exists_no_mutate(self):
        fake_row_exists = self._get_fake_row_no_mutate(
            column_value=[self.new_value])
        self._test__addvalue_to_list_no_mutate(fake_row_exists)

    def test__delvalue_from_list_mutate(self):
        fake_row_mutate = self._get_fake_row_mutate()
        commands._delvalue_from_list(
            fake_row_mutate, self.column, self.old_value)
        fake_row_mutate.delvalue.assert_called_once_with(
            self.column, self.old_value)
        fake_row_mutate.verify.assert_not_called()

    def _test__delvalue_from_list_no_mutate(self, fake_row):
        commands._delvalue_from_list(fake_row, self.column, self.old_value)
        fake_row.verify.assert_called_once_with(self.column)
        self.assertEqual([], fake_row.ovn)

    def test__delvalue_from_list_new_no_mutate(self):
        fake_row_new = self._get_fake_row_no_mutate()
        self._test__delvalue_from_list_no_mutate(fake_row_new)

    def test__delvalue_from_list_exists_no_mutate(self):
        fake_row_exists = self._get_fake_row_no_mutate(
            column_value=[self.old_value])
        self._test__delvalue_from_list_no_mutate(fake_row_exists)

    def test__updatevalues_in_list_empty_mutate(self):
        fake_row_mutate = self._get_fake_row_mutate()
        commands._updatevalues_in_list(fake_row_mutate, self.column, [], [])
        fake_row_mutate.addvalue.assert_not_called()
        fake_row_mutate.delvalue.assert_not_called()
        fake_row_mutate.verify.assert_not_called()

    def test__updatevalues_in_list_mutate(self):
        fake_row_mutate = self._get_fake_row_mutate()
        commands._updatevalues_in_list(
            fake_row_mutate, self.column,
            new_values=[self.new_value],
            old_values=[self.old_value])
        fake_row_mutate.addvalue.assert_called_once_with(
            self.column, self.new_value)
        fake_row_mutate.delvalue.assert_called_once_with(
            self.column, self.old_value)
        fake_row_mutate.verify.assert_not_called()

    def test__updatevalues_in_list_empty_no_mutate(self):
        fake_row_no_mutate = self._get_fake_row_no_mutate()
        commands._updatevalues_in_list(fake_row_no_mutate, self.column, [], [])
        fake_row_no_mutate.verify.assert_called_once_with(self.column)
        self.assertEqual([], fake_row_no_mutate.ovn)

    def _test__updatevalues_in_list_no_mutate(self, fake_row):
        commands._updatevalues_in_list(
            fake_row, self.column,
            new_values=[self.new_value],
            old_values=[self.old_value])
        fake_row.verify.assert_called_once_with(self.column)
        self.assertEqual([self.new_value], fake_row.ovn)

    def test__updatevalues_in_list_new_no_mutate(self):
        fake_row_new = self._get_fake_row_no_mutate()
        self._test__updatevalues_in_list_no_mutate(fake_row_new)

    def test__updatevalues_in_list_exists_no_mutate(self):
        fake_row_exists = self._get_fake_row_no_mutate(
            column_value=[self.old_value, self.new_value])
        self._test__updatevalues_in_list_no_mutate(fake_row_exists)


class TestBaseCommand(base.TestCase):
    def setUp(self):
        super(TestBaseCommand, self).setUp()
        self.ovn_api = fakes.FakeOvsdbNbOvnIdl()
        self.transaction = fakes.FakeOvsdbTransaction()
        self.ovn_api.transaction = self.transaction


class TestAddLSwitchCommand(TestBaseCommand):

    def test_lswitch_exists(self):
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=mock.ANY):
            cmd = commands.AddLSwitchCommand(
                self.ovn_api, 'fake-lswitch', may_exist=True, foo='bar')
            cmd.run_idl(self.transaction)
            self.transaction.insert.assert_not_called()

    def _test_lswitch_add(self, may_exist=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=None):
            fake_lswitch = fakes.FakeOvsdbRow.create_one_ovsdb_row()
            self.transaction.insert.return_value = fake_lswitch
            cmd = commands.AddLSwitchCommand(
                self.ovn_api, 'fake-lswitch', may_exist=may_exist, foo='bar')
            cmd.run_idl(self.transaction)
            self.transaction.insert.assert_called_once_with(
                self.ovn_api.lswitch_table)
            self.assertEqual('fake-lswitch', fake_lswitch.name)
            self.assertEqual('bar', fake_lswitch.foo)

    def test_lswitch_add_may_exist(self):
        self._test_lswitch_add(may_exist=True)

    def test_lswitch_add_ignore_exists(self):
        self._test_lswitch_add(may_exist=False)


class TestDelLSwitchCommand(TestBaseCommand):

    def _test_lswitch_del_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.DelLSwitchCommand(
                self.ovn_api, 'fake-lswitch', if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_lswitch_no_exist_ignore(self):
        self._test_lswitch_del_no_exist(if_exists=True)

    def test_lswitch_no_exist_fail(self):
        self._test_lswitch_del_no_exist(if_exists=False)

    def test_lswitch_del(self):
        fake_lswitch = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        self.ovn_api.lswitch_table.rows[fake_lswitch.uuid] = fake_lswitch
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lswitch):
            cmd = commands.DelLSwitchCommand(
                self.ovn_api, fake_lswitch.name, if_exists=True)
            cmd.run_idl(self.transaction)
            fake_lswitch.delete.assert_called_once_with()


class TestLSwitchSetExternalIdCommand(TestBaseCommand):

    def _test_lswitch_extid_update_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.LSwitchSetExternalIdCommand(
                self.ovn_api, 'fake-lswitch',
                ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY, 'neutron-network',
                if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_lswitch_no_exist_ignore(self):
        self._test_lswitch_extid_update_no_exist(if_exists=True)

    def test_lswitch_no_exist_fail(self):
        self._test_lswitch_extid_update_no_exist(if_exists=False)

    def test_lswitch_extid_update(self):
        network_name = 'private'
        new_network_name = 'private-new'
        ext_ids = {ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: network_name}
        new_ext_ids = {ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: new_network_name}
        fake_lswitch = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': ext_ids})
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lswitch):
            cmd = commands.LSwitchSetExternalIdCommand(
                self.ovn_api, fake_lswitch.name,
                ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY,
                new_network_name,
                if_exists=True)
            cmd.run_idl(self.transaction)
            self.assertEqual(new_ext_ids, fake_lswitch.external_ids)


class TestAddLSwitchPortCommand(TestBaseCommand):
    def setUp(self):
        super(TestAddLSwitchPortCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestSetLSwitchPortCommand(TestBaseCommand):

    def _test_lswitch_port_update_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.SetLSwitchPortCommand(
                self.ovn_api, 'fake-lsp', if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_lswitch_port_no_exist_ignore(self):
        self._test_lswitch_port_update_no_exist(if_exists=True)

    def test_lswitch_port_no_exist_fail(self):
        self._test_lswitch_port_update_no_exist(if_exists=False)

    def test_lswitch_port_update(self):
        ext_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: 'test'}
        new_ext_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: 'test-new'}
        fake_lsp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': ext_ids})
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lsp):
            cmd = commands.SetLSwitchPortCommand(
                self.ovn_api, fake_lsp.name, if_exists=True,
                external_ids=new_ext_ids)
            cmd.run_idl(self.transaction)
            self.assertEqual(new_ext_ids, fake_lsp.external_ids)

    def test_lswitch_port_update_del_dhcp(self):
        ext_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: 'test'}
        new_ext_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: 'test-new'}
        fake_dhcp_options = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': {'port_id': 'fake-lsp'}})
        self.ovn_api.dhcp_options_table.rows[fake_dhcp_options.uuid] = \
            fake_dhcp_options
        fake_lsp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'fake-lsp',
                   'external_ids': ext_ids,
                   'dhcpv4_options': [fake_dhcp_options]})
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lsp):
            cmd = commands.SetLSwitchPortCommand(
                self.ovn_api, fake_lsp.name, if_exists=True,
                external_ids=new_ext_ids)
            cmd.run_idl(self.transaction)
            self.assertEqual(new_ext_ids, fake_lsp.external_ids)
            fake_dhcp_options.delete.assert_called_once_with()


class TestDelLSwitchPortCommand(TestBaseCommand):
    def setUp(self):
        super(TestDelLSwitchPortCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestAddLRouterCommand(TestBaseCommand):
    def setUp(self):
        super(TestAddLRouterCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestUpdateLRouterCommand(TestBaseCommand):

    def _test_lrouter_update_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.UpdateLRouterCommand(
                self.ovn_api, 'fake-lrouter', if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_lrouter_no_exist_ignore(self):
        self._test_lrouter_update_no_exist(if_exists=True)

    def test_lrouter_no_exist_fail(self):
        self._test_lrouter_update_no_exist(if_exists=False)

    def test_lrouter_update(self):
        ext_ids = {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'richard'}
        new_ext_ids = {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: 'richard-new'}
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': ext_ids})
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lrouter):
            cmd = commands.UpdateLRouterCommand(
                self.ovn_api, fake_lrouter.name, if_exists=True,
                external_ids=new_ext_ids)
            cmd.run_idl(self.transaction)
            self.assertEqual(new_ext_ids, fake_lrouter.external_ids)


class TestDelLRouterCommand(TestBaseCommand):
    def setUp(self):
        super(TestDelLRouterCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestAddLRouterPortCommand(TestBaseCommand):
    def setUp(self):
        super(TestAddLRouterPortCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestUpdateLRouterPortCommand(TestBaseCommand):

    def _test_lrouter_port_update_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.UpdateLRouterPortCommand(
                self.ovn_api, 'fake-lrp', 'fake-lrouter', if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_lrouter_port_no_exist_ignore(self):
        self._test_lrouter_port_update_no_exist(if_exists=True)

    def test_lrouter_port_no_exist_fail(self):
        self._test_lrouter_port_update_no_exist(if_exists=False)

    def test_lrouter_port_update(self):
        old_networks = []
        new_networks = ['10.1.0.0/24']
        fake_lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'networks': old_networks})
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lrp):
            cmd = commands.UpdateLRouterPortCommand(
                self.ovn_api, fake_lrp.name, 'fake-lrouter', if_exists=True,
                networks=new_networks)
            cmd.run_idl(self.transaction)
            self.assertEqual(new_networks, fake_lrp.networks)


class TestDelLRouterPortCommand(TestBaseCommand):
    def setUp(self):
        super(TestDelLRouterPortCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestSetLRouterPortInLSwitchPortCommand(TestBaseCommand):

    def test_lswitch_port_no_exist_fail(self):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.SetLRouterPortInLSwitchPortCommand(
                self.ovn_api, 'fake-lsp', 'fake-lrp')
            self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_lswitch_port_router_update(self):
        lrp_name = 'fake-lrp'
        fake_lsp = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lsp):
            cmd = commands.SetLRouterPortInLSwitchPortCommand(
                self.ovn_api, fake_lsp.name, lrp_name)
            cmd.run_idl(self.transaction)
            self.assertEqual({'router-port': lrp_name}, fake_lsp.options)
            self.assertEqual('router', fake_lsp.type)


class TestAddACLCommand(TestBaseCommand):
    def setUp(self):
        super(TestAddACLCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestDelACLCommand(TestBaseCommand):
    def setUp(self):
        super(TestDelACLCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestUpdateACLsCommand(TestBaseCommand):
    def setUp(self):
        super(TestUpdateACLsCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestAddStaticRouteCommand(TestBaseCommand):

    def test_lrouter_not_found(self):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.AddStaticRouteCommand(self.ovn_api, 'fake-lrouter')
            self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)
            self.transaction.insert.assert_not_called()

    def test_static_route_add(self):
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lrouter):
            fake_static_route = fakes.FakeOvsdbRow.create_one_ovsdb_row()
            self.transaction.insert.return_value = fake_static_route
            cmd = commands.AddStaticRouteCommand(
                self.ovn_api, fake_lrouter.name,
                nexthop='40.0.0.100',
                ip_prefix='30.0.0.0/24')
            cmd.run_idl(self.transaction)
            self.transaction.insert.assert_called_once_with(
                self.ovn_api.lrouter_static_route_table)
            self.assertEqual('40.0.0.100', fake_static_route.nexthop)
            self.assertEqual('30.0.0.0/24', fake_static_route.ip_prefix)
            fake_lrouter.verify.assert_called_once_with('static_routes')
            self.assertEqual([fake_static_route.uuid],
                             fake_lrouter.static_routes)


class TestDelStaticRouteCommand(TestBaseCommand):

    def _test_lrouter_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.DelStaticRouteCommand(
                self.ovn_api, 'fake-lrouter',
                '30.0.0.0/24', '40.0.0.100',
                if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_lrouter_no_exist_ignore(self):
        self._test_lrouter_no_exist(if_exists=True)

    def test_lrouter_no_exist_fail(self):
        self._test_lrouter_no_exist(if_exists=False)

    def test_static_route_del(self):
        fake_static_route = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip_prefix': '50.0.0.0/24', 'nexthop': '40.0.0.101'})
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'static_routes': [fake_static_route]})
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lrouter):
            cmd = commands.DelStaticRouteCommand(
                self.ovn_api, fake_lrouter.name,
                fake_static_route.ip_prefix, fake_static_route.nexthop,
                if_exists=True)
            cmd.run_idl(self.transaction)
            fake_lrouter.verify.assert_called_once_with('static_routes')
            self.assertEqual([], fake_lrouter.static_routes)

    def test_static_route_del_not_found(self):
        fake_static_route1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip_prefix': '50.0.0.0/24', 'nexthop': '40.0.0.101'})
        fake_static_route2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip_prefix': '60.0.0.0/24', 'nexthop': '70.0.0.101'})
        fake_lrouter = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'static_routes': [fake_static_route2]})
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_lrouter):
            cmd = commands.DelStaticRouteCommand(
                self.ovn_api, fake_lrouter.name,
                fake_static_route1.ip_prefix, fake_static_route1.nexthop,
                if_exists=True)
            cmd.run_idl(self.transaction)
            fake_lrouter.verify.assert_not_called()
            self.assertEqual([mock.ANY], fake_lrouter.static_routes)


class TestAddAddrSetCommand(TestBaseCommand):
    def setUp(self):
        super(TestAddAddrSetCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestDelAddrSetCommand(TestBaseCommand):
    def setUp(self):
        super(TestDelAddrSetCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestUpdateAddrSetCommand(TestBaseCommand):

    def _test_addrset_update_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.UpdateAddrSetCommand(
                self.ovn_api, 'fake-addrset',
                addrs_add=[], addrs_remove=[],
                if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_addrset_no_exist_ignore(self):
        self._test_addrset_update_no_exist(if_exists=True)

    def test_addrset_no_exist_fail(self):
        self._test_addrset_update_no_exist(if_exists=False)

    def _test_addrset_update(self, addrs_add=None, addrs_del=None):
        save_address = '10.0.0.1'
        initial_addresses = [save_address]
        final_addresses = [save_address]
        if addrs_add:
            for addr_add in addrs_add:
                final_addresses.append(addr_add)
        if addrs_del:
            for addr_del in addrs_del:
                initial_addresses.append(addr_del)
        fake_addrset = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'addresses': initial_addresses})
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_addrset):
            cmd = commands.UpdateAddrSetCommand(
                self.ovn_api, fake_addrset.name,
                addrs_add=addrs_add, addrs_remove=addrs_del,
                if_exists=True)
            cmd.run_idl(self.transaction)
            fake_addrset.verify.assert_called_once_with('addresses')
            self.assertEqual(final_addresses, fake_addrset.addresses)

    def test_addrset_update_add(self):
        self._test_addrset_update(addrs_add=['10.0.0.4'])

    def test_addrset_update_del(self):
        self._test_addrset_update(addrs_del=['10.0.0.2'])


class TestUpdateAddrSetExtIdsCommand(TestBaseCommand):
    def setUp(self):
        super(TestUpdateAddrSetExtIdsCommand, self).setUp()
        self.ext_ids = {ovn_const.OVN_SG_NAME_EXT_ID_KEY: 'default'}

    def _test_addrset_extids_update_no_exist(self, if_exists=True):
        with mock.patch.object(idlutils, 'row_by_value',
                               side_effect=idlutils.RowNotFound):
            cmd = commands.UpdateAddrSetExtIdsCommand(
                self.ovn_api, 'fake-addrset', self.ext_ids,
                if_exists=if_exists)
            if if_exists:
                cmd.run_idl(self.transaction)
            else:
                self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_addrset_no_exist_ignore(self):
        self._test_addrset_extids_update_no_exist(if_exists=True)

    def test_addrset_no_exist_fail(self):
        self._test_addrset_extids_update_no_exist(if_exists=False)

    def test_addrset_extids_update(self):
        new_ext_ids = {ovn_const.OVN_SG_NAME_EXT_ID_KEY: 'default-new'}
        fake_addrset = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': self.ext_ids})
        with mock.patch.object(idlutils, 'row_by_value',
                               return_value=fake_addrset):
            cmd = commands.UpdateAddrSetExtIdsCommand(
                self.ovn_api, fake_addrset.name,
                new_ext_ids, if_exists=True)
            cmd.run_idl(self.transaction)
            self.assertEqual(new_ext_ids, fake_addrset.external_ids)


class TestAddDHCPOptionsCommand(TestBaseCommand):

    def test_dhcp_options_exists(self):
        fake_ext_ids = {'subnet_id': 'fake-subnet-id',
                        'port_id': 'fake-port-id'}
        fake_dhcp_options = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': fake_ext_ids})
        self.ovn_api.dhcp_options_table.rows[fake_dhcp_options.uuid] = \
            fake_dhcp_options
        cmd = commands.AddDHCPOptionsCommand(
            self.ovn_api, fake_ext_ids['subnet_id'], fake_ext_ids['port_id'],
            may_exist=True, external_ids=fake_ext_ids)
        cmd.run_idl(self.transaction)
        self.transaction.insert.assert_not_called()
        self.assertEqual(fake_ext_ids, fake_dhcp_options.external_ids)

    def _test_dhcp_options_add(self, may_exist=True):
        fake_ext_ids = {'subnet_id': 'fake-subnet-id-' + str(may_exist)}
        fake_dhcp_options = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': fake_ext_ids})
        self.transaction.insert.return_value = fake_dhcp_options
        cmd = commands.AddDHCPOptionsCommand(
            self.ovn_api, fake_ext_ids['subnet_id'], may_exist=may_exist,
            external_ids=fake_ext_ids)
        cmd.run_idl(self.transaction)
        self.transaction.insert.assert_called_once_with(
            self.ovn_api.dhcp_options_table)
        self.assertEqual(fake_ext_ids, fake_dhcp_options.external_ids)

    def test_dhcp_options_add_may_exist(self):
        self._test_dhcp_options_add(may_exist=True)

    def test_dhcp_options_add_ignore_exists(self):
        self._test_dhcp_options_add(may_exist=False)


class TestDelDHCPOptionsCommand(TestBaseCommand):

    def _test_dhcp_options_del_no_exist(self, if_exists=True):
        cmd = commands.DelDHCPOptionsCommand(
            self.ovn_api, 'fake-dhcp-options', if_exists=if_exists)
        if if_exists:
            cmd.run_idl(self.transaction)
        else:
            self.assertRaises(RuntimeError, cmd.run_idl, self.transaction)

    def test_dhcp_options_no_exist_ignore(self):
        self._test_dhcp_options_del_no_exist(if_exists=True)

    def test_dhcp_options_no_exist_fail(self):
        self._test_dhcp_options_del_no_exist(if_exists=False)

    def test_dhcp_options_del(self):
        fake_dhcp_options = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': {'subnet_id': 'fake-subnet-id'}})
        self.ovn_api.dhcp_options_table.rows[fake_dhcp_options.uuid] = \
            fake_dhcp_options
        cmd = commands.DelDHCPOptionsCommand(
            self.ovn_api, fake_dhcp_options.uuid, if_exists=True)
        cmd.run_idl(self.transaction)
        fake_dhcp_options.delete.assert_called_once_with()

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

from networking_ovn.ovsdb import commands
from networking_ovn.tests import base
from networking_ovn.tests.unit import fakes


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
    def setUp(self):
        super(TestLSwitchSetExternalIdCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestAddLSwitchPortCommand(TestBaseCommand):
    def setUp(self):
        super(TestAddLSwitchPortCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestSetLSwitchPortCommand(TestBaseCommand):
    def setUp(self):
        super(TestSetLSwitchPortCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestDelLSwitchPortCommand(TestBaseCommand):
    def setUp(self):
        super(TestDelLSwitchPortCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestAddLRouterCommand(TestBaseCommand):
    def setUp(self):
        super(TestAddLRouterCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestUpdateLRouterCommand(TestBaseCommand):
    def setUp(self):
        super(TestUpdateLRouterCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestDelLRouterCommand(TestBaseCommand):
    def setUp(self):
        super(TestDelLRouterCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestAddLRouterPortCommand(TestBaseCommand):
    def setUp(self):
        super(TestAddLRouterPortCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestUpdateLRouterPortCommand(TestBaseCommand):
    def setUp(self):
        super(TestUpdateLRouterPortCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestDelLRouterPortCommand(TestBaseCommand):
    def setUp(self):
        super(TestDelLRouterPortCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestSetLRouterPortInLSwitchPortCommand(TestBaseCommand):
    def setUp(self):
        super(TestSetLRouterPortInLSwitchPortCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


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
    def setUp(self):
        super(TestAddStaticRouteCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestDelStaticRouteCommand(TestBaseCommand):
    def setUp(self):
        super(TestDelStaticRouteCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestAddAddrSetCommand(TestBaseCommand):
    def setUp(self):
        super(TestAddAddrSetCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestDelAddrSetCommand(TestBaseCommand):
    def setUp(self):
        super(TestDelAddrSetCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestUpdateAddrSetCommand(TestBaseCommand):
    def setUp(self):
        super(TestUpdateAddrSetCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


class TestUpdateAddrSetExtIdsCommand(TestBaseCommand):
    def setUp(self):
        super(TestUpdateAddrSetExtIdsCommand, self).setUp()

    # TODO(rtheis): Add unit tests.


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

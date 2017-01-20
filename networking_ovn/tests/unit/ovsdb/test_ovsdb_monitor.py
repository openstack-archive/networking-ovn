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

import copy
import mock
import time

from oslo_utils import uuidutils

from neutron_lib import constants
from neutron_lib.plugins import directory
from ovs.db import idl as ovs_idl
from ovs import poller

from networking_ovn.common import config as ovn_config
from networking_ovn.ovsdb import ovsdb_monitor
from networking_ovn.tests import base
from networking_ovn.tests.unit.ml2 import test_mech_driver
from neutron.agent.ovsdb.native import idlutils


OVN_NB_SCHEMA = {
    "name": "OVN_Northbound", "version": "3.0.0",
    "tables": {
        "Logical_Switch_Port": {
            "columns": {
                "name": {"type": "string"},
                "type": {"type": "string"},
                "addresses": {"type": {"key": "string",
                                       "min": 0,
                                       "max": "unlimited"}},
                "port_security": {"type": {"key": "string",
                                           "min": 0,
                                           "max": "unlimited"}},
                "up": {"type": {"key": "boolean", "min": 0, "max": 1}}},
            "indexes": [["name"]],
            "isRoot": False,
        },
        "Logical_Switch": {
            "columns": {"name": {"type": "string"}},
            "indexes": [["name"]],
            "isRoot": True,
        }
    }
}


OVN_SB_SCHEMA = {
    "name": "OVN_Southbound", "version": "1.3.0",
    "tables": {
        "Chassis": {
            "columns": {
                "name": {"type": "string"},
                "hostname": {"type": "string"},
                "external_ids": {
                    "type": {"key": "string", "value": "string",
                             "min": 0, "max": "unlimited"}}},
            "isRoot": True,
            "indexes": [["name"]]
        }
    }
}


class TestOvnNbIdlNotifyHandler(test_mech_driver.OVNMechanismDriverTestCase):

    def setUp(self):
        super(TestOvnNbIdlNotifyHandler, self).setUp()
        helper = ovs_idl.SchemaHelper(schema_json=OVN_NB_SCHEMA)
        helper.register_all()
        self.idl = ovsdb_monitor.OvnNbIdl(self.driver, "remote", helper)
        self.idl.lock_name = self.idl.event_lock_name
        self.idl.has_lock = True
        self.lp_table = self.idl.tables.get('Logical_Switch_Port')
        self.driver.set_port_status_up = mock.Mock()
        self.driver.set_port_status_down = mock.Mock()

    def _test_lsp_helper(self, event, new_row_json, old_row_json=None,
                         table=None):
        row_uuid = uuidutils.generate_uuid()
        if not table:
            table = self.lp_table
        lp_row = ovs_idl.Row.from_json(self.idl, table,
                                       row_uuid, new_row_json)
        if old_row_json:
            old_row = ovs_idl.Row.from_json(self.idl, table,
                                            row_uuid, old_row_json)
        else:
            old_row = None
        self.idl.notify(event, lp_row, updates=old_row)
        # sleep for a second so that the notify handler green thread
        # handles the notify event
        time.sleep(1)

    def test_lsp_up_create_event(self):
        row_data = {"up": True, "name": "foo-name"}
        self._test_lsp_helper('create', row_data)
        self.driver.set_port_status_up.assert_called_once_with("foo-name")
        self.assertFalse(self.driver.set_port_status_down.called)

    def test_lsp_down_create_event(self):
        row_data = {"up": False, "name": "foo-name"}
        self._test_lsp_helper('create', row_data)
        self.driver.set_port_status_down.assert_called_once_with("foo-name")
        self.assertFalse(self.driver.set_port_status_up.called)

    def test_lsp_up_not_set_event(self):
        row_data = {"up": ['set', []], "name": "foo-name"}
        self._test_lsp_helper('create', row_data)
        self.assertFalse(self.driver.set_port_status_up.called)
        self.assertFalse(self.driver.set_port_status_down.called)

    def test_unwatch_logical_switch_port_create_events(self):
        self.idl.unwatch_logical_switch_port_create_events()
        row_data = {"up": True, "name": "foo-name"}
        self._test_lsp_helper('create', row_data)
        self.assertFalse(self.driver.set_port_status_up.called)
        self.assertFalse(self.driver.set_port_status_down.called)

        row_data["up"] = False
        self._test_lsp_helper('create', row_data)
        self.assertFalse(self.driver.set_port_status_up.called)
        self.assertFalse(self.driver.set_port_status_down.called)

    def test_post_initialize(self):
        self.idl.post_initialize(self.driver)
        self.assertIsNone(self.idl._lsp_create_up_event)
        self.assertIsNone(self.idl._lsp_create_down_event)

    def test_lsp_up_update_event(self):
        new_row_json = {"up": True, "name": "foo-name"}
        old_row_json = {"up": False}
        self._test_lsp_helper('update', new_row_json,
                              old_row_json=old_row_json)
        self.driver.set_port_status_up.assert_called_once_with("foo-name")
        self.assertFalse(self.driver.set_port_status_down.called)

    def test_lsp_down_update_event(self):
        new_row_json = {"up": False, "name": "foo-name"}
        old_row_json = {"up": True}
        self._test_lsp_helper('update', new_row_json,
                              old_row_json=old_row_json)
        self.driver.set_port_status_down.assert_called_once_with("foo-name")
        self.assertFalse(self.driver.set_port_status_up.called)

    def test_lsp_up_update_event_no_old_data(self):
        new_row_json = {"up": True, "name": "foo-name"}
        self._test_lsp_helper('update', new_row_json,
                              old_row_json=None)
        self.assertFalse(self.driver.set_port_status_up.called)
        self.assertFalse(self.driver.set_port_status_down.called)

    def test_lsp_down_update_event_no_old_data(self):
        new_row_json = {"up": False, "name": "foo-name"}
        self._test_lsp_helper('update', new_row_json,
                              old_row_json=None)
        self.assertFalse(self.driver.set_port_status_up.called)
        self.assertFalse(self.driver.set_port_status_down.called)

    def test_lsp_other_column_update_event(self):
        new_row_json = {"up": False, "name": "foo-name",
                        "addresses": ["10.0.0.2"]}
        old_row_json = {"addresses": ["10.0.0.3"]}
        self._test_lsp_helper('update', new_row_json,
                              old_row_json=old_row_json)
        self.assertFalse(self.driver.set_port_status_up.called)
        self.assertFalse(self.driver.set_port_status_down.called)

    def test_notify_other_table(self):
        new_row_json = {"name": "foo-name"}
        self._test_lsp_helper('create', new_row_json,
                              table=self.idl.tables.get("Logical_Switch"))
        self.assertFalse(self.driver.set_port_status_up.called)
        self.assertFalse(self.driver.set_port_status_down.called)

    def test_notify_no_ovsdb_lock(self):
        self.idl.has_lock = False
        self.idl.is_lock_contended = True
        self.idl.notify_handler.notify = mock.Mock()
        self.idl.notify("create", mock.ANY)
        self.assertFalse(self.idl.notify_handler.notify.called)

    def test_notify_ovsdb_lock_not_yet_contended(self):
        self.idl.has_lock = False
        self.idl.is_lock_contended = False
        self.idl.notify_handler.notify = mock.Mock()
        self.idl.notify("create", mock.ANY)
        self.assertTrue(self.idl.notify_handler.notify.called)


class TestOvnSbIdlNotifyHandler(test_mech_driver.OVNMechanismDriverTestCase):

    l3_plugin = 'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin'

    def setUp(self):
        super(TestOvnSbIdlNotifyHandler, self).setUp()
        sb_helper = ovs_idl.SchemaHelper(schema_json=OVN_SB_SCHEMA)
        sb_helper.register_table('Chassis')
        self.sb_idl = ovsdb_monitor.OvnSbIdl(self.driver, "remote", sb_helper)
        self.sb_idl.lock_name = self.sb_idl.event_lock_name
        self.sb_idl.has_lock = True
        self.sb_idl.post_initialize(self.driver)
        self.chassis_table = self.sb_idl.tables.get('Chassis')
        self.driver.update_segment_host_mapping = mock.Mock()
        self.l3_plugin = directory.get_plugin(constants.L3)
        if ovn_config.is_ovn_l3():
            self.l3_plugin.schedule_unhosted_routers = mock.Mock()

        self.row_json = {
            "name": "fake-name",
            "hostname": "fake-hostname",
            "external_ids": ['map', [["ovn-bridge-mappings",
                                      "fake-phynet1:fake-br1"]]]
        }

    def _test_chassis_helper(self, event, new_row_json, old_row_json=None):
        row_uuid = uuidutils.generate_uuid()
        table = self.chassis_table
        row = ovs_idl.Row.from_json(self.sb_idl, table, row_uuid, new_row_json)
        if old_row_json:
            old_row = ovs_idl.Row.from_json(self.sb_idl, table,
                                            row_uuid, old_row_json)
        else:
            old_row = None
        self.sb_idl.notify(event, row, updates=old_row)
        # sleep for a second so that the notify handler green thread
        # handles the notify event
        time.sleep(1)

    def test_chassis_create_event(self):
        self._test_chassis_helper('create', self.row_json)
        self.driver.update_segment_host_mapping.assert_called_once_with(
            'fake-hostname', ['fake-phynet1'])
        if ovn_config.is_ovn_l3():
            self.assertEqual(
                1,
                self.l3_plugin.schedule_unhosted_routers.call_count)

    def test_chassis_delete_event(self):
        self._test_chassis_helper('delete', self.row_json)
        self.driver.update_segment_host_mapping.assert_called_once_with(
            'fake-hostname', [])
        if ovn_config.is_ovn_l3():
            self.assertEqual(
                1,
                self.l3_plugin.schedule_unhosted_routers.call_count)

    def test_chassis_update_event(self):
        old_row_json = copy.deepcopy(self.row_json)
        old_row_json['external_ids'][1][0][1] = (
            "fake-phynet2:fake-br2")
        self._test_chassis_helper('update', self.row_json, old_row_json)
        self.driver.update_segment_host_mapping.assert_called_once_with(
            'fake-hostname', ['fake-phynet1'])
        if ovn_config.is_ovn_l3():
            self.assertEqual(
                1,
                self.l3_plugin.schedule_unhosted_routers.call_count)


class TestOvnDbNotifyHandler(base.TestCase):

    def setUp(self):
        super(TestOvnDbNotifyHandler, self).setUp()
        self.handler = ovsdb_monitor.OvnDbNotifyHandler(mock.ANY)
        self.watched_events = self.handler._OvnDbNotifyHandler__watched_events

    def test_watch_and_unwatch_events(self):
        expected_events = set()
        networking_event = mock.Mock()
        ovn_event = mock.Mock()
        unknown_event = mock.Mock()

        self.assertItemsEqual(set(), self.watched_events)

        expected_events.add(networking_event)
        self.handler.watch_event(networking_event)
        self.assertItemsEqual(expected_events, self.watched_events)

        expected_events.add(ovn_event)
        self.handler.watch_events([ovn_event])
        self.assertItemsEqual(expected_events, self.watched_events)

        self.handler.unwatch_events([networking_event, ovn_event])
        self.handler.unwatch_event(unknown_event)
        self.handler.unwatch_events([unknown_event])
        self.assertItemsEqual(set(), self.watched_events)

    def test_shutdown(self):
        self.handler.shutdown()


class TestOvnBaseConnection(base.TestCase):

    def setUp(self):
        super(TestOvnBaseConnection, self).setUp()

    @mock.patch.object(idlutils, 'get_schema_helper')
    def test_get_schema_helper_success(self, mock_gsh):
        mock_gsh_helper = mock.Mock()
        mock_gsh.side_effect = [mock_gsh_helper]
        ovn_base_connection = ovsdb_monitor.OvnBaseConnection(
            mock.Mock(), mock.Mock(), mock.Mock())
        helper = ovn_base_connection.get_schema_helper()
        mock_gsh.assert_called_once_with(ovn_base_connection.connection,
                                         ovn_base_connection.schema_name)
        self.assertEqual(mock_gsh_helper, helper)

    @mock.patch.object(idlutils, 'get_schema_helper')
    def test_get_schema_helper_initial_exception(self, mock_gsh):
        mock_gsh_helper = mock.Mock()
        mock_gsh.side_effect = [Exception, mock_gsh_helper]
        ovn_base_connection = ovsdb_monitor.OvnBaseConnection(
            mock.Mock(), mock.Mock(), mock.Mock())
        helper = ovn_base_connection.get_schema_helper()
        gsh_call = mock.call(ovn_base_connection.connection,
                             ovn_base_connection.schema_name)
        mock_gsh.assert_has_calls([gsh_call, gsh_call])
        self.assertEqual(mock_gsh_helper, helper)

    @mock.patch.object(idlutils, 'get_schema_helper')
    def test_get_schema_helper_all_exception(self, mock_gsh):
        mock_gsh.side_effect = RuntimeError
        ovn_base_connection = ovsdb_monitor.OvnBaseConnection(
            mock.Mock(), mock.Mock(), mock.Mock())
        self.assertRaises(RuntimeError, ovn_base_connection.get_schema_helper)


class TestOvnConnection(base.TestCase):

    def setUp(self):
        super(TestOvnConnection, self).setUp()

    @mock.patch.object(ovsdb_monitor, 'OvnSbIdl')
    @mock.patch.object(ovsdb_monitor, 'OvnNbIdl')
    @mock.patch.object(idlutils, 'get_schema_helper')
    @mock.patch.object(idlutils, 'wait_for_change')
    def _test_connection_start(self, mock_wfc, mock_gsh,
                               mock_nb_idl, mock_sb_idl,
                               schema=None, table_name=None):
        mock_helper = mock.Mock()
        mock_gsh.side_effect = [Exception, mock_helper]
        self.ovn_connection = ovsdb_monitor.OvnConnection(
            mock.Mock(), mock.Mock(), schema)
        with mock.patch.object(poller, 'Poller'), \
            mock.patch('threading.Thread'):
            if table_name:
                table_name_list = [table_name]
            else:
                table_name_list = None
            self.ovn_connection.start(
                mock.Mock(), table_name_list=table_name_list)
            # A second start attempt shouldn't re-register.
            self.ovn_connection.start(
                mock.Mock(), table_name_list=table_name_list)

        if table_name:
            mock_helper.register_table.assert_called_once_with(table_name)
        else:
            mock_helper.register_all.assert_called_once_with()

    def test_connection_nb_start(self):
        self._test_connection_start(
            schema='OVN_Northbound', table_name=None)

    def test_connection_sb_start(self):
        self._test_connection_start(
            schema='OVN_Southbound', table_name='Chassis')

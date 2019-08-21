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
import os

import mock
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from oslo_utils import uuidutils
from ovs.db import idl as ovs_idl
from ovs import poller
from ovs.stream import Stream
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import idlutils

from networking_ovn.common import config as ovn_config
from networking_ovn.ovsdb import ovsdb_monitor
from networking_ovn.tests import base
from networking_ovn.tests.unit import fakes
from networking_ovn.tests.unit.ml2 import test_mech_driver

basedir = os.path.dirname(os.path.abspath(__file__))
schema_files = {
    'OVN_Northbound': os.path.join(basedir, 'schemas', 'ovn-nb.ovsschema'),
    'OVN_Southbound': os.path.join(basedir, 'schemas', 'ovn-sb.ovsschema'),
}

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
        # Add a STOP EVENT to the queue
        self.idl.notify_handler.shutdown()
        # Execute the notifications queued
        self.idl.notify_handler.notify_loop()

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

    def test_post_connect(self):
        self.idl.post_connect()
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
        self.idl.is_lock_contended = True
        self.idl.notify_handler.notify = mock.Mock()
        self.idl.notify("create", mock.ANY)
        self.assertFalse(self.idl.notify_handler.notify.called)

    def test_notify_ovsdb_lock_not_yet_contended(self):
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
        self.sb_idl.post_connect()
        self.chassis_table = self.sb_idl.tables.get('Chassis')
        self.driver.update_segment_host_mapping = mock.Mock()
        self.l3_plugin = directory.get_plugin(constants.L3)
        self.l3_plugin.schedule_unhosted_gateways = mock.Mock()

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
        # Add a STOP EVENT to the queue
        self.sb_idl.notify_handler.shutdown()
        # Execute the notifications queued
        self.sb_idl.notify_handler.notify_loop()

    def test_chassis_create_event(self):
        self._test_chassis_helper('create', self.row_json)
        self.driver.update_segment_host_mapping.assert_called_once_with(
            'fake-hostname', ['fake-phynet1'])
        self.assertEqual(
            1,
            self.l3_plugin.schedule_unhosted_gateways.call_count)

    def test_chassis_delete_event(self):
        self._test_chassis_helper('delete', self.row_json)
        self.driver.update_segment_host_mapping.assert_called_once_with(
            'fake-hostname', [])
        self.assertEqual(
            1,
            self.l3_plugin.schedule_unhosted_gateways.call_count)

    def test_chassis_update_event(self):
        old_row_json = copy.deepcopy(self.row_json)
        old_row_json['external_ids'][1][0][1] = (
            "fake-phynet2:fake-br2")
        self._test_chassis_helper('update', self.row_json, old_row_json)
        self.driver.update_segment_host_mapping.assert_called_once_with(
            'fake-hostname', ['fake-phynet1'])
        self.assertEqual(
            1,
            self.l3_plugin.schedule_unhosted_gateways.call_count)


class TestOvnDbNotifyHandler(base.TestCase):

    def setUp(self):
        super(TestOvnDbNotifyHandler, self).setUp()
        self.handler = ovsdb_monitor.OvnDbNotifyHandler(mock.ANY)
        self.watched_events = self.handler._RowEventHandler__watched_events

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


# class TestOvnBaseConnection(base.TestCase):
#
# Each test is being deleted, but for reviewers sake I wanted to exaplain why:
#
#     @mock.patch.object(idlutils, 'get_schema_helper')
#     def testget_schema_helper_success(self, mock_gsh):
#
# 1. OvnBaseConnection and OvnConnection no longer exist
# 2. get_schema_helper is no longer a part of the Connection class
#
#     @mock.patch.object(idlutils, 'get_schema_helper')
#     def testget_schema_helper_initial_exception(self, mock_gsh):
#
#     @mock.patch.object(idlutils, 'get_schema_helper')
#     def testget_schema_helper_all_exception(self, mock_gsh):
#
# 3. The only reason get_schema_helper had a retry loop was for Neutron's
#    use case of trying to set the Manager to listen on ptcp:127.0.0.1:6640
#    if it wasn't already set up. Since that code being removed was the whole
#    reason to re-implement get_schema_helper here,the exception retry is not
#    needed and therefor is not a part of ovsdbapp's implementation of
#    idlutils.get_schema_helper which we now use directly in from_server()
# 4. These tests now would be testing the various from_server() calls, but
#    there is almost nothing to test in those except maybe SSL being set up
#    but that was done below.

class TestOvnConnection(base.TestCase):

    def setUp(self):
        super(TestOvnConnection, self).setUp()

    @mock.patch.object(idlutils, 'get_schema_helper')
    @mock.patch.object(idlutils, 'wait_for_change')
    def _test_connection_start(self, mock_wfc, mock_gsh,
                               idl_class, schema):
        mock_gsh.return_value = ovs_idl.SchemaHelper(
            location=schema_files[schema])
        _idl = idl_class.from_server('punix:/tmp/fake', schema, mock.Mock())
        self.ovn_connection = connection.Connection(_idl, mock.Mock())
        with mock.patch.object(poller, 'Poller'), \
            mock.patch('threading.Thread'):
            self.ovn_connection.start()
            # A second start attempt shouldn't re-register.
            self.ovn_connection.start()

        self.ovn_connection.thread.start.assert_called_once_with()

    def test_connection_nb_start(self):
        ovn_config.cfg.CONF.set_override('ovn_nb_private_key', 'foo-key',
                                         'ovn')
        Stream.ssl_set_private_key_file = mock.Mock()
        Stream.ssl_set_certificate_file = mock.Mock()
        Stream.ssl_set_ca_cert_file = mock.Mock()

        self._test_connection_start(idl_class=ovsdb_monitor.OvnNbIdl,
                                    schema='OVN_Northbound')

        Stream.ssl_set_private_key_file.assert_called_once_with('foo-key')
        Stream.ssl_set_certificate_file.assert_not_called()
        Stream.ssl_set_ca_cert_file.assert_not_called()

    def test_connection_sb_start(self):
        self._test_connection_start(idl_class=ovsdb_monitor.OvnSbIdl,
                                    schema='OVN_Southbound')


class TestPortBindingChassisUpdateEvent(base.TestCase):
    def setUp(self):
        super(TestPortBindingChassisUpdateEvent, self).setUp()
        self.driver = mock.Mock()
        self.event = ovsdb_monitor.PortBindingChassisUpdateEvent(self.driver)

    def _test_event(self, event, row, old):
        if self.event.matches(event, row, old):
            self.event.run(event, row, old)
            self.driver.set_port_status_up.assert_called()
        else:
            self.driver.set_port_status_up.assert_not_called()

    def test_event_matches(self):
        # NOTE(twilson) This primarily tests implementation details. If a
        # scenario test is written that handles shutting down a compute
        # node uncleanly and performing a 'host-evacuate', this can be removed
        pbtable = fakes.FakeOvsdbTable.create_one_ovsdb_table(
            attrs={'name': 'Port_Binding'})
        ovsdb_row = fakes.FakeOvsdbRow.create_one_ovsdb_row
        self.driver._nb_ovn.lookup.return_value = ovsdb_row(attrs={'up': True})
        self._test_event(
            self.event.ROW_UPDATE,
            ovsdb_row(attrs={'_table': pbtable, 'chassis': 'one',
                             'type': '_fake_', 'logical_port': 'foo'}),
            ovsdb_row(attrs={'_table': pbtable, 'chassis': 'two',
                             'type': '_fake_'}))

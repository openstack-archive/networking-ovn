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
import uuid

from ovs.db import idl as ovs_idl

from networking_ovn.common import config as ovn_config
from networking_ovn.ovsdb import ovsdb_monitor
from networking_ovn.tests.unit.ml2 import test_mech_driver
from neutron import manager
from neutron.plugins.common import constants as service_constants


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


class TestOvnIdlNotifyHandler(test_mech_driver.OVNMechanismDriverTestCase):

    def setUp(self):
        super(TestOvnIdlNotifyHandler, self).setUp()
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
        row_uuid = str(uuid.uuid4())
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
        mgr = manager.NeutronManager.get_instance()
        self.l3_plugin = mgr.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        if ovn_config.is_ovn_l3():
            self.l3_plugin.schedule_unhosted_routers = mock.Mock()

        self.row_json = {
            "name": "fake-name",
            "hostname": "fake-hostname",
            "external_ids": ['map', [["ovn-bridge-mappings",
                                      "fake-phynet1:fake-br1"]]]
        }

    def _test_chassis_helper(self, event, new_row_json, old_row_json=None):
        row_uuid = str(uuid.uuid4())
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
                self.l3_plugin.schedule_unhosted_routers.call_count,
                1)

    def test_chassis_delete_event(self):
        self._test_chassis_helper('delete', self.row_json)
        self.driver.update_segment_host_mapping.assert_called_once_with(
            'fake-hostname', [])
        if ovn_config.is_ovn_l3():
            self.assertEqual(
                self.l3_plugin.schedule_unhosted_routers.call_count,
                1)

    def test_chassis_update_event(self):
        old_row_json = copy.deepcopy(self.row_json)
        old_row_json['external_ids'][1][0][1] = (
            "fake-phynet2:fake-br2")
        self._test_chassis_helper('update', self.row_json, old_row_json)
        self.driver.update_segment_host_mapping.assert_called_once_with(
            'fake-hostname', ['fake-phynet1'])
        if ovn_config.is_ovn_l3():
            self.assertEqual(
                self.l3_plugin.schedule_unhosted_routers.call_count,
                1)

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
import uuid

from networking_ovn.common import constants as ovn_const
from networking_ovn import ovn_db_sync
from networking_ovn.ovsdb import commands as cmd
from networking_ovn.tests.functional import base
from neutron.agent.ovsdb.native import idlutils
from neutron import context
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.extensions import test_extraroute


class TestOvnNbSync(base.TestOVNFunctionalBase):

    def setUp(self):
        super(TestOvnNbSync, self).setUp()
        ext_mgr = test_extraroute.ExtraRouteTestExtensionManager()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.create_lswitches = []
        self.create_lswitch_ports = []
        self.create_lrouters = []
        self.create_lrouter_ports = []
        self.create_lrouter_routes = []
        self.delete_lswitches = []
        self.delete_lswitch_ports = []
        self.delete_lrouters = []
        self.delete_lrouter_ports = []
        self.delete_lrouter_routes = []

    def _create_resources(self):
        n1 = self._make_network(self.fmt, 'n1', True)
        res = self._create_subnet(self.fmt, n1['network']['id'],
                                  '10.0.0.0/24')
        n1_s1 = self.deserialize(self.fmt, res)
        for p in ['p1', 'p2', 'p3']:
            port = self._make_port(self.fmt, n1['network']['id'],
                                   name='n1-' + p)
            if p == 'p2':
                self.delete_lswitch_ports.append(
                    (port['port']['id'], 'neutron-' + n1['network']['id'])
                )

        n2 = self._make_network(self.fmt, 'n2', True)
        res = self._create_subnet(self.fmt, n2['network']['id'],
                                  '20.0.0.0/24')
        n2_s1 = self.deserialize(self.fmt, res)
        for p in ['p1', 'p2']:
            port = self._make_port(self.fmt, n2['network']['id'],
                                   name='n2-' + p)

        self.create_lswitches.append('neutron-' + uuid.uuid4().hex)
        self.create_lswitch_ports.append(('neutron-' + uuid.uuid4().hex,
                                          'neutron-' + n1['network']['id']))
        self.delete_lswitches.append('neutron-' + n2['network']['id'])

        r1 = self.l3_plugin.create_router(
            self.context,
            {'router': {'name': 'r1', 'admin_state_up': True,
                        'tenant_id': self._tenant_id}})
        self.l3_plugin.add_router_interface(
            self.context, r1['id'], {'subnet_id': n1_s1['subnet']['id']})
        r1_p2 = self.l3_plugin.add_router_interface(
            self.context, r1['id'], {'subnet_id': n2_s1['subnet']['id']})
        self.delete_lrouter_ports.append(('lrp-' + r1_p2['port_id'],
                                          'neutron-' + r1['id']))
        self.l3_plugin.update_router(
            self.context, r1['id'],
            {'router': {'routes': [{'destination': '10.10.0.0/24',
                                    'nexthop': '20.0.0.10'},
                                   {'destination': '10.11.0.0/24',
                                    'nexthop': '20.0.0.11'}]}})
        self.create_lrouter_routes.append(('neutron-' + r1['id'],
                                           '10.12.0.0/24',
                                           '20.0.0.12'))
        self.delete_lrouter_routes.append(('neutron-' + r1['id'],
                                           '10.10.0.0/24',
                                           '20.0.0.10'))

        r2 = self.l3_plugin.create_router(
            self.context,
            {'router': {'name': 'r2', 'admin_state_up': True,
                        'tenant_id': self._tenant_id}})
        n1_p4 = self._make_port(self.fmt, n1['network']['id'],
                                name='n1-p4')
        self.l3_plugin.add_router_interface(
            self.context, r2['id'], {'port_id': n1_p4['port']['id']})
        self.l3_plugin.update_router(
            self.context, r2['id'],
            {'router': {'routes': [{'destination': '10.20.0.0/24',
                                    'nexthop': '10.0.0.20'}]}})
        self.create_lrouters.append('neutron-' + uuid.uuid4().hex)
        self.create_lrouter_ports.append(('lrp-' + uuid.uuid4().hex,
                                          'neutron-' + r1['id']))
        self.delete_lrouters.append('neutron-' + r2['id'])

    def _modify_resources_in_nb_db(self):
        fake_api = mock.MagicMock()
        fake_api.idl = self.monitor_nb_db_idl
        fake_api._tables = self.monitor_nb_db_idl.tables

        with self.idl_transaction(fake_api, check_error=True) as txn:
            for lswitch_name in self.create_lswitches:
                external_ids = {ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY:
                                lswitch_name}
                txn.add(cmd.AddLSwitchCommand(fake_api, lswitch_name, True,
                                              external_ids=external_ids))

            for lswitch_name in self.delete_lswitches:
                txn.add(cmd.DelLSwitchCommand(fake_api, lswitch_name, True))

            for lport_name, lswitch_name in self.create_lswitch_ports:
                external_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY:
                                lport_name}
                txn.add(cmd.AddLSwitchPortCommand(fake_api, lport_name,
                                                  lswitch_name, True,
                                                  external_ids=external_ids))

            for lport_name, lswitch_name in self.delete_lswitch_ports:
                txn.add(cmd.DelLSwitchPortCommand(fake_api, lport_name,
                                                  lswitch_name, True))

            for lrouter_name in self.create_lrouters:
                external_ids = {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                                lrouter_name}
                txn.add(cmd.AddLRouterCommand(fake_api, lrouter_name, True,
                                              external_ids=external_ids))

            for lrouter_name in self.delete_lrouters:
                txn.add(cmd.DelLRouterCommand(fake_api, lrouter_name, True))

            for lrport, lrouter_name in self.create_lrouter_ports:
                txn.add(cmd.AddLRouterPortCommand(fake_api, lrport,
                                                  lrouter_name))

            for lrport, lrouter_name in self.delete_lrouter_ports:
                txn.add(cmd.DelLRouterPortCommand(fake_api, lrport,
                                                  lrouter_name, True))

            for lrouter_name, ip_prefix, nexthop in self.create_lrouter_routes:
                txn.add(cmd.AddStaticRouteCommand(fake_api, lrouter_name,
                                                  ip_prefix=ip_prefix,
                                                  nexthop=nexthop))

            for lrouter_name, ip_prefix, nexthop in self.delete_lrouter_routes:
                txn.add(cmd.DelStaticRouteCommand(fake_api, lrouter_name,
                                                  ip_prefix, nexthop, True))

    def _validate_networks(self, should_match=True):
        db_networks = self._list('networks')
        db_net_ids = [net['id'] for net in db_networks['networks']]

        # Get the list of lswitch ids stored in the OVN plugin IDL
        _plugin_nb_ovn = self.mech_driver._nb_ovn
        plugin_lswitch_ids = [
            row.name.replace('neutron-', '') for row in (
                _plugin_nb_ovn._tables['Logical_Switch'].rows.values())]

        # Get the list of lswitch ids stored in the monitor IDL connection
        monitor_lswitch_ids = [
            row.name.replace('neutron-', '') for row in (
                self.monitor_nb_db_idl.tables['Logical_Switch'].rows.values())]

        if should_match:
            self.assertItemsEqual(db_net_ids, plugin_lswitch_ids)
            self.assertItemsEqual(db_net_ids, monitor_lswitch_ids)
        else:
            self.assertRaises(
                AssertionError, self.assertItemsEqual, db_net_ids,
                plugin_lswitch_ids)

            self.assertRaises(
                AssertionError, self.assertItemsEqual, db_net_ids,
                monitor_lswitch_ids)

    def _validate_ports(self, should_match=True):
        db_ports = self._list('ports')
        db_port_ids = [port['id'] for port in db_ports['ports']]

        _plugin_nb_ovn = self.mech_driver._nb_ovn
        plugin_lport_ids = [
            row.name for row in (
                _plugin_nb_ovn._tables['Logical_Switch_Port'].rows.values())]

        monitor_lport_ids = [
            row.name for row in (
                self.monitor_nb_db_idl.tables['Logical_Switch_Port'].
                rows.values())]

        if should_match:
            self.assertItemsEqual(db_port_ids, plugin_lport_ids)
            self.assertItemsEqual(db_port_ids, monitor_lport_ids)
        else:
            self.assertRaises(
                AssertionError, self.assertItemsEqual, db_port_ids,
                plugin_lport_ids)

            self.assertRaises(
                AssertionError, self.assertItemsEqual, db_port_ids,
                monitor_lport_ids)

    def _validate_routers_and_router_ports(self, should_match=True):
        db_routers = self._list('routers')
        db_router_ids = []
        db_routes = {}
        for db_router in db_routers['routers']:
            db_router_ids.append(db_router['id'])
            db_routes[db_router['id']] = [db_route['destination'] +
                                          db_route['nexthop']
                                          for db_route in db_router['routes']]

        _plugin_nb_ovn = self.mech_driver._nb_ovn
        plugin_lrouter_ids = [
            row.name.replace('neutron-', '') for row in (
                _plugin_nb_ovn._tables['Logical_Router'].rows.values())]

        monitor_lrouter_ids = [
            row.name.replace('neutron-', '') for row in (
                self.monitor_nb_db_idl.tables['Logical_Router'].rows.values())]

        if should_match:
            self.assertItemsEqual(db_router_ids, plugin_lrouter_ids)
            self.assertItemsEqual(db_router_ids, monitor_lrouter_ids)
        else:
            self.assertRaises(
                AssertionError, self.assertItemsEqual, db_router_ids,
                plugin_lrouter_ids)

            self.assertRaises(
                AssertionError, self.assertItemsEqual, db_router_ids,
                monitor_lrouter_ids)

        for router_id in db_router_ids:
            r_ports = self._list('ports',
                                 query_params='device_id=%s' % (router_id))
            r_port_ids = [p['id'] for p in r_ports['ports']]
            r_routes = db_routes[router_id]

            try:
                lrouter = idlutils.row_by_value(
                    self.mech_driver._nb_ovn.idl, 'Logical_Router', 'name',
                    'neutron-' + str(router_id), None)
                lports = getattr(lrouter, 'ports', [])
                plugin_lrouter_port_ids = [lport.name.replace('lrp-', '')
                                           for lport in lports]
                sroutes = getattr(lrouter, 'static_routes', [])
                plugin_routes = [sroute.ip_prefix + sroute.nexthop
                                 for sroute in sroutes]
            except idlutils.RowNotFound:
                plugin_lrouter_port_ids = []
                plugin_routes = []

            try:
                lrouter = idlutils.row_by_value(
                    self.monitor_nb_db_idl, 'Logical_Router', 'name',
                    'neutron-' + router_id, None)
                lports = getattr(lrouter, 'ports', [])
                monitor_lrouter_port_ids = [lport.name.replace('lrp-', '')
                                            for lport in lports]
                sroutes = getattr(lrouter, 'static_routes', [])
                monitor_routes = [sroute.ip_prefix + sroute.nexthop
                                  for sroute in sroutes]
            except idlutils.RowNotFound:
                monitor_lrouter_port_ids = []
                monitor_routes = []

            if should_match:
                self.assertItemsEqual(r_port_ids, plugin_lrouter_port_ids)
                self.assertItemsEqual(r_port_ids, monitor_lrouter_port_ids)
                self.assertItemsEqual(r_routes, plugin_routes)
                self.assertItemsEqual(r_routes, monitor_routes)
            else:
                self.assertRaises(
                    AssertionError, self.assertItemsEqual, r_port_ids,
                    plugin_lrouter_port_ids)

                self.assertRaises(
                    AssertionError, self.assertItemsEqual, r_port_ids,
                    monitor_lrouter_port_ids)

                self.assertRaises(
                    AssertionError, self.assertItemsEqual, r_routes,
                    plugin_routes)

                self.assertRaises(
                    AssertionError, self.assertItemsEqual, r_routes,
                    monitor_routes)

    def _validate_resources(self, should_match=True):
        self._validate_networks(should_match=should_match)
        self._validate_ports(should_match=should_match)
        self._validate_routers_and_router_ports(should_match=should_match)

    def _sync_resources(self, mode):
        # TODO(numans) - Need to sync ACLs
        nb_synchronizer = ovn_db_sync.OvnNbSynchronizer(
            self.plugin, self.mech_driver._nb_ovn, mode, self.mech_driver)

        ctx = context.get_admin_context()
        nb_synchronizer.sync_networks_and_ports(ctx)
        nb_synchronizer.sync_routers_and_rports(ctx)

    def _test_ovn_nb_sync_helper(self, mode, modify_resources=True,
                                 restart_ovsdb_processes=False,
                                 should_match_after_sync=True):
        self._create_resources()
        self._validate_resources(should_match=True)

        if modify_resources:
            self._modify_resources_in_nb_db()

        if restart_ovsdb_processes:
            # Restart the ovsdb-server and plugin idl.
            # This causes a new ovsdb-server to be started with empty
            # OVN NB DB
            self.restart()

        if modify_resources or restart_ovsdb_processes:
            self._validate_resources(should_match=False)

        self._sync_resources(mode)
        self._validate_resources(should_match=should_match_after_sync)

    def test_ovn_nb_sync_repair(self):
        self._test_ovn_nb_sync_helper('repair')

    def test_ovn_nb_sync_repair_delete_ovn_nb_db(self):
        # In this test case, the ovsdb-server for OVN NB DB is restarted
        # with empty OVN NB DB.
        self._test_ovn_nb_sync_helper('repair', modify_resources=False,
                                      restart_ovsdb_processes=True)

    def test_ovn_nb_sync_log(self):
        self._test_ovn_nb_sync_helper('log', should_match_after_sync=False)

    def test_ovn_nb_sync_off(self):
        self._test_ovn_nb_sync_helper('off', should_match_after_sync=False)

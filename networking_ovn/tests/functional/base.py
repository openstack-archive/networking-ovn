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

import fixtures
import mock
import time

from oslo_config import cfg
from oslo_log import log

from neutron._i18n import _LE
from neutron.agent.ovsdb import impl_idl
from neutron.agent.ovsdb.native import connection
from neutron import manager
from neutron.plugins.common import constants as service_constants
from neutron.plugins.ml2 import config
from neutron.tests.unit.plugins.ml2 import test_plugin

from networking_ovn.ovsdb import impl_idl_ovn
from networking_ovn.ovsdb import ovsdb_monitor
from networking_ovn.tests.functional.resources import process

PLUGIN_NAME = ('networking_ovn.plugin.OVNPlugin')

LOG = log.getLogger(__name__)


class TestOVNFunctionalBase(test_plugin.Ml2PluginV2TestCase):

    # Please see networking_ovn/tests/contrib/gate_hook.sh.
    # It installs openvswitch in the '/usr/local' path and the ovn-nb schema
    # file will be present in this path.
    OVS_INSTALL_SHARE_PATH = '/usr/local/share/openvswitch'
    _mechanism_drivers = ['logger', 'ovn']
    _extension_drivers = ['port_security']
    l3_plugin = 'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin'

    def setUp(self, ovn_worker=False):
        config.cfg.CONF.set_override('extension_drivers',
                                     self._extension_drivers,
                                     group='ml2')
        config.cfg.CONF.set_override('tenant_network_types',
                                     ['geneve'],
                                     group='ml2')
        config.cfg.CONF.set_override('vni_ranges',
                                     ['1:65536'],
                                     group='ml2_type_geneve')

        super(TestOVNFunctionalBase, self).setUp()
        mm = manager.NeutronManager.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers['ovn'].obj
        self.mech_driver.initialize()
        mgr = manager.NeutronManager.get_instance()
        self.l3_plugin = mgr.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        self.ovsdb_server_mgr = None
        self.ovn_worker = ovn_worker
        self._start_ovsdb_server_and_idls()

    def tearDown(self):
        # Need to set OvsdbNbOvnIdl.ovsdb_connection and
        # OvsdbSbOvnIdl.ovsdb_connection to None.
        # This is because, when the test worker runs the next functional test
        # case, the plugin will try to use the ovsdb_connection from the
        # previous test case and will cause the test case to fail.
        impl_idl_ovn.OvsdbNbOvnIdl.ovsdb_connection = None
        impl_idl_ovn.OvsdbSbOvnIdl.ovsdb_connection = None
        super(TestOVNFunctionalBase, self).tearDown()

    def _start_ovsdb_server_and_idls(self):
        self.temp_dir = self.useFixture(fixtures.TempDir()).path
        # Start 2 ovsdb-servers one each for OVN NB DB and OVN SB DB
        # ovsdb-server with OVN SB DB can be used to test the chassis up/down
        # events.
        self.ovsdb_server_mgr = self.useFixture(
            process.OvsdbServer(self.temp_dir, self.OVS_INSTALL_SHARE_PATH,
                                ovn_nb_db=True, ovn_sb_db=True))
        cfg.CONF.set_override(
            'ovn_nb_connection',
            self.ovsdb_server_mgr.get_ovsdb_connection_path(),
            'ovn')
        cfg.CONF.set_override(
            'ovn_sb_connection',
            self.ovsdb_server_mgr.get_ovsdb_connection_path(db_type='sb'),
            'ovn')
        num_attempts = 0

        # Created monitor IDL connection to the OVN NB DB.
        # This monitor IDL connection can be used to
        #   - Verify that the ML2 OVN driver has written to the OVN NB DB
        #     as expected.
        #   - Create and delete resources in OVN NB DB outside of the
        #     ML2 OVN driver scope to test scenarios like ovn_nb_sync.
        while num_attempts < 3:
            try:
                self.monitor_idl_con = connection.Connection(
                    self.ovsdb_server_mgr.get_ovsdb_connection_path(),
                    60, 'OVN_Northbound')
                self.monitor_idl_con.start()
                self.monitor_nb_db_idl = self.monitor_idl_con.idl
                break
            except Exception:
                LOG.exception(_LE("Error connecting to the OVN_Northbound DB"))
                num_attempts += 1
                time.sleep(1)

        trigger = mock.MagicMock()
        if self.ovn_worker:
            trigger.im_class = ovsdb_monitor.OvnWorker
            cfg.CONF.set_override('neutron_sync_mode', 'off', 'ovn')

        # mech_driver.post_fork_initialize creates the IDL connections
        self.mech_driver.post_fork_initialize(mock.ANY, mock.ANY, trigger)

    def idl_transaction(self, fake_api, check_error=False, log_errors=True,
                        **kwargs):
        return impl_idl.Transaction(fake_api, self.monitor_idl_con, 60,
                                    check_error, log_errors)

    def restart(self):
        if self.ovsdb_server_mgr:
            self.ovsdb_server_mgr.stop()

        impl_idl_ovn.OvsdbNbOvnIdl.ovsdb_connection = None
        impl_idl_ovn.OvsdbSbOvnIdl.ovsdb_connection = None
        self.mech_driver._nb_ovn = None
        self.mech_driver._sb_ovn = None
        self.l3_plugin._nb_ovn = None
        self.monitor_idl_con = None

        self._start_ovsdb_server_and_idls()

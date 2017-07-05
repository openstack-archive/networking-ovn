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

import time

import fixtures
import mock
from neutron.plugins.ml2 import config
from neutron.plugins.ml2.drivers import type_geneve  # noqa
from neutron.tests.unit.plugins.ml2 import test_plugin
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import command
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import transaction

from networking_ovn.ovsdb import impl_idl_ovn
from networking_ovn.ovsdb import ovsdb_monitor
from networking_ovn.tests.functional.resources import process

LOG = log.getLogger(__name__)


class AddFakeChassisCommand(command.BaseCommand):
    """Add a fake chassis in OVN SB DB for functional test."""

    def __init__(self, api, name, ip, **columns):
        super(AddFakeChassisCommand, self).__init__(api)
        self.name = name
        self.ip = ip
        self.columns = columns

    def run_idl(self, txn):
        encap_row = txn.insert(self.api._tables['Encap'])
        encap_row.type = 'geneve'
        encap_row.ip = self.ip
        self.columns.update({'encaps': [encap_row.uuid]})

        row = txn.insert(self.api._tables['Chassis'])
        row.name = self.name
        for col, val in self.columns.items():
            setattr(row, col, val)


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
        mm = directory.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers['ovn'].obj
        self.l3_plugin = directory.get_plugin(constants.L3)
        self.ovsdb_server_mgr = None
        self.ovn_worker = ovn_worker
        self._start_ovsdb_server_and_idls()

    def tearDown(self):
        # Set Mock() to idl to avoid SSL file access errors.
        # This is because, destroying temporary directory containing SSL files
        # is earlier than terminating thread in Connection() object that
        # the errors are likely to occur in the short period of time.
        # However, Connection() does not provider a stop method for run(), we
        # replace idl with Mock() to avoid accessing.
        if self._ovsdb_protocol == 'ssl':
            impl_idl_ovn.OvsdbNbOvnIdl.ovsdb_connection.idl = mock.Mock()
            impl_idl_ovn.OvsdbSbOvnIdl.ovsdb_connection.idl = mock.Mock()
            self.monitor_nb_idl_con.idl = mock.Mock()
            self.monitor_sb_idl_con.idl = mock.Mock()
        # Need to set OvsdbNbOvnIdl.ovsdb_connection and
        # OvsdbSbOvnIdl.ovsdb_connection to None.
        # This is because, when the test worker runs the next functional test
        # case, the plugin will try to use the ovsdb_connection from the
        # previous test case and will cause the test case to fail.
        impl_idl_ovn.OvsdbNbOvnIdl.ovsdb_connection = None
        impl_idl_ovn.OvsdbSbOvnIdl.ovsdb_connection = None
        super(TestOVNFunctionalBase, self).tearDown()

    @property
    def _ovsdb_protocol(self):
        return self.get_ovsdb_server_protocol()

    def get_ovsdb_server_protocol(self):
        return 'unix'

    def _start_ovsdb_server_and_idls(self):
        self.temp_dir = self.useFixture(fixtures.TempDir()).path
        # Start 2 ovsdb-servers one each for OVN NB DB and OVN SB DB
        # ovsdb-server with OVN SB DB can be used to test the chassis up/down
        # events.
        self.ovsdb_server_mgr = self.useFixture(
            process.OvsdbServer(self.temp_dir, self.OVS_INSTALL_SHARE_PATH,
                                ovn_nb_db=True, ovn_sb_db=True,
                                protocol=self._ovsdb_protocol))
        set_cfg = cfg.CONF.set_override
        set_cfg('ovn_nb_connection',
                self.ovsdb_server_mgr.get_ovsdb_connection_path(), 'ovn')
        set_cfg('ovn_sb_connection',
                self.ovsdb_server_mgr.get_ovsdb_connection_path(
                    db_type='sb'), 'ovn')
        set_cfg('ovn_nb_private_key', self.ovsdb_server_mgr.private_key, 'ovn')
        set_cfg('ovn_nb_certificate', self.ovsdb_server_mgr.certificate, 'ovn')
        set_cfg('ovn_nb_ca_cert', self.ovsdb_server_mgr.ca_cert, 'ovn')
        set_cfg('ovn_sb_private_key', self.ovsdb_server_mgr.private_key, 'ovn')
        set_cfg('ovn_sb_certificate', self.ovsdb_server_mgr.certificate, 'ovn')
        set_cfg('ovn_sb_ca_cert', self.ovsdb_server_mgr.ca_cert, 'ovn')

        num_attempts = 0
        # 5 seconds should be more than enough for the transaction to complete
        # for the test cases.
        # This also fixes the bug #1607639.
        cfg.CONF.set_override(
            'ovsdb_connection_timeout', 5,
            'ovn')

        # Created monitor IDL connection to the OVN NB DB.
        # This monitor IDL connection can be used to
        #   - Verify that the ML2 OVN driver has written to the OVN NB DB
        #     as expected.
        #   - Create and delete resources in OVN NB DB outside of the
        #     ML2 OVN driver scope to test scenarios like ovn_nb_sync.
        while num_attempts < 3:
            try:
                _idlnb = ovsdb_monitor.BaseOvnIdl.from_server(
                    self.ovsdb_server_mgr.get_ovsdb_connection_path(),
                    'OVN_Northbound')
                self.monitor_nb_idl_con = connection.Connection(
                    idl=_idlnb, timeout=60)
                self.monitor_nb_idl_con.start()
                self.monitor_nb_db_idl = self.monitor_nb_idl_con.idl
                break
            except Exception:
                LOG.exception("Error connecting to the OVN_Northbound DB")
                num_attempts += 1
                time.sleep(1)

        num_attempts = 0

        # Create monitor IDL connection to the OVN SB DB.
        # This monitor IDL connection can be used to
        #  - Create chassis rows
        #  - Update chassis columns etc.
        while num_attempts < 3:
            try:
                _idlsb = ovsdb_monitor.BaseOvnIdl.from_server(
                    self.ovsdb_server_mgr.get_ovsdb_connection_path('sb'),
                    'OVN_Southbound')
                self.monitor_sb_idl_con = connection.Connection(
                    idl=_idlsb, timeout=60)
                self.monitor_sb_idl_con.start()
                self.monitor_sb_db_idl = self.monitor_sb_idl_con.idl
                break
            except Exception:
                LOG.exception("Error connecting to the OVN_Southbound DB")
                num_attempts += 1
                time.sleep(1)

        trigger = mock.MagicMock()
        if self.ovn_worker:
            trigger.im_class = ovsdb_monitor.OvnWorker
            cfg.CONF.set_override('neutron_sync_mode', 'off', 'ovn')
        trigger.im_class.__name__ = 'trigger'

        # mech_driver.post_fork_initialize creates the IDL connections
        self.mech_driver.post_fork_initialize(mock.ANY, mock.ANY, trigger)

    def nb_idl_transaction(self, fake_api, check_error=False, log_errors=True,
                           **kwargs):
        return transaction.Transaction(fake_api, self.monitor_nb_idl_con, 60,
                                       check_error, log_errors)

    def sb_idl_transaction(self, fake_api, check_error=False, log_errors=True,
                           **kwargs):
        return transaction.Transaction(fake_api, self.monitor_sb_idl_con, 60,
                                       check_error, log_errors)

    def restart(self):
        if self.ovsdb_server_mgr:
            self.ovsdb_server_mgr.stop()

        if self._ovsdb_protocol == 'ssl':
            impl_idl_ovn.OvsdbNbOvnIdl.ovsdb_connection.idl = mock.Mock()
            impl_idl_ovn.OvsdbSbOvnIdl.ovsdb_connection.idl = mock.Mock()
            self.monitor_nb_idl_con.idl = mock.Mock()
            self.monitor_sb_idl_con.idl = mock.Mock()
        impl_idl_ovn.OvsdbNbOvnIdl.ovsdb_connection = None
        impl_idl_ovn.OvsdbSbOvnIdl.ovsdb_connection = None
        self.mech_driver._nb_ovn = None
        self.mech_driver._sb_ovn = None
        self.l3_plugin._nb_ovn_idl = None
        self.l3_plugin._sb_ovn_idl = None
        self.monitor_nb_idl_con = None
        self.monitor_sb_idl_con = None

        self._start_ovsdb_server_and_idls()

    def add_fake_chassis(self, host, physical_nets=None, external_ids=None):
        physical_nets = physical_nets or []
        external_ids = external_ids or {}
        fake_api = mock.MagicMock()
        fake_api.idl = self.monitor_sb_db_idl
        fake_api._tables = self.monitor_sb_db_idl.tables

        bridge_mapping = ",".join(["%s:br-provider%s" % (phys_net, i)
                                  for i, phys_net in enumerate(physical_nets)])
        name = uuidutils.generate_uuid()
        with self.sb_idl_transaction(fake_api, check_error=True) as txn:
            external_ids['ovn-bridge-mappings'] = bridge_mapping
            txn.add(AddFakeChassisCommand(fake_api, name, "172.24.4.10",
                                          external_ids=external_ids,
                                          hostname=host))
        return name

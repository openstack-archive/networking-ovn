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

import os
import time

import fixtures
import mock
from neutron.conf.plugins.ml2 import config
from neutron.plugins.ml2.drivers import type_geneve  # noqa
from neutron.tests.unit.plugins.ml2 import test_plugin
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import command
from ovsdbapp.backend.ovs_idl import connection


# Load all the models to register them into SQLAlchemy metadata before using
# the SqlFixture
from networking_ovn.db import models  # noqa
from networking_ovn.ovsdb import impl_idl_ovn
from networking_ovn.ovsdb import ovsdb_monitor
from networking_ovn.tests import base
from networking_ovn.tests.functional.resources import process

LOG = log.getLogger(__name__)

# This is the directory from which infra fetches log files for functional tests
DEFAULT_LOG_DIR = os.path.join(os.environ.get('OS_LOG_PATH', '/tmp'),
                               'dsvm-functional-logs')


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


class ConnectionFixture(fixtures.Fixture):
    def __init__(self, idl=None, constr=None, schema=None, timeout=60):
        self.idl = idl or ovsdb_monitor.BaseOvnIdl.from_server(
            constr, schema)
        self.connection = connection.Connection(
            idl=self.idl, timeout=timeout)

    def _setUp(self):
        self.addCleanup(self.stop)
        self.connection.start()

    def stop(self):
        self.connection.stop()


class TestOVNFunctionalBase(test_plugin.Ml2PluginV2TestCase):

    # Please see networking_ovn/tests/contrib/gate_hook.sh.
    # It installs openvswitch in the '/usr/local' path and the ovn-nb schema
    # file will be present in this path.
    OVS_INSTALL_SHARE_PATH = '/usr/local/share/openvswitch'
    _mechanism_drivers = ['logger', 'ovn']
    _extension_drivers = ['port_security']
    _counter = 0
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
        config.cfg.CONF.set_override('dns_servers',
                                     ['10.10.10.10'],
                                     group='ovn')

        super(TestOVNFunctionalBase, self).setUp()
        base.setup_test_logging(
            cfg.CONF, DEFAULT_LOG_DIR, "%s.txt" % self.id())

        mm = directory.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers['ovn'].obj
        self.l3_plugin = directory.get_plugin(constants.L3)
        self.ovsdb_server_mgr = None
        self.ovn_worker = ovn_worker
        self._start_ovsdb_server_and_idls()

    def get_additional_service_plugins(self):
        p = super(TestOVNFunctionalBase, self).get_additional_service_plugins()
        p.update({'revision_plugin_name': 'revisions'})
        return p

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
        mgr = self.ovsdb_server_mgr = self.useFixture(
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
                con = self.useFixture(ConnectionFixture(
                    constr=mgr.get_ovsdb_connection_path(),
                    schema='OVN_Northbound')).connection
                self.nb_api = impl_idl_ovn.OvsdbNbOvnIdl(con)
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
                con = self.useFixture(ConnectionFixture(
                    constr=mgr.get_ovsdb_connection_path('sb'),
                    schema='OVN_Southbound')).connection
                self.sb_api = impl_idl_ovn.OvsdbSbOvnIdl(con)
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

        self.addCleanup(self.stop)

        # mech_driver.post_fork_initialize creates the IDL connections
        self.mech_driver.post_fork_initialize(mock.ANY, mock.ANY, trigger)

    def stop(self):
        if self.ovn_worker:
            self.mech_driver.nb_synchronizer.stop()
            self.mech_driver.sb_synchronizer.stop()
        self.mech_driver._nb_ovn.ovsdb_connection.stop()
        self.mech_driver._sb_ovn.ovsdb_connection.stop()

    def restart(self):
        self.stop()
        # The OVN sync test starts its own synchronizers...
        self.l3_plugin._nb_ovn_idl.ovsdb_connection.stop()
        self.l3_plugin._sb_ovn_idl.ovsdb_connection.stop()
        # Stop our monitor connections
        self.nb_api.ovsdb_connection.stop()
        self.sb_api.ovsdb_connection.stop()

        if self.ovsdb_server_mgr:
            self.ovsdb_server_mgr.stop()

        self.mech_driver._nb_ovn = None
        self.mech_driver._sb_ovn = None
        self.l3_plugin._nb_ovn_idl = None
        self.l3_plugin._sb_ovn_idl = None
        self.nb_api.ovsdb_connection = None
        self.sb_api.ovsdb_connection = None

        self._start_ovsdb_server_and_idls()

    def add_fake_chassis(self, host, physical_nets=None, external_ids=None):
        physical_nets = physical_nets or []
        external_ids = external_ids or {}

        bridge_mapping = ",".join(["%s:br-provider%s" % (phys_net, i)
                                  for i, phys_net in enumerate(physical_nets)])
        name = uuidutils.generate_uuid()
        external_ids['ovn-bridge-mappings'] = bridge_mapping
        # We'll be using different IP addresses every time for the Encap of
        # the fake chassis as the SB schema doesn't allow to have two entries
        # with same (ip,type) pairs as of OVS 2.11. This shouldn't have any
        # impact as the tunnels won't get created anyways since ovn-controller
        # is not running. Ideally we shouldn't be creating more than 255
        # fake chassis but from the SB db point of view, 'ip' column can be
        # any string so we could add entries with ip='172.24.4.1000'.
        self._counter += 1
        self.sb_api.chassis_add(
            name, ['geneve'], '172.24.4.%d' % self._counter,
            external_ids=external_ids, hostname=host).execute(check_error=True)
        return name

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

from datetime import datetime
import os
import shutil
import time

import fixtures
import mock
from neutron.conf.plugins.ml2 import config
from neutron.plugins.ml2.drivers import type_geneve  # noqa
from neutron.tests.unit.plugins.ml2 import test_plugin
from neutron_lib import fixture
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_db import exception as os_db_exc
from oslo_db.sqlalchemy import provision
from oslo_log import log
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import connection

# Load all the models to register them into SQLAlchemy metadata before using
# the SqlFixture
from networking_ovn.db import models  # noqa
from networking_ovn.ovsdb import impl_idl_ovn
from networking_ovn.ovsdb import ovsdb_monitor
from networking_ovn.ovsdb import worker
from networking_ovn.tests import base
from networking_ovn.tests.functional.resources import process

LOG = log.getLogger(__name__)

# This is the directory from which infra fetches log files for functional tests
DEFAULT_LOG_DIR = os.path.join(os.environ.get('OS_LOG_PATH', '/tmp'),
                               'dsvm-functional-logs')
SQL_FIXTURE_LOCK = 'sql_fixture_lock'


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


class OVNSqlFixture(fixture.StaticSqlFixture):

    @classmethod
    @lockutils.synchronized(SQL_FIXTURE_LOCK)
    def _init_resources(cls):
        cls.schema_resource = provision.SchemaResource(
            provision.DatabaseResource("sqlite"),
            cls._generate_schema, teardown=False)
        dependency_resources = {}
        for name, resource in cls.schema_resource.resources:
            dependency_resources[name] = resource.getResource()
        cls.schema_resource.make(dependency_resources)
        cls.engine = dependency_resources['database'].engine

    def _delete_from_schema(self, engine):
        try:
            super(OVNSqlFixture, self)._delete_from_schema(engine)
        except os_db_exc.DBNonExistentTable:
            pass


class TestOVNFunctionalBase(test_plugin.Ml2PluginV2TestCase):

    # Please see networking_ovn/tests/contrib/gate_hook.sh.
    # It installs openvswitch in the '/usr/local' path and the ovn-nb schema
    # file will be present in this path.
    OVS_INSTALL_SHARE_PATH = '/usr/local/share/openvswitch'
    _mechanism_drivers = ['logger', 'ovn']
    _extension_drivers = ['port_security']
    _counter = 0
    l3_plugin = 'networking_ovn.l3.l3_ovn.OVNL3RouterPlugin'

    def setUp(self, maintenance_worker=False):
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
        self.test_log_dir = os.path.join(DEFAULT_LOG_DIR, self.id())
        base.setup_test_logging(
            cfg.CONF, self.test_log_dir, "testrun.txt")

        mm = directory.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers['ovn'].obj
        self.l3_plugin = directory.get_plugin(constants.L3)
        self.ovsdb_server_mgr = None
        self.ovn_northd_mgr = None
        self.maintenance_worker = maintenance_worker
        self.temp_dir = self.useFixture(fixtures.TempDir()).path
        self._start_ovsdb_server_and_idls()
        self._start_ovn_northd()

    # FIXME(lucasagomes): Workaround for
    # https://bugs.launchpad.net/networking-ovn/+bug/1808146. We should
    # investigate and properly fix the problem. This method is just a
    # workaround to alleviate the gate for now and should not be considered
    # a proper fix.
    def _setup_database_fixtures(self):
        fixture = OVNSqlFixture()
        self.useFixture(fixture)
        self.engine = fixture.engine

    def get_additional_service_plugins(self):
        p = super(TestOVNFunctionalBase, self).get_additional_service_plugins()
        p.update({'revision_plugin_name': 'revisions'})
        return p

    @property
    def _ovsdb_protocol(self):
        return self.get_ovsdb_server_protocol()

    def get_ovsdb_server_protocol(self):
        return 'unix'

    def _start_ovn_northd(self):
        if not self.ovsdb_server_mgr:
            return
        ovn_nb_db = self.ovsdb_server_mgr.get_ovsdb_connection_path('nb')
        ovn_sb_db = self.ovsdb_server_mgr.get_ovsdb_connection_path('sb')
        self.ovn_northd_mgr = self.useFixture(
            process.OvnNorthd(self.temp_dir,
                              ovn_nb_db, ovn_sb_db,
                              protocol=self._ovsdb_protocol))

    def _start_ovsdb_server_and_idls(self):
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

        class TriggerCls(mock.MagicMock):
            def trigger(self):
                pass

        trigger_cls = TriggerCls()
        if self.maintenance_worker:
            trigger_cls.trigger.__self__.__class__ = worker.MaintenanceWorker
            cfg.CONF.set_override('neutron_sync_mode', 'off', 'ovn')

        self.addCleanup(self._collect_processes_logs)
        self.addCleanup(self.stop)

        # mech_driver.post_fork_initialize creates the IDL connections
        self.mech_driver.post_fork_initialize(
            mock.ANY, mock.ANY, trigger_cls.trigger)

    def _collect_processes_logs(self):
        for database in ("nb", "sb"):
            for file_suffix in ("log", "db"):
                src_filename = "ovn_%(db)s.%(suffix)s" % {
                    'db': database,
                    'suffix': file_suffix
                }
                dst_filename = "ovn_%(db)s-%(timestamp)s.%(suffix)s" % {
                    'db': database,
                    'suffix': file_suffix,
                    'timestamp': datetime.now().strftime('%y-%m-%d_%H-%M-%S'),
                }

                filepath = os.path.join(self.temp_dir, src_filename)
                shutil.copyfile(
                    filepath, os.path.join(self.test_log_dir, dst_filename))

    def stop(self):
        if self.maintenance_worker:
            self.mech_driver.nb_synchronizer.stop()
            self.mech_driver.sb_synchronizer.stop()
        self.mech_driver._nb_ovn.ovsdb_connection.stop()
        self.mech_driver._sb_ovn.ovsdb_connection.stop()

    def restart(self):
        self.stop()

        if self.ovsdb_server_mgr:
            self.ovsdb_server_mgr.stop()
        if self.ovn_northd_mgr:
            self.ovn_northd_mgr.stop()

        self.ovsdb_server_mgr.delete_dbs()
        self._start_ovsdb_server_and_idls()
        self._start_ovn_northd()

    def add_fake_chassis(self, host, physical_nets=None, external_ids=None,
                         name=None):
        physical_nets = physical_nets or []
        external_ids = external_ids or {}

        bridge_mapping = ",".join(["%s:br-provider%s" % (phys_net, i)
                                  for i, phys_net in enumerate(physical_nets)])
        if name is None:
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

    def del_fake_chassis(self, chassis, if_exists=True):
        self.sb_api.chassis_del(
            chassis, if_exists=if_exists).execute(check_error=True)

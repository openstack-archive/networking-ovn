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


from distutils import spawn

import fixtures

from neutron.agent.linux import utils


class OvsdbServer(fixtures.Fixture):

    def __init__(self, temp_dir, ovs_dir, ovn_nb_db=True, ovn_sb_db=False):
        super(OvsdbServer, self).__init__()
        self.temp_dir = temp_dir
        self.ovs_dir = ovs_dir
        self.ovn_nb_db = ovn_nb_db
        self.ovn_sb_db = ovn_sb_db
        self.ovsdb_server_processes = []

    def _setUp(self):
        if self.ovn_nb_db:
            self.ovsdb_server_processes.append(
                {'db_path': self.temp_dir + '/ovn_nb.db',
                 'schema_path': self.ovs_dir + '/ovn-nb.ovsschema',
                 'remote_path': self.temp_dir + '/ovnnb_db.sock',
                 'unixctl_path': self.temp_dir + '/ovnnb_db.ctl',
                 'log_file_path': self.temp_dir + '/ovn_nb.log',
                 'db_type': 'nb'})

        if self.ovn_sb_db:
            self.ovsdb_server_processes.append(
                {'db_path': self.temp_dir + '/ovn_sb.db',
                 'schema_path': self.ovs_dir + '/ovn-sb.ovsschema',
                 'remote_path': self.temp_dir + '/ovnsb_db.sock',
                 'unixctl_path': self.temp_dir + '/ovnsb_db.ctl',
                 'log_file_path': self.temp_dir + '/ovn_sb.log',
                 'db_type': 'sb'})
        self.addCleanup(self.stop)
        self.start()

    def start(self):
        for ovsdb_process in self.ovsdb_server_processes:
            # create the db from the schema using ovsdb-tool
            ovsdb_tool_cmd = [spawn.find_executable('ovsdb-tool'),
                              'create', ovsdb_process['db_path'],
                              ovsdb_process['schema_path']]
            utils.execute(ovsdb_tool_cmd)

            # start the ovsdb-server
            ovsdb_server_cmd = [
                spawn.find_executable('ovsdb-server'),
                '--detach', '-vconsole:off',
                '--log-file=%s' % (ovsdb_process['log_file_path']),
                '--remote=punix:%s' % (ovsdb_process['remote_path']),
                '--unixctl=%s' % (ovsdb_process['unixctl_path']),
                ovsdb_process['db_path']]
            utils.execute(ovsdb_server_cmd)

    def stop(self):
        for ovsdb_process in self.ovsdb_server_processes:
            try:
                stop_cmd = ['ovs-appctl', '-t', ovsdb_process['unixctl_path'],
                            'exit']
                utils.execute(stop_cmd)
                # Delete the db
                cmd = ['rm', '-f', ovsdb_process['db_path']]
                utils.execute(cmd)
            except Exception:
                pass

    def get_ovsdb_connection_path(self, db_type='nb'):
        for ovsdb_process in self.ovsdb_server_processes:
            if ovsdb_process['db_type'] == db_type:
                return 'unix:' + ovsdb_process['remote_path']

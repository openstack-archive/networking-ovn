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
import os

import fixtures
from neutron.agent.linux import utils
import psutil
import tenacity


class OvsdbServer(fixtures.Fixture):

    def __init__(self, temp_dir, ovs_dir, ovn_nb_db=True, ovn_sb_db=False,
                 protocol='unix'):
        super(OvsdbServer, self).__init__()
        self.temp_dir = temp_dir
        self.ovs_dir = ovs_dir
        self.ovn_nb_db = ovn_nb_db
        self.ovn_sb_db = ovn_sb_db
        # The value of the protocol must be unix or tcp or ssl
        self.protocol = protocol
        self.ovsdb_server_processes = []
        self.private_key = os.path.join(self.temp_dir, 'ovn-privkey.pem')
        self.certificate = os.path.join(self.temp_dir, 'ovn-cert.pem')
        self.ca_cert = os.path.join(self.temp_dir, 'controllerca',
                                    'cacert.pem')

    def _setUp(self):
        if self.ovn_nb_db:
            self.ovsdb_server_processes.append(
                {'db_path': self.temp_dir + '/ovn_nb.db',
                 'schema_path': self.ovs_dir + '/ovn-nb.ovsschema',
                 'remote_path': self.temp_dir + '/ovnnb_db.sock',
                 'protocol': self.protocol,
                 'remote_ip': '127.0.0.1',
                 'remote_port': '6641',
                 'unixctl_path': self.temp_dir + '/ovnnb_db.ctl',
                 'log_file_path': self.temp_dir + '/ovn_nb.log',
                 'db_type': 'nb'})

        if self.ovn_sb_db:
            self.ovsdb_server_processes.append(
                {'db_path': self.temp_dir + '/ovn_sb.db',
                 'schema_path': self.ovs_dir + '/ovn-sb.ovsschema',
                 'remote_path': self.temp_dir + '/ovnsb_db.sock',
                 'protocol': self.protocol,
                 'remote_ip': '127.0.0.1',
                 'remote_port': '6642',
                 'unixctl_path': self.temp_dir + '/ovnsb_db.ctl',
                 'log_file_path': self.temp_dir + '/ovn_sb.log',
                 'db_type': 'sb'})
        self.addCleanup(self.stop)
        self.start()

    def _init_ovsdb_pki(self):
        os.chdir(self.temp_dir)
        pki_init_cmd = [spawn.find_executable('ovs-pki'), 'init',
                        '-d', self.temp_dir, '-l',
                        os.path.join(self.temp_dir, 'pki.log'), '--force']
        utils.execute(pki_init_cmd)
        pki_req_sign = [spawn.find_executable('ovs-pki'), 'req+sign', 'ovn',
                        'controller', '-d', self.temp_dir, '-l',
                        os.path.join(self.temp_dir, 'pki.log'), '--force']
        utils.execute(pki_req_sign)

    def start(self):
        pki_done = False
        for ovsdb_process in self.ovsdb_server_processes:
            # create the db from the schema using ovsdb-tool
            ovsdb_tool_cmd = [spawn.find_executable('ovsdb-tool'),
                              'create', ovsdb_process['db_path'],
                              ovsdb_process['schema_path']]
            utils.execute(ovsdb_tool_cmd)

            # start the ovsdb-server
            ovsdb_server_cmd = [
                spawn.find_executable('ovsdb-server'), '-vconsole:off',
                '--log-file=%s' % (ovsdb_process['log_file_path']),
                '--remote=punix:%s' % (ovsdb_process['remote_path']),
                '--unixctl=%s' % (ovsdb_process['unixctl_path'])]
            if ovsdb_process['protocol'] != 'unix':
                ovsdb_server_cmd.append(
                    '--remote=p%s:0:%s' % (ovsdb_process['protocol'],
                                           ovsdb_process['remote_ip'])
                )
            if ovsdb_process['protocol'] == 'ssl':
                if not pki_done:
                    pki_done = True
                    self._init_ovsdb_pki()
                ovsdb_server_cmd.append('--private-key=%s' % self.private_key)
                ovsdb_server_cmd.append('--certificate=%s' % self.certificate)
                ovsdb_server_cmd.append('--ca-cert=%s' % self.ca_cert)
            ovsdb_server_cmd.append(ovsdb_process['db_path'])
            obj, _ = utils.create_process(ovsdb_server_cmd)

            @tenacity.retry(
                wait=tenacity.wait_exponential(multiplier=0.1),
                stop=tenacity.stop_after_delay(10),
                reraise=True)
            def get_ovsdb_remote_port_retry(pid):
                process = psutil.Process(pid)
                for connect in process.connections():
                    if connect.status == 'LISTEN':
                        return connect.laddr[1]
                raise Exception(_("Could not find LISTEN port."))

            if ovsdb_process['protocol'] != 'unix':
                ovsdb_process['remote_port'] = \
                    get_ovsdb_remote_port_retry(obj.pid)

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
                if ovsdb_process['protocol'] == 'unix':
                    return 'unix:' + ovsdb_process['remote_path']
                else:
                    return '%s:%s:%s' % (ovsdb_process['protocol'],
                                         ovsdb_process['remote_ip'],
                                         ovsdb_process['remote_port'])

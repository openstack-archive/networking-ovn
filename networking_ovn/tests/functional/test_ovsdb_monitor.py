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
from oslo_utils import uuidutils

from networking_ovn.ovsdb import ovsdb_monitor
from networking_ovn.tests.functional import base
from neutron.common import utils as n_utils
from neutron_lib.api.definitions import portbindings
from neutron_lib.plugins import directory


class TestNBDbMonitor(base.TestOVNFunctionalBase):

    def setUp(self):
        super(TestNBDbMonitor, self).setUp(ovn_worker=True)
        self.chassis = self.add_fake_chassis('ovs-host1')

    def create_port(self):
        net = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net, '20.0.0.1',
                          '20.0.0.0/24', ip_version=4)
        arg_list = ('device_owner', 'device_id', portbindings.HOST_ID)
        host_arg = {'device_owner': 'compute:nova',
                    'device_id': uuidutils.generate_uuid(),
                    portbindings.HOST_ID: 'ovs-host1'}
        port_res = self._create_port(self.fmt, net['network']['id'],
                                     arg_list=arg_list, **host_arg)
        port = self.deserialize(self.fmt, port_res)['port']
        return port

    def _test_port_binding_and_status(self, port_id, action, status):
        # This function binds or unbinds port to chassis and
        # checks if port status matches with input status
        core_plugin = directory.get_plugin()
        self.sb_api.check_for_row_by_value_and_retry(
            'Port_Binding', 'logical_port', port_id)

        def check_port_status(status):
            port = core_plugin.get_ports(
                self.context, filters={'id': [port_id]})[0]
            return port['status'] == status
        if action == 'bind':
            self.sb_api.lsp_bind(port_id, self.chassis,
                                 may_exist=True).execute(check_error=True)
        else:
            self.sb_api.lsp_unbind(port_id).execute(check_error=True)
        n_utils.wait_until_true(lambda: check_port_status(status))

    def test_port_up_down_events(self):
        """Test the port up down events.

        This test case creates a port, binds the port to chassis,
        tests if the ovsdb monitor calls mech_driver to set port status
        to 'ACTIVE'. Then unbinds the port and checks if the port status
        is set to "DOWN'
        """
        port = self.create_port()
        self._test_port_binding_and_status(port['id'], 'bind', 'ACTIVE')
        self._test_port_binding_and_status(port['id'], 'unbind', 'DOWN')

    def test_ovsdb_monitor_lock(self):
        """Test case to test the ovsdb monitor lock used by OvnConnection.

        This test case created another IDL connection to the NB DB using
        the ovsdb_monitor.OvnConnection.

        With this we will have 2 'ovsdb_monitor.OvnConnection's. At the
        start the lock should be with the IDL connection created by the
        'TestOVNFunctionalBase' setup() function.

        The port up/down events should be handled by the first IDL connection.
        Then the first IDL connection will release the lock so that the 2nd IDL
        connection created in this test case gets the lock and it should
        handle the port up/down events. Later when 2nd IDL connection releases
        lock, first IDL connection will get the lock and handles the
        port up/down events.

        Please note that the "self.monitor_nb_idl_con" created by the base
        class is created using 'connection.Connection' and hence it will not
        contend for any lock.
        """
        fake_driver = mock.MagicMock()
        _idl = ovsdb_monitor.OvnNbIdl.from_server(
            self.ovsdb_server_mgr.get_ovsdb_connection_path(),
            'OVN_Northbound', fake_driver)
        tst_ovn_conn = self.useFixture(
            base.ConnectionFixture(idl=_idl, timeout=10)).connection
        tst_ovn_conn.start()

        port = self.create_port()

        # mech_driver will release the lock to fake test driver. During chassis
        # binding and unbinding, port status won't change(i.e will be DOWN)
        # as mech driver can't update it.
        self.mech_driver._nb_ovn.idl.set_lock(None)
        n_utils.wait_until_true(lambda: tst_ovn_conn.idl.has_lock)
        self.mech_driver._nb_ovn.idl.set_lock(
            self.mech_driver._nb_ovn.idl.event_lock_name)
        self._test_port_binding_and_status(port['id'], 'bind', 'DOWN')
        self._test_port_binding_and_status(port['id'], 'unbind', 'DOWN')

        # Fake driver will relase the lock to mech driver. Port status will be
        # updated to 'ACTIVE' for chassis binding and to 'DOWN' for chassis
        # unbinding.
        tst_ovn_conn.idl.set_lock(None)
        n_utils.wait_until_true(lambda: self.mech_driver._nb_ovn.idl.has_lock)
        self._test_port_binding_and_status(port['id'], 'bind', 'ACTIVE')
        self._test_port_binding_and_status(port['id'], 'unbind', 'DOWN')


class TestNBDbMonitorOverTcp(TestNBDbMonitor):
    def get_ovsdb_server_protocol(self):
        return 'tcp'


class TestNBDbMonitorOverSsl(TestNBDbMonitor):
    def get_ovsdb_server_protocol(self):
        return 'ssl'

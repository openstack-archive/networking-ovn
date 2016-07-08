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

from networking_ovn.ovsdb import commands as cmd
from networking_ovn.ovsdb import ovsdb_monitor
from networking_ovn.tests.functional import base
from neutron.agent.linux import utils as n_utils


class TestNBDbMonitor(base.TestOVNFunctionalBase):

    def setUp(self):
        super(TestNBDbMonitor, self).setUp(ovn_worker=True)
        self.fake_api = mock.MagicMock()
        self.fake_api.idl = self.monitor_nb_db_idl
        self.fake_api._tables = self.monitor_nb_db_idl.tables

    def _test_port_up_down_helper(self, port, ovn_mech_driver):
        # Set the Logical_Switch_Port.up to True. This is to mock
        # the vif plug. When the Logical_Switch_Port.up changes from
        # False to True, ovsdb_monitor should call
        # mech_driver.set_port_status_up.
        with self.idl_transaction(self.fake_api, check_error=True) as txn:
            txn.add(cmd.SetLSwitchPortCommand(self.fake_api, port['id'], True,
                                              up=True))

        ovn_mech_driver.set_port_status_up.assert_called_once_with(port['id'])
        ovn_mech_driver.set_port_status_down.assert_not_called()

        # Set the Logical_Switch_Port.up to False. ovsdb_monitor should
        # call mech_driver.set_port_status_down
        with self.idl_transaction(self.fake_api, check_error=True) as txn:
            txn.add(cmd.SetLSwitchPortCommand(self.fake_api, port['id'], True,
                                              up=False))
        ovn_mech_driver.set_port_status_down.assert_called_once_with(
            port['id'])

    def test_port_up_down_events(self):
        """Test the port up down events.

        This test case creates a port, sets the LogicalSwitchPort.up
        to True and False to test if the ovsdb monitor handles these
        events from the ovsdb server and calls the mech_driver
        functions 'set_port_status_up()' or 'set_port_status_down()' are not.

        For now mocking the 'set_port_status_up()' and 'set_port_status_down()'
        OVN mech driver functions to check if these functions are called or
        not by the ovsdb monitor.

        Ideally it would have been good to check that the port status
        is set to ACTIVE when mech_driver.set_port_status_up calls
        "provisioning_blocks.provisioning_complete". But it is not
        happening because port.binding.vif_type is unbound.

        TODO(numans) - Remove the mocking of these functions and instead create
        the port properly so that vif_type is set to "ovs".
        """
        self.mech_driver.set_port_status_up = mock.Mock()
        self.mech_driver.set_port_status_down = mock.Mock()
        with self.port(name='port') as p:
            p = p['port']
            # using the monitor IDL connection to the NB DB, set the
            # Logical_Switch_Port.up to False first. This is to mock the
            # ovn-controller setting it to False when the logical switch
            # port is created.
            with self.idl_transaction(self.fake_api, check_error=True) as txn:
                txn.add(cmd.SetLSwitchPortCommand(self.fake_api, p['id'], True,
                                                  up=False))

            self._test_port_up_down_helper(p, self.mech_driver)

    def test_ovsdb_monitor_lock(self):
        """Test case to test the ovsdb monitor lock used by OvnConnection.

        This test case created another IDL connection to the NB DB using
        the ovsdb_monitor.OvnConnection.

        With this we will have 2 'ovsdb_monitor.OvnConnection's. At the
        start the lock should be with the IDL connection created by the
        'TestOVNFunctionalBase' setup() function.

        The port up/down events should be handled by the first IDL connection.
        Then we will restart the first IDL connection so that the 2nd IDL
        connection created in this test case gets the lock and it should
        handle the port up/down events.

        Please note that the "self.monitor_idl_con" created by the base class
        is created using 'connection.Connection' and hence it will not contend
        for any lock.
        """
        tst_ovn_idl_conn = ovsdb_monitor.OvnConnection(
            self.ovsdb_server_mgr.get_ovsdb_connection_path(), 10,
            'OVN_Northbound')
        fake_driver = mock.MagicMock()
        tst_ovn_idl_conn.start(fake_driver)

        self.mech_driver.set_port_status_up = mock.Mock()
        self.mech_driver.set_port_status_down = mock.Mock()

        with self.port(name='port') as p:
            p = p['port']
            with self.idl_transaction(self.fake_api, check_error=True) as txn:
                txn.add(cmd.SetLSwitchPortCommand(self.fake_api, p['id'], True,
                                                  up=False))

            self._test_port_up_down_helper(p, self.mech_driver)
            fake_driver.set_port_status_up.assert_not_called()
            fake_driver.set_port_status_down.assert_not_called()

            # Now restart the mech_driver's IDL connection.
            self.mech_driver._nb_ovn.idl.force_reconnect()
            # Wait till the test_ovn_idl_conn has acquired the lock.
            n_utils.wait_until_true(lambda: tst_ovn_idl_conn.idl.has_lock)

            self.mech_driver.set_port_status_up.reset_mock()
            self.mech_driver.set_port_status_down.reset_mock()
            fake_driver.set_port_status_up.reset_mock()
            fake_driver.set_port_status_down.reset_mock()

            self._test_port_up_down_helper(p, fake_driver)
            self.assertFalse(self.mech_driver.set_port_status_up.called)
            self.assertFalse(self.mech_driver.set_port_status_down.called)

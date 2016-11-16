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
#

import mock

from networking_ovn.cmd import neutron_ovn_db_sync_util as cmd
from networking_ovn.tests import base


class TestNeutronOVNDBSyncUtil(base.TestCase):

    def setUp(self):
        super(TestNeutronOVNDBSyncUtil, self).setUp()
        self.cmd_log = mock.Mock()
        cmd.LOG = self.cmd_log
        self.cmd_sync = mock.Mock()
        self.cmd_sync.sync_address_sets = mock.Mock()
        self.cmd_sync.sync_networks_ports_and_dhcp_opts = mock.Mock()
        self.cmd_sync.sync_acls = mock.Mock()
        self.cmd_sync.sync_routers_and_rports = mock.Mock()
        self.cmd_sync_stages = [
            self.cmd_sync.sync_address_sets,
            self.cmd_sync.sync_networks_ports_and_dhcp_opts,
            self.cmd_sync.sync_acls,
            self.cmd_sync.sync_routers_and_rports,
        ]

    def _setup_default_mock_cfg(self, mock_cfg):
        mock_cfg.ovn.neutron_sync_mode = 'log'
        mock_cfg.core_plugin = 'neutron.plugins.ml2.plugin.Ml2Plugin'
        mock_cfg.ml2.mechanism_drivers = ['ovn']

    # Test that the configuration can be loaded successfully.
    def test_setup_conf(self):
        cmd.setup_conf()

    def test_main_invalid_conf(self):
        with mock.patch(
                'networking_ovn.cmd.neutron_ovn_db_sync_util.setup_conf',
                return_value=None):
            cmd.main()
        self.cmd_log.error.assert_called_once_with(
            'Error parsing the configuration values. Please verify.')

    @mock.patch('oslo_log.log.setup')
    @mock.patch('networking_ovn.cmd.neutron_ovn_db_sync_util.setup_conf')
    def test_main_invalid_nb_idl(self, mock_conf, mock_log_setup):
        with mock.patch('oslo_config.cfg.CONF') as mock_cfg, \
            mock.patch('networking_ovn.ovsdb.impl_idl_ovn.OvsdbNbOvnIdl',
                       side_effect=RuntimeError):
            self._setup_default_mock_cfg(mock_cfg)
            cmd.main()
        self.cmd_log.error.assert_called_once_with(
            'Invalid --ovn-ovn_nb_connection parameter provided.')

    @mock.patch('neutron_lib.plugins.directory.get_plugin')
    @mock.patch('networking_ovn.ovsdb.impl_idl_ovn.OvsdbNbOvnIdl')
    @mock.patch('oslo_log.log.setup')
    @mock.patch('networking_ovn.cmd.neutron_ovn_db_sync_util.setup_conf')
    def _test_main(self, mock_conf, mock_log_setup, mock_nb_idl, mock_plugin):
        cmd.main()

    def test_main_invalid_sync_mode(self):
        with mock.patch('oslo_config.cfg.CONF') as mock_cfg:
            self._setup_default_mock_cfg(mock_cfg)
            mock_cfg.ovn.neutron_sync_mode = 'off'
            self._test_main()
        self.cmd_log.error.assert_called_once_with(
            'Invalid sync mode : ["%s"]. Should be "log" or "repair"', 'off')

    def test_main_invalid_core_plugin(self):
        with mock.patch('oslo_config.cfg.CONF') as mock_cfg:
            self._setup_default_mock_cfg(mock_cfg)
            mock_cfg.core_plugin = 'foo'
            self._test_main()
        self.cmd_log.error.assert_called_once_with(
            'Invalid core plugin : ["%s"].', 'foo')

    def test_main_invalid_mechanism_driver(self):
        with mock.patch('oslo_config.cfg.CONF') as mock_cfg:
            self._setup_default_mock_cfg(mock_cfg)
            mock_cfg.ml2.mechanism_drivers = ['foo']
            self._test_main()
        self.cmd_log.error.assert_called_once_with(
            'No "ovn" mechanism driver found : "%s".', ['foo'])

    def _test_main_sync(self):
        with mock.patch('networking_ovn.ovn_db_sync.OvnNbSynchronizer',
                        return_value=self.cmd_sync), \
            mock.patch('oslo_config.cfg.CONF') as mock_cfg:
            self._setup_default_mock_cfg(mock_cfg)
            self._test_main()

    def test_main_sync_success(self):
        self._test_main_sync()
        self.cmd_sync.sync_address_sets.assert_called_once_with(mock.ANY)
        self.cmd_sync.sync_networks_ports_and_dhcp_opts.\
            assert_called_once_with(mock.ANY)
        self.cmd_sync.sync_acls.assert_called_once_with(mock.ANY)
        self.cmd_sync.sync_routers_and_rports.assert_called_once_with(mock.ANY)
        self.cmd_log.info.assert_called_with('Sync completed')

    def _test_main_sync_fail(self, stage):
        self.cmd_sync_stages[(stage - 1)].side_effect = Exception
        self._test_main_sync()
        for sync_stage in self.cmd_sync_stages[:stage]:
            sync_stage.assert_called_once_with(mock.ANY)
        for sync_stage in self.cmd_sync_stages[stage:]:
            sync_stage.assert_not_called()

    def test_main_sync_stage1_fail(self):
        self._test_main_sync_fail(1)
        self.cmd_log.exception.assert_called_once_with(
            "Error syncing  the Address Sets. Check the "
            "--database-connection value again")

    def test_main_sync_stage2_fail(self):
        self._test_main_sync_fail(2)
        self.cmd_log.exception.assert_called_once_with(
            "Error syncing  Networks, Ports and DHCP options "
            "for unknown reason please try again")

    def test_main_sync_stage3_fail(self):
        self._test_main_sync_fail(3)
        self.cmd_log.exception.assert_called_once_with(
            "Error syncing  ACLs for unknown "
            "reason please try again")

    def test_main_sync_stage4_fail(self):
        self._test_main_sync_fail(4)
        self.cmd_log.exception.assert_called_once_with(
            "Error syncing  Routers and Router ports "
            "please try again")

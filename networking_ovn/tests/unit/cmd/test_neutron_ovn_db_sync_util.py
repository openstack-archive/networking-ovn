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
        self.cmd_sync.do_sync = mock.Mock()
        self.cmd_sb_sync = mock.Mock()
        self.cmd_sb_sync.do_sync = mock.Mock()

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
    @mock.patch('networking_ovn.ovsdb.impl_idl_ovn.get_connection')
    def test_main_invalid_nb_idl(self, mock_con, mock_conf, mock_log_setup):
        with mock.patch('oslo_config.cfg.CONF') as mock_cfg, \
            mock.patch('networking_ovn.ovsdb.impl_idl_ovn.OvsdbNbOvnIdl',
                       side_effect=RuntimeError):
            self._setup_default_mock_cfg(mock_cfg)
            cmd.main()
        self.cmd_log.error.assert_called_once_with(
            'Invalid --ovn-ovn_nb_connection parameter provided.')

    @mock.patch('oslo_log.log.setup')
    @mock.patch('networking_ovn.cmd.neutron_ovn_db_sync_util.setup_conf')
    @mock.patch('networking_ovn.ovsdb.impl_idl_ovn.get_connection')
    def test_main_invalid_sb_idl(self, mock_con, mock_conf, mock_log_setup):
        with mock.patch('oslo_config.cfg.CONF') as mock_cfg, \
                mock.patch('networking_ovn.ovsdb.impl_idl_ovn.OvsdbSbOvnIdl',
                           side_effect=RuntimeError):
            self._setup_default_mock_cfg(mock_cfg)
            cmd.main()
        self.cmd_log.error.assert_called_once_with(
            'Invalid --ovn-ovn_sb_connection parameter provided.')

    @mock.patch('neutron.manager.init')
    @mock.patch('neutron_lib.plugins.directory.get_plugin')
    @mock.patch('networking_ovn.ovsdb.impl_idl_ovn.OvsdbNbOvnIdl')
    @mock.patch('oslo_log.log.setup')
    @mock.patch('networking_ovn.cmd.neutron_ovn_db_sync_util.setup_conf')
    @mock.patch('networking_ovn.ovsdb.impl_idl_ovn.get_connection')
    def _test_main(self, mock_con, mock_conf, mock_log_setup, mock_nb_idl,
                   mock_plugin, mock_manager_init):
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

    def test_main_no_mechanism_driver(self):
        with mock.patch('oslo_config.cfg.CONF') as mock_cfg:
            mock_cfg.ovn.neutron_sync_mode = 'repair'
            mock_cfg.core_plugin = 'ml2'
            mock_cfg.ml2.mechanism_drivers = []
            self._test_main()
        self.cmd_log.error.assert_called_once_with(
            'please use --config-file to specify '
            'neutron and ml2 configuration file.')

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
                mock.patch('networking_ovn.ovn_db_sync.OvnSbSynchronizer',
                           return_value=self.cmd_sb_sync), \
                mock.patch('oslo_config.cfg.CONF') as mock_cfg:
            self._setup_default_mock_cfg(mock_cfg)
            self._test_main()

    def test_main_sync_success(self):
        self._test_main_sync()
        self.cmd_sync.do_sync.assert_called_once_with()
        self.cmd_sb_sync.do_sync.assert_called_once_with()

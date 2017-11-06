# Copyright 2017 Red Hat, Inc.
# All Rights Reserved.
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

from neutron.tests.unit.plugins.ml2 import test_plugin
from neutron_lib.db import api as db_api

from networking_ovn.common import constants
from networking_ovn.common import maintenance
from networking_ovn.db import maintenance as db_maint
from networking_ovn.db import revision as db_rev
from networking_ovn.tests.unit.db import base as db_base


@mock.patch.object(maintenance.DBInconsistenciesPeriodics,
                   'has_lock', lambda _: True)
class TestDBInconsistenciesPeriodics(db_base.DBTestCase,
                                     test_plugin.Ml2PluginV2TestCase):

    def setUp(self):
        super(TestDBInconsistenciesPeriodics, self).setUp()
        self.net = self._make_network(
            self.fmt, name='net1', admin_state_up=True)['network']
        self.fake_ovn_client = mock.Mock()
        self.periodic = maintenance.DBInconsistenciesPeriodics(
            self.fake_ovn_client)
        self.session = db_api.get_writer_session()

    @mock.patch.object(maintenance.DBInconsistenciesPeriodics,
                       '_fix_create_update_network')
    @mock.patch.object(db_maint, 'get_inconsistent_resources')
    def test_check_for_inconsistencies(self, mock_get_incon_res, mock_fix_net):
        fake_row = mock.Mock(resource_type=constants.TYPE_NETWORKS)
        mock_get_incon_res.return_value = [fake_row, ]
        self.periodic.check_for_inconsistencies()
        mock_fix_net.assert_called_once_with(fake_row)

    def _test_fix_create_update_network(self, ovn_rev, neutron_rev):
        self.net['revision_number'] = neutron_rev

        # Create an entry to the revision_numbers table and assert the
        # initial revision_number for our test object is the expected
        db_rev.create_initial_revision(
            self.net['id'], constants.TYPE_NETWORKS, self.session,
            revision_number=ovn_rev)
        row = self.get_revision_row(self.net['id'])
        self.assertEqual(ovn_rev, row.revision_number)

        if ovn_rev < 0:
            self.fake_ovn_client._nb_idl.get_lswitch.return_value = None
        else:
            fake_ls = mock.Mock(external_ids={
                constants.OVN_REV_NUM_EXT_ID_KEY: ovn_rev})
            self.fake_ovn_client._nb_idl.get_lswitch.return_value = fake_ls

        self.fake_ovn_client._plugin.get_network.return_value = self.net
        self.periodic._fix_create_update_network(row)

        # Since the revision number was < 0, make sure create_network()
        # is invoked with the latest version of the object in the neutron
        # database
        if ovn_rev < 0:
            self.fake_ovn_client.create_network.assert_called_once_with(
                self.net)
        # If the revision number is > 0 it means that the object already
        # exist and we just need to update to match the latest in the
        # neutron database so, update_network() should be called.
        else:
            self.fake_ovn_client.update_network.assert_called_once_with(
                self.net)

    def test_fix_network_create(self):
        self._test_fix_create_update_network(ovn_rev=-1, neutron_rev=2)

    def test_fix_network_update(self):
        self._test_fix_create_update_network(ovn_rev=5, neutron_rev=7)

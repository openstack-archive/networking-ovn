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
from networking_ovn.db import revision as db_rev
from networking_ovn.tests.unit.db import base as db_base


class TestRevisionNumber(db_base.DBTestCase, test_plugin.Ml2PluginV2TestCase):

    def setUp(self):
        super(TestRevisionNumber, self).setUp()
        res = self._create_network(fmt=self.fmt, name='net',
                                   admin_state_up=True)
        self.net = self.deserialize(self.fmt, res)['network']
        self.session = db_api.get_writer_session()

    def test_bump_revision(self):
        db_rev.create_initial_revision(self.net['id'], constants.TYPE_NETWORKS,
                                       self.session)
        self.net['revision_number'] = 123
        db_rev.bump_revision(self.net, constants.TYPE_NETWORKS)
        row = db_rev.get_revision_row(self.net['id'])
        self.assertEqual(123, row.revision_number)

    def test_bump_older_revision(self):
        db_rev.create_initial_revision(self.net['id'], constants.TYPE_NETWORKS,
                                       self.session, revision_number=123)
        self.net['revision_number'] = 1
        db_rev.bump_revision(self.net, constants.TYPE_NETWORKS)
        # Assert the revision number wasn't bumped
        row = db_rev.get_revision_row(self.net['id'])
        self.assertEqual(123, row.revision_number)

    @mock.patch.object(db_rev.LOG, 'warning')
    def test_bump_revision_row_not_found(self, mock_log):
        self.net['revision_number'] = 123
        db_rev.bump_revision(self.net, constants.TYPE_NETWORKS)
        # Assert the revision number wasn't bumped
        row = db_rev.get_revision_row(self.net['id'])
        self.assertEqual(123, row.revision_number)
        self.assertIn('No revision row found for', mock_log.call_args[0][0])

    def test_delete_revision(self):
        db_rev.create_initial_revision(self.net['id'], constants.TYPE_NETWORKS,
                                       self.session)
        db_rev.delete_revision(self.net['id'], constants.TYPE_NETWORKS)
        row = db_rev.get_revision_row(self.net['id'])
        self.assertIsNone(row)

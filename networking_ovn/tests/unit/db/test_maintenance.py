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

from neutron.services.revisions import revision_plugin
from neutron.tests.unit.plugins.ml2 import test_plugin
from neutron_lib.db import api as db_api

from networking_ovn.common import constants
from networking_ovn.db import maintenance as db_maint
from networking_ovn.db import revision as db_rev
from networking_ovn.tests.unit.db import base as db_base


class TestMaintenance(db_base.DBTestCase, test_plugin.Ml2PluginV2TestCase):

    def setUp(self):
        super(TestMaintenance, self).setUp()
        self.net = self._make_network(
            self.fmt, name='net1', admin_state_up=True)['network']
        self.session = db_api.get_writer_session()
        revision_plugin.RevisionPlugin()

    def test_get_inconsistent_resources(self):
        # Set the intial revision to -1 to force it to be incosistent
        db_rev.create_initial_revision(
            self.net['id'], constants.TYPE_NETWORKS, self.session,
            revision_number=-1)
        res = db_maint.get_inconsistent_resources()
        self.assertEqual(1, len(res))
        self.assertEqual(self.net['id'], res[0].resource_uuid)

    def test_get_inconsistent_resources_consistent(self):
        # Set the initial revision to 0 which is the initial revision_number
        # for recently created resources
        db_rev.create_initial_revision(
            self.net['id'], constants.TYPE_NETWORKS, self.session,
            revision_number=0)
        res = db_maint.get_inconsistent_resources()
        # Assert nothing is inconsistent
        self.assertEqual([], res)

    def test_get_deleted_resources(self):
        db_rev.create_initial_revision(
            self.net['id'], constants.TYPE_NETWORKS, self.session,
            revision_number=0)
        self._delete('networks', self.net['id'])
        res = db_maint.get_deleted_resources()

        self.assertEqual(1, len(res))
        self.assertEqual(self.net['id'], res[0].resource_uuid)
        self.assertIsNone(res[0].standard_attr_id)

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

from neutron.tests.unit.testlib_api import SqlTestCaseLight
from neutron_lib import context
from neutron_lib.db import api as db_api
from sqlalchemy.orm import exc

from networking_ovn.db import models


class DBTestCase(SqlTestCaseLight):

    def setUp(self):
        super(DBTestCase, self).setUp()
        self.session = context.get_admin_context().session

    def tearDown(self):
        super(DBTestCase, self).tearDown()
        self.session.query(models.OVNRevisionNumbers).delete()

    def get_revision_row(self, resource_uuid):
        try:
            session = db_api.get_reader_session()
            with session.begin():
                return session.query(models.OVNRevisionNumbers).filter_by(
                    resource_uuid=resource_uuid).one()
        except exc.NoResultFound:
            pass

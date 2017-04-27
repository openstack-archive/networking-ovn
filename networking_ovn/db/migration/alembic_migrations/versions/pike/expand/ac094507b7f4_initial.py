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

"""initial networking-ovn contract branch

Revision ID: ac094507b7f4
Create Date: 2017-04-27 17:10:02.788089

"""

from neutron.db.migration import cli


# revision identifiers, used by Alembic.
revision = 'ac094507b7f4'
down_revision = 'initial_branchpoint'
branch_labels = (cli.EXPAND_BRANCH,)


def upgrade():
    pass

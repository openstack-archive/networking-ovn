# Copyright 2017 Red Hat, Inc.
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

"""Drop journaling related tables

Revision ID: bc9e24bb9da2
Revises: e229b8aad9f2
Create Date: 2017-08-10 11:00:25.428857

"""

# revision identifiers, used by Alembic.
revision = 'bc9e24bb9da2'
down_revision = 'e229b8aad9f2'

from alembic import op


def upgrade():
    op.drop_table('ovn_journal')
    op.drop_table('ovn_maintenance')

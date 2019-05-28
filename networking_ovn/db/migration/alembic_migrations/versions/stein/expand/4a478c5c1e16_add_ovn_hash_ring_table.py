# Copyright 2019 Red Hat, Inc.
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

from alembic import op
import sqlalchemy as sa

"""add ovn_hash_ring table

Revision ID: 4a478c5c1e16
Revises: 5c198d2723b6
Create Date: 2019-04-09 10:43:48.960899

"""

# revision identifiers, used by Alembic.
revision = '4a478c5c1e16'
down_revision = '5c198d2723b6'


def upgrade():
    op.create_table(
        'ovn_hash_ring',
        sa.Column('node_uuid', sa.String(36), nullable=False,
                  primary_key=True),
        sa.Column('hostname', sa.String(length=256), nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False,
                  default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False,
                  default=sa.func.now()),
    )

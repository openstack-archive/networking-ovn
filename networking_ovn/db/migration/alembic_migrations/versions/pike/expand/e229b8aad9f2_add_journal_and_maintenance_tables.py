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

"""add ovn_journal and ovn_maintenance tables

Revision ID: e229b8aad9f2
Revises: ac094507b7f4
Create Date: 2017-04-28 11:41:47.487584

"""

from alembic import op
from oslo_utils import uuidutils
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e229b8aad9f2'
down_revision = 'ac094507b7f4'


def upgrade():
    op.create_table(
        'ovn_journal',
        sa.Column('seqnum', sa.BigInteger(),
                  primary_key=True, autoincrement=True),
        sa.Column('object_type', sa.String(36), nullable=False),
        sa.Column('object_uuid', sa.String(36), nullable=False),
        sa.Column('operation', sa.String(36), nullable=False),
        sa.Column('data', sa.PickleType, nullable=True),
        sa.Column('state', sa.Enum('pending', 'processing',
                                   'failed', 'completed',
                                   name='state'),
                  nullable=False, default='pending'),
        sa.Column('retry_count', sa.Integer, default=0),
        sa.Column('created_at', sa.DateTime, default=sa.func.now()),
        sa.Column('last_retried', sa.TIMESTAMP, server_default=sa.func.now(),
                  onupdate=sa.func.now()),
    )

    maint_table = op.create_table(
        'ovn_maintenance',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('state', sa.Enum('pending', 'processing',
                                   name='state'),
                  nullable=False),
        sa.Column('processing_operation', sa.String(70)),
        sa.Column('lock_updated', sa.TIMESTAMP, nullable=False,
                  server_default=sa.func.now(),
                  onupdate=sa.func.now())
    )

    # Insert the only row here that is used to synchronize the lock between
    # different Neutron processes.
    op.bulk_insert(maint_table,
                   [{'id': uuidutils.generate_uuid(),
                     'state': 'pending'}])

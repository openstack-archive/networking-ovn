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

"""add_ovn_revision_numbers_table

Revision ID: f48286668608
Revises: 9a50bdf0c677
Create Date: 2017-08-18 09:59:20.021013

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f48286668608'
down_revision = 'bc9e24bb9da2'


def upgrade():
    op.create_table(
        'ovn_revision_numbers',
        sa.Column('standard_attr_id', sa.BigInteger, nullable=True),
        sa.Column('resource_uuid', sa.String(36), nullable=False,
                  primary_key=True),
        sa.Column('resource_type', sa.String(36), nullable=False),
        sa.Column('revision_number', sa.BigInteger, nullable=False, default=0),
        sa.Column('created_at', sa.DateTime, nullable=False,
                  default=sa.func.now()),
        sa.Column('updated_at', sa.TIMESTAMP, server_default=sa.func.now(),
                  onupdate=sa.func.now()),
        sa.ForeignKeyConstraint(
            ['standard_attr_id'], ['standardattributes.id'],
            ondelete='SET NULL')
    )

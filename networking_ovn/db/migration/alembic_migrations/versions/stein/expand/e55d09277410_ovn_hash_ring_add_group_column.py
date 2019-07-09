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
from sqlalchemy.engine.reflection import Inspector as insp

"""ovn_hash_ring_add_group_column

Revision ID: e55d09277410
Revises: 4a478c5c1e16
Create Date: 2019-07-09 13:26:31.356414

"""

# revision identifiers, used by Alembic.
revision = 'e55d09277410'
down_revision = '4a478c5c1e16'

MYSQL_ENGINE = 'mysql'


def upgrade():
    op.add_column(
        'ovn_hash_ring',
        sa.Column('group_name', sa.String(length=256), nullable=False))

    # Make node_uuid and group_name a composite PK
    bind = op.get_bind()
    engine = bind.engine

    if (engine.name == MYSQL_ENGINE):
        op.execute("ALTER TABLE ovn_hash_ring DROP PRIMARY KEY,"
                   "ADD PRIMARY KEY (node_uuid, group_name);")
    else:
        inspector = insp.from_engine(bind)
        pk_constraint = inspector.get_pk_constraint('ovn_hash_ring')
        op.drop_constraint(pk_constraint.get('name'), 'ovn_hash_ring',
                           type_='primary')
        op.create_primary_key(op.f('pk_ovn_hash_ring'),
                              'ovn_hash_ring', ['node_uuid', 'group_name'])

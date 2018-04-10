# Copyright 2018 Red Hat, Inc.
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

"""add_ovn_revision_resource_type_as_pk

Revision ID: 5c198d2723b6
Revises: f48286668608
Create Date: 2018-01-17 16:10:20.232123

"""

from alembic import op
from sqlalchemy.engine.reflection import Inspector as insp


# revision identifiers, used by Alembic.
revision = '5c198d2723b6'
down_revision = 'f48286668608'

MYSQL_ENGINE = 'mysql'
OVN_REVISION_NUMBER = 'ovn_revision_numbers'


def upgrade():

    bind = op.get_bind()
    engine = bind.engine

    if (engine.name == MYSQL_ENGINE):
        op.execute("ALTER TABLE ovn_revision_numbers DROP PRIMARY KEY,"
                   "ADD PRIMARY KEY (resource_uuid, resource_type);")
    else:
        inspector = insp.from_engine(bind)
        pk_constraint = inspector.get_pk_constraint(OVN_REVISION_NUMBER)
        op.drop_constraint(pk_constraint.get('name'), OVN_REVISION_NUMBER,
                           type_='primary')
        op.create_primary_key(op.f('pk_ovn_revision_numbers'),
                              OVN_REVISION_NUMBER, ['resource_uuid',
                                                    'resource_type'])

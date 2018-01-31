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

from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite


class OVNRevisionNumbers(model_base.BASEV2):
    __tablename__ = 'ovn_revision_numbers'
    __table_args__ = (
        model_base.BASEV2.__table_args__
    )
    standard_attr_id = sa.Column(
        sa.BigInteger().with_variant(sa.Integer(), 'sqlite'),
        sa.ForeignKey('standardattributes.id', ondelete='SET NULL'),
        nullable=True)
    resource_uuid = sa.Column(sa.String(36), nullable=False, primary_key=True)
    resource_type = sa.Column(sa.String(36), nullable=False, primary_key=True)
    revision_number = sa.Column(
        sa.BigInteger().with_variant(sa.Integer(), 'sqlite'),
        server_default='0', nullable=False)
    created_at = sa.Column(
        sa.DateTime().with_variant(
            sqlite.DATETIME(truncate_microseconds=True), 'sqlite'),
        default=sa.func.now())
    updated_at = sa.Column(sa.TIMESTAMP, server_default=sa.func.now(),
                           onupdate=sa.func.now())

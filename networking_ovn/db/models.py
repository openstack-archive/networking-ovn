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

from networking_ovn.journal import constants as journal_const


class OVNJournal(model_base.BASEV2):
    __tablename__ = 'ovn_journal'

    seqnum = sa.Column(sa.BigInteger().with_variant(sa.Integer(), 'sqlite'),
                       primary_key=True, autoincrement=True)
    object_type = sa.Column(sa.String(36), nullable=False)
    object_uuid = sa.Column(sa.String(36), nullable=False)
    operation = sa.Column(sa.String(36), nullable=False)
    data = sa.Column(sa.PickleType, nullable=True)
    state = sa.Column(sa.Enum(journal_const.PENDING,
                              journal_const.FAILED,
                              journal_const.PROCESSING,
                              journal_const.COMPLETED),
                      nullable=False, default=journal_const.PENDING)
    retry_count = sa.Column(sa.Integer, default=0)
    created_at = sa.Column(
        sa.DateTime().with_variant(
            sqlite.DATETIME(truncate_microseconds=True), 'sqlite'),
        server_default=sa.func.now())
    last_retried = sa.Column(sa.TIMESTAMP, server_default=sa.func.now(),
                             onupdate=sa.func.now())


class OVNMaintenance(model_base.BASEV2, model_base.HasId):
    __tablename__ = 'ovn_maintenance'

    state = sa.Column(sa.Enum(journal_const.PENDING, journal_const.PROCESSING),
                      nullable=False)
    processing_operation = sa.Column(sa.String(70))
    lock_updated = sa.Column(sa.TIMESTAMP, nullable=False,
                             server_default=sa.func.now(),
                             onupdate=sa.func.now())

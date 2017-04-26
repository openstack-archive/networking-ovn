# Copyright (c) 2015 OpenStack Foundation
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

import datetime

from neutron.db import api as db_api
from oslo_db import api as oslo_db_api
from sqlalchemy import asc
from sqlalchemy import func

from networking_ovn.db import models
from networking_ovn.journal import constants as journal_const

#
# Journal functions
#


# Retry deadlock exception for Galera DB.
# If two (or more) different threads call this method at the same time, they
# might both succeed in changing the same row to pending, but at least one
# of them will get a deadlock from Galera and will have to retry the operation.
@db_api.retry_db_errors
def get_oldest_pending_db_row_with_lock(session):
    with session.begin():
        row = session.query(models.OVNJournal).filter_by(
            state=journal_const.PENDING).order_by(
            asc(models.OVNJournal.last_retried)).with_for_update(
        ).first()
        if row:
            update_db_row_state(session, row, journal_const.PROCESSING)

    return row


@oslo_db_api.wrap_db_retry(max_retries=db_api.MAX_RETRIES)
def update_db_row_state(session, row, state):
    row.state = state
    session.merge(row)
    session.flush()


def update_pending_db_row_retry(session, row, retry_count):
    if row.retry_count >= retry_count:
        update_db_row_state(session, row, journal_const.FAILED)
    else:
        row.retry_count += 1
        update_db_row_state(session, row, journal_const.PENDING)


@oslo_db_api.wrap_db_retry(max_retries=db_api.MAX_RETRIES)
def create_pending_row(session, object_type, object_uuid,
                       operation, data):
    row = models.OVNJournal(object_type=object_type,
                            object_uuid=object_uuid,
                            operation=operation, data=data,
                            created_at=func.now(),
                            state=journal_const.PENDING)
    session.add(row)
    session.flush()


#
# Journal maintenance functions
#


@db_api.retry_db_errors
def _update_maintenance_state(session, expected_state, state):
    with session.begin():
        row = session.query(models.OVNMaintenance).filter_by(
            state=expected_state).with_for_update().one_or_none()
        if row is None:
            return False

        row.state = state
        return True


def lock_maintenance(session):
    return _update_maintenance_state(session, journal_const.PENDING,
                                     journal_const.PROCESSING)


def unlock_maintenance(session):
    return _update_maintenance_state(session, journal_const.PROCESSING,
                                     journal_const.PENDING)


def update_maintenance_operation(session, operation=None):
    """Update the current maintenance operation details.

    The function assumes the lock is held, so it mustn't be run outside
    of a locked context.
    """
    op_text = None
    if operation:
        op_text = operation.__name__

    with session.begin():
        row = session.query(models.OVNMaintenance).one_or_none()
        row.processing_operation = op_text


#
# Journal clean up functions
#


def delete_rows_by_state_and_time(session, state, time_delta):
    with session.begin():
        now = session.execute(func.now()).scalar()
        session.query(models.OVNJournal).filter(
            models.OVNJournal.state == state,
            models.OVNJournal.last_retried < now - time_delta).delete(
            synchronize_session=False)
        session.expire_all()


def reset_processing_rows(session, max_timedelta):
    with session.begin():
        now = session.execute(func.now()).scalar()
        max_timedelta = datetime.timedelta(seconds=max_timedelta)
        rows = session.query(models.OVNJournal).filter(
            models.OVNJournal.last_retried < now - max_timedelta,
            models.OVNJournal.state == journal_const.PROCESSING,
        ).update({'state': journal_const.PENDING})

    return rows

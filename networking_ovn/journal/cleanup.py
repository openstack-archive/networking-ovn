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

from datetime import timedelta

from oslo_log import log as logging

from networking_ovn.db import db
from networking_ovn.journal import constants as journal_const

LOG = logging.getLogger(__name__)


class JournalCleanup(object):

    def __init__(self, completed_rows_retention, processing_timeout):
        """Journal maintenance operation for deleting completed rows.

        :param completed_rows_retention: Time (in seconds) to keep rows
            marked as COMPLETED in the database.
        :param processing_timeout: Time (in seconds) to wait before a
            row marked as PROCESSING is set back to PENDING.
        """
        self._completed_rows_retention = completed_rows_retention
        self._processing_timeout = processing_timeout

    def delete_completed_rows(self, session):
        if self._completed_rows_retention > 0:
            LOG.debug('Journal clean up: Deleting completed rows')
            db.delete_rows_by_state_and_time(
                session, journal_const.COMPLETED,
                timedelta(seconds=self._completed_rows_retention))

    def cleanup_processing_rows(self, session):
        row_count = db.reset_processing_rows(session, self._processing_timeout)
        if row_count:
            LOG.info('Reset %(num)s orphaned rows back to pending',
                     {'num': row_count})

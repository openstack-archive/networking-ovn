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

import abc
import random
import threading
import time

from neutron.db import api as neutron_db_api
from oslo_log import log
from oslo_utils import uuidutils
import six

from networking_ovn.db import db
from networking_ovn.journal import constants
from networking_ovn.journal import exceptions

LOG = log.getLogger(__name__)

WAKE_UP_EVENTS = {}


def _wake_random_journal_thread():
    """Wake up a random journal sync thread."""
    try:
        thread_id = random.choice(list(WAKE_UP_EVENTS))
    except IndexError:
        return
    WAKE_UP_EVENTS[thread_id].set()


def wake_journal_thread_on_end(func):
    def new_func(obj, *args, **kwargs):
        return_value = func(obj, *args, **kwargs)
        _wake_random_journal_thread()
        return return_value
    return new_func


def record(plugin_context, object_type, object_uuid, operation, data):
    db.create_pending_row(plugin_context.session, object_type, object_uuid,
                          operation, data)


@six.add_metaclass(abc.ABCMeta)
class JournalThread(object):
    """Thread worker for the Journal Database."""

    def __init__(self, sync_timeout, retry_count):
        self._sync_timeout = sync_timeout
        self._retry_count = retry_count
        self._stop_event = threading.Event()
        self._sync_thread = None
        self.uuid = uuidutils.generate_uuid()

    def start(self):
        """Start the journal sync thread."""
        if self._sync_thread is not None:
            raise exceptions.JournalAlreadyStarted()

        LOG.debug('Starting the journal sync thread')
        WAKE_UP_EVENTS[self.uuid] = threading.Event()
        self._stop_event.clear()
        self._sync_thread = threading.Thread(name='sync', target=self._run)
        self._sync_thread.start()

    def stop(self):
        """Stop the journal sync thread."""
        LOG.debug('Stopping the journal sync thread')
        self._stop_event.set()
        if self.uuid in WAKE_UP_EVENTS:
            WAKE_UP_EVENTS[self.uuid].set()
            del WAKE_UP_EVENTS[self.uuid]

    @abc.abstractmethod
    def validate_dependencies(self, session, entry):
        """Validate resource dependency in journaled operations.

        :returns: Boolean value. True if validation succeed, False
            otherwise.
        """

    @abc.abstractmethod
    def sync_entry(self, entry):
        """Performance a synchronization operation on a given entry.

        :raises: NonRetryableError
        """

    def _run(self):
        while not self._stop_event.is_set():
            try:
                session = neutron_db_api.get_writer_session()
                self._sync_pending_entries(session)
            except Exception:
                LOG.exception('Unknown error while running the journal sync')

            WAKE_UP_EVENTS[self.uuid].wait(timeout=self._sync_timeout)
            WAKE_UP_EVENTS[self.uuid].clear()

        # Clear the _sync_thread after it's fully stopped
        self._sync_thread = None

    def _sync_pending_entries(self, session):

        entry = db.get_oldest_pending_db_row_with_lock(session)
        if entry is None:
            return

        LOG.debug('Start processing journal entries')
        while entry is not None:
            log_dict = {'op': entry.operation, 'type': entry.object_type,
                        'id': entry.object_uuid}

            if not self.validate_dependencies(session, entry):
                db.update_db_row_state(session, entry, constants.PENDING)
                LOG.info('Skipping %(op)s %(type)s %(id)s due to '
                         'unprocessed dependencies', log_dict)
                break

            LOG.info('Processing - %(op)s %(type)s %(id)s', log_dict)
            try:
                self.sync_entry(entry)
                db.update_db_row_state(session, entry, constants.COMPLETED)
            except exceptions.NonRetryableError as e:
                log_dict['error'] = e
                db.update_db_row_state(session, entry, constants.PENDING)
                LOG.error('Non-retryable error while processing %(op)s '
                          '%(type)s %(id)s, will not process additional '
                          'entries. Error: %(error)s. ', log_dict)
                break
            except Exception:
                LOG.exception('Error while processing %(op)s %(type)s %(id)s',
                              log_dict)
                db.update_pending_db_row_retry(session, entry,
                                               self._retry_count)
                # TODO(lucasagomes): Make this interval configurable ?!
                time.sleep(1)

            entry = db.get_oldest_pending_db_row_with_lock(session)
        LOG.debug('Finished processing journal entries')

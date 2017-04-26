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

from neutron.db import api as neutron_db_api
from oslo_log import log as logging
from oslo_service import loopingcall

from networking_ovn.db import db


LOG = logging.getLogger(__name__)


class MaintenanceThread(object):

    def __init__(self, interval):
        self._timer = loopingcall.FixedIntervalLoopingCall(self.execute_ops)
        self._interval = interval
        self._operations = []

    def start(self):
        self._timer.start(self._interval, stop_on_exception=False)

    def _execute_op(self, operation, session):
        op_details = operation.__name__
        if operation.__doc__:
            op_details += ' (%s)' % operation.func_doc

        try:
            LOG.info('Starting maintenance operation %s', op_details)
            db.update_maintenance_operation(session, operation=operation)
            operation(session=session)
            LOG.info('Finished maintenance operation %s', op_details)
        except Exception:
            LOG.exception('Unknown error during maintenance operation %s',
                          op_details)

    def execute_ops(self):
        LOG.debug('Starting journal maintenance run')
        session = neutron_db_api.get_writer_session()
        if not db.lock_maintenance(session):
            return

        try:
            for operation in self._operations:
                self._execute_op(operation, session)
        finally:
            db.update_maintenance_operation(session, operation=None)
            db.unlock_maintenance(session)
            LOG.debug('Finished journal maintenance run')

    def register_operation(self, func):
        """Register a function to be run by the maintenance thread.

        :param f: Function to call when the thread runs. The function will
        receive a DB session to use for DB operations.
        """
        self._operations.append(func)

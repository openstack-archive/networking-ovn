# Copyright 2015 Red Hat, Inc.
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

from oslo_log import log as logging
from ovs.db import idl
import six

from neutron.agent.ovsdb.native import idlutils

LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class RowEvent(object):
    ROW_CREATE = idl.ROW_CREATE
    ROW_UPDATE = idl.ROW_UPDATE
    ROW_DELETE = idl.ROW_DELETE
    ONETIME = False

    def __init__(self, events, table, conditions, old_conditions=None):
        self.table = table
        self.events = events
        self.conditions = conditions
        self.old_conditions = old_conditions
        self.event_name = 'RowEvent'

    def _key(self):
        return (self.__class__, self.table, self.events, self.conditions)

    def __hash__(self):
        return hash(self._key())

    def __eq__(self, other):
        return self._key() == other._key()

    def matches(self, event, row, old=None):
        if event not in self.events:
            return False
        if row._table.name != self.table:
            return False
        if self.conditions and not idlutils.row_match(row, self.conditions):
            return False
        if self.old_conditions:
            if not old:
                return False
            try:
                if not idlutils.row_match(old, self.old_conditions):
                    return False
            except (KeyError, AttributeError):
                # Its possible that old row may not have all columns in it
                return False

        LOG.debug("%s : Matched %s, %s, %s %s", self.event_name, self.table,
                  str(self.events), str(self.conditions),
                  str(self.old_conditions))
        return True

    @abc.abstractmethod
    def run(self, event, row, old):
        """Method to run when the event matches"""

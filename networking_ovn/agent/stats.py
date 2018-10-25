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

import collections

from oslo_utils import timeutils

Stats = collections.namedtuple("Stats", ['nb_cfg', 'updated_at'])


class _AgentStats(object):
    def __init__(self):
        self._agents = {}

    def add_stat(self, uuid, nb_cfg, updated_at=None):
        self._agents[uuid] = Stats(nb_cfg, updated_at or timeutils.utcnow())

    def get_stat(self, uuid):
        return self._agents[uuid]

    def del_agent(self, uuid):
        del self._agents[uuid]


AgentStats = _AgentStats()

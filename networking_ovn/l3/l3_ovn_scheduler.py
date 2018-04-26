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

import abc
import copy
import random

from oslo_log import log
import six

from networking_ovn.common import config as ovn_config
from networking_ovn.common import constants as ovn_const


LOG = log.getLogger(__name__)

OVN_SCHEDULER_CHANCE = 'chance'
OVN_SCHEDULER_LEAST_LOADED = 'leastloaded'

MAX_GW_CHASSIS = 5


@six.add_metaclass(abc.ABCMeta)
class OVNGatewayScheduler(object):

    def __init__(self):
        pass

    @abc.abstractmethod
    def select(self, nb_idl, sb_idl, gateway_name, candidates=None):
        """Schedule the gateway port of a router to an OVN chassis.

        Schedule the gateway router port only if it is not already
        scheduled.
        """
        pass

    def _schedule_gateway(self, nb_idl, sb_idl, gateway_name, candidates):
        existing_chassis = nb_idl.get_gateway_chassis_binding(gateway_name)
        candidates = candidates or self._get_chassis_candidates(sb_idl)
        # if no candidates or all chassis in existing_chassis also present
        # in candidates, then return existing_chassis
        # TODO(anilvenkata): If more candidates avaialable, then schedule
        # on them also?
        if existing_chassis and (not candidates or
           not (set(existing_chassis) - set(candidates))):
            return existing_chassis
        if not candidates:
            return [ovn_const.OVN_GATEWAY_INVALID_CHASSIS]
        # The actual binding of the gateway to a chassis via the options
        # column or gateway_chassis column in the OVN_Northbound is done
        # by the caller
        chassis = self._select_gateway_chassis(
            nb_idl, candidates)[:MAX_GW_CHASSIS]

        LOG.debug("Gateway %s scheduled on chassis %s",
                  gateway_name, chassis)
        return chassis

    @abc.abstractmethod
    def _select_gateway_chassis(self, nb_idl, candidates):
        """Choose a chassis from candidates based on a specific policy."""
        pass

    def _get_chassis_candidates(self, sb_idl):
        # TODO(azbiswas): Allow selection of a specific type of chassis when
        # the upstream code merges.
        # return sb_idl.get_all_chassis('gateway_router') or \
        #    sb_idl.get_all_chassis()
        return sb_idl.get_all_chassis()


class OVNGatewayChanceScheduler(OVNGatewayScheduler):
    """Randomly select an chassis for a gateway port of a router"""

    def select(self, nb_idl, sb_idl, gateway_name, candidates=None):
        return self._schedule_gateway(nb_idl, sb_idl, gateway_name, candidates)

    def _select_gateway_chassis(self, nb_idl, candidates):
        candidates = copy.deepcopy(candidates)
        random.shuffle(candidates)
        return candidates


class OVNGatewayLeastLoadedScheduler(OVNGatewayScheduler):
    """Select the least loaded chassis for a gateway port of a router"""

    def select(self, nb_idl, sb_idl, gateway_name, candidates=None):
        return self._schedule_gateway(nb_idl, sb_idl, gateway_name, candidates)

    @staticmethod
    def _get_chassis_load_by_prios(chassis_info):
        """Retrieve the amount of ports by priorities hosted in the chassis.

        @param   chassis_info: list of (port, prio) hosted by this chassis
        @type    chassis_info: []
        @return: A list of (prio, number_of_ports) tuples.
        """
        chassis_load = {}
        for lrp, prio in chassis_info:
            chassis_load[prio] = chassis_load.get(prio, 0) + 1
        return chassis_load.items()

    @staticmethod
    def _get_chassis_load(chassis):
        chassis_ports_prios = chassis[1]
        return sorted(
            OVNGatewayLeastLoadedScheduler._get_chassis_load_by_prios(
                chassis_ports_prios), reverse=True)

    def _select_gateway_chassis(self, nb_idl, candidates):
        chassis_bindings = nb_idl.get_all_chassis_gateway_bindings(candidates)
        return [chassis for chassis, load in sorted(chassis_bindings.items(),
                key=OVNGatewayLeastLoadedScheduler._get_chassis_load)]


OVN_SCHEDULER_STR_TO_CLASS = {
    OVN_SCHEDULER_CHANCE: OVNGatewayChanceScheduler,
    OVN_SCHEDULER_LEAST_LOADED: OVNGatewayLeastLoadedScheduler
    }


def get_scheduler():
    return OVN_SCHEDULER_STR_TO_CLASS[ovn_config.get_ovn_l3_scheduler()]()

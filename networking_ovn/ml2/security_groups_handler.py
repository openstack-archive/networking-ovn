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

from oslo_log import log as logging

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources


LOG = logging.getLogger(__name__)


class OvnSecurityGroupsHandler(object):

    def __init__(self, ovn_api):
        self.ovn_api = ovn_api
        self.subscribe()

    def security_group_after_create(self, resource, event,
                                    trigger, **kwargs):
        pass

    def security_group_after_update(self, resource, event,
                                    trigger, **kwargs):
        pass

    def security_group_after_delete(self, resource, event,
                                    trigger, **kwargs):
        pass

    def security_group_rule_after_create(self, resource, event,
                                         trigger, **kwargs):
        pass

    def security_group_rule_after_delete(self, resource, event,
                                         trigger, **kwargs):
        pass

    def subscribe(self):
        registry.subscribe(
            self.security_group_after_create,
            resources.SECURITY_GROUP, events.AFTER_CREATE)
        registry.subscribe(
            self.security_group_after_update,
            resources.SECURITY_GROUP, events.AFTER_UPDATE)
        registry.subscribe(
            self.security_group_after_delete,
            resources.SECURITY_GROUP, events.AFTER_DELETE)
        registry.subscribe(
            self.security_group_rule_after_create,
            resources.SECURITY_GROUP_RULE, events.AFTER_CREATE)
        registry.subscribe(
            self.security_group_rule_after_delete,
            resources.SECURITY_GROUP_RULE, events.AFTER_DELETE)

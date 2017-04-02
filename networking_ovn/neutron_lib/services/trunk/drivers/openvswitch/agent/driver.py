# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_log import log as logging
import oslo_messaging

#from neutron._i18n import _LE
from networking_ovn._i18n import _LE
from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
#from neutron.services.trunk.drivers.openvswitch.agent import ovsdb_handler
from networking_ovn.neutron_lib.services.trunk.drivers.openvswitch.agent import ovsdb_handler
#from neutron.services.trunk.drivers.openvswitch.agent import trunk_manager
from networking_ovn.neutron_lib.services.trunk.drivers.openvswitch.agent import trunk_manager
#from neutron.services.trunk.rpc import agent
from networking_ovn.neutron_lib.services.trunk.rpc import agent

LOG = logging.getLogger(__name__)

TRUNK_SKELETON = None


class OVSTrunkSkeleton(agent.TrunkSkeleton):
    """It processes Neutron Server events to create the physical resources
    associated to a logical trunk in response to user initiated API events
    (such as trunk subport add/remove). It collaborates with the OVSDBHandler
    to implement the trunk control plane.
    """

    def __init__(self, ovsdb_handler):
        super(OVSTrunkSkeleton, self).__init__()
        self.ovsdb_handler = ovsdb_handler
        registry.unsubscribe(self.handle_trunks, resources.TRUNK)

    def handle_trunks(self, trunk, event_type):
        """This method is not required by the OVS Agent driver.

        Trunk notifications are handled via local OVSDB events.
        """
        raise NotImplementedError()

    def handle_subports(self, subports, event_type):
        # Subports are always created with the same trunk_id and there is
        # always at least one item in subports list
        trunk_id = subports[0].trunk_id

        if self.ovsdb_handler.manages_this_trunk(trunk_id):
            if event_type not in (events.CREATED, events.DELETED):
                LOG.error(_LE("Unknown or unimplemented event %s"), event_type)
                return

            ctx = self.ovsdb_handler.context
            try:
                LOG.debug("Event %s for subports: %s", event_type, subports)
                if event_type == events.CREATED:
                    status = self.ovsdb_handler.wire_subports_for_trunk(
                            ctx, trunk_id, subports)
                elif event_type == events.DELETED:
                    subport_ids = [subport.port_id for subport in subports]
                    status = self.ovsdb_handler.unwire_subports_for_trunk(
                        trunk_id, subport_ids)
                self.ovsdb_handler.report_trunk_status(ctx, trunk_id, status)
            except oslo_messaging.MessagingException as e:
                LOG.error(_LE(
                    "Error on event %(event)s for subports "
                    "%(subports)s: %(err)s"),
                    {'event': event_type, 'subports': subports, 'err': e})


def init_handler(resource, event, trigger, agent=None):
    """Handler for agent init event."""
    # Set up agent-side RPC for receiving trunk events; we may want to
    # make this setup conditional based on server-side capabilities.
    global TRUNK_SKELETON

    manager = trunk_manager.TrunkManager(agent.int_br)
    handler = ovsdb_handler.OVSDBHandler(manager)
    TRUNK_SKELETON = OVSTrunkSkeleton(handler)

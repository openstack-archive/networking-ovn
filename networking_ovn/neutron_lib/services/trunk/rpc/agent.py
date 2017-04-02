# Copyright 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import abc

import oslo_messaging

from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
#from neutron.common import rpc as n_rpc
from networking_ovn.neutron_lib.common import rpc as n_rpc
#from neutron.services.trunk.rpc import constants as trunk_consts
from networking_ovn.neutron_lib.services.trunk.rpc import constants as trunk_consts

# This module contains stub (client-side) and skeleton (server-side)
# proxy code that executes in the Neutron L2 Agent process space. This
# is needed if trunk service plugin drivers have a remote component
# (e.g. agent), that needs to communicate with the Neutron Server.

# The Agent side exposes the following remote methods:
#
# - update methods to learn about a trunk and its subports: these
#   methods are used by the server to tell the agent about trunk
#   updates; agents may selectively choose to listen to either
#   trunk or subports updates or both.
#
# For server-side stub and skeleton proxy code, please look at server.py


class TrunkSkeleton(object):
    """Skeleton proxy code for server->agent communication."""

    def __init__(self):
        registry.subscribe(self.handle_trunks, resources.TRUNK)
        registry.subscribe(self.handle_subports, resources.SUBPORT)

        self._connection = n_rpc.create_connection()
        endpoints = [resources_rpc.ResourcesPushRpcCallback()]
        topic = resources_rpc.resource_type_versioned_topic(resources.SUBPORT)
        self._connection.create_consumer(topic, endpoints, fanout=True)
        topic = resources_rpc.resource_type_versioned_topic(resources.TRUNK)
        self._connection.create_consumer(topic, endpoints, fanout=True)
        self._connection.consume_in_threads()

    @abc.abstractmethod
    def handle_trunks(self, trunks, event_type):
        """Handle trunk events."""
        # if common logic may be extracted out, consider making a base
        # version of this method that can be overidden by the inherited
        # skeleton.
        # NOTE: If trunk is not managed by the agent, the notification can
        # either be ignored or cached for future use.

    @abc.abstractmethod
    def handle_subports(self, subports, event_type):
        """Handle subports event."""
        # if common logic may be extracted out, consider making a base
        # version of this method that can be overidden by the inherited
        # skeleton.
        # NOTE: If the subport belongs to a trunk which the agent does not
        # manage, the notification should be ignored.


class TrunkStub(object):
    """Stub proxy code for agent->server communication."""
    # API HISTORY
    #   1.0 - initial version
    VERSION = '1.0'

    def __init__(self):
        self.stub = resources_rpc.ResourcesPullRpcApi()
        target = oslo_messaging.Target(
            topic=trunk_consts.TRUNK_BASE_TOPIC,
            version=self.VERSION,
            namespace=trunk_consts.TRUNK_BASE_NAMESPACE)
        self.rpc_client = n_rpc.get_client(target)

    def get_trunk_details(self, context, parent_port_id):
        """Get information about the trunk for the given parent port."""
        return self.stub.pull(context, resources.TRUNK, parent_port_id)

    def update_trunk_status(self, context, trunk_id, status):
        """Update the trunk status to reflect outcome of data plane wiring."""
        return self.rpc_client.prepare().call(
            context, 'update_trunk_status',
            trunk_id=trunk_id, status=status)

    def update_subport_bindings(self, context, subports):
        """Update subport bindings to match parent port host binding."""
        return self.rpc_client.prepare().call(
            context, 'update_subport_bindings', subports=subports)

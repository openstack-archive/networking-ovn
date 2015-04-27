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

from neutron.common import constants as n_const
from neutron.extensions import portbindings
from neutron.plugins.ml2 import driver_api

from networking_ovn.ovsdb import impl_idl_ovn


class OVNMechDriver(driver_api.MechanismDriver):

    """OVN ML2 MechanismDriver for Neutron.

    This driver currently executes the ovn-nbctl utility.  This works as an
    initial pass to make something work, but the driver will need to be
    reworked to use ovsdb directly.
    """
    def __init__(self):
        super(OVNMechDriver, self).__init__()

    def initialize(self):
        self.vif_type = portbindings.VIF_TYPE_OVS
        # When set to True, Nova plugs the VIF directly into the ovs bridge
        # instead of using the hybrid mode.
        self.vif_details = {portbindings.CAP_PORT_FILTER: True}

        self._ovn = impl_idl_ovn.OvsdbOvnIdl()

    @staticmethod
    def _ovn_name(id):
        # The name of the OVN entry will be neutron-<UUID>
        # This is due to the fact that the OVN appliaction checks if the name
        # is a UUID. If so then there will be no matches.
        # We prefix the UUID to enable us to use the Neutron UUID when
        # updating, deleting etc.
        return 'neutron-%s' % id

    def _set_network_name(self, network):
        ext_id = ['neutron:network_name', network['name']]
        self._ovn.set_lswitch_ext_id(
            OVNMechDriver._ovn_name(network['id']),
            ext_id).execute()

    def _set_network_id(self, network):
        ext_id = ['neutron:network_id', network['id']]
        self._ovn.set_lswitch_ext_id(
            OVNMechDriver._ovn_name(network['id']),
            ext_id).execute()

    def create_network_postcommit(self, context):
        network = context.current
        # Create a logical switch with a name equal to the Neutron network
        # UUID.  This provides an easy way to refer to the logical switch
        # without having to track what UUID OVN assigned to it.
        self._ovn.create_lswitch(
            OVNMechDriver._ovn_name(network['id'])).execute()
        self._set_network_id(network)
        self._set_network_name(network)

    def update_network_postcommit(self, context):
        network = context.current
        # The only field that might get updated that we care about right now is
        # the name.
        self._set_network_name(network)

    def delete_network_postcommit(self, context):
        network = context.current
        self._ovn.delete_lswitch(
            OVNMechDriver._ovn_name(network['id'])).execute()

    def create_subnet_postcommit(self, context):
        pass

    def update_subnet_postcommit(self, context):
        pass

    def delete_subnet_postcommit(self, context):
        pass

    def _set_port_name(self, port):
        ext_id = ['neutron:port_name', port['name']]
        self._ovn.set_lport_ext_id(port['id'], ext_id).execute()

    def create_port_postcommit(self, context):
        port = context.current
        # The port name *must* be port['id'].  It must match the iface-id set
        # in the Interfaces table of the Open_vSwitch database, which nova sets
        # to be the port ID.
        self._ovn.create_lport(
            port['id'],
            OVNMechDriver._ovn_name(port['network_id'])).execute()
        self._ovn.set_lport_ext_id(port['id'], port['mac_address']).execute()
        self._set_port_name(port)

    def update_port_postcommit(self, context):
        port = context.current
        # Neutron allows you to update the MAC address on a port.
        self._ovn.set_lport_ext_id(port['id'], port['mac_address']).execute()
        # Neutron allows you to update the name on a port.
        self._set_port_name(port)

    def delete_port_postcommit(self, context):
        port = context.current
        self._ovn.delete_lport(port['id']).execute()

    def bind_port(self, context):
        # This is just a temp solution so that Nova can boot images
        for segment in context.segments_to_bind:
            context.set_binding(segment[driver_api.ID],
                                self.vif_type,
                                self.vif_details,
                                status=n_const.PORT_STATUS_ACTIVE)

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

import six

from neutron.common import constants as n_const
from neutron.common import exceptions as n_exc
from neutron.extensions import portbindings
from neutron.i18n import _
from neutron.plugins.ml2 import driver_api

from networking_ovn.common import config as cfg
from networking_ovn.common import constants as ovn_const
from networking_ovn.common import utils
from networking_ovn.ml2 import ovn_nb_sync
from networking_ovn.ml2 import security_groups_handler as sec_handler
from networking_ovn.ovsdb import impl_idl_ovn


class OVNMechDriver(driver_api.MechanismDriver):

    """OVN ML2 MechanismDriver for Neutron.

    """
    def initialize(self):
        self.vif_type = portbindings.VIF_TYPE_OVS
        # When set to True, Nova plugs the VIF directly into the ovs bridge
        # instead of using the hybrid mode.
        self.vif_details = {portbindings.CAP_PORT_FILTER: True}

        self._ovn = impl_idl_ovn.OvsdbOvnIdl()
        self.security_handler = sec_handler.OvnSecurityGroupsHandler(self._ovn)

        # Call the synchronization task, this sync neutron DB to OVN-NB DB
        # only in inconsistent states
        self.synchronizer = (
            ovn_nb_sync.OvnNbSynchronizer(self,
                                          self._ovn,
                                          cfg.get_ovn_neutron_sync_mode()))
        self.synchronizer.sync()

    def _set_network_name(self, network):
        ext_id = [ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY, network['name']]
        self._ovn.set_lswitch_ext_id(
            utils.ovn_name(network['id']),
            ext_id).execute(check_error=True)

    def create_network_postcommit(self, context):
        network = context.current
        # Create a logical switch with a name equal to the Neutron network
        # UUID.  This provides an easy way to refer to the logical switch
        # without having to track what UUID OVN assigned to it.
        external_ids = {ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: network['name']}
        self._ovn.create_lswitch(lswitch_name=utils.ovn_name(network['id']),
                                 external_ids=external_ids).execute(
                                     check_error=True)

    def update_network_postcommit(self, context):
        network = context.current
        # The only field that might get updated that we care about right now is
        # the name.
        self._set_network_name(network)

    def delete_network_postcommit(self, context):
        network = context.current
        self._ovn.delete_lswitch(
            utils.ovn_name(network['id'])).execute(check_error=True)

    def create_subnet_postcommit(self, context):
        pass

    def update_subnet_postcommit(self, context):
        pass

    def delete_subnet_postcommit(self, context):
        pass

    def _validate_binding_profile(self, context):
        # Validate binding:profile if it exists in precommit so that we can
        # fail port creation if the contents are invalid.
        port = context.current
        if ovn_const.OVN_PORT_BINDING_PROFILE not in port:
            return
        parent_name = (
            port[ovn_const.OVN_PORT_BINDING_PROFILE].get('parent_name'))
        tag = port[ovn_const.OVN_PORT_BINDING_PROFILE].get('tag')
        if not any((parent_name, tag)):
            # An empty profile is fine.
            return
        if not all((parent_name, tag)):
            # If one is set, they both must be set.
            msg = _('Invalid binding:profile. parent_name and tag are '
                    'both required.')
            raise n_exc.InvalidInput(error_message=msg)
        if not isinstance(parent_name, six.string_types):
            msg = _('Invalid binding:profile. parent_name "%s" must be '
                    'a string.') % parent_name
            raise n_exc.InvalidInput(error_message=msg)
        if not isinstance(tag, int) or tag < 0 or tag > 4095:
            # The tag range is defined by ovn-nb.ovsschema.
            # https://github.com/openvswitch/ovs/blob/ovn/ovn/ovn-nb.ovsschema
            msg = _('Invalid binding:profile. tag "%s" must be '
                    'an int between 1 and 4096, inclusive.') % tag
            raise n_exc.InvalidInput(error_message=msg)
        # Make sure we can successfully look up the port indicated by
        # parent_name.  Just let it raise the right exception if there is a
        # problem.
        context._plugin.get_port(context._plugin_context, parent_name)

    def _get_data_from_binding_profile(self, port):
        parent_name = None
        tag = None
        if ovn_const.OVN_PORT_BINDING_PROFILE in port:
            # If binding:profile exists, we know the contents are valid as they
            # were validated in create_port_precommit().
            parent_name = (
                port[ovn_const.OVN_PORT_BINDING_PROFILE].get('parent_name'))
            tag = port[ovn_const.OVN_PORT_BINDING_PROFILE].get('tag')
        return parent_name, tag

    def _get_allowed_mac_addresses_from_port(self, port):
        if not port.get('port_security_enabled', True):
            return []
        allowed_macs = set()
        allowed_macs.add(port['mac_address'])
        allowed_address_pairs = port.get('allowed_address_pairs', [])
        for allowed_address in allowed_address_pairs:
            allowed_macs.add(allowed_address['mac_address'])
        return list(allowed_macs)

    def create_port_precommit(self, context):
        self._validate_binding_profile(context)

    def create_port_postcommit(self, context):
        port = context.current
        # The port name *must* be port['id'].  It must match the iface-id set
        # in the Interfaces table of the Open_vSwitch database, which nova sets
        # to be the port ID.
        external_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port['name']}
        parent_name, tag = self._get_data_from_binding_profile(port)
        allowed_macs = self._get_allowed_mac_addresses_from_port(port)
        self._ovn.create_lport(
            lport_name=port['id'],
            lswitch_name=utils.ovn_name(port['network_id']),
            macs=[port['mac_address']], external_ids=external_ids,
            parent_name=parent_name, tag=tag,
            port_security=allowed_macs).execute(check_error=True)

    def update_port_precommit(self, context):
        self._validate_binding_profile(context)

    def update_port_postcommit(self, context):
        port = context.current
        # Neutron allows you to update the MAC address on a port.
        # Neutron allows you to update the name on a port.
        # Neutron allows to update binding profile data (parent_name, tag)
        external_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port['name']}
        parent_name, tag = self._get_data_from_binding_profile(port)
        allowed_macs = self._get_allowed_mac_addresses_from_port(port)
        self._ovn.set_lport(lport_name=port['id'],
                            macs=[port['mac_address']],
                            external_ids=external_ids,
                            parent_name=parent_name, tag=tag,
                            port_security=allowed_macs).execute(
                                check_error=True)

    def delete_port_postcommit(self, context):
        port = context.current
        self._ovn.delete_lport(port['id']).execute(check_error=True)

    def bind_port(self, context):
        # This is just a temp solution so that Nova can boot images
        for segment in context.segments_to_bind:
            context.set_binding(segment[driver_api.ID],
                                self.vif_type,
                                self.vif_details,
                                status=n_const.PORT_STATUS_ACTIVE)

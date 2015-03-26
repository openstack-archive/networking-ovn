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

from oslo_config import cfg

import neutron.agent.linux.utils as linux_utils
from neutron.extensions import portbindings
from neutron.plugins.ml2 import driver_api


ovn_opts = [
    cfg.StrOpt('database',
               help=_('location of the ovn-nb database')),
]

cfg.CONF.register_opts(ovn_opts, 'ovn')


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

    @staticmethod
    def _nbctl_opts():
        if cfg.CONF.ovn.database:
            return '-d %s' % cfg.CONF.ovn.database
        return ''

    def _set_network_name(self, network):
        linux_utils.execute(
            'ovn-nbctl %s lswitch-set-external-id %s '
            'neutron:network_name %s'
            % (self._nbctl_opts(), network['id'], network['name']),
            run_as_root=True)

    def create_network_postcommit(self, context):
        network = context.current
        # Create a logical switch with a name equal to the Neutron network
        # UUID.  This provides an easy way to refer to the logical switch
        # without having to track what UUID OVN assigned to it.
        linux_utils.execute('ovn-nbctl %s lswitch-add %s' % (
            self._nbctl_opts(), network['id']), run_as_root=True)
        # Go ahead and also set the Neutron ID as an external:id, as that's
        # where we want to store it long term.
        linux_utils.execute(
            'ovn-nbctl %s lswitch-set-external-id %s neutron:network_id %s'
            % (self._nbctl_opts(), network['id'], network['id']),
            run_as_root=True)
        self._set_network_name(network)

    def update_network_postcommit(self, context):
        network = context.current
        # The only field that might get updated that we care about right now is
        # the name.
        self._set_network_name(network)

    def delete_network_postcommit(self, context):
        network = context.current
        linux_utils.execute('ovn-nbctl %s lswitch-del %s' % (
            self._nbctl_opts(), network['id']), run_as_root=True)

    def create_subnet_postcommit(self, context):
        pass

    def update_subnet_postcommit(self, context):
        pass

    def delete_subnet_postcommit(self, context):
        pass

    def create_port_postcommit(self, context):
        port = context.current
        linux_utils.execute(
            'ovn-nbctl %s lport-add %s %s'
            % (self._nbctl_opts(), port['id'], port['network_id']),
            run_as_root=True)
        linux_utils.execute(
            'ovn-nbctl %s lport-set-external-id %s neutron:port_name %s'
            % (self._nbctl_opts(), port['id'], port['name']),
            run_as_root=True)
        linux_utils.execute(
            'ovn-nbctl %s lport-set-macs %s %s'
            % (self._nbctl_opts(), port['id'], port['mac_address']),
            run_as_root=True)

    def update_port_postcommit(self, context):
        port = context.current
        # Neutron allows you to update the MAC address on a port.
        linux_utils.execute(
            'ovn-nbctl %s lport-set-macs %s %s'
            % (self._nbctl_opts(), port['id'], port['mac_address']),
            run_as_root=True)

    def delete_port_postcommit(self, context):
        port = context.current
        linux_utils.execute(
            'ovn-nbctl %s lport-del %s'
            % (self._nbctl_opts(), port['id']),
            run_as_root=True)

    def bind_port(self, context):
        pass

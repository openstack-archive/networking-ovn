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

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib import context as n_context
from neutron_lib.plugins import directory

from neutron.common import constants as n_consts
from neutron.objects.qos import policy as qos_policy
from neutron.objects.qos import rule as qos_rule
from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron.services.qos.drivers import base
from neutron.services.qos import qos_consts

from oslo_config import cfg

LOG = logging.getLogger(__name__)

OVN_QOS = 'qos'
SUPPORTED_RULES = {
    qos_consts.RULE_TYPE_BANDWIDTH_LIMIT: {
        qos_consts.MAX_KBPS: {
            'type:range': [0, n_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.MAX_BURST: {
            'type:range': [0, n_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.DIRECTION: {
            'type:values': [n_consts.EGRESS_DIRECTION]}
    },
}

VIF_TYPES = [portbindings.VIF_TYPE_OVS, portbindings.VIF_TYPE_VHOST_USER]
VNIC_TYPES = [portbindings.VNIC_NORMAL]


class OVNQosNotificationDriver(base.DriverBase):
    """OVN notification driver for QoS."""

    def __init__(self, name='OVNQosDriver',
                 vif_types=VIF_TYPES,
                 vnic_types=VNIC_TYPES,
                 supported_rules=SUPPORTED_RULES,
                 requires_rpc_notifications=False):
        super(OVNQosNotificationDriver, self).__init__(
            name, vif_types, vnic_types, supported_rules,
            requires_rpc_notifications)
        self._driver_property = None

    @staticmethod
    def create():
        return OVNQosNotificationDriver()

    @property
    def is_loaded(self):
        return OVN_QOS in cfg.CONF.ml2.extension_drivers

    @property
    def _driver(self):
        if self._driver_property is None:
            plugin = directory.get_plugin()
            if isinstance(plugin, ml2_plugin.Ml2Plugin):
                self._driver_property = \
                    plugin.mechanism_manager.mech_drivers['ovn'].obj
        return self._driver_property

    def create_policy(self, context, policy):
        # No need to update OVN on create
        pass

    def update_policy(self, context, policy):
        # Call into qos_driver to update the policy
        self._driver.qos_driver.update_policy(context, policy)

    def delete_policy(self, context, policy):
        # No need to update OVN on delete
        pass


class OVNQosDriver(object):
    """Qos driver for OVN"""

    def __init__(self, driver):
        LOG.info("Starting OVNQosDriver")
        super(OVNQosDriver, self).__init__()
        self._driver = driver
        self._plugin_property = None

    @property
    def _plugin(self):
        if self._plugin_property is None:
            self._plugin_property = directory.get_plugin()
        return self._plugin_property

    def _is_network_device_port(self, port):
        device_owner = port.get('device_owner')
        if (device_owner and
                device_owner.startswith(constants.DEVICE_OWNER_PREFIXES)):
            return True
        return False

    def _generate_port_options(self, context, policy_id):
        if policy_id is None:
            return {}
        options = {}
        # The policy might not have any rules
        all_rules = qos_rule.get_rules(context, policy_id)
        for rule in all_rules:
            if isinstance(rule, qos_rule.QosBandwidthLimitRule):
                if rule.max_kbps:
                    options['qos_max_rate'] = str(rule.max_kbps * 1000)
                if rule.max_burst_kbps:
                    options['qos_burst'] = str(rule.max_burst_kbps * 1000)
        return options

    def get_qos_options(self, port):
        # Is qos service enabled
        if 'qos_policy_id' not in port:
            return {}
        # Don't apply qos rules to network devices
        if self._is_network_device_port(port):
            return {}

        # Determine if port or network policy should be used
        context = n_context.get_admin_context()
        port_policy_id = port.get('qos_policy_id')
        network_policy_id = None
        if not port_policy_id:
            network_policy = qos_policy.QosPolicy.get_network_policy(
                context, port['network_id'])
            network_policy_id = network_policy.id if network_policy else None

        # Generate qos options for the selected policy
        policy_id = port_policy_id or network_policy_id
        return self._generate_port_options(context, policy_id)

    def _update_network_ports(self, context, network_id, options):
        # Retrieve all ports for this network
        ports = self._plugin.get_ports(context,
                                       filters={'network_id': [network_id]})
        for port in ports:
            # Don't apply qos rules if port has a policy
            port_policy_id = port.get('qos_policy_id')
            if port_policy_id:
                continue
            # Don't apply qos rules to network devices
            if self._is_network_device_port(port):
                continue
            # Call into mech driver to update port
            self._driver.update_port(port, port, options)

    def update_network(self, network, original_network):
        # Is qos service enabled
        if 'qos_policy_id' not in network:
            return
        # Was network qos policy changed
        network_policy_id = network.get('qos_policy_id')
        old_network_policy_id = original_network.get('qos_policy_id')
        if network_policy_id == old_network_policy_id:
            return

        # Update the qos options on each network port
        context = n_context.get_admin_context()
        options = self._generate_port_options(context, network_policy_id)
        self._update_network_ports(context, network.get('id'), options)

    def update_policy(self, context, policy):
        options = self._generate_port_options(context, policy.id)

        # Update each network bound to this policy
        network_bindings = policy.get_bound_networks()
        for network_id in network_bindings:
            self._update_network_ports(context, network_id, options)

        # Update each port bound to this policy
        port_bindings = policy.get_bound_ports()
        for port_id in port_bindings:
            port = self._plugin.get_port(context, port_id)
            self._driver.update_port(port, port, options)

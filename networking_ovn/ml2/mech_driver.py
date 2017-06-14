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

from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib import context as n_context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg
from oslo_db import exception as os_db_exc
from oslo_log import log

from neutron.common import utils as n_utils
from neutron.db import provisioning_blocks
from neutron.services.qos import qos_consts
from neutron.services.segments import db as segment_service_db

from networking_ovn._i18n import _
from networking_ovn.common import acl as ovn_acl
from networking_ovn.common import config
from networking_ovn.common import constants as ovn_const
from networking_ovn.common import ovn_client
from networking_ovn.common import utils
from networking_ovn.ml2 import qos_driver
from networking_ovn.ml2 import trunk_driver
from networking_ovn import ovn_db_sync
from networking_ovn.ovsdb import impl_idl_ovn
from networking_ovn.ovsdb import ovsdb_monitor


LOG = log.getLogger(__name__)
METADATA_READY_WAIT_TIMEOUT = 15


class MetadataServiceReadyWaitTimeoutException(Exception):
    pass


class OVNMechanismDriver(api.MechanismDriver):
    """OVN ML2 mechanism driver

    A mechanism driver is called on the creation, update, and deletion
    of networks and ports. For every event, there are two methods that
    get called - one within the database transaction (method suffix of
    _precommit), one right afterwards (method suffix of _postcommit).

    Exceptions raised by methods called inside the transaction can
    rollback, but should not make any blocking calls (for example,
    REST requests to an outside controller). Methods called after
    transaction commits can make blocking external calls, though these
    will block the entire process. Exceptions raised in calls after
    the transaction commits may cause the associated resource to be
    deleted.

    Because rollback outside of the transaction is not done in the
    update network/port case, all data validation must be done within
    methods that are part of the database transaction.
    """

    supported_qos_rule_types = [qos_consts.RULE_TYPE_BANDWIDTH_LIMIT]

    def initialize(self):
        """Perform driver initialization.

        Called after all drivers have been loaded and the database has
        been initialized. No abstract methods defined below will be
        called prior to this method being called.
        """
        LOG.info("Starting OVNMechanismDriver")
        self._nb_ovn = None
        self._sb_ovn = None
        self._plugin_property = None
        self._ovn_client = None
        self.sg_enabled = ovn_acl.is_sg_enabled()
        if cfg.CONF.SECURITYGROUP.firewall_driver:
            LOG.warning('Firewall driver configuration is ignored')
        self._setup_vif_port_bindings()
        self.subscribe()
        qos_driver.OVNQosNotificationDriver.create()
        self.qos_driver = qos_driver.OVNQosDriver(self)
        self.trunk_driver = trunk_driver.OVNTrunkDriver.create(self)

    @property
    def _plugin(self):
        if self._plugin_property is None:
            self._plugin_property = directory.get_plugin()
        return self._plugin_property

    def _get_attribute(self, obj, attribute):
        res = obj.get(attribute)
        if res is const.ATTR_NOT_SPECIFIED:
            res = None
        return res

    def _setup_vif_port_bindings(self):
        self.supported_vnic_types = [portbindings.VNIC_NORMAL]
        self.vif_details = {
            portbindings.VIF_TYPE_OVS: {
                portbindings.CAP_PORT_FILTER: self.sg_enabled
            },
            portbindings.VIF_TYPE_VHOST_USER: {
                portbindings.CAP_PORT_FILTER: False,
                portbindings.VHOST_USER_MODE:
                portbindings.VHOST_USER_MODE_CLIENT,
                portbindings.VHOST_USER_OVS_PLUG: True
            }
        }

    def subscribe(self):
        registry.subscribe(self.post_fork_initialize,
                           resources.PROCESS,
                           events.AFTER_INIT)

        registry.subscribe(self._add_segment_host_mapping_for_segment,
                           resources.SEGMENT,
                           events.PRECOMMIT_CREATE)

        # Handle security group/rule notifications
        if self.sg_enabled:
            registry.subscribe(self._process_sg_notification,
                               resources.SECURITY_GROUP,
                               events.AFTER_CREATE)
            registry.subscribe(self._process_sg_notification,
                               resources.SECURITY_GROUP,
                               events.AFTER_UPDATE)
            registry.subscribe(self._process_sg_notification,
                               resources.SECURITY_GROUP,
                               events.BEFORE_DELETE)
            registry.subscribe(self._process_sg_rule_notification,
                               resources.SECURITY_GROUP_RULE,
                               events.AFTER_CREATE)
            registry.subscribe(self._process_sg_rule_notification,
                               resources.SECURITY_GROUP_RULE,
                               events.BEFORE_DELETE)

    def post_fork_initialize(self, resource, event, trigger, **kwargs):
        # NOTE(rtheis): This will initialize all workers (API, RPC,
        # plugin service and OVN) with OVN IDL connections.
        self._nb_ovn, self._sb_ovn = impl_idl_ovn.get_ovn_idls(self,
                                                               trigger)
        self._ovn_client = ovn_client.OVNClient(self._nb_ovn, self._sb_ovn)

        if trigger.im_class == ovsdb_monitor.OvnWorker:
            # Call the synchronization task if its ovn worker
            # This sync neutron DB to OVN-NB DB only in inconsistent states
            self.nb_synchronizer = ovn_db_sync.OvnNbSynchronizer(
                self._plugin,
                self._nb_ovn,
                config.get_ovn_neutron_sync_mode(),
                self
            )
            self.nb_synchronizer.sync()

            # This sync neutron DB to OVN-SB DB only in inconsistent states
            self.sb_synchronizer = ovn_db_sync.OvnSbSynchronizer(
                self._plugin,
                self._sb_ovn,
                self
            )
            self.sb_synchronizer.sync()

    def _process_sg_notification(self, resource, event, trigger, **kwargs):
        sg = {'name': kwargs['security_group']['name'],
              'id': kwargs['security_group']['id']}
        if event == events.AFTER_CREATE:
            self._ovn_client.create_security_group(sg)
        elif event == events.AFTER_UPDATE:
            self._ovn_client.update_security_group(sg)
        elif event == events.BEFORE_DELETE:
            self._ovn_client.delete_security_group(sg)

    def _process_sg_rule_notification(
            self, resource, event, trigger, **kwargs):
        if event == events.AFTER_CREATE:
            self._ovn_client.create_security_group_rule(
                kwargs.get('security_group_rule'))
        elif event == events.BEFORE_DELETE:
            admin_context = n_context.get_admin_context()
            sg_rule = self._plugin.get_security_group_rule(
                admin_context, kwargs.get('security_group_rule_id'))
            self._ovn_client.delete_security_group_rule(sg_rule)

    def _is_network_type_supported(self, network_type):
        return (network_type in [const.TYPE_LOCAL,
                                 const.TYPE_FLAT,
                                 const.TYPE_GENEVE,
                                 const.TYPE_VLAN])

    def _validate_network_segments(self, network_segments):
        for network_segment in network_segments:
            network_type = network_segment['network_type']
            segmentation_id = network_segment['segmentation_id']
            physical_network = network_segment['physical_network']
            LOG.debug('Validating network segment with '
                      'type %(network_type)s, '
                      'segmentation ID %(segmentation_id)s, '
                      'physical network %(physical_network)s' %
                      {'network_type': network_type,
                       'segmentation_id': segmentation_id,
                       'physical_network': physical_network})
            if not self._is_network_type_supported(network_type):
                msg = _('Network type %s is not supported') % network_type
                raise n_exc.InvalidInput(error_message=msg)

    def create_network_precommit(self, context):
        """Allocate resources for a new network.

        :param context: NetworkContext instance describing the new
        network.

        Create a new network, allocating resources as necessary in the
        database. Called inside transaction context on session. Call
        cannot block.  Raising an exception will result in a rollback
        of the current transaction.
        """
        self._validate_network_segments(context.network_segments)

    def create_network_postcommit(self, context):
        """Create a network.

        :param context: NetworkContext instance describing the new
        network.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.
        """
        network = context.current
        physnet = self._get_attribute(network, pnet.PHYSICAL_NETWORK)
        segid = self._get_attribute(network, pnet.SEGMENTATION_ID)
        self._ovn_client.create_network(network, physnet, segid)

    def update_network_precommit(self, context):
        """Update resources of a network.

        :param context: NetworkContext instance describing the new
        state of the network, as well as the original state prior
        to the update_network call.

        Update values of a network, updating the associated resources
        in the database. Called inside transaction context on session.
        Raising an exception will result in rollback of the
        transaction.

        update_network_precommit is called for all changes to the
        network state. It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        self._validate_network_segments(context.network_segments)

    def update_network_postcommit(self, context):
        """Update a network.

        :param context: NetworkContext instance describing the new
        state of the network, as well as the original state prior
        to the update_network call.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.

        update_network_postcommit is called for all changes to the
        network state.  It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        network = context.current
        original_network = context.original
        if network['name'] != original_network['name']:
            self._ovn_client.update_network(network, original_network)

    def delete_network_postcommit(self, context):
        """Delete a network.

        :param context: NetworkContext instance describing the current
        state of the network, prior to the call to delete it.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.
        """
        self._ovn_client.delete_network(context.current['id'])

    def create_subnet_postcommit(self, context):
        self._ovn_client.create_subnet(context.current,
                                       context.network.current)

    def update_subnet_postcommit(self, context):
        self._ovn_client.update_subnet(context.current, context.original,
                                       context.network.current)

    def delete_subnet_postcommit(self, context):
        self._ovn_client.delete_subnet(context.current['id'])

    def create_port_precommit(self, context):
        """Allocate resources for a new port.

        :param context: PortContext instance describing the port.

        Create a new port, allocating resources as necessary in the
        database. Called inside transaction context on session. Call
        cannot block.  Raising an exception will result in a rollback
        of the current transaction.
        """
        port = context.current
        utils.validate_and_get_data_from_binding_profile(port)
        if self._is_port_provisioning_required(port, context.host):
            self._insert_port_provisioning_block(context._plugin_context, port)

    def _is_port_provisioning_required(self, port, host, original_host=None):
        vnic_type = port.get(portbindings.VNIC_TYPE, portbindings.VNIC_NORMAL)
        if vnic_type not in self.supported_vnic_types:
            LOG.debug('No provisioning block for port %(port_id)s due to '
                      'unsupported vnic_type: %(vnic_type)s',
                      {'port_id': port['id'], 'vnic_type': vnic_type})
            return False

        if port['status'] == const.PORT_STATUS_ACTIVE:
            LOG.debug('No provisioning block for port %s since it is active',
                      port['id'])
            return False

        if not host:
            LOG.debug('No provisioning block for port %s since it does not '
                      'have a host', port['id'])
            return False

        if host == original_host:
            LOG.debug('No provisioning block for port %s since host unchanged',
                      port['id'])
            return False

        if not self._sb_ovn.chassis_exists(host):
            LOG.debug('No provisioning block for port %(port_id)s since no '
                      'OVN chassis for host: %(host)s',
                      {'port_id': port['id'], 'host': host})
            return False

        return True

    def _insert_port_provisioning_block(self, context, port):
        # Insert a provisioning block to prevent the port from
        # transitioning to active until OVN reports back that
        # the port is up.
        provisioning_blocks.add_provisioning_component(
            context,
            port['id'], resources.PORT,
            provisioning_blocks.L2_AGENT_ENTITY
        )

    def _notify_dhcp_updated(self, port_id):
        """Notifies Neutron that the DHCP has been update for port."""
        provisioning_blocks.provisioning_complete(
            n_context.get_admin_context(), port_id, resources.PORT,
            provisioning_blocks.DHCP_ENTITY)

    def create_port_postcommit(self, context):
        """Create a port.

        :param context: PortContext instance describing the port.

        Called after the transaction completes. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance.  Raising an exception will
        result in the deletion of the resource.
        """
        port = context.current
        self._ovn_client.create_port(port)
        self._notify_dhcp_updated(port['id'])

    def update_port_precommit(self, context):
        """Update resources of a port.

        :param context: PortContext instance describing the new
        state of the port, as well as the original state prior
        to the update_port call.

        Called inside transaction context on session to complete a
        port update as defined by this mechanism driver. Raising an
        exception will result in rollback of the transaction.

        update_port_precommit is called for all changes to the port
        state. It is up to the mechanism driver to ignore state or
        state changes that it does not know or care about.
        """
        port = context.current
        utils.validate_and_get_data_from_binding_profile(port)
        if self._is_port_provisioning_required(port, context.host,
                                               context.original_host):
            self._insert_port_provisioning_block(context._plugin_context, port)

    def update_port_postcommit(self, context):
        """Update a port.

        :param context: PortContext instance describing the new
        state of the port, as well as the original state prior
        to the update_port call.

        Called after the transaction completes. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance.  Raising an exception will
        result in the deletion of the resource.

        update_port_postcommit is called for all changes to the port
        state. It is up to the mechanism driver to ignore state or
        state changes that it does not know or care about.
        """
        port = context.current
        original_port = context.original
        self._ovn_client.update_port(port, original_port)
        self._notify_dhcp_updated(port['id'])

    # TODO(lucasagomes): We need this because the QOS driver is still
    # relying on a method called update_port(), delete it after QOS driver
    # is updated
    def update_port(self, port, original_port, qos_options=None):
        self._ovn_client.update_port(port, original_port)

    def delete_port_postcommit(self, context):
        """Delete a port.

        :param context: PortContext instance describing the current
        state of the port, prior to the call to delete it.

        Called after the transaction completes. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance.  Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.
        """
        port = context.current
        self._ovn_client.delete_port(port)

    def bind_port(self, context):
        """Attempt to bind a port.

        :param context: PortContext instance describing the port

        This method is called outside any transaction to attempt to
        establish a port binding using this mechanism driver. Bindings
        may be created at each of multiple levels of a hierarchical
        network, and are established from the top level downward. At
        each level, the mechanism driver determines whether it can
        bind to any of the network segments in the
        context.segments_to_bind property, based on the value of the
        context.host property, any relevant port or network
        attributes, and its own knowledge of the network topology. At
        the top level, context.segments_to_bind contains the static
        segments of the port's network. At each lower level of
        binding, it contains static or dynamic segments supplied by
        the driver that bound at the level above. If the driver is
        able to complete the binding of the port to any segment in
        context.segments_to_bind, it must call context.set_binding
        with the binding details. If it can partially bind the port,
        it must call context.continue_binding with the network
        segments to be used to bind at the next lower level.

        If the binding results are committed after bind_port returns,
        they will be seen by all mechanism drivers as
        update_port_precommit and update_port_postcommit calls. But if
        some other thread or process concurrently binds or updates the
        port, these binding results will not be committed, and
        update_port_precommit and update_port_postcommit will not be
        called on the mechanism drivers with these results. Because
        binding results can be discarded rather than committed,
        drivers should avoid making persistent state changes in
        bind_port, or else must ensure that such state changes are
        eventually cleaned up.

        Implementing this method explicitly declares the mechanism
        driver as having the intention to bind ports. This is inspected
        by the QoS service to identify the available QoS rules you
        can use with ports.
        """
        port = context.current
        vnic_type = port.get(portbindings.VNIC_TYPE, portbindings.VNIC_NORMAL)
        if vnic_type not in self.supported_vnic_types:
            LOG.debug('Refusing to bind port %(port_id)s due to unsupported '
                      'vnic_type: %(vnic_type)s' %
                      {'port_id': port['id'], 'vnic_type': vnic_type})
            return

        # OVN chassis information is needed to ensure a valid port bind.
        # Collect port binding data and refuse binding if the OVN chassis
        # cannot be found.
        chassis_physnets = []
        try:
            datapath_type, iface_types, chassis_physnets = \
                self._sb_ovn.get_chassis_data_for_ml2_bind_port(context.host)
            iface_types = iface_types.split(',') if iface_types else []
        except RuntimeError:
            LOG.debug('Refusing to bind port %(port_id)s due to '
                      'no OVN chassis for host: %(host)s' %
                      {'port_id': port['id'], 'host': context.host})
            return

        for segment_to_bind in context.segments_to_bind:
            network_type = segment_to_bind['network_type']
            segmentation_id = segment_to_bind['segmentation_id']
            physical_network = segment_to_bind['physical_network']
            LOG.debug('Attempting to bind port %(port_id)s on host %(host)s '
                      'for network segment with type %(network_type)s, '
                      'segmentation ID %(segmentation_id)s, '
                      'physical network %(physical_network)s' %
                      {'port_id': port['id'],
                       'host': context.host,
                       'network_type': network_type,
                       'segmentation_id': segmentation_id,
                       'physical_network': physical_network})
            # TODO(rtheis): This scenario is only valid on an upgrade from
            # neutron ML2 OVS since invalid network types are prevented during
            # network creation and update. The upgrade should convert invalid
            # network types. Once bug/1621879 is fixed, refuse to bind
            # ports with unsupported network types.
            if not self._is_network_type_supported(network_type):
                LOG.info('Upgrade allowing bind port %(port_id)s with '
                         'unsupported network type: %(network_type)s',
                         {'port_id': port['id'],
                          'network_type': network_type})

            if (network_type in ['flat', 'vlan']) and \
               (physical_network not in chassis_physnets):
                LOG.info('Refusing to bind port %(port_id)s on '
                         'host %(host)s due to the OVN chassis '
                         'bridge mapping physical networks '
                         '%(chassis_physnets)s not supporting '
                         'physical network: %(physical_network)s',
                         {'port_id': port['id'],
                          'host': context.host,
                          'chassis_physnets': chassis_physnets,
                          'physical_network': physical_network})
            else:
                if datapath_type == ovn_const.CHASSIS_DATAPATH_NETDEV and (
                    ovn_const.CHASSIS_IFACE_DPDKVHOSTUSER in iface_types):
                    vhost_user_socket = utils.ovn_vhu_sockpath(
                        config.get_ovn_vhost_sock_dir(), port['id'])
                    vif_type = portbindings.VIF_TYPE_VHOST_USER
                    port[portbindings.VIF_DETAILS].update({
                        portbindings.VHOST_USER_SOCKET: vhost_user_socket
                        })
                    vif_details = dict(self.vif_details[vif_type])
                    vif_details[portbindings.VHOST_USER_SOCKET] = \
                        vhost_user_socket
                else:
                    vif_type = portbindings.VIF_TYPE_OVS
                    vif_details = self.vif_details[vif_type]

                context.set_binding(segment_to_bind[api.ID], vif_type,
                                    vif_details)
                break

    def get_workers(self):
        """Get any worker instances that should have their own process

        Any driver that needs to run processes separate from the API or RPC
        workers, can return a sequence of worker instances.
        """
        # See doc/source/design/ovn_worker.rst for more details.
        return [ovsdb_monitor.OvnWorker()]

    def set_port_status_up(self, port_id):
        # Port provisioning is complete now that OVN has reported that the
        # port is up. Any provisioning block (possibly added during port
        # creation or when OVN reports that the port is down) must be removed.
        LOG.info("OVN reports status up for port: %s", port_id)

        if config.is_ovn_metadata_enabled() and self._sb_ovn:
            # Wait until metadata service has been setup for this port in the
            # chassis it resides.
            chassis, datapath = (
                self._sb_ovn.get_logical_port_chassis_and_datapath(port_id))
            try:
                n_utils.wait_until_true(
                    lambda: datapath in
                    self._sb_ovn.get_chassis_metadata_networks(chassis),
                    timeout=METADATA_READY_WAIT_TIMEOUT,
                    exception=MetadataServiceReadyWaitTimeoutException)
            except MetadataServiceReadyWaitTimeoutException:
                # If we reach this point it means that metadata agent didn't
                # provision the datapath for this port on its chassis. Either
                # the agent is not running or it crashed. We'll complete the
                # provisioning block though.
                LOG.warning("Metadata service is not ready for port %s, check"
                            " networking-ovn-metadata-agent status/logs.",
                            port_id)

        provisioning_blocks.provisioning_complete(
            n_context.get_admin_context(),
            port_id,
            resources.PORT,
            provisioning_blocks.L2_AGENT_ENTITY)

    def set_port_status_down(self, port_id):
        # Port provisioning is required now that OVN has reported that the
        # port is down. Insert a provisioning block and mark the port down
        # in neutron. The block is inserted before the port status update
        # to prevent another entity from bypassing the block with its own
        # port status update.
        LOG.info("OVN reports status down for port: %s", port_id)
        admin_context = n_context.get_admin_context()
        try:
            port = self._plugin.get_port(admin_context, port_id)
            self._insert_port_provisioning_block(admin_context, port)
            self._plugin.update_port_status(admin_context,
                                            port['id'],
                                            const.PORT_STATUS_DOWN)
        except (os_db_exc.DBReferenceError, n_exc.PortNotFound):
            LOG.debug("Port not found during OVN status down report: %s",
                      port_id)

    def update_segment_host_mapping(self, host, phy_nets):
        """Update SegmentHostMapping in DB"""
        if not host:
            return

        ctx = n_context.get_admin_context()
        segments = segment_service_db.get_segments_with_phys_nets(
            ctx, phy_nets)

        available_seg_ids = {
            segment['id'] for segment in segments
            if segment['network_type'] in ('flat', 'vlan')}

        segment_service_db.update_segment_host_mapping(
            ctx, host, available_seg_ids)

    def _add_segment_host_mapping_for_segment(self, resource, event, trigger,
                                              context, segment):
        phynet = segment.physical_network
        if not phynet:
            return

        host_phynets_map = self._sb_ovn.get_chassis_hostname_and_physnets()
        hosts = {host for host, phynets in host_phynets_map.items()
                 if phynet in phynets}
        segment_service_db.map_segment_to_hosts(context, segment.id, hosts)

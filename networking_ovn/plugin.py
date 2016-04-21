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

import collections

import netaddr

from neutron_lib import constants as const
from oslo_config import cfg
from oslo_log import log
from oslo_utils import importutils
from sqlalchemy.orm import exc as sa_exc

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.rpc.callbacks.consumer import registry as callbacks_registry
from neutron.api.rpc.callbacks import events as callbacks_events
from neutron.api.rpc.callbacks import resources as callbacks_resources
from neutron.api.rpc.handlers import dhcp_rpc
from neutron.api.rpc.handlers import l3_rpc
from neutron.api.rpc.handlers import metadata_rpc
from neutron.api.rpc.handlers import resources_rpc
from neutron.api.v2 import attributes as attr
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context as n_context
from neutron.core_extensions import base as base_core
from neutron.core_extensions import qos as qos_core
from neutron.db import address_scope_db
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import api as db_api
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.db import l3_hamode_db
from neutron.db import l3_hascheduler_db
from neutron.db import models_v2
from neutron.db import netmtu_db
from neutron.db import portbindings_db
from neutron.db import portsecurity_db_common as ps_db_common
from neutron.db import securitygroups_db
from neutron.db import segments_db
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.extensions import availability_zone as az_ext
from neutron.extensions import extra_dhcp_opt as edo_ext
from neutron.extensions import portbindings
from neutron.extensions import portsecurity as psec
from neutron.extensions import providernet as pnet
from neutron.objects.qos import policy as qos_policy
from neutron.objects.qos import rule as qos_rule
from neutron.services.qos import qos_consts

from networking_ovn._i18n import _, _LE, _LI, _LW
from networking_ovn.common import config
from networking_ovn.common import constants as ovn_const
from networking_ovn.common import extensions
from networking_ovn.common import utils
from networking_ovn import ovn_nb_sync
from networking_ovn.ovsdb import impl_idl_ovn
from networking_ovn.ovsdb import ovsdb_monitor

LOG = log.getLogger(__name__)

OvnPortInfo = collections.namedtuple('OvnPortInfo', ['type', 'options',
                                                     'addresses',
                                                     'port_security',
                                                     'parent_name', 'tag'])


class OVNPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                securitygroups_db.SecurityGroupDbMixin,
                l3_hamode_db.L3_HA_NAT_db_mixin,
                l3_hascheduler_db.L3_HA_scheduler_db_mixin,
                l3_gwmode_db.L3_NAT_db_mixin,
                external_net_db.External_net_db_mixin,
                portbindings_db.PortBindingMixin,
                extradhcpopt_db.ExtraDhcpOptMixin,
                extraroute_db.ExtraRoute_db_mixin,
                agentschedulers_db.AZDhcpAgentSchedulerDbMixin,
                netmtu_db.Netmtu_db_mixin,
                ps_db_common.PortSecurityDbCommon,
                addr_pair_db.AllowedAddressPairsMixin,
                address_scope_db.AddressScopeDbMixin):

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = extensions.SUPPORTED_API_EXTENSIONS
    supported_qos_rule_types = [qos_consts.RULE_TYPE_BANDWIDTH_LIMIT]

    def __init__(self):
        super(OVNPlugin, self).__init__()
        LOG.info(_LI("Starting OVNPlugin"))
        self._setup_base_binding_dict()

        self.core_ext_handler = qos_core.QosCoreResourceExtension()
        registry.subscribe(self.post_fork_initialize, resources.PROCESS,
                           events.AFTER_CREATE)
        callbacks_registry.subscribe(self._handle_qos_notification,
                                     callbacks_resources.QOS_POLICY)
        self._setup_dhcp()
        self._start_rpc_notifiers()

    def _setup_base_binding_dict(self):
        if config.get_ovn_vif_type() == portbindings.VIF_TYPE_VHOST_USER:
            self.base_binding_dict = {
                portbindings.VIF_TYPE: portbindings.VIF_TYPE_VHOST_USER,
                portbindings.VIF_DETAILS: {
                    portbindings.CAP_PORT_FILTER: False,
                    portbindings.VHOST_USER_MODE:
                    portbindings.VHOST_USER_MODE_CLIENT,
                    portbindings.VHOST_USER_OVS_PLUG: True,
                }
            }
        else:
            if config.get_ovn_vif_type() != portbindings.VIF_TYPE_OVS:
                LOG.warning(_LW('VIF type should be one of %(ovs)s, %(vhu)s') %
                            {"vhu": portbindings.VIF_TYPE_VHOST_USER,
                             "ovs": portbindings.VIF_TYPE_OVS})
            self.base_binding_dict = {
                portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS,
                portbindings.VIF_DETAILS: {
                    portbindings.CAP_PORT_FILTER:
                    'security-group' in self.supported_extension_aliases
                }
            }

    def post_fork_initialize(self, resource, event, trigger, **kwargs):
        self._ovn = impl_idl_ovn.OvsdbOvnIdl(self, trigger)

        if trigger.im_class == ovsdb_monitor.OvnWorker:
            # Call the synchronization task if its ovn worker
            # This sync neutron DB to OVN-NB DB only in inconsistent states
            self.synchronizer = ovn_nb_sync.OvnNbSynchronizer(
                self, self._ovn, config.get_ovn_neutron_sync_mode())
            self.synchronizer.sync()

            # start periodic check task to monitor the dhcp agents.
            # This task is created in the Ovn Worker and not in the parent
            # neutron process because
            # - dhcp agent scheduler calls port_update to reschedule a network
            #   from a dead dhcp agent to active one and idl object
            #   (self._ovn) is not created in the main neutron process plugin
            #   object.
            # - Its created only in the worker processes.
            # - Ovn worker seems to be the right candidate.
            self.start_periodic_dhcp_agent_status_check()

            # start periodic check task for L3 agent
            if not config.is_ovn_l3():
                self.start_periodic_l3_agent_status_check()

    def _setup_rpc(self):
        self.endpoints = [dhcp_rpc.DhcpRpcCallback(),
                          agents_db.AgentExtRpcCallback(),
                          metadata_rpc.MetadataRpcCallback()]
        if not config.is_ovn_l3():
            self.endpoints.append(l3_rpc.L3RpcCallback())

    def _setup_dhcp(self):
        """Initialize components to support DHCP."""
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )

    def _start_rpc_notifiers(self):
        """Initialize RPC notifiers for agents."""
        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        )
        if not config.is_ovn_l3():
            self.router_scheduler = importutils.import_object(
                cfg.CONF.router_scheduler_driver)
            l3_db.subscribe()
            self.agent_notifiers[const.AGENT_TYPE_L3] = (
                l3_rpc_agent_api.L3AgentNotifyAPI()
            )

    def start_rpc_listeners(self):
        self._setup_rpc()
        self.conn = n_rpc.create_connection()
        self.conn.create_consumer(topics.PLUGIN, self.endpoints, fanout=False)
        if not config.is_ovn_l3():
            self.conn.create_consumer(topics.L3PLUGIN, self.endpoints,
                                      fanout=False)

        # topics.REPORTS was added for the Mitaka release, therefore, to
        # work with stable/liberty, check to see if topics.REPORTS exists
        # if it does, use it.
        if hasattr(topics, 'REPORTS'):
            self.conn.create_consumer(
                topics.REPORTS, [agents_db.AgentExtRpcCallback()],
                fanout=False)
        qos_topic = resources_rpc.resource_type_versioned_topic(
            callbacks_resources.QOS_POLICY)
        self.conn.create_consumer(
            qos_topic, [resources_rpc.ResourcesPushRpcCallback()],
            fanout=False)
        return self.conn.consume_in_threads()

    def _handle_qos_notification(self, qos_policy, event_type):
        if event_type == callbacks_events.UPDATED:
            if hasattr(qos_policy, "rules"):
                # rules updated
                context = n_context.get_admin_context()
                network_bindings = qos_policy.get_bound_networks()
                for binding in network_bindings:
                    self._update_network_qos(
                        context, binding.network_id, qos_policy.id)

                port_bindings = qos_policy.get_bound_ports()
                for binding in port_bindings:
                    port = self.get_port(context, binding.port_id)
                    qos_options = self.qos_get_ovn_port_options(
                        context, port)

                    binding_profile = self.get_data_from_binding_profile(
                        context, port)
                    ovn_port_info = self.get_ovn_port_options(binding_profile,
                                                              qos_options,
                                                              port)
                    self._update_port_in_ovn(context, port,
                                             port, ovn_port_info)

    def _get_attribute(self, obj, attribute):
        res = obj.get(attribute)
        if res is attr.ATTR_NOT_SPECIFIED:
            res = None
        return res

    def _extend_network_dict_provider(self, context, network):
        """Extend network dict with provider network attributes"""
        segments = segments_db.get_network_segments(
            context.session, network['id'])
        if segments:
            # OVN plugin creates segments for provider networks only
            segment = segments[0]
            network[pnet.NETWORK_TYPE] = segment[segments_db.NETWORK_TYPE]
            network[pnet.PHYSICAL_NETWORK] = segment[
                segments_db.PHYSICAL_NETWORK]
            network[pnet.SEGMENTATION_ID] = segment[
                segments_db.SEGMENTATION_ID]

    def get_network(self, context, id, fields=None):
        result = super(OVNPlugin, self).get_network(context, id, None)
        self._extend_network_dict_provider(context, result)
        return self._fields(result, fields)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        with context.session.begin(subtransactions=True):
            nets = super(OVNPlugin, self).get_networks(
                context, filters, None, sorts, limit, marker, page_reverse)
            for net in nets:
                self._extend_network_dict_provider(context, net)

        return (nets if not fields else
                [self._fields(net, fields) for net in nets])

    def create_network(self, context, network):
        net = network['network']  # obviously..
        ext_ids = {}
        physnet = self._get_attribute(net, pnet.PHYSICAL_NETWORK)
        segid = None
        nettype = None
        if physnet:
            # If this is a provider network, validate that it's a type we
            # support. (flat or vlan)
            nettype = self._get_attribute(net, pnet.NETWORK_TYPE)
            if nettype not in ('flat', 'vlan'):
                msg = _('%s network type is not supported with provider '
                        'networks (only flat or vlan).') % nettype
                raise n_exc.InvalidInput(error_message=msg)

            segid = self._get_attribute(net, pnet.SEGMENTATION_ID)

        with context.session.begin(subtransactions=True):
            result = super(OVNPlugin, self).create_network(context,
                                                           network)
            if psec.PORTSECURITY not in net:
                net[psec.PORTSECURITY] = (
                    psec.EXTENDED_ATTRIBUTES_2_0['networks']
                    [psec.PORTSECURITY]['default'])
            self._process_network_port_security_create(context, net, result)
            self._process_l3_create(context, result, net)

            if physnet:
                segment = {segments_db.NETWORK_TYPE: nettype,
                           segments_db.PHYSICAL_NETWORK: physnet,
                           segments_db.SEGMENTATION_ID: segid}
                segments_db.add_network_segment(
                    context.session, result['id'], segment)
                self._extend_network_dict_provider(context, result)

            self.core_ext_handler.process_fields(
                context, base_core.NETWORK, net, result)
            if az_ext.AZ_HINTS in net:
                self.validate_availability_zones(context, 'network',
                                                 net[az_ext.AZ_HINTS])
                az_hints = az_ext.convert_az_list_to_string(
                    net[az_ext.AZ_HINTS])
                super(OVNPlugin, self).update_network(
                    context,
                    result['id'],
                    {'network': {az_ext.AZ_HINTS: az_hints}})
                result[az_ext.AZ_HINTS] = az_hints

        # This extra lookup is necessary to get the latest db model
        # for the extension functions.
        net_model = self._get_network(context, result['id'])
        self._apply_dict_extend_functions('networks', result, net_model)
        try:
            return self.create_network_in_ovn(result, ext_ids,
                                              physnet, segid)

        except Exception:
            LOG.exception(_LE('Unable to create lswitch for %s'),
                          result['id'])
            self.delete_network(context, result['id'])
            raise n_exc.ServiceUnavailable()

    def create_network_in_ovn(self, network, ext_ids,
                              physnet=None, segid=None):
        # Create a logical switch with a name equal to the Neutron network
        # UUID.  This provides an easy way to refer to the logical switch
        # without having to track what UUID OVN assigned to it.
        ext_ids.update({
            ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: network['name']
        })

        lswitch_name = utils.ovn_name(network['id'])
        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.create_lswitch(
                lswitch_name=lswitch_name,
                external_ids=ext_ids))
            if physnet:
                vlan_id = None
                if segid is not None:
                    vlan_id = int(segid)
                txn.add(self._ovn.create_lport(
                    lport_name='provnet-%s' % network['id'],
                    lswitch_name=lswitch_name,
                    addresses=['unknown'],
                    external_ids=None,
                    type='localnet',
                    tag=vlan_id,
                    options={'network_name': physnet}))
        return network

    def delete_network(self, context, network_id):
        first_try = True
        while True:
            try:
                with context.session.begin(subtransactions=True):
                    self._process_l3_delete(context, network_id)
                    super(OVNPlugin, self).delete_network(context,
                                                          network_id)
                break
            except n_exc.NetworkInUse:
                # There is a race condition in delete_network() that we need
                # to work around here.  delete_network() issues a query to
                # automatically delete DHCP ports and then checks to see if any
                # ports exist on the network.  If a network is created and
                # deleted quickly, such as when running tempest, the DHCP agent
                # may be creating its port for the network around the same time
                # that the network is deleted.  This can result in the DHCP
                # port getting created in between these two queries in
                # delete_network().  To work around that, we'll call
                # delete_network() a second time if we get a NetworkInUse
                # exception but the only port(s) that exist are ones that
                # delete_network() is supposed to automatically delete.
                if not first_try:
                    # We tried once to work around the known race condition,
                    # but we still got the exception, so something else is
                    # wrong that we can't recover from.
                    raise
                first_try = False
                ports_in_use = context.session.query(models_v2.Port).filter_by(
                    network_id=network_id).all()
                if not all([p.device_owner in
                            db_base_plugin_v2.AUTO_DELETE_PORT_OWNERS
                            for p in ports_in_use]):
                    # There is a port on the network that is not going to be
                    # automatically deleted (such as a tenant created port), so
                    # we have nothing else to do but raise the exception.
                    raise

        try:
            self._ovn.delete_lswitch(
                utils.ovn_name(network_id), if_exists=True).execute(
                    check_error=True)
        except Exception:
            LOG.exception(_LE('Unable to delete lswitch for %s'), network_id)

    def _set_network_name(self, network_id, name):
        ext_id = [ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY, name]
        self._ovn.set_lswitch_ext_id(
            utils.ovn_name(network_id),
            ext_id).execute(check_error=True)

    def _qos_get_ovn_options(self, context, policy_id):
        all_rules = qos_rule.get_rules(context, policy_id)
        options = {}
        for rule in all_rules:
            if isinstance(rule, qos_rule.QosBandwidthLimitRule):
                if rule.max_kbps:
                    options['policing_rate'] = str(rule.max_kbps)
                if rule.max_burst_kbps:
                    options['policing_burst'] = str(rule.max_burst_kbps)

        return options

    def _get_network_ports_for_policy(self, context, network_id, policy_id):
        all_rules = qos_rule.get_rules(context, policy_id)
        ports = super(OVNPlugin, self).get_ports(
            context, filters={"network_id": [network_id]})
        port_ids = []

        for port in ports:
            include = True
            for rule in all_rules:
                if not rule.should_apply_to_port(port):
                    include = False
                    break

            if include:
                port_ids.append(port['id'])

        return port_ids

    def _ovn_extend_network_attributes(self, result, netdb):
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            result.update(self.core_ext_handler.extract_fields(
                base_core.NETWORK, netdb))

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attr.NETWORKS, ['_ovn_extend_network_attributes'])

    def _update_network_qos(self, context, network_id, policy_id):
        port_ids = self._get_network_ports_for_policy(
            context, network_id, policy_id)
        qos_rule_options = self._qos_get_ovn_options(
            context, policy_id)

        if qos_rule_options is not None:
            with self._ovn.transaction(check_error=True) as txn:
                for port_id in port_ids:
                    txn.add(self._ovn.set_lport(
                        lport_name=port_id,
                        options=qos_rule_options))

    def update_network(self, context, network_id, network):
        pnet._raise_if_updates_provider_attributes(network['network'])
        # FIXME(arosen) - rollback...
        if 'name' in network['network']:
            self._set_network_name(network_id, network['network']['name'])

        net_dict = network['network']
        with context.session.begin(subtransactions=True):
            updated_network = super(OVNPlugin, self).update_network(
                context, network_id, network)
            self._extend_network_dict_provider(context, updated_network)
            self._process_l3_update(
                context, updated_network, network['network'])
            self._process_network_port_security_update(
                context, network['network'], updated_network)
            if 'qos_policy_id' in net_dict:
                self.core_ext_handler.process_fields(
                    context, base_core.NETWORK, net_dict, updated_network)

        if 'qos_policy_id' in net_dict:
            self._update_network_qos(
                context, network_id, net_dict['qos_policy_id'])

        return updated_network

    def qos_get_ovn_port_options(self, context, port):
        port_policy_id = port.get("qos_policy_id", None)
        nw_policy = qos_policy.QosPolicy.get_network_policy(
            context, port['network_id'])
        nw_policy_id = nw_policy.id if nw_policy else None

        for policy_id in [port_policy_id, nw_policy_id, None]:
            if not policy_id:
                continue

            should_apply = True

            all_rules = qos_rule.get_rules(
                context, policy_id)
            for rule in all_rules:
                if not rule.should_apply_to_port(port):
                    should_apply = False
                    break

            if should_apply:
                break

        if policy_id:
            return self._qos_get_ovn_options(context, policy_id)
        return {}

    def _ovn_extend_port_attributes(self, result, portdb):
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            result.update(self.core_ext_handler.extract_fields(
                base_core.PORT, portdb))

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attr.PORTS, ['_ovn_extend_port_attributes'])

    def update_port(self, context, id, port):
        pdict = port['port']
        with context.session.begin(subtransactions=True):
            # FIXME(arosen): if binding data isn't passed in here
            # we should fetch it from the db instead and not set it to
            # None since neutron implements patch sematics for updates
            binding_profile = self.get_data_from_binding_profile(
                context, pdict)

            try:
                original_port = self.get_port(context, id)
            except n_exc.PortNotFound:
                if port == {'port': {'id': id}}:
                    # There is a race condition in create_subnet for
                    # ipv6 auto address subnets. When
                    # NeutronDbPluginV2._create_subnet tries to update the
                    # internal ports of the network and if any of the internal
                    # port is deleted by another worker, subnet creation
                    # fails. This is seen for the
                    # tempest.api.network.test_dhcp_ipv6.NetworksTestDHCPv6.*
                    # tests in the CI.
                    # This is a workaround until its fixed in the neutron.
                    # Since NeutronDbPluginV2._create_subnet calls port_update
                    # with port_info dict as {'port': {'id': id}}, we can
                    # ignore this error.
                    # Returning None as NeutronDbPluginV2._create_subnet
                    # doesn't check for the return value.
                    LOG.debug('Ignoring PortNotFound exception for port %s',
                              ' as update_port is called by create_subnet',
                              id)
                    return
                raise

            updated_port = super(OVNPlugin, self).update_port(context, id,
                                                              port)
            self._process_port_port_security_update(context, port['port'],
                                                    updated_port)

            self._portsec_ext_port_update_processing(updated_port, context,
                                                     port)

            self._process_portbindings_create_and_update(context,
                                                         pdict,
                                                         updated_port)
            self.update_security_group_on_port(
                context, id, port, original_port, updated_port)

            if addr_pair.ADDRESS_PAIRS in port['port']:
                self.update_address_pairs_on_port(context, id, port,
                                                  original_port,
                                                  updated_port)

            self._update_extra_dhcp_opts_on_port(context, id, port,
                                                 updated_port=updated_port)
            self.core_ext_handler.process_fields(
                context, base_core.PORT, pdict, updated_port)
            qos_options = self.qos_get_ovn_port_options(
                context, updated_port)

        ovn_port_info = self.get_ovn_port_options(binding_profile,
                                                  qos_options,
                                                  updated_port)
        return self._update_port_in_ovn(context, original_port,
                                        updated_port, ovn_port_info)

    def _portsec_ext_port_create_processing(self, context, port_data, port):
        # This function  is borrowed from ml2 plugin
        port_security = ((port_data.get(psec.PORTSECURITY) is None) or
                         port_data[psec.PORTSECURITY])

        # allowed address pair checks
        if self._check_update_has_allowed_address_pairs(port):
            if not port_security:
                raise addr_pair.AddressPairAndPortSecurityRequired()
        else:
            # remove ATTR_NOT_SPECIFIED
            port['port'][addr_pair.ADDRESS_PAIRS] = []

        if port_security:
            self._ensure_default_security_group_on_port(context, port)
        elif self._check_update_has_security_groups(port):
            raise psec.PortSecurityAndIPRequiredForSecurityGroups()

    def _portsec_ext_port_update_processing(self, updated_port, context, port):
        # This function  is borrowed from ml2 plugin
        port_security = ((updated_port.get(psec.PORTSECURITY) is None) or
                         updated_port[psec.PORTSECURITY])

        if port_security:
            return

        # check the address-pairs
        if self._check_update_has_allowed_address_pairs(port):
            #  has address pairs in request
            raise addr_pair.AddressPairAndPortSecurityRequired()
        elif (not self._check_update_deletes_allowed_address_pairs(port)):
            # not a request for deleting the address-pairs
            updated_port[addr_pair.ADDRESS_PAIRS] = (
                self.get_allowed_address_pairs(context, updated_port['id']))

            if updated_port[addr_pair.ADDRESS_PAIRS]:
                raise addr_pair.AddressPairAndPortSecurityRequired()

        # checks if security groups were updated adding/modifying
        # security groups, port security is set
        if self._check_update_has_security_groups(port):
            raise psec.PortSecurityAndIPRequiredForSecurityGroups()
        elif (not self._check_update_deletes_security_groups(port)):
            # Update did not have security groups passed in. Check
            # that port does not have any security groups already on it.
            filters = {'port_id': [updated_port['id']]}
            security_groups = self._get_port_security_group_bindings(
                context, filters)

            if security_groups:
                raise psec.PortSecurityPortHasSecurityGroup()

    def _update_port_in_ovn(self, context, original_port, port,
                            ovn_port_info):
        external_ids = {
            ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port['name']}
        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.set_lport(lport_name=port['id'],
                    addresses=ovn_port_info.addresses,
                    external_ids=external_ids,
                    parent_name=ovn_port_info.parent_name,
                    tag=ovn_port_info.tag,
                    type=ovn_port_info.type,
                    options=ovn_port_info.options,
                    enabled=port['admin_state_up'],
                    port_security=ovn_port_info.port_security))
            # Note that the ovsdb IDL suppresses the transaction down to what
            # has actually changed.
            txn.add(self._ovn.delete_acl(
                    utils.ovn_name(port['network_id']),
                    port['id']))
            sg_ports_cache = {}
            subnet_cache = {}
            acls_new = self._add_acls(context, port,
                                      sg_ports_cache=sg_ports_cache,
                                      subnet_cache=subnet_cache)
            for acl in acls_new:
                txn.add(self._ovn.add_acl(**acl))

        # Refresh remote security groups for changed security groups
        old_sg_ids = set(original_port.get('security_groups', []))
        new_sg_ids = set(port.get('security_groups', []))
        detached_sg_ids = old_sg_ids - new_sg_ids
        attached_sg_ids = new_sg_ids - old_sg_ids

        if (len(port.get('fixed_ips')) == 0 and
                len(original_port.get('fixed_ips')) == 0):
            # No need to process remote security group if the port
            # didn't have any IP Addresses.
            return port

        for sg_id in (attached_sg_ids | detached_sg_ids):
            self._refresh_remote_security_group(
                context, sg_id,
                sg_ports_cache=sg_ports_cache,
                exclude_ports=[port['id']],
                subnet_cache=subnet_cache)

        # Refresh remote security groups if remote_group_match_ip is set
        if original_port.get('fixed_ips') != port.get('fixed_ips'):
            # We have refreshed attached and detached security groups, so
            # now we only need to take care of unchanged security groups.
            unchanged_sg_ids = new_sg_ids & old_sg_ids
            for sg_id in unchanged_sg_ids:
                self._refresh_remote_security_group(
                    context, sg_id,
                    sg_ports_cache=sg_ports_cache,
                    exclude_ports=[port['id']],
                    subnet_cache=subnet_cache)

        return port

    def get_data_from_binding_profile(self, context, port):
        if (ovn_const.OVN_PORT_BINDING_PROFILE not in port or
                not attr.is_attr_set(
                    port[ovn_const.OVN_PORT_BINDING_PROFILE])):
            return {}

        param_dict = {}
        for param_set in ovn_const.OVN_PORT_BINDING_PROFILE_PARAMS:
            param_keys = param_set.keys()
            for param_key in param_keys:
                try:
                    param_dict[param_key] = (port[
                        ovn_const.OVN_PORT_BINDING_PROFILE][param_key])
                except KeyError:
                    pass
            if len(param_dict) == 0:
                continue
            if len(param_dict) != len(param_keys):
                msg = _('Invalid binding:profile. %s are all '
                        'required.') % param_keys
                raise n_exc.InvalidInput(error_message=msg)
            if (len(port[ovn_const.OVN_PORT_BINDING_PROFILE]) != len(
                    param_keys)):
                msg = _('Invalid binding:profile. too many parameters')
                raise n_exc.InvalidInput(error_message=msg)
            break

        if not param_dict:
            return {}

        for param_key, param_type in param_set.items():
            if param_type is None:
                continue
            param_value = param_dict[param_key]
            if not isinstance(param_value, param_type):
                msg = _('Invalid binding:profile. %(key)s %(value)s '
                        'value invalid type') % {'key': param_key,
                                                 'value': param_value}
                raise n_exc.InvalidInput(error_message=msg)

        # Make sure we can successfully look up the port indicated by
        # parent_name.  Just let it raise the right exception if there is a
        # problem.
        if 'parent_name' in param_set:
            self.get_port(context, param_dict['parent_name'])

        if 'tag' in param_set:
            tag = int(param_dict['tag'])
            if tag < 0 or tag > 4095:
                msg = _('Invalid binding:profile. tag "%s" must be '
                        'an int between 1 and 4096, inclusive.') % tag
                raise n_exc.InvalidInput(error_message=msg)

        return param_dict

    def _get_allowed_addresses_from_port(self, port):
        if not port.get(psec.PORTSECURITY):
            return []

        allowed_addresses = set()
        addresses = port['mac_address']
        for ip in port.get('fixed_ips', []):
            addresses += ' ' + ip['ip_address']

        for allowed_address in port.get('allowed_address_pairs', []):
            # If allowed address pair has same mac as the port mac,
            # append the allowed ip address to the 'addresses'.
            # Else we will have multiple entries for the same mac in
            # 'Logical_Port.port_security'.
            if allowed_address['mac_address'] == port['mac_address']:
                addresses += ' ' + allowed_address['ip_address']
            else:
                allowed_addresses.add(allowed_address['mac_address'] + ' ' +
                                      allowed_address['ip_address'])

        allowed_addresses.add(addresses)

        return list(allowed_addresses)

    def _update_port_binding(self, port_res):
        port_res[portbindings.VNIC_TYPE] = portbindings.VNIC_NORMAL
        if config.get_ovn_vif_type() == portbindings.VIF_TYPE_VHOST_USER:
            port_res[portbindings.VIF_DETAILS].update({
                portbindings.VHOST_USER_SOCKET: utils.ovn_vhu_sockpath(
                    cfg.CONF.ovn.vhost_sock_dir, port_res['id'])
                })

    def create_port(self, context, port):
        pdict = port['port']
        with context.session.begin(subtransactions=True):
            binding_profile = self.get_data_from_binding_profile(
                context, pdict)

            # set the status of the port to down by default
            port['port']['status'] = const.PORT_STATUS_DOWN

            dhcp_opts = port['port'].get(edo_ext.EXTRADHCPOPTS, [])
            db_port = super(OVNPlugin, self).create_port(context, port)
            self.core_ext_handler.process_fields(
                context, base_core.PORT, pdict, db_port)
            port['port'][psec.PORTSECURITY] = self._determine_port_security(
                context, port['port'])
            self._process_port_port_security_create(context, port['port'],
                                                    db_port)
            self._portsec_ext_port_create_processing(context, db_port, port)
            sgids = self._get_security_groups_on_port(context, port)
            self._process_port_create_security_group(context, db_port,
                                                     sgids)
            self._process_portbindings_create_and_update(context,
                                                         pdict,
                                                         db_port)
            self._update_port_binding(db_port)

            # NOTE(arosen): _process_portbindings_create_and_update
            # does not set the binding on the port so we do it here.
            if (ovn_const.OVN_PORT_BINDING_PROFILE in pdict and
                attr.is_attr_set(
                    pdict[ovn_const.OVN_PORT_BINDING_PROFILE])):
                db_port[ovn_const.OVN_PORT_BINDING_PROFILE] = \
                    pdict[ovn_const.OVN_PORT_BINDING_PROFILE]

            db_port[addr_pair.ADDRESS_PAIRS] = (
                self._process_create_allowed_address_pairs(
                    context, db_port,
                    port['port'].get(addr_pair.ADDRESS_PAIRS)))
            self._process_port_create_extra_dhcp_opts(context, db_port,
                                                      dhcp_opts)
            qos_options = self.qos_get_ovn_port_options(
                context, db_port)

        # This extra lookup is necessary to get the latest db model
        # for the extension functions.
        port_model = self._get_port(context, db_port['id'])
        self._apply_dict_extend_functions('ports', db_port, port_model)

        ovn_port_info = self.get_ovn_port_options(
            binding_profile, qos_options, db_port)
        return self.create_port_in_ovn(context, db_port, ovn_port_info)

    def get_ovn_port_options(self, binding_profile, qos_options, port):
        vtep_physical_switch = binding_profile.get('vtep_physical_switch')
        vtep_logical_switch = None
        parent_name = None
        tag = None
        port_type = None
        options = None

        if vtep_physical_switch:
            vtep_logical_switch = binding_profile.get('vtep_logical_switch')
            port_type = 'vtep'
            options = {'vtep_physical_switch': vtep_physical_switch,
                       'vtep_logical_switch': vtep_logical_switch}
            addresses = "unknown"
            port_security = []
        else:
            options = qos_options
            parent_name = binding_profile.get('parent_name')
            tag = binding_profile.get('tag')
            addresses = port['mac_address']
            for ip in port.get('fixed_ips', []):
                addresses += ' ' + ip['ip_address']
            port_security = self._get_allowed_addresses_from_port(port)

        return OvnPortInfo(port_type, options, [addresses], port_security,
                           parent_name, tag)

    def _determine_port_security(self, context, port):
        """Returns a boolean (port_security_enabled).

        This function is borrowed from ml2 port security extension driver.
        Port_security is the value associated with the port if one is present
        otherwise the value associated with the network is returned.
        """
        # we don't apply port security for dhcp, router
        if port.get('device_owner') and port['device_owner'].startswith(
            const.DEVICE_OWNER_NETWORK_PREFIX):
            return False

        if attr.is_attr_set(port.get(psec.PORTSECURITY)):
            port_security_enabled = port[psec.PORTSECURITY]
        else:
            try:
                port_security_enabled = self._get_network_security_binding(
                    context, port['network_id'])
            except psec.PortSecurityBindingNotFound:
                # If Network security binding doesn't exist return True.
                # This could happen for networks created prior to port
                # security extension support in the plugin.
                port_security_enabled = True

        return port_security_enabled

    def _acl_direction(self, r, port):
        if r['direction'] == 'ingress':
            portdir = 'outport'
            remote_portdir = 'inport'
        else:
            portdir = 'inport'
            remote_portdir = 'outport'
        match = '%s == "%s"' % (portdir, port['id'])
        return match, remote_portdir

    def _acl_ethertype(self, r):
        match = ''
        ip_version = None
        icmp = None
        if r['ethertype'] == 'IPv4':
            match = ' && ip4'
            ip_version = 'ip4'
            icmp = 'icmp4'
        elif r['ethertype'] == 'IPv6':
            match = ' && ip6'
            ip_version = 'ip6'
            icmp = 'icmp6'
        return match, ip_version, icmp

    def _acl_remote_ip_prefix(self, r, ip_version):
        if not r['remote_ip_prefix']:
            return ''
        src_or_dst = 'src' if r['direction'] == 'ingress' else 'dst'
        return ' && %s.%s == %s' % (ip_version, src_or_dst,
                                    r['remote_ip_prefix'])

    def _acl_get_subnet_from_cache(self, context, subnet_cache, subnet_id):
        if subnet_id in subnet_cache:
            return subnet_cache[subnet_id]
        else:
            subnet = self.get_subnet(context, subnet_id)
            if subnet:
                subnet_cache[subnet_id] = subnet
            return subnet

    def _acl_remote_match_ip(self, context, sg_ports, subnet_cache,
                             ip_version, src_or_dst):
        ip_version_map = {'ip4': 4,
                          'ip6': 6}
        match = ''
        port_ids = [sg_port['port_id'] for sg_port in sg_ports]
        ports = self.get_ports(context, filters={'id': port_ids})
        for port in ports:
            for fixed_ip in port['fixed_ips']:
                subnet = self._acl_get_subnet_from_cache(context,
                                                         subnet_cache,
                                                         fixed_ip['subnet_id'])
                if subnet['ip_version'] == ip_version_map.get(ip_version):
                    match += '%s.%s == %s || ' % (ip_version,
                                                  src_or_dst,
                                                  fixed_ip['ip_address'])

        if match:
            match = match[:-4]  # Remove the last ' || '
            match = ' && (%s)' % match

        return match

    def _acl_remote_group_id(self, context, r, sg_ports_cache, subnet_cache,
                             port, remote_portdir, ip_version):
        if not r['remote_group_id']:
            return '', False
        match = ''
        elevated_context = context.elevated()
        if r['remote_group_id'] in sg_ports_cache:
            sg_ports = sg_ports_cache[r['remote_group_id']]
        else:
            filters = {'security_group_id': [r['remote_group_id']]}
            sg_ports = self._get_port_security_group_bindings(
                elevated_context, filters)
            sg_ports_cache[r['remote_group_id']] = sg_ports
        sg_ports = [p for p in sg_ports if p['port_id'] != port['id']]
        if not sg_ports:
            # If there are no other ports on this security group, then this
            # rule can never match, so no ACL row will be created for this
            # rule.
            return '', True

        src_or_dst = 'src' if r['direction'] == 'ingress' else 'dst'
        remote_group_match = self._acl_remote_match_ip(elevated_context,
                                                       sg_ports,
                                                       subnet_cache,
                                                       ip_version,
                                                       src_or_dst)

        match += remote_group_match

        return match, False

    def _acl_protocol_and_ports(self, r, icmp):
        protocol = None
        match = ''
        if r['protocol'] in ('tcp', 'udp'):
            protocol = r['protocol']
            port_match = '%s.dst' % protocol
        elif r['protocol'] == 'icmp':
            protocol = icmp
            port_match = '%s.type' % icmp
        if protocol:
            match += ' && %s' % protocol
            # If min or max are set to -1, then we just treat it like it wasn't
            # specified at all and don't match on it.
            min_port = r['port_range_min']
            max_port = r['port_range_max']
            if (min_port and min_port == max_port and min_port != -1):
                match += ' && %s == %d' % (port_match, min_port)
            else:
                if min_port and min_port != -1:
                    match += ' && %s >= %d' % (port_match, min_port)
                if max_port and max_port != -1:
                    match += ' && %s <= %d' % (port_match, max_port)
        return match

    def _add_sg_rule_acl_for_port(self, context, port, r, sg_ports_cache,
                                  subnet_cache):
        # Update the match based on which direction this rule is for (ingress
        # or egress).
        match, remote_portdir = self._acl_direction(r, port)

        # Update the match for IPv4 vs IPv6.
        ip_match, ip_version, icmp = self._acl_ethertype(r)
        match += ip_match

        # Update the match if an IPv4 or IPv6 prefix was specified.
        match += self._acl_remote_ip_prefix(r, ip_version)

        group_match, empty_match = self._acl_remote_group_id(context, r,
                                                             sg_ports_cache,
                                                             subnet_cache,
                                                             port,
                                                             remote_portdir,
                                                             ip_version)
        if empty_match:
            # If there are no other ports on this security group, then this
            # rule can never match, so no ACL row will be created for this
            # rule.
            return None
        match += group_match

        # Update the match for the protocol (tcp, udp, icmp) and port/type
        # range if specified.
        match += self._acl_protocol_and_ports(r, icmp)

        # Finally, create the ACL entry for the direction specified.
        dir_map = {
            'ingress': 'to-lport',
            'egress': 'from-lport',
        }
        acl = {"lswitch": utils.ovn_name(port['network_id']),
               "lport": port['id'],
               "priority": ovn_const.ACL_PRIORITY_ALLOW,
               "action": ovn_const.ACL_ACTION_ALLOW_RELATED,
               "log": False,
               "direction": dir_map[r['direction']],
               "match": match,
               "external_ids": {'neutron:lport': port['id']}}
        return acl

    def _add_acl_dhcp(self, context, port, subnet_cache):
        # Allow DHCP responses through from source IPs on the local subnet.
        # We do this even if DHCP isn't enabled.  It could be enabled later.
        # We could hook into handling when it's enabled/disabled for a subnet,
        # but this code is temporary anyway.  It's likely no longer needed
        # once OVN native DHCP support merges, which is under development and
        # review already.
        # TODO(russellb) Remove this once OVN native DHCP support is merged.
        acl_list = []
        for ip in port['fixed_ips']:
            subnet = self._acl_get_subnet_from_cache(context, subnet_cache,
                                                     ip['subnet_id'])
            if subnet['ip_version'] != 4:
                continue
            acl = {"lswitch": utils.ovn_name(port['network_id']),
                   "lport": port['id'],
                   "priority": ovn_const.ACL_PRIORITY_ALLOW,
                   "action": ovn_const.ACL_ACTION_ALLOW,
                   "log": False,
                   "direction": 'to-lport',
                   "match": ('outport == "%s" && ip4 && ip4.src == %s && '
                             'udp && udp.src == 67 && udp.dst == 68'
                             ) % (port['id'], subnet['cidr']),
                   "external_ids": {'neutron:lport': port['id']}}
            acl_list.append(acl)
            acl = {"lswitch": utils.ovn_name(port['network_id']),
                   "lport": port['id'],
                   "priority": ovn_const.ACL_PRIORITY_ALLOW,
                   "action": ovn_const.ACL_ACTION_ALLOW,
                   "log": False,
                   "direction": 'from-lport',
                   "match": ('inport == "%s" && ip4 && '
                             '(ip4.dst == 255.255.255.255 || '
                             'ip4.dst == %s) && '
                             'udp && udp.src == 68 && udp.dst == 67'
                             ) % (port['id'], subnet['cidr']),
                   "external_ids": {'neutron:lport': port['id']}}
            acl_list.append(acl)
        return acl_list

    def _drop_all_ip_traffic_for_port(self, port):
        acl_list = []
        for direction, p in (('from-lport', 'inport'),
                             ('to-lport', 'outport')):
            lswitch = utils.ovn_name(port['network_id'])
            lport = port['id']
            acl = {"lswitch": lswitch, "lport": lport,
                   "priority": ovn_const.ACL_PRIORITY_DROP,
                   "action": ovn_const.ACL_ACTION_DROP,
                   "log": False,
                   "direction": direction,
                   "match": '%s == "%s" && ip' % (p, port['id']),
                   "external_ids": {'neutron:lport': port['id']}}
            acl_list.append(acl)
        return acl_list

    def _add_acls(self, context, port,
                  sg_cache=None, sg_ports_cache=None, subnet_cache=None):
        acl_list = []
        sec_groups = port.get('security_groups', [])
        if not sec_groups:
            return acl_list

        # Drop all IP traffic to and from the logical port by default.
        acl_list += self._drop_all_ip_traffic_for_port(port)

        if subnet_cache is None:
            subnet_cache = {}
        acl_list += self._add_acl_dhcp(context, port, subnet_cache)

        # We often need a list of all ports on a security group.  Cache these
        # results so we only do the query once throughout this processing.
        if sg_ports_cache is None:
            sg_ports_cache = {}

        # We create an ACL entry for each rule on each security group applied
        # to this port.
        for sg_id in sec_groups:
            if sg_cache and sg_id in sg_cache:
                sg = sg_cache[sg_id]
            else:
                sg = self.get_security_group(context, sg_id)
                if sg_cache is not None:
                    sg_cache[sg_id] = sg
            for r in sg['security_group_rules']:
                acl = self._add_sg_rule_acl_for_port(context, port, r,
                                                     sg_ports_cache,
                                                     subnet_cache)
                if acl and acl not in acl_list:
                    acl_list.append(acl)

        return acl_list

    def create_port_in_ovn(self, context, port, ovn_port_info):
        external_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port['name']}
        lswitch_name = utils.ovn_name(port['network_id'])

        with self._ovn.transaction(check_error=True) as txn:
            # The lport_name *must* be neutron port['id'].  It must match the
            # iface-id set in the Interfaces table of the Open_vSwitch
            # database which nova sets to be the port ID.
            txn.add(self._ovn.create_lport(
                    lport_name=port['id'],
                    lswitch_name=lswitch_name,
                    addresses=ovn_port_info.addresses,
                    external_ids=external_ids,
                    parent_name=ovn_port_info.parent_name,
                    tag=ovn_port_info.tag,
                    enabled=port.get('admin_state_up'),
                    options=ovn_port_info.options,
                    type=ovn_port_info.type,
                    port_security=ovn_port_info.port_security))
            sg_ports_cache = {}
            subnet_cache = {}
            acls_new = self._add_acls(context, port,
                                      sg_ports_cache=sg_ports_cache,
                                      subnet_cache=subnet_cache)
            for acl in acls_new:
                txn.add(self._ovn.add_acl(**acl))

        if len(port.get('fixed_ips')):
            for sg_id in port.get('security_groups', []):
                self._refresh_remote_security_group(
                    context, sg_id, sg_ports_cache=sg_ports_cache,
                    exclude_ports=[port['id']], subnet_cache=subnet_cache)

        return port

    def _refresh_remote_security_group(self, context, sec_group,
                                       sg_ports_cache=None,
                                       exclude_ports=None,
                                       subnet_cache=None):
        # For sec_group, refresh acls for all other security groups that have
        # rules referencing sec_group as 'remote_group'.
        filters = {'remote_group_id': [sec_group]}
        # Elevate the context so that we can see sec-groups and port-sg
        # bindings that do not belong to the current tenant.
        elevated_context = context.elevated()
        refering_rules = self.get_security_group_rules(
            elevated_context, filters, fields=['security_group_id'])
        sg_ids = set(r['security_group_id'] for r in refering_rules)
        for sg_id in sg_ids:
            self._update_acls_for_security_group(elevated_context, sg_id,
                                                 sg_ports_cache,
                                                 exclude_ports,
                                                 subnet_cache=subnet_cache)

    def delete_port(self, context, port_id, l3_port_check=True):
        port = self.get_port(context, port_id)
        num_fixed_ips = len(port.get('fixed_ips'))
        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.delete_lport(port_id,
                    utils.ovn_name(port['network_id'])))
            txn.add(self._ovn.delete_acl(
                    utils.ovn_name(port['network_id']), port['id']))

        sg_ids = port.get('security_groups', [])

        with context.session.begin(subtransactions=True):
            self.disassociate_floatingips(context, port_id)
            super(OVNPlugin, self).delete_port(context, port_id)

        if num_fixed_ips:
            for sg_id in sg_ids:
                self._refresh_remote_security_group(context, sg_id)

    def extend_port_dict_binding(self, port_res, port_db):
        super(OVNPlugin, self).extend_port_dict_binding(port_res, port_db)
        self._update_port_binding(port_res)

    # Register extend dict methods for network and port resources.
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attr.NETWORKS, ['_extend_network_dict'])

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attr.PORTS, ['_extend_port_dict'])

    def _extend_network_dict(self, net_result, net_db):
        self._extend_port_security_dict(net_result, net_db)

    def _extend_port_dict(self, port_result, port_db):
        self._extend_port_security_dict(port_result, port_db)

    def _extend_port_security_dict(self, response_data, db_data):
        if db_data.get('port_security') is None:
            response_data[psec.PORTSECURITY] = (
                psec.EXTENDED_ATTRIBUTES_2_0['networks']
                [psec.PORTSECURITY]['default'])
        else:
            response_data[psec.PORTSECURITY] = (
                db_data['port_security'][psec.PORTSECURITY])

    def create_router(self, context, router):
        router = super(OVNPlugin, self).create_router(
            context, router)
        try:
            self.create_lrouter_in_ovn(router)
        except Exception:
            LOG.exception(_LE('Unable to create lrouter for %s'),
                          router['id'])
            super(OVNPlugin, self).delete_router(context, router['id'])
            raise n_exc.ServiceUnavailable()

        return router

    def create_lrouter_in_ovn(self, router):
        """Create lrouter in OVN

        @param router: Router to be created in OVN
        @return: Nothing
        """

        router_name = utils.ovn_name(router['id'])
        external_ids = {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                        router.get('name', 'no_router_name')}
        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.create_lrouter(router_name,
                                             external_ids=external_ids
                                             ))

    def delete_router(self, context, router_id):
        router_name = utils.ovn_name(router_id)
        ret_val = super(OVNPlugin, self).delete_router(context,
                                                       router_id)
        self._ovn.delete_lrouter(router_name).execute(check_error=True)
        return ret_val

    def update_router(self, context, id, router):
        original_router = self.get_router(context, id)
        result = super(OVNPlugin, self).update_router(
            context, id, router)
        if 'name' in router['router']:
            router_name = utils.ovn_name(id)
            external_ids = {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                            router['router']['name']}
            try:
                self._ovn.update_lrouter(router_name,
                                         external_ids=external_ids
                                         ).execute(check_error=True)
            except Exception:
                LOG.exception(_LE('Unable to update lrouter for %s'), id)
                super(OVNPlugin, self).update_router(context,
                                                     id,
                                                     original_router)
                raise n_exc.ServiceUnavailable()

        return result

    def create_lrouter_port_in_ovn(self, context, router_id, port):
        """Create lrouter port in OVN

        @param router id : LRouter ID for the port that needs to be created
        @param port : LRouter port that needs to be created
        @return: Nothing
        """
        subnet_id = port['fixed_ips'][0]['subnet_id']
        subnet = self.get_subnet(context, subnet_id)
        lrouter = utils.ovn_name(router_id)
        cidr = netaddr.IPNetwork(subnet['cidr'])
        network = "%s/%s" % (port['fixed_ips'][0]['ip_address'],
                             str(cidr.prefixlen))

        lrouter_port_name = utils.ovn_lrouter_port_name(port['id'])
        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.add_lrouter_port(name=lrouter_port_name,
                                               lrouter=lrouter,
                                               mac=port['mac_address'],
                                               network=network))

            txn.add(self._ovn.set_lrouter_port_in_lport(port['id'],
                                                        lrouter_port_name))

    def add_router_interface(self, context, router_id, interface_info):
        router_interface_info = super(OVNPlugin, self).add_router_interface(
            context, router_id, interface_info)

        if not config.is_ovn_l3():
            LOG.debug("OVN L3 mode is disabled, skipping "
                      "add_router_interface")
            return router_interface_info

        port = self.get_port(context, router_interface_info['port_id'])
        self.create_lrouter_port_in_ovn(context, router_id, port)
        return router_interface_info

    def remove_router_interface(self, context, router_id, interface_info):
        if not config.is_ovn_l3():
            LOG.debug("OVN L3 mode is disabled, skipping "
                      "remove_router_interface")
            return super(OVNPlugin, self).remove_router_interface(
                context, router_id, interface_info)
        # TODO(chandrav)
        # Need to rework this code to get the port_id when the incoming request
        # contains only the subnet_id. Also need to figure out if OVN needs to
        # care about multiple prefix subnets on a single router interface.
        # This code is duplicated from neutron. Probably a better thing to do
        # is to handle everything in the plugin and just call delete_port
        # update_port.
        port_id = None
        if 'port_id' in interface_info:
            port_id = interface_info['port_id']
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            subnet = self.get_subnet(context, subnet_id)
            device_filter = {'device_id': [router_id],
                             'device_owner': [const.DEVICE_OWNER_ROUTER_INTF],
                             'network_id': [subnet['network_id']]}
            ports = super(OVNPlugin, self).get_ports(context,
                                                     filters=device_filter)
            for p in ports:
                port_subnets = [fip['subnet_id'] for fip in p['fixed_ips']]
                if subnet_id in port_subnets and len(port_subnets) == 1:
                    port_id = p['id']
                    break

        router_interface_info = super(OVNPlugin, self).remove_router_interface(
            context, router_id, interface_info)

        if port_id is not None:
            self._ovn.delete_lrouter_port(utils.ovn_lrouter_port_name(port_id),
                                          utils.ovn_name(router_id),
                                          if_exists=False
                                          ).execute(check_error=True)
        return router_interface_info

    def _update_acls_for_security_group(self, context, security_group_id,
                                        sg_ports_cache=None,
                                        exclude_ports=None,
                                        subnet_cache=None,
                                        rule=None, is_add_acl=True):
        if exclude_ports is None:
            exclude_ports = []
        filters = {'security_group_id': [security_group_id]}
        sg_ports = self._get_port_security_group_bindings(context, filters)
        sg_cache = {}
        if sg_ports_cache is None:
            sg_ports_cache = {}
        if subnet_cache is None:
            subnet_cache = {}
        port_list = []

        # ACLs associated with a security group may span logical switches
        sg_port_ids = [binding['port_id'] for binding in sg_ports]
        sg_port_ids = list(set(sg_port_ids) - set(exclude_ports))
        port_list = self.get_ports(context, filters={'id': sg_port_ids})
        lswitch_names = set([p['network_id'] for p in port_list])
        acl_new_values_dict = {}

        # NOTE(lizk): When a certain rule is given, we can directly locate
        # the affected acl records, so no need to compare new acl values with
        # existing acl objects, such as case create_security_group_rule or
        # delete_security_group_rule is calling this. But for other cases,
        # since we don't know which acl records need be updated, compare will
        # be needed.
        need_compare = True
        if rule:
            need_compare = False
            for port in port_list:
                acl = self._add_sg_rule_acl_for_port(
                    context, port, rule, {}, {})
                # Remove lport and lswitch since we don't need them
                acl.pop('lport')
                acl.pop('lswitch')
                acl_new_values_dict[port['id']] = acl
        else:
            for port in port_list:
                acls_new = self._add_acls(context, port, sg_cache,
                                          sg_ports_cache, subnet_cache)
                acl_new_values_dict[port['id']] = acls_new

        self._ovn.update_acls(list(lswitch_names),
                              iter(port_list),
                              acl_new_values_dict,
                              need_compare=need_compare,
                              is_add_acl=is_add_acl).execute(check_error=True)

    def update_security_group(self, context, id, security_group):
        res = super(OVNPlugin, self).update_security_group(context, id,
                                                           security_group)
        self._update_acls_for_security_group(context, id)
        return res

    def delete_security_group(self, context, id):
        super(OVNPlugin, self).delete_security_group(context, id)
        # Neutron will only delete a security group if it is not associated
        # with any active ports, so we have nothing to do here.

    def create_security_group_rule(self, context, security_group_rule):
        res = super(OVNPlugin, self).create_security_group_rule(
            context, security_group_rule)
        rule = security_group_rule['security_group_rule']
        group_id = rule['security_group_id']
        # TODO(russellb) It's possible for Neutron and OVN to get out of sync
        # here.  We put the rule in the Neutron db above and then update all
        # affected ports next.  If updating ports fails somehow, we're out of
        # sync until another change causes another refresh attempt.
        self._update_acls_for_security_group(context, group_id, rule=rule,
                                             is_add_acl=True)
        return res

    def delete_security_group_rule(self, context, id):
        security_group_rule = self.get_security_group_rule(context, id)
        group_id = security_group_rule['security_group_id']
        super(OVNPlugin, self).delete_security_group_rule(context, id)
        # TODO(russellb) It's possible for Neutron and OVN to get out of sync
        # here.  We delete the rule from the Neutron db first and then do an
        # ACL update to reflect the current state in OVN.  If updating OVN
        # fails, we'll be out of sync until another change happens that
        # triggers a refresh.
        self._update_acls_for_security_group(context, group_id,
                                             rule=security_group_rule,
                                             is_add_acl=False)

    def get_workers(self):
        # See doc/source/design/ovn_worker.rst for more details.
        return [ovsdb_monitor.OvnWorker()]

    def _update_port_status(self, ctx, port_id, status):
        try:
            with ctx.session.begin(subtransactions=True):
                db_port = self._get_port(ctx, port_id)
                if db_port.status != status:
                    LOG.debug("Updating port status of port - %s to %s",
                              port_id, status)
                    db_port.status = status
        except (n_exc.PortNotFound, sa_exc.StaleDataError):
            # Its possible that port could have been deleted
            # or being deleted concurrently
            LOG.debug("Port update unsuccessful - %s", port_id)

    def set_port_status_up(self, port_id):
        ctx = n_context.get_admin_context()
        self._update_port_status(ctx, port_id, const.PORT_STATUS_ACTIVE)

    def set_port_status_down(self, port_id):
        ctx = n_context.get_admin_context()
        self._update_port_status(ctx, port_id, const.PORT_STATUS_DOWN)

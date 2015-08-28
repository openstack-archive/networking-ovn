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

from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import importutils
import six
from sqlalchemy.orm import exc as sa_exc


from neutron.agent.ovsdb.native import idlutils
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.rpc.handlers import dhcp_rpc
from neutron.api.rpc.handlers import l3_rpc
from neutron.api.rpc.handlers import metadata_rpc
from neutron.api.v2 import attributes as attr
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import exceptions as n_exc
from neutron.extensions import extra_dhcp_opt as edo_ext
from neutron.extensions import portbindings
from neutron.extensions import providernet as pnet

from neutron.common import constants as const
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import extraroute_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_gwmode_db
from neutron.db import portbindings_db
from neutron.db import securitygroups_db
from neutron.i18n import _LE, _LI

from networking_ovn.common import config
from networking_ovn.common import constants as ovn_const
from networking_ovn.common import utils
from networking_ovn import ovn_nb_sync
from networking_ovn.ovsdb import impl_idl_ovn


LOG = log.getLogger(__name__)


# OVN ACLs have priorities.  The highest priority ACL that matches is the one
# that takes effect.  Our choice of priority numbers is arbitrary, but it
# leaves room above and below the ACLs we create.  We only need two priorities.
# The first is for all the things we allow.  The second is for dropping traffic
# by default.
ACL_PRIORITY_ALLOW = 1002
ACL_PRIORITY_DROP = 1001


class OVNPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                securitygroups_db.SecurityGroupDbMixin,
                l3_agentschedulers_db.L3AgentSchedulerDbMixin,
                l3_gwmode_db.L3_NAT_db_mixin,
                external_net_db.External_net_db_mixin,
                portbindings_db.PortBindingMixin,
                extradhcpopt_db.ExtraDhcpOptMixin,
                extraroute_db.ExtraRoute_db_mixin,
                agentschedulers_db.DhcpAgentSchedulerDbMixin):

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = ["quotas",
                                   "extra_dhcp_opt",
                                   "binding",
                                   "agent",
                                   "dhcp_agent_scheduler",
                                   "security-group",
                                   "extraroute",
                                   "external-net",
                                   "router",
                                   "provider"]

    def __init__(self):
        super(OVNPlugin, self).__init__()
        LOG.info(_("Starting OVNPlugin"))
        self.vif_type = portbindings.VIF_TYPE_OVS
        # When set to True, Nova plugs the VIF directly into the ovs bridge
        # instead of using the hybrid mode.
        self.vif_details = {portbindings.CAP_PORT_FILTER: True}
        registry.subscribe(self.post_fork_initialize, resources.PROCESS,
                           events.AFTER_CREATE)
        self._setup_dhcp()
        self._start_rpc_notifiers()

    def post_fork_initialize(self, resource, event, trigger, **kwargs):
        self._ovn = impl_idl_ovn.OvsdbOvnIdl()

        # Call the synchronization task, this sync neutron DB to OVN-NB DB
        # only in inconsistent states
        self.synchronizer = (
            ovn_nb_sync.OvnNbSynchronizer(self,
                                          self._ovn,
                                          config.get_ovn_neutron_sync_mode()))
        self.base_binding_dict = {
            portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS,
            portbindings.VIF_DETAILS: {
                # TODO(rkukura): Replace with new VIF security details
                portbindings.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}}

        self.synchronizer.sync()

    def _setup_rpc(self):
        self.endpoints = [dhcp_rpc.DhcpRpcCallback(),
                          l3_rpc.L3RpcCallback(),
                          agents_db.AgentExtRpcCallback(),
                          metadata_rpc.MetadataRpcCallback()]

    def _setup_dhcp(self):
        """Initialize components to support DHCP."""
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )
        self.start_periodic_dhcp_agent_status_check()

    def _start_rpc_notifiers(self):
        """Initialize RPC notifiers for agents."""
        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        )
        self.agent_notifiers[const.AGENT_TYPE_L3] = (
            l3_rpc_agent_api.L3AgentNotifyAPI()
        )

    def start_rpc_listeners(self):
        self._setup_rpc()
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(topics.PLUGIN, self.endpoints, fanout=False)
        self.conn.create_consumer(topics.L3PLUGIN, self.endpoints,
                                  fanout=False)
        self.conn.create_consumer(topics.REPORTS,
                                  [agents_db.AgentExtRpcCallback()],
                                  fanout=False)
        return self.conn.consume_in_threads()

    def _delete_ports(self, context, ports):
        for port in ports:
            try:
                self.delete_port(context, port.id)
            except (n_exc.PortNotFound, sa_exc.ObjectDeletedError):
                context.session.expunge(port)
                # concurrent port deletion can be performed by
                # release_dhcp_port caused by concurrent subnet_delete
                LOG.info(_LI("Port %s was deleted concurrently"), port.id)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_LE("Exception auto-deleting port %s"),
                                  port.id)

    def _get_attribute(self, obj, attribute):
        res = obj.get(attribute)
        if res is attr.ATTR_NOT_SPECIFIED:
            res = None
        return res

    def create_network(self, context, network):
        net = network['network']  # obviously..
        if self._get_attribute(net, pnet.PHYSICAL_NETWORK):
            # If this is a provider network, validate that it's a type we
            # support. (flat or vlan)
            nettype = self._get_attribute(net, pnet.NETWORK_TYPE)
            if nettype not in ('flat', 'vlan'):
                msg = _('%s network type is not supported with provider '
                        'networks (only flat or vlan).') % nettype
                raise n_exc.InvalidInput(error_message=msg)

        ext_ids = {}
        physnet = self._get_attribute(net, pnet.PHYSICAL_NETWORK)
        if physnet:
            # NOTE(russellb) This is the provider network case.  We stash the
            # provider networks fields on OVN Logical Switch.  This logical
            # switch isn't actually used for anything else because a special
            # switch is created for every port attached to the provider
            # network.  The reason we stash them is because these fields are
            # not actually stored in the Neutron database anywhere. :-(
            # They are stored in an ML2 specific db table by the ML2 plugin,
            # but there's no common code and table for other plugins.  Stashing
            # them here is the easy solution for now, but a common Neutron db
            # table and YAM (yet another mixin) would be better eventually.
            nettype = self._get_attribute(net, pnet.NETWORK_TYPE)
            segid = self._get_attribute(net, pnet.SEGMENTATION_ID)
            ext_ids.update({
                ovn_const.OVN_PHYSNET_EXT_ID_KEY: physnet,
                ovn_const.OVN_NETTYPE_EXT_ID_KEY: nettype,
            })
            if segid:
                ext_ids.update({
                    ovn_const.OVN_SEGID_EXT_ID_KEY: str(segid),
                })

        with context.session.begin(subtransactions=True):
            result = super(OVNPlugin, self).create_network(context,
                                                           network)
            self._process_l3_create(context, result, net)

        return self.create_network_in_ovn(result, ext_ids)

    def create_network_in_ovn(self, network, ext_ids):
        # Create a logical switch with a name equal to the Neutron network
        # UUID.  This provides an easy way to refer to the logical switch
        # without having to track what UUID OVN assigned to it.
        ext_ids.update({
            ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: network['name']
        })

        # TODO(arosen): Undo logical switch creation on failure
        self._ovn.create_lswitch(lswitch_name=utils.ovn_name(network['id']),
                                 external_ids=ext_ids).execute(
                                     check_error=True)
        return network

    def delete_network(self, context, network_id):
        with context.session.begin(subtransactions=True):
            super(OVNPlugin, self).delete_network(context,
                                                  network_id)
        self._ovn.delete_lswitch(
            utils.ovn_name(network_id), if_exists=True).execute(
                check_error=True)

    def _set_network_name(self, network_id, name):
        ext_id = [ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY, name]
        self._ovn.set_lswitch_ext_id(
            utils.ovn_name(network_id),
            ext_id).execute(check_error=True)

    def update_network(self, context, network_id, network):
        pnet._raise_if_updates_provider_attributes(network['network'])
        # FIXME(arosen) - rollback...
        if 'name' in network['network']:
            self._set_network_name(network_id, network['network']['name'])
        with context.session.begin(subtransactions=True):
            return super(OVNPlugin, self).update_network(context, network_id,
                                                         network)

    def update_port(self, context, id, port):
        with context.session.begin(subtransactions=True):
            # FIXME(arosen): if binding data isn't passed in here
            # we should fetch it from the db instead and not set it to
            # None since neutron implements patch sematics for updates
            binding_profile = self._get_data_from_binding_profile(
                context, port['port'])
            parent_name = binding_profile.get('parent_name')
            tag = binding_profile.get('tag')
            vtep_physical_switch = binding_profile.get('vtep_physical_switch')
            vtep_logical_switch = binding_profile.get('vtep_logical_switch')

            original_port = self._get_port(context, id)
            updated_port = super(OVNPlugin, self).update_port(context, id,
                                                              port)

            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         updated_port)
            self.update_security_group_on_port(
                context, id, port, original_port, updated_port)

        if vtep_physical_switch:
            port_type = 'vtep'
            options = {'vtep_physical_switch': vtep_physical_switch,
                       'vtep_logical_switch': vtep_logical_switch}
            macs = ["unknown"]
            allowed_macs = []
        else:
            port_type = None
            options = None
            macs = [updated_port['mac_address']]
            allowed_macs = self._get_allowed_mac_addresses_from_port(
                updated_port)

        external_ids = {
            ovn_const.OVN_PORT_NAME_EXT_ID_KEY: updated_port['name']}
        allowed_macs = self._get_allowed_mac_addresses_from_port(
            updated_port)
        with self._ovn.transaction(check_error=True) as txn:
            txn.add(self._ovn.set_lport(lport_name=updated_port['id'],
                    addresses=macs,
                    external_ids=external_ids,
                    parent_name=parent_name, tag=tag,
                    type=port_type,
                    options=options,
                    enabled=updated_port['admin_state_up'],
                    port_security=allowed_macs))
            # Note that the ovsdb IDL supresses the transaction down to what
            # has actually changed.
            txn.add(self._ovn.delete_acl(
                    utils.ovn_name(updated_port['network_id']),
                    updated_port['id']))
            self._add_acls(context, updated_port, txn)
        return updated_port

    def _get_data_from_binding_profile(self, context, port):
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
                msg = _('Invalid binding:profile. %(key)s %(value)s'
                        'value invalid type') % {'key': param_key,
                                                 'value': param_value}
                raise n_exc.InvalidInput(error_message=msg)

        # Make sure we can successfully look up the port indicated by
        # parent_name.  Just let it raise the right exception if there is a
        # problem.
        if 'parent_name' in param_set.keys():
            self.get_port(context, param_dict['parent_name'])

        if 'tag' in param_set.keys():
            tag = int(param_dict['tag'])
            if tag < 0 or tag > 4095:
                msg = _('Invalid binding:profile. tag "%s" must be '
                        'an int between 1 and 4096, inclusive.') % tag
                raise n_exc.InvalidInput(error_message=msg)

        return param_dict

    def _get_allowed_mac_addresses_from_port(self, port):
        allowed_macs = set()
        allowed_macs.add(port['mac_address'])
        allowed_address_pairs = port.get('allowed_address_pairs', [])
        for allowed_address in allowed_address_pairs:
            allowed_macs.add(allowed_address['mac_address'])
        return list(allowed_macs)

    def create_port(self, context, port):
        with context.session.begin(subtransactions=True):
            binding_profile = self._get_data_from_binding_profile(
                context, port['port'])
            parent_name = binding_profile.get('parent_name')
            tag = binding_profile.get('tag')
            vtep_physical_switch = binding_profile.get('vtep_physical_switch')
            vtep_logical_switch = binding_profile.get('vtep_logical_switch')

            dhcp_opts = port['port'].get(edo_ext.EXTRADHCPOPTS, [])
            db_port = super(OVNPlugin, self).create_port(context, port)
            sgids = self._get_security_groups_on_port(context, port)
            self._process_port_create_security_group(context, db_port,
                                                     sgids)
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         db_port)

            db_port[portbindings.VNIC_TYPE] = portbindings.VNIC_NORMAL
            # NOTE(arosen): _process_port_bindings_create_and_update
            # does not set the binding on the port so we do it here.
            if (ovn_const.OVN_PORT_BINDING_PROFILE in port['port'] and
                attr.is_attr_set(
                    port['port'][ovn_const.OVN_PORT_BINDING_PROFILE])):
                db_port[ovn_const.OVN_PORT_BINDING_PROFILE] = \
                    port['port'][ovn_const.OVN_PORT_BINDING_PROFILE]

            self._process_port_create_extra_dhcp_opts(context, db_port,
                                                      dhcp_opts)

            if vtep_physical_switch:
                port_type = 'vtep'
                options = {'vtep_physical_switch': vtep_physical_switch,
                           'vtep_logical_switch': vtep_logical_switch}
                macs = ["unknown"]
                allowed_macs = []
            else:
                port_type = None
                options = None
                macs = [db_port['mac_address']]
                allowed_macs = self._get_allowed_mac_addresses_from_port(
                    db_port)

        return self._create_port_in_ovn(context, db_port, macs, parent_name,
                                        tag, port_type, options, allowed_macs)

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
        ip = None
        icmp = None
        if r['ethertype'] == 'IPv4':
            match = ' && ip4'
            ip = 'ip4'
            icmp = 'icmp4'
        elif r['ethertype'] == 'IPv6':
            match = ' && ip6'
            ip = 'ip6'
            icmp = 'icmp6'
        return match, ip, icmp

    def _acl_remote_ip_prefix(self, r, ip):
        if not r['remote_ip_prefix']:
            return ''
        return ' && %s.dst == %s' % (ip, r['remote_ip_prefix'])

    def _acl_remote_group_id(self, context, r, sg_ports_cache, port,
                             remote_portdir):
        if not r['remote_group_id']:
            return '', False
        match = ''
        if r['remote_group_id'] in sg_ports_cache:
            sg_ports = sg_ports_cache[r['remote_group_id']]
        else:
            filters = {'security_group_id': [r['remote_group_id']]}
            sg_ports = self._get_port_security_group_bindings(
                context, filters)
            sg_ports_cache[r['remote_group_id']] = sg_ports
        sg_ports = [p for p in sg_ports if p['port_id'] != port['id']]
        if not sg_ports:
            # If there are no other ports on this security group, then this
            # rule can never match, so no ACL row will be created for this
            # rule.
            return '', True
        # TODO(russellb) This doesn't actually work for ports on a provider
        # network.  In that case, the ports aren't on the same OVN logical
        # switch so referring to them by port ID doesn't work.  In that case,
        # we should instead just match on src IP addresses.
        match += ' && %s == {' % remote_portdir
        for p in sg_ports:
            match += '"%s",' % p['port_id']
        if match[-1] == ',':
            match = match[:-1]
        match += '}'
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
            if r['port_range_min'] and r['port_range_min'] != -1:
                match += ' && %s >= %d' % (port_match,
                                           r['port_range_min'])
            if r['port_range_max'] and r['port_range_max'] != -1:
                match += ' && %s <= %d' % (port_match,
                                           r['port_range_max'])
        return match

    def _add_sg_rule_acl_for_port(self, context, port, r, sg_ports_cache):
        # Update the match based on which direction this rule is for (ingress
        # or egress).
        match, remote_portdir = self._acl_direction(r, port)

        # Update the match for IPv4 vs IPv6.
        ip_match, ip, icmp = self._acl_ethertype(r)
        match += ip_match

        # Update the match if an IPv4 or IPv6 prefix was specified.
        match += self._acl_remote_ip_prefix(r, ip)

        group_match, empty_match = self._acl_remote_group_id(context, r,
                                                             sg_ports_cache,
                                                             port,
                                                             remote_portdir)
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
        cmd = self._ovn.add_acl(
            lswitch=utils.ovn_name(port['network_id']),
            lport=port['id'],
            priority=ACL_PRIORITY_ALLOW,
            action='allow-related',
            log=False,
            direction=dir_map[r['direction']],
            match=match,
            external_ids={'neutron:lport': port['id']})
        return cmd

    def _add_acl_cmd(self, acls, cmd):
        if not cmd:
            return
        key = (cmd.columns['direction'],
               cmd.columns['priority'],
               cmd.columns['action'],
               cmd.columns['match'])
        if key not in acls:
            # Make sure we don't create duplicate ACL rows.
            acls[key] = cmd

    def _add_acls(self, context, port, txn,
                  sg_cache=None, sg_ports_cache=None):
        # Return a list of security groups applied to this port that have a
        # rule that matches on a remote_group_id.  This helps us figure out
        # which security groups need a full ACL refresh when a port gets
        # created.
        remote_group_sgs = set()

        sec_groups = port.get('security_groups', [])
        if not sec_groups:
            return remote_group_sgs

        # Drop all IP traffic to and from the logical port by default.
        for direction, p in (('from-lport', 'inport'),
                             ('to-lport', 'outport')):
            txn.add(self._ovn.add_acl(
                lswitch=utils.ovn_name(port['network_id']),
                lport=port['id'],
                priority=ACL_PRIORITY_DROP,
                action='drop',
                log=False,
                direction=direction,
                match='%s == "%s" && ip' % (p, port['id']),
                external_ids={'neutron:lport': port['id']}))

        # We often need a list of all ports on a security group.  Cache these
        # results so we only do the query once throughout this processing.
        if sg_ports_cache is None:
            sg_ports_cache = {}

        # We create an ACL entry for each rule on each security group applied
        # to this port.
        acls = {}

        for sg_id in sec_groups:
            if sg_cache and sg_id in sg_cache:
                sg = sg_cache[sg_id]
            else:
                sg = self.get_security_group(context, sg_id)
                if sg_cache is not None:
                    sg_cache[sg_id] = sg
            for r in sg['security_group_rules']:
                if r['remote_group_id']:
                    remote_group_sgs.add(r['remote_group_id'])
                cmd = self._add_sg_rule_acl_for_port(context, port, r,
                                                     sg_ports_cache)
                self._add_acl_cmd(acls, cmd)

        for cmd in six.itervalues(acls):
            txn.add(cmd)

        return remote_group_sgs

    def _create_port_in_ovn(self, context, port, macs, parent_name, tag,
                            port_type, options, allowed_macs):
        # When we create a port on a provider network, the mapping to
        # OVN_Northbound is a bit different.  Every port on a provider network
        # is modeled as a special OVN logical switch.
        #
        #    Logical Switch
        #      Logical Port LP1 (maps to the neutron port)
        #      Logical Port LP2 (type=localnet, models connection to the
        #                        physical network)
        #
        # There is a logical switch associated with the network itself, but
        # it's only used to stash the provider network attributes as
        # external_ids.

        external_ids = {ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port['name']}
        lswitch_name = utils.ovn_name(port['network_id'])
        try:
            lswitch = idlutils.row_by_value(self._ovn.idl, 'Logical_Switch',
                                            'name', lswitch_name)
        except idlutils.RowNotFound:
            msg = _("Logical Switch %s does not exist") % lswitch_name
            LOG.error(msg)
            raise RuntimeError(msg)
        net_ext_ids = getattr(lswitch, 'external_ids', {})

        physnet = net_ext_ids.get(ovn_const.OVN_PHYSNET_EXT_ID_KEY)
        if physnet:
            # TODO(russellb) We should be able to do this all in 1 transaction,
            # but our API wrappers aren't making that easy...
            lswitch_name = utils.ovn_name(port['id'])
            with self._ovn.transaction(check_error=True) as txn:
                txn.add(self._ovn.create_lswitch(
                    lswitch_name=lswitch_name,
                    external_ids=external_ids))

        with self._ovn.transaction(check_error=True) as txn:
            if physnet:
                vlan_id = net_ext_ids.get(ovn_const.OVN_SEGID_EXT_ID_KEY)
                if vlan_id is not None:
                    vlan_id = int(vlan_id)
                txn.add(self._ovn.create_lport(
                    lport_name='provnet-%s' % port['id'],
                    lswitch_name=lswitch_name,
                    addresses=['unknown'],
                    external_ids=external_ids,
                    type='localnet',
                    tag=vlan_id,
                    options={'network_name': physnet}))
            # The port name *must* be port['id'].  It must match the iface-id
            # set in the Interfaces table of the Open_vSwitch database, which
            # nova sets to be the port ID.
            txn.add(self._ovn.create_lport(
                    lport_name=port['id'],
                    lswitch_name=lswitch_name,
                    addresses=macs,
                    external_ids=external_ids,
                    parent_name=parent_name, tag=tag,
                    enabled=port.get('admin_state_up', None),
                    port_security=allowed_macs))
            sg_ports_cache = {}
            remote_group_sgs = self._add_acls(context, port, txn,
                                              sg_ports_cache=sg_ports_cache)
        for sg_id in remote_group_sgs:
            # Update ACLs for all other ports on a security group with this
            # port that includes a remote_group_id match.  We can skip updating
            # ACLs for this port though, because we just did it.
            self._update_acls_for_security_group(context, sg_id,
                                                 sg_ports_cache,
                                                 exclude_ports=[port['id']])

        return port

    def delete_port(self, context, port_id, l3_port_check=True):
        port = self.get_port(context, port_id)
        try:
            # If this is a port on a provider network, we just need to delete
            # the special logical switch for this port, and the 2 ports on the
            # switch will get garbage collected.  Note that if the switch
            # doesn't exist, we'll get an exception without actually having to
            # execute a transaction with the remote db.  The check is local.
            self._ovn.delete_lswitch(
                utils.ovn_name(port['id']), if_exists=False).execute(
                    check_error=True, log_errors=False)
        except RuntimeError:
            # If the switch doesn't exist, we'll get a RuntimeError, meaning
            # we just need to delete a port.
            with self._ovn.transaction(check_error=True) as txn:
                txn.add(self._ovn.delete_lport(port_id,
                        utils.ovn_name(port['network_id'])))
                txn.add(self._ovn.delete_acl(
                        utils.ovn_name(port['network_id']), port['id']))

        # NOTE(russellb): If this port had a security group applied with a rule
        # that used "remote_group_id", technically we could update the ACLs for
        # all ports on that security group to remove references to this port
        # we're deleting.  However, it's harmless to leave it for now and saves
        # some additional churn in the OVN db.  References to this port will
        # get automatically removed the next time something else triggers a
        # refresh of ACLs for ports on that security group.

        with context.session.begin(subtransactions=True):
            self.disassociate_floatingips(context, port_id)
            super(OVNPlugin, self).delete_port(context, port_id)

    def extend_port_dict_binding(self, port_res, port_db):
        super(OVNPlugin, self).extend_port_dict_binding(port_res, port_db)
        port_res[portbindings.VNIC_TYPE] = portbindings.VNIC_NORMAL

    def create_router(self, context, router):
        router = super(OVNPlugin, self).create_router(
            context, router)
        router_name = utils.ovn_name(router['id'])
        external_ids = {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                        router.get('name', 'no_router_name')}
        self._ovn.create_lrouter(router_name,
                                 external_ids=external_ids
                                 ).execute(check_error=True)

        # TODO(gsagie) rollback router creation on OVN failure
        return router

    def delete_router(self, context, router_id):
        router_name = utils.ovn_name(router_id)
        self._ovn.delete_lrouter(router_name).execute(check_error=True)
        ret_val = super(OVNPlugin, self).delete_router(context,
                                                       router_id)
        return ret_val

    def update_router(self, context, id, router):
        router = super(OVNPlugin, self).update_router(
            context, id, router)
        router_name = utils.ovn_name(router['id'])
        external_ids = {ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                        router.get('name', 'no_router_name')}
        self._ovn.update_lrouter(router_name,
                                 external_ids=external_ids
                                 ).execute(check_error=True)

        # TODO(Sisir) Rollback router update on OVN NB DB Update Failure.
        return router

    def _update_acls_for_security_group(self, context, security_group_id,
                                        sg_ports_cache=None,
                                        exclude_ports=None):
        # Update ACLs for all ports using this security group.  Note that the
        # ovsdb IDL supresses the transaction down to what has actually
        # changed.
        if exclude_ports is None:
            exclude_ports = []
        filters = {'security_group_id': [security_group_id]}
        sg_ports = self._get_port_security_group_bindings(context, filters)
        with self._ovn.transaction(check_error=True) as txn:
            sg_cache = {}
            if sg_ports_cache is None:
                sg_ports_cache = {}
            for binding in sg_ports:
                if binding['port_id'] in exclude_ports:
                    continue
                port = self.get_port(context, binding['port_id'])
                txn.add(self._ovn.delete_acl(
                        utils.ovn_name(port['network_id']), port['id']))
                self._add_acls(context, port, txn, sg_cache, sg_ports_cache)

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
        # sync until another change causes another refresh attmept.
        self._update_acls_for_security_group(context, group_id)
        return res

    def delete_security_group_rule(self, context, id):
        security_group_rule = self.get_security_group_rule(context, id)
        group_id = security_group_rule['security_group_id']
        super(OVNPlugin, self).delete_security_group_rule(context, id)
        # TODO(russellb) It's possible for Neutorn and OVN to get out of sync
        # here.  We delete the rule from the Neutron db first and then do an
        # ACL update to reflect the current state in OVN.  If updating OVN
        # fails, we'll be out of sync until another change happens that
        # triggers a refresh.
        self._update_acls_for_security_group(context, group_id)

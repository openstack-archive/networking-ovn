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

from datetime import datetime
from eventlet import greenthread
import itertools
from oslo_log import log

from neutron.api.v2 import attributes as attr
from neutron import context
from neutron.extensions import providernet as pnet

from networking_ovn._i18n import _LW
from networking_ovn.common import constants as ovn_const
from networking_ovn.common import utils
from neutron.db import db_base_plugin_v2
from neutron.db import securitygroups_db
import six

LOG = log.getLogger(__name__)

SYNC_MODE_OFF = 'off'
SYNC_MODE_LOG = 'log'
SYNC_MODE_REPAIR = 'repair'


class OvnNbSynchronizer(db_base_plugin_v2.NeutronDbPluginV2,
                        securitygroups_db.SecurityGroupDbMixin):
    """Synchronizer class for NB."""

    def __init__(self, plugin, ovn_api, mode):
        self.core_plugin = plugin
        self.ovn_api = ovn_api
        self.mode = mode

    def sync(self):
        greenthread.spawn_n(self._sync)

    def _sync(self):
        if self.mode == SYNC_MODE_OFF:
            LOG.debug("Neutron sync mode is off")
            return

        # Initial delay until service is up
        greenthread.sleep(10)
        LOG.debug("Starting OVN-Northbound DB sync process")

        ctx = context.get_admin_context()
        self.sync_networks_and_ports(ctx)
        self.sync_acls(ctx)

    @staticmethod
    def _get_attribute(obj, attribute):
        res = obj.get(attribute)
        if res is attr.ATTR_NOT_SPECIFIED:
            res = None
        return res

    def _create_network_in_ovn(self, net):
        ext_ids = {}
        physnet = self._get_attribute(net, pnet.PHYSICAL_NETWORK)
        if physnet:
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

        self.core_plugin.create_network_in_ovn(net, ext_ids)

    def _create_port_in_ovn(self, ctx, port):
        binding_profile = self.core_plugin.get_data_from_binding_profile(
            ctx, port)
        qos_options = self.core_plugin.qos_get_ovn_port_options(
            ctx, port)
        ovn_port_info = self.core_plugin.get_ovn_port_options(binding_profile,
                                                              qos_options,
                                                              port)
        return self.core_plugin.create_port_in_ovn(ctx, port, ovn_port_info)

    def remove_common_acls(self, neutron_acls, nb_acls):
        """Take out common acls of the two acl dictionaries.

        @param   neutron_acls: neutron dictionary of port vs acls
        @type    neutron_acls: {}
        @param   nb_acls: nb dictionary of port vs acls
        @type    nb_acls: {}
        @return: Nothing, original dictionary modified
        """
        for port in neutron_acls.keys():
            for acl in list(neutron_acls[port]):
                if port in nb_acls and acl in nb_acls[port]:
                    neutron_acls[port].remove(acl)
                    nb_acls[port].remove(acl)

    def get_acls(self, context):
        """create the list of ACLS in OVN.

        @param context: neutron context
        @type  context: object of type neutron.context.Context
        @var   filters: to be used for filtering out group bindings, null here
        @var   lswitch_names: List of lswitch names
        @var   acl_list: List of NB acls
        @var   acl_list_dict: Dictionary of acl-lists based on lport as key
        @var   sg_ports: List of ports associated to SGs
        @return: acl_list-dict
        """
        filters = {}
        sg_ports = self.core_plugin._get_port_security_group_bindings(context,
                                                                      filters)
        lswitch_names = set([])
        for binding in sg_ports:
            port = self.get_port(context, binding['port_id'])
            lswitch_names.add(port['network_id'])
        acl_dict, ignore1, ignore2 = \
            self.ovn_api.get_acls_for_lswitches(lswitch_names)
        acl_list = list(itertools.chain(*six.itervalues(acl_dict)))
        acl_list_dict = {}
        for acl in acl_list:
            key = acl['lport']
            if key in acl_list_dict:
                acl_list_dict[key].append(acl)
            else:
                acl_list_dict[key] = list([acl])
        return acl_list_dict

    def sync_acls(self, ctx):
        """Sync ACLs between neutron and NB.

        @param ctx: neutron context
        @type  ctx: object of type neutron.context.Context
        @var   db_secs: List of SGs from neutron DB
        @var   db_ports: List of ports from neutron DB
        @var   neutron_acls: neutron dictionary of port
               vs list-of-acls
        @var   nb_acls: NB dictionary of port
               vs list-of-acls
        @var   sg_ports_cache: cache for sg_ports
        @var   subnet_cache: cache for subnets
        @return: Nothing
        """
        LOG.debug('ACL-SYNC: started @ %s' %
                  str(datetime.now()))
        db_secs = {}
        for sg in self.core_plugin.get_security_groups(ctx):
            db_secs[sg['id']] = sg

        db_ports = {}
        for port in self.core_plugin.get_ports(ctx):
            db_ports[port['id']] = port

        neutron_acls = []
        sg_ports_cache = {}
        subnet_cache = {}
        neutron_acls = {}
        for port_id, port in db_ports.items():
            if port['security_groups']:
                if port_id in neutron_acls:
                    neutron_acls[port_id].extend(
                        self.core_plugin._add_acls(ctx,
                                                   port,
                                                   sg_ports_cache,
                                                   subnet_cache))
                else:
                    neutron_acls[port_id] = \
                        self.core_plugin._add_acls(ctx,
                                                   port,
                                                   sg_ports_cache,
                                                   subnet_cache)

        nb_acls = self.get_acls(ctx)

        self.remove_common_acls(neutron_acls, nb_acls)

        LOG.debug('ACLs-to-be-addded %d ACLs-to-be-removed %d' %
                  (len(list(itertools.chain(*six.itervalues(neutron_acls)))),
                   len(list(itertools.chain(*six.itervalues(nb_acls))))))

        LOG.debug('ACL-SYNC: transaction started @ %s' % str(datetime.now()))
        with self.ovn_api.transaction(check_error=True) as txn:
            for acla in list(itertools.chain(*six.itervalues(neutron_acls))):
                txn.add(self.ovn_api.add_acl(**acla))
            for aclr in list(itertools.chain(*six.itervalues(nb_acls))):
                txn.add(self.ovn_api.delete_acl(aclr['lswitch'],
                                                aclr['lport']))
        LOG.debug('ACL-SYNC: transaction finished @ %s' % str(datetime.now()))

    def sync_networks_and_ports(self, ctx):
        LOG.debug('OVN-NB Sync networks and ports started')
        db_networks = {}
        for net in self.core_plugin.get_networks(ctx):
            db_networks[utils.ovn_name(net['id'])] = net

        db_ports = {}
        for port in self.core_plugin.get_ports(ctx):
            db_ports[port['id']] = port

        lswitches = self.ovn_api.get_all_logical_switches_with_ports()
        del_lswitchs_list = []
        del_lports_list = []
        for lswitch in lswitches:
            if lswitch['name'] in db_networks:
                for lport in lswitch['ports']:
                    if lport in db_ports:
                        del db_ports[lport]
                    else:
                        del_lports_list.append({'port': lport,
                                                'lswitch': lswitch['name']})
                del db_networks[lswitch['name']]
            else:
                del_lswitchs_list.append(lswitch)

        for net_id, network in db_networks.items():
            LOG.warning(_LW("Network found in Neutron but not in "
                            "OVN DB, network_id=%s"), network['id'])
            if self.mode == SYNC_MODE_REPAIR:
                try:
                    LOG.debug('Creating the network %s in OVN NB DB',
                              network['id'])
                    self._create_network_in_ovn(network)
                except RuntimeError:
                    LOG.warning(_LW("Create network in OVN NB failed for"
                                    " network %s"), network['id'])

        for port_id, port in db_ports.items():
            LOG.warning(_LW("Port found in Neutron but not in OVN "
                            "DB, port_id=%s"), port['id'])
            if self.mode == SYNC_MODE_REPAIR:
                try:
                    LOG.debug('Creating the port %s in OVN NB DB',
                              port['id'])
                    self._create_port_in_ovn(ctx, port)
                except RuntimeError:
                    LOG.warning(_LW("Create port in OVN NB failed for"
                                    " port %s"), port['id'])

        with self.ovn_api.transaction(check_error=True) as txn:
            for lswitch in del_lswitchs_list:
                LOG.warning(_LW("Network found in OVN but not in "
                                "Neutron, network_id=%s"), lswitch['name'])
                if self.mode == SYNC_MODE_REPAIR:
                    LOG.debug('Deleting the network %s from OVN NB DB',
                              lswitch['name'])
                    txn.add(self.ovn_api.delete_lswitch(
                        lswitch_name=lswitch['name']))

            for lport_info in del_lports_list:
                LOG.warning(_LW("Port found in OVN but not in "
                                "Neutron, port_id=%s"), lport_info['port'])
                if self.mode == SYNC_MODE_REPAIR:
                    LOG.debug('Deleting the port %s from OVN NB DB',
                              lport_info['port'])
                    txn.add(self.ovn_api.delete_lport(
                        lport_name=lport_info['port'],
                        lswitch=lport_info['lswitch']))
        LOG.debug('OVN-NB Sync networks and ports finished')

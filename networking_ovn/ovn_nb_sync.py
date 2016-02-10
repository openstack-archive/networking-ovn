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

from eventlet import greenthread
from oslo_log import log

from neutron.api.v2 import attributes as attr
from neutron import context
from neutron.extensions import providernet as pnet

from networking_ovn._i18n import _LW
from networking_ovn.common import constants as ovn_const
from networking_ovn.common import utils

LOG = log.getLogger(__name__)

SYNC_MODE_OFF = 'off'
SYNC_MODE_LOG = 'log'
SYNC_MODE_REPAIR = 'repair'


class OvnNbSynchronizer(object):

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
        ovn_port_info = self.core_plugin.get_ovn_port_options(binding_profile,
                                                              port)
        return self.core_plugin.create_port_in_ovn(ctx, port, ovn_port_info)

    # TODO(gsagie) design this to optionally work in bulks to save transactions
    # OVSDB only actually commit transaction if its different then current
    # values
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

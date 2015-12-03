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

from neutron import context

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
        self._sync_networks(ctx)
        self._sync_ports(ctx)

    # TODO(gsagie) design this to optionally work in bulks to save transactions
    # OVSDB only actually commit transaction if its different then current
    # values
    def _sync_networks(self, ctx):
        LOG.debug("OVN-NB Sync networks started")

        lswitches = self.ovn_api.get_all_logical_switches_ids()

        for network in self.core_plugin.get_networks(ctx):
            try:
                if self.mode == SYNC_MODE_REPAIR:
                    self.core_plugin.create_network_in_ovn(network)
                res = lswitches.pop(utils.ovn_name(
                                    network['id']), None)
                if self.mode == SYNC_MODE_LOG:
                    if res is None:
                        LOG.warn(_LW("Network found in Neutron but not in OVN "
                                     "DB, network_id=%s"),
                                 network['id'])

            except RuntimeError:
                LOG.warn(_LW("Create network failed for "
                             "network %s"), network['id'])

        # Only delete logical switch if it was previously created by neutron
        with self.ovn_api.transaction() as txn:
            for lswitch, ext_ids in lswitches.items():
                if ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY in ext_ids:
                    if self.mode == SYNC_MODE_REPAIR:
                        txn.add(self.ovn_api.delete_lswitch(lswitch))
                    if self.mode == SYNC_MODE_LOG:
                        LOG.warn(_LW("Network found in OVN but not in Neutron,"
                                     " network_name=%s"),
                                 (ext_ids
                                  [ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY]))

        LOG.debug("OVN-NB Sync networks finished")

    def _sync_ports(self, ctx):
        LOG.debug("OVN-NB Sync ports started")

        lports = self.ovn_api.get_all_logical_ports_ids()

        for port in self.core_plugin.get_ports(ctx):
            try:
                if self.mode == SYNC_MODE_REPAIR:
                    self.core_plugin.create_port_in_ovn(port)
                res = lports.pop(port['id'], None)
                if self.mode == SYNC_MODE_LOG:
                    if res is None:
                        LOG.warn(_LW("Port found in Neutron but not in OVN "
                                     "DB, port_id=%s"),
                                 port['id'])

            except RuntimeError:
                LOG.warn(_LW("Create port failed for"
                             " port %s"), port['id'])

        # Only delete logical port if it was previously created by neutron
        with self.ovn_api.transaction() as txn:
            for lport, ext_ids in lports.items():
                if ovn_const.OVN_PORT_NAME_EXT_ID_KEY in ext_ids:
                    if self.mode == SYNC_MODE_REPAIR:
                        txn.add(self.ovn_api.delete_lport(lport))
                    if self.mode == SYNC_MODE_LOG:
                        LOG.warn(_LW("Port found in OVN but not in Neutron,"
                                     " port_name=%s"),
                                 ext_ids[ovn_const.OVN_PORT_NAME_EXT_ID_KEY])

        LOG.debug("OVN-NB Sync ports finished")

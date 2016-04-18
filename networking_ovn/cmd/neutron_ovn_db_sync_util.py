# Copyright 2016 Red Hat, Inc.
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
from oslo_db import options as db_options
from oslo_log import log as logging

from neutron import context
from neutron import manager

from networking_ovn._i18n import _LI, _LE
from networking_ovn.common import config as ovn_config
from networking_ovn import ovn_nb_sync
from networking_ovn.ovsdb import impl_idl_ovn
from networking_ovn import plugin as ovn_plugin

LOG = logging.getLogger(__name__)


class OVNPlugin(ovn_plugin.OVNPlugin):

    supported_extension_aliases = []

    def _start_rpc_notifiers(self):
        pass

    def post_fork_initialize(self, resource, event, trigger, **kwargs):
        pass


def setup_conf():
    conf = cfg.CONF
    cfg.CONF.core_plugin = (
        'networking_ovn.cmd.neutron_ovn_db_sync_util.OVNPlugin')
    ovn_group, ovn_opts = ovn_config.list_opts()[0]
    # 'ovn_l3_mode' option is not used for sync, hence deleting it
    for index, opt in enumerate(ovn_opts):
        if opt.name == 'ovn_l3_mode':
            del ovn_opts[index]

    cfg.CONF.register_cli_opts(ovn_opts, group=ovn_group)
    db_group, neutron_db_opts = db_options.list_opts()[0]
    cfg.CONF.register_cli_opts(neutron_db_opts, db_group)
    return conf


def main():
    """Main method for syncing neutron networks and ports with ovn nb db.

    The utility syncs neutron db with ovn nb db.
    """
    conf = setup_conf()

    # if no config file is passed or no configuration options are passed
    # then load configuration from /etc/neutron/neutron.conf
    try:
        conf(project='neutron')
    except TypeError:
        LOG.error(_LE('Error parsing the configuration values. '
                      'Please verify.'))
        return

    logging.setup(conf, 'neutron_ovn_db_sync_util')
    LOG.info(_LI('Started Neutron OVN db sync'))
    mode = ovn_config.get_ovn_neutron_sync_mode()
    if mode not in [ovn_nb_sync.SYNC_MODE_LOG, ovn_nb_sync.SYNC_MODE_REPAIR]:
        LOG.error(_LE('Invalid sync mode : ["%s"]. Should be "log" or '
                      '"repair"'), mode)
        return

    # we dont want the service plugins to be loaded.
    conf.service_plugins = []
    ovn_plugin = manager.NeutronManager.get_plugin()
    try:
        ovn_plugin._ovn = impl_idl_ovn.OvsdbOvnIdl(ovn_plugin)
    except RuntimeError:
        LOG.error(_LE('Invalid --ovn-ovsdb_connection parameter provided.'))
        return

    synchronizer = ovn_nb_sync.OvnNbSynchronizer(
        ovn_plugin, ovn_plugin._ovn, mode)

    ctx = context.get_admin_context()

    LOG.info(_LI('Syncing the networks and ports with mode : %s'), mode)
    try:
        synchronizer.sync_networks_and_ports(ctx)
    except Exception:
        LOG.exception(_LE("Error syncing  the networks and ports. Check the "
                          "--database-connection value again"))
        return
    try:
        synchronizer.sync_acls(ctx)
    except Exception:
        LOG.exception(_LE("Error syncing  ACLs for unknown reason "
                          "please try again"))
        return
    try:
        synchronizer.sync_routers_and_rports(ctx)
    except Exception:
        LOG.exception(_LE("Error syncing  Routers and Router ports "
                          "please try again"))
        return
    LOG.info(_LI('Sync completed'))

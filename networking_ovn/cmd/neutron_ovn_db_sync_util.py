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

from neutron.agent import securitygroups_rpc
from neutron import context
from neutron import manager
from neutron import opts as neutron_options
from neutron.plugins.ml2 import plugin as ml2_plugin

from networking_ovn._i18n import _LI, _LE
from networking_ovn.common import config as ovn_config
from networking_ovn.ml2 import mech_driver
from networking_ovn import ovn_db_sync
from networking_ovn.ovsdb import impl_idl_ovn

LOG = logging.getLogger(__name__)


class Ml2Plugin(ml2_plugin.Ml2Plugin):

    def _setup_dhcp(self):
        pass

    def _start_rpc_notifiers(self):
        pass


class OVNMechanismDriver(mech_driver.OVNMechanismDriver):

    def subscribe(self):
        pass

    def post_fork_initialize(self, resource, event, trigger, **kwargs):
        pass


def setup_conf():
    conf = cfg.CONF
    ml2_group, ml2_opts = neutron_options.list_ml2_conf_opts()[0]
    cfg.CONF.register_cli_opts(ml2_opts, ml2_group)
    cfg.CONF.register_cli_opts(securitygroups_rpc.security_group_opts,
                               'SECURITYGROUP')
    ovn_group, ovn_opts = ovn_config.list_opts()[0]
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
    if mode not in [ovn_db_sync.SYNC_MODE_LOG, ovn_db_sync.SYNC_MODE_REPAIR]:
        LOG.error(_LE('Invalid sync mode : ["%s"]. Should be "log" or '
                      '"repair"'), mode)
        return

    # Validate and modify core plugin and ML2 mechanism drivers for syncing.
    if cfg.CONF.core_plugin.endswith('.Ml2Plugin'):
        cfg.CONF.core_plugin = (
            'networking_ovn.cmd.neutron_ovn_db_sync_util.Ml2Plugin')
        if 'ovn' not in cfg.CONF.ml2.mechanism_drivers:
            LOG.error(_LE('No "ovn" mechanism driver found : "%s".'),
                      cfg.CONF.ml2.mechanism_drivers)
            return
        cfg.CONF.ml2.mechanism_drivers = ['ovn-sync']
        conf.service_plugins = ['networking_ovn.l3.l3_ovn.OVNL3RouterPlugin']
    else:
        LOG.error(_LE('Invalid core plugin : ["%s"].'), cfg.CONF.core_plugin)
        return

    try:
        ovn_api = impl_idl_ovn.OvsdbNbOvnIdl(None)
    except RuntimeError:
        LOG.error(_LE('Invalid --ovn-ovn_nb_connection parameter provided.'))
        return

    core_plugin = manager.NeutronManager.get_plugin()
    ovn_driver = core_plugin.mechanism_manager.mech_drivers['ovn-sync'].obj
    ovn_driver._nb_ovn = ovn_api

    synchronizer = ovn_db_sync.OvnNbSynchronizer(
        core_plugin, ovn_api, mode, ovn_driver)

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

# Copyright 2017 Red Hat, Inc.
# All Rights Reserved.
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

import inspect
import threading

from futurist import periodics
from neutron.common import config as n_conf
from neutron_lib import context as n_context
from neutron_lib import worker
from oslo_log import log

from networking_ovn.common import constants as ovn_const
from networking_ovn.common import utils
from networking_ovn.db import maintenance as db_maint
from networking_ovn.db import revision as db_rev

LOG = log.getLogger(__name__)

DB_CONSISTENCY_CHECK_INTERVAL = 300  # 5 minutes


class MaintenanceWorker(worker.BaseWorker):

    def start(self):
        super(MaintenanceWorker, self).start()
        # NOTE(twilson) The super class will trigger the post_fork_initialize
        # in the driver, which starts the connection/IDL notify loop which
        # keeps the process from exiting

    def stop(self):
        """Stop service."""
        super(MaintenanceWorker, self).stop()

    def wait(self):
        """Wait for service to complete."""
        super(MaintenanceWorker, self).wait()

    @staticmethod
    def reset():
        n_conf.reset_service()


class MaintenanceThread(object):

    def __init__(self):
        self._callables = []
        self._thread = None
        self._worker = None

    def add_periodics(self, obj):
        for name, member in inspect.getmembers(obj):
            if periodics.is_periodic(member):
                LOG.debug('Periodic task found: %(owner)s.%(member)s',
                          {'owner': obj.__class__.__name__, 'member': name})
                self._callables.append((member, (), {}))

    def start(self):
        if self._thread is None:
            self._worker = periodics.PeriodicWorker(self._callables)
            self._thread = threading.Thread(target=self._worker.start)
            self._thread.daemon = True
            self._thread.start()

    def stop(self):
        self._worker.stop()
        self._worker.wait()
        self._thread.join()
        self._worker = self._thread = None


class DBInconsistenciesPeriodics(object):

    def __init__(self, ovn_client):
        self._ovn_client = ovn_client
        # FIXME(lucasagomes): We should not be accessing private
        # attributes like that, perhaps we should extend the OVNClient
        # class and create an interface for the locks ?
        self._nb_idl = self._ovn_client._nb_idl
        self._idl = self._nb_idl.idl
        self._idl.set_lock('ovn_db_inconsistencies_periodics')

    @property
    def has_lock(self):
        return not self._idl.is_lock_contended

    def _fix_create_update_network(self, row):
        # Get the latest version of the resource in Neutron DB
        admin_context = n_context.get_admin_context()
        n_db_obj = self._ovn_client._plugin.get_network(
            admin_context, row.resource_uuid)
        ovn_net = self._nb_idl.get_lswitch(utils.ovn_name(row.resource_uuid))

        if not ovn_net:
            # If the resource doesn't exist in the OVN DB, create it.
            self._ovn_client.create_network(n_db_obj)
        else:
            ext_ids = getattr(ovn_net, 'external_ids', {})
            ovn_revision = int(ext_ids.get(
                ovn_const.OVN_REV_NUM_EXT_ID_KEY, -1))
            # If the resource exist in the OVN DB but the revision
            # number is different from Neutron DB, updated it.
            if ovn_revision != n_db_obj['revision_number']:
                self._ovn_client.update_network(n_db_obj)
            else:
                # If the resource exist and the revision number
                # is equal on both databases just bump the revision on
                # the cache table.
                db_rev.bump_revision(n_db_obj, ovn_const.TYPE_NETWORKS)

    def _fix_delete_network(self, row):
        ovn_net = self._nb_idl.get_lswitch(utils.ovn_name(row.resource_uuid))
        if not ovn_net:
            db_rev.delete_revision(row.resource_uuid)
        else:
            self._ovn_client.delete_network(row.resource_uuid)

    def _fix_create_update_port(self, row):
        # Get the latest version of the resource in Neutron DB
        admin_context = n_context.get_admin_context()
        p_db_obj = self._ovn_client._plugin.get_port(
            admin_context, row.resource_uuid)
        ovn_port = self._nb_idl.get_lswitch_port(
            utils.ovn_name(row.resource_uuid))

        if not ovn_port:
            # If the resource doesn't exist in the OVN DB, create it.
            self._ovn_client.create_port(p_db_obj)
        else:
            ext_ids = getattr(ovn_port, 'external_ids', {})
            ovn_revision = int(ext_ids.get(
                ovn_const.OVN_REV_NUM_EXT_ID_KEY, -1))
            # If the resource exist in the OVN DB but the revision
            # number is different from Neutron DB, updated it.
            if ovn_revision != p_db_obj['revision_number']:
                self._ovn_client.update_port(p_db_obj)
            else:
                # If the resource exist and the revision number
                # is equal on both databases just bump the revision on
                # the cache table.
                db_rev.bump_revision(p_db_obj, ovn_const.TYPE_PORTS)

    def _fix_delete_port(self, row):
        ovn_port = self._nb_idl.get_lswitch_port(
            utils.ovn_name(row.resource_uuid))
        if not ovn_port:
            db_rev.delete_revision(row.resource_uuid)
        else:
            self._ovn_client.delete_port(row.resource_uuid)

    def _fix_delete_sg_rule(self, row):
        acl = self._nb_idl.get_acl_by_id(row.resource_uuid)
        if not acl:
            db_rev.delete_revision(row.resource_uuid)
        else:
            self._ovn_client.delete_security_group_rule(
                row.resource_uuid)

    def _fix_create_sg_rule(self, row):
        # Get the latest version of the sg rule in Neutron DB
        admin_context = n_context.get_admin_context()
        sgr_db_obj = self._ovn_client._plugin.get_security_group_rule(
            admin_context, row.resource_uuid)

        if row.revision_number == ovn_const.INITIAL_REV_NUM:
            self._ovn_client.create_security_group_rule(sgr_db_obj)
        else:
            LOG.error("SG rule %s found with a revision number while this "
                      "resource doesn't support updates.", row.resource_uuid)

    def _fix_create_update_routers(self, row):
        # Get the latest version of the resource in Neutron DB
        admin_context = n_context.get_admin_context()
        r_db_obj = self._ovn_client._l3_plugin.get_router(
            admin_context, row.resource_uuid)
        ovn_router = self._nb_idl.get_lrouter(
            utils.ovn_name(row.resource_uuid))

        if not ovn_router:
            # If the resource doesn't exist in the OVN DB, create it.
            self._ovn_client.create_router(r_db_obj)
        else:
            ext_ids = getattr(ovn_router, 'external_ids', {})
            ovn_revision = int(ext_ids.get(
                ovn_const.OVN_REV_NUM_EXT_ID_KEY, -1))
            # If the resource exist in the OVN DB but the revision
            # number is different from Neutron DB, updated it.
            if ovn_revision != r_db_obj['revision_number']:
                self._ovn_client.update_router(r_db_obj)
            else:
                # If the resource exist and the revision number
                # is equal on both databases just bump the revision on
                # the cache table.
                db_rev.bump_revision(r_db_obj, ovn_const.TYPE_ROUTERS)

    def _fix_delete_router(self, row):
        ovn_router = self._nb_idl.get_lrouter(
            utils.ovn_name(row.resource_uuid))
        if not ovn_router:
            db_rev.delete_revision(row.resource_uuid)
        else:
            self._ovn_client.delete_router(row.resource_uuid)

    def _fix_create_security_group(self, row):
        # Get the latest version of the resource in Neutron DB
        admin_context = n_context.get_admin_context()
        sg_db_obj = self._ovn_client._plugin.get_security_group(
            admin_context, row.resource_uuid)
        ovn_sg = self._nb_idl.get_address_set(
            utils.ovn_addrset_name(row.resource_uuid, 'ip4'))

        # Since we don't have updates for Security Groups, we only need to
        # check whether its been created or not.
        if not ovn_sg:
            self._ovn_client.create_security_group(sg_db_obj)
        else:
            db_rev.bump_revision(sg_db_obj, ovn_const.TYPE_SECURITY_GROUPS)

    def _fix_delete_security_group(self, row):
        ovn_sg = self._nb_idl.get_address_set(
            utils.ovn_addrset_name(row.resource_uuid, 'ip4'))
        if not ovn_sg:
            db_rev.delete_revision(row.resource_uuid)
        else:
            self._ovn_client.delete_security_group(row.resource_uuid)

    @periodics.periodic(spacing=DB_CONSISTENCY_CHECK_INTERVAL,
                        run_immediately=True)
    def check_for_inconsistencies(self):
        # Only the worker holding a valid lock within OVSDB will run
        # this periodic
        if not self.has_lock:
            return

        create_update_inconsistencies = db_maint.get_inconsistent_resources()
        delete_inconsistencies = db_maint.get_deleted_resources()
        if not any([create_update_inconsistencies, delete_inconsistencies]):
            return
        LOG.warning('Inconsistencies found in the database!')

        # Fix the create/update resources inconsistencies
        for row in create_update_inconsistencies:
            try:
                if row.resource_type == ovn_const.TYPE_NETWORKS:
                    self._fix_create_update_network(row)
                elif row.resource_type == ovn_const.TYPE_PORTS:
                    self._fix_create_update_port(row)
                elif row.resource_type == ovn_const.TYPE_SECURITY_GROUP_RULES:
                    self._fix_create_sg_rule(row)
                elif row.resource_type == ovn_const.TYPE_ROUTERS:
                    self._fix_create_update_routers(row)
                elif row.resource_type == ovn_const.TYPE_SECURITY_GROUPS:
                    self._fix_create_security_group(row)
            except Exception:
                LOG.exception('Failed to fix resource %(res_uuid)s '
                              '(type: %(res_type)s)',
                              {'res_uuid': row.resource_uuid,
                               'res_type': row.resource_type})

        # Fix the deleted resources inconsistencies
        for row in delete_inconsistencies:
            try:
                if row.resource_type == ovn_const.TYPE_NETWORKS:
                    self._fix_delete_network(row)
                elif row.resource_type == ovn_const.TYPE_PORTS:
                    self._fix_delete_port(row)
                elif row.resource_type == ovn_const.TYPE_SECURITY_GROUP_RULES:
                    self._fix_delete_sg_rule(row)
                elif row.resource_type == ovn_const.TYPE_ROUTERS:
                    self._fix_delete_router(row)
                elif row.resource_type == ovn_const.TYPE_SECURITY_GROUPS:
                    self._fix_delete_security_group(row)
            except Exception:
                LOG.exception('Failed to fix deleted resource %(res_uuid)s '
                              '(type: %(res_type)s)',
                              {'res_uuid': row.resource_uuid,
                               'res_type': row.resource_type})

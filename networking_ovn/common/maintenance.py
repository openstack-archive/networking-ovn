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
from neutron_lib import exceptions as n_exc
from neutron_lib import worker
from oslo_log import log
from oslo_utils import timeutils

from networking_ovn.common import constants as ovn_const
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
        self._sync_timer = timeutils.StopWatch()

        self._resources_func_map = {
            ovn_const.TYPE_NETWORKS: {
                'neutron_get': self._ovn_client._plugin.get_network,
                'ovn_get': self._nb_idl.get_lswitch,
                'ovn_create': self._ovn_client.create_network,
                'ovn_update': self._ovn_client.update_network,
                'ovn_delete': self._ovn_client.delete_network,
            },
            ovn_const.TYPE_PORTS: {
                'neutron_get': self._ovn_client._plugin.get_port,
                'ovn_get': self._nb_idl.get_lswitch_port,
                'ovn_create': self._ovn_client.create_port,
                'ovn_update': self._ovn_client.update_port,
                'ovn_delete': self._ovn_client.delete_port,
            },
            ovn_const.TYPE_FLOATINGIPS: {
                'neutron_get': self._ovn_client._l3_plugin.get_floatingip,
                'ovn_get': self._nb_idl.get_floatingip,
                'ovn_create': self._ovn_client.create_floatingip,
                'ovn_update': self._ovn_client.update_floatingip,
                'ovn_delete': self._ovn_client.delete_floatingip,
            },
            ovn_const.TYPE_ROUTERS: {
                'neutron_get': self._ovn_client._l3_plugin.get_router,
                'ovn_get': self._nb_idl.get_lrouter,
                'ovn_create': self._ovn_client.create_router,
                'ovn_update': self._ovn_client.update_router,
                'ovn_delete': self._ovn_client.delete_router,
            },
            ovn_const.TYPE_SECURITY_GROUPS: {
                'neutron_get': self._ovn_client._plugin.get_security_group,
                'ovn_get': self._nb_idl.get_address_set,
                'ovn_create': self._ovn_client.create_security_group,
                'ovn_delete': self._ovn_client.delete_security_group,
            },
            ovn_const.TYPE_SECURITY_GROUP_RULES: {
                'neutron_get':
                    self._ovn_client._plugin.get_security_group_rule,
                'ovn_get': self._nb_idl.get_acl_by_id,
                'ovn_create': self._ovn_client.create_security_group_rule,
                'ovn_delete': self._ovn_client.delete_security_group_rule,
            },
            ovn_const.TYPE_ROUTER_PORTS: {
                'neutron_get':
                    self._ovn_client._plugin.get_port,
                'ovn_get': self._nb_idl.get_lrouter_port,
                'ovn_create': self._create_lrouter_port,
                'ovn_update': self._ovn_client.update_router_port,
                'ovn_delete': self._ovn_client.delete_router_port,
            },
        }

    @property
    def has_lock(self):
        return not self._idl.is_lock_contended

    def _fix_create_update(self, row):
        res_map = self._resources_func_map[row.resource_type]
        admin_context = n_context.get_admin_context()
        try:
            # Get the latest version of the resource in Neutron DB
            n_obj = res_map['neutron_get'](admin_context, row.resource_uuid)
        except n_exc.NotFound:
            LOG.warning('Skip fixing resource %(res_uuid)s (type: '
                        '%(res_type)s). Resource does not exist in Neutron '
                        'database anymore', {'res_uuid': row.resource_uuid,
                                             'res_type': row.resource_type})
            return

        ovn_obj = res_map['ovn_get'](row.resource_uuid)

        if not ovn_obj:
            res_map['ovn_create'](n_obj)
        else:
            if row.resource_type == ovn_const.TYPE_SECURITY_GROUP_RULES:
                LOG.error("SG rule %s found with a revision number while "
                          "this resource doesn't support updates",
                          row.resource_uuid)
            elif row.resource_type == ovn_const.TYPE_SECURITY_GROUPS:
                # In OVN, we don't care about updates to security groups,
                # so just bump the revision number to whatever it's
                # supposed to be.
                db_rev.bump_revision(n_obj, row.resource_type)
            else:
                ext_ids = getattr(ovn_obj, 'external_ids', {})
                ovn_revision = int(ext_ids.get(
                    ovn_const.OVN_REV_NUM_EXT_ID_KEY, -1))
                # If the resource exist in the OVN DB but the revision
                # number is different from Neutron DB, updated it.
                if ovn_revision != n_obj['revision_number']:
                    res_map['ovn_update'](n_obj)
                else:
                    # If the resource exist and the revision number
                    # is equal on both databases just bump the revision on
                    # the cache table.
                    db_rev.bump_revision(n_obj, row.resource_type)

    def _fix_delete(self, row):
        res_map = self._resources_func_map[row.resource_type]
        ovn_obj = res_map['ovn_get'](row.resource_uuid)
        if not ovn_obj:
            db_rev.delete_revision(row.resource_uuid, row.resource_type)
        else:
            res_map['ovn_delete'](row.resource_uuid)

    def _fix_create_update_subnet(self, row):
        # Get the lasted version of the port in Neutron DB
        admin_context = n_context.get_admin_context()
        sn_db_obj = self._ovn_client._plugin.get_subnet(
            admin_context, row.resource_uuid)
        n_db_obj = self._ovn_client._plugin.get_network(
            admin_context, sn_db_obj['network_id'])

        if row.revision_number == ovn_const.INITIAL_REV_NUM:
            self._ovn_client.create_subnet(sn_db_obj, n_db_obj)
        else:
            self._ovn_client.update_subnet(sn_db_obj, n_db_obj)

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
        self._sync_timer.restart()

        # Fix the create/update resources inconsistencies
        for row in create_update_inconsistencies:
            try:
                # NOTE(lucasagomes): The way to fix subnets is bit
                # different than other resources. A subnet in OVN language
                # is just a DHCP rule but, this rule only exist if the
                # subnet in Neutron has the "enable_dhcp" attribute set
                # to True. So, it's possible to have a consistent subnet
                # resource even when it does not exist in the OVN database.
                if row.resource_type == ovn_const.TYPE_SUBNETS:
                    self._fix_create_update_subnet(row)
                else:
                    self._fix_create_update(row)
            except Exception:
                LOG.exception('Failed to fix resource %(res_uuid)s '
                              '(type: %(res_type)s)',
                              {'res_uuid': row.resource_uuid,
                               'res_type': row.resource_type})

        # Fix the deleted resources inconsistencies
        for row in delete_inconsistencies:
            try:
                if row.resource_type == ovn_const.TYPE_SUBNETS:
                    self._ovn_client.delete_subnet(row.resource_uuid)
                else:
                    self._fix_delete(row)
            except Exception:
                LOG.exception('Failed to fix deleted resource %(res_uuid)s '
                              '(type: %(res_type)s)',
                              {'res_uuid': row.resource_uuid,
                               'res_type': row.resource_type})

        self._sync_timer.stop()
        LOG.info('Maintenance thread synchronization finished '
                 '(took %.2f seconds)', self._sync_timer.elapsed())

    def _create_lrouter_port(self, port):
        admin_context = n_context.get_admin_context()
        router_id = port['device_id']
        self._ovn_client._l3_plugin.add_router_interface(
            admin_context, router_id, {'port_id': port['id']})

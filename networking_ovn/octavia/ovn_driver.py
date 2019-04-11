#    Copyright 2018 Red Hat, Inc. All rights reserved.
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

import atexit
import copy
import threading

from octavia_lib.api.drivers import data_models as o_datamodels
from octavia_lib.api.drivers import driver_lib as o_driver_lib
from octavia_lib.api.drivers import exceptions as driver_exceptions
from octavia_lib.api.drivers import provider_base as driver_base
from octavia_lib.common import constants
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
from ovs.stream import Stream
from ovsdbapp.schema.ovn_northbound import impl_idl as idl_ovn
from six.moves import queue as Queue
from stevedore import driver

from networking_ovn._i18n import _
from networking_ovn.common import config as ovn_cfg
from networking_ovn.common import utils as ovn_utils

CONF = cfg.CONF  # Gets Octavia Conf as it runs under o-api domain

LOG = logging.getLogger(__name__)

"""
OVN Northbound schema [1] has a table to store load balancers.
The table looks like

"Load_Balancer": {
    "columns": {
        "name": {"type": "string"},
        "vips": {
            "type": {"key": "string", "value": "string",
                     "min": 0, "max": "unlimited"}},
        "protocol": {
            "type": {"key": {"type": "string",
                             "enum": ["set", ["tcp", "udp"]]},
                             "min": 0, "max": 1}},
        "external_ids": {
            "type": {"key": "string", "value": "string",
                    "min": 0, "max": "unlimited"}}},
        "isRoot": true},

Logical_Switch table (which corresponds to neutron network) has a column
'load_balancers' which refers to the 'Load_Balancer' table.

This driver updates this database. When a load balancer is created, a row in
this table is created. And when the listeners and members are added, 'vips'
column is updated accordingly. And the Logical_Switch's 'load_balancers'
column is also updated accordingly.

ovn-northd service which monitors for changes to the OVN Northbound db,
generates OVN logical flows to enable load balancing and ovn-controller running
on each compute node, translates the logical flows into actual OF Flows.
[1] - https://github.com/openvswitch/ovs/blob/
d1b235d7a6246e00d4afc359071d3b6b3ed244c3/ovn/ovn-nb.ovsschema#L117.

Below  are few examples on what happens when loadbalancer commands are
executed and what changes in the Load_Balancer Northbound db table.

1. Create a load balancer
$openstack loadbalancer create --provider ovn --vip-subnet-id=private lb1


$ ovn-nbctl list load_balancer

_uuid         : 9dd65bae-2501-43f2-b34e-38a9cb7e4251
external_ids  : {
    lr_ref="neutron-52b6299c-6e38-4226-a275-77370296f257",
    ls_refs="{\"neutron-2526c68a-5a9e-484c-8e00-0716388f6563\": 1}",
    neutron:vip="10.0.0.10",
    neutron:vip_port_id="2526c68a-5a9e-484c-8e00-0716388f6563"}

name          : "973a201a-8787-4f6e-9b8f-ab9f93c31f44"
protocol      : []
vips          : {}


2.  Create a pool
$openstack loadbalancer pool create --name p1 --loadbalancer lb1
 --protocol TCP   --lb-algorithm ROUND_ROBIN

$ovn-nbctl list load_balancer
_uuid         : 9dd65bae-2501-43f2-b34e-38a9cb7e4251
external_ids  : {
    lr_ref="neutron-52b6299c-6e38-4226-a275-77370296f257",
    ls_refs="{\"neutron-2526c68a-5a9e-484c-8e00-0716388f6563\": 1}",
    "pool_f2ddf7a6-4047-4cc9-97be-1d1a6c47ece9"="", neutron:vip="10.0.0.10",
    neutron:vip_port_id="2526c68a-5a9e-484c-8e00-0716388f6563"}
name          : "973a201a-8787-4f6e-9b8f-ab9f93c31f44"
protocol      : []
vips          : {}

3. Create a member
$openstack loadbalancer member create --address 10.0.0.107
 --subnet-id 2d54ec67-c589-473b-bc67-41f3d1331fef  --protocol-port 80 p1

$ovn-nbctl list load_balancer
_uuid         : 9dd65bae-2501-43f2-b34e-38a9cb7e4251
external_ids  : {
    lr_ref="neutron-52b6299c-6e38-4226-a275-77370296f257",
    ls_refs="{\"neutron-2526c68a-5a9e-484c-8e00-0716388f6563\": 2}",
    "pool_f2ddf7a6-4047-4cc9-97be-1d1a6c47ece9"=
    "member_579c0c9f-d37d-4ba5-beed-cabf6331032d_10.0.0.107:80",
    neutron:vip="10.0.0.10",
    neutron:vip_port_id="2526c68a-5a9e-484c-8e00-0716388f6563"}
name          : "973a201a-8787-4f6e-9b8f-ab9f93c31f44"
protocol      : []
vips          : {}

4. Create another member

$openstack loadbalancer member create --address 20.0.0.107
 --subnet-id c2e2da10-1217-4fe2-837a-1c45da587df7   --protocol-port 80 p1

$ovn-nbctl list load_balancer
_uuid         : 9dd65bae-2501-43f2-b34e-38a9cb7e4251
external_ids  : {
    lr_ref="neutron-52b6299c-6e38-4226-a275-77370296f257",
    ls_refs="{\"neutron-2526c68a-5a9e-484c-8e00-0716388f6563\": 2,
              \"neutron-12c42705-3e15-4e2d-8fc0-070d1b80b9ef\": 1}",
    "pool_f2ddf7a6-4047-4cc9-97be-1d1a6c47ece9"=
    "member_579c0c9f-d37d-4ba5-beed-cabf6331032d_10.0.0.107:80,
     member_d100f2ed-9b55-4083-be78-7f203d095561_20.0.0.107:80",
    neutron:vip="10.0.0.10",
    neutron:vip_port_id="2526c68a-5a9e-484c-8e00-0716388f6563"}
name          : "973a201a-8787-4f6e-9b8f-ab9f93c31f44"
protocol      : []
vips          : {}

5. Create a listener

$openstack loadbalancer listener create --name l1 --protocol TCP
 --protocol-port 82 --default-pool p1 lb1

$ovn-nbctl list load_balancer
_uuid         : 9dd65bae-2501-43f2-b34e-38a9cb7e4251
external_ids  : {
    lr_ref="neutron-52b6299c-6e38-4226-a275-77370296f257",
    ls_refs="{\"neutron-2526c68a-5a9e-484c-8e00-0716388f6563\": 2,
              \"neutron-12c42705-3e15-4e2d-8fc0-070d1b80b9ef\": 1}",
    "pool_f2ddf7a6-4047-4cc9-97be-1d1a6c47ece9"="10.0.0.107:80,20.0.0.107:80",
    "listener_12345678-2501-43f2-b34e-38a9cb7e4132"=
        "82:pool_f2ddf7a6-4047-4cc9-97be-1d1a6c47ece9",
    neutron:vip="10.0.0.10",
    neutron:vip_port_id="2526c68a-5a9e-484c-8e00-0716388f6563"}
name          : "973a201a-8787-4f6e-9b8f-ab9f93c31f44"
protocol      : []
vips          : {"10.0.0.10:82"="10.0.0.107:80,20.0.0.107:80"}

"""


REQ_TYPE_LB_CREATE = 'lb_create'
REQ_TYPE_LB_DELETE = 'lb_delete'
REQ_TYPE_LB_FAILOVER = 'lb_failover'
REQ_TYPE_LB_UPDATE = 'lb_update'
REQ_TYPE_LISTENER_CREATE = 'listener_create'
REQ_TYPE_LISTENER_DELETE = 'listener_delete'
REQ_TYPE_LISTENER_UPDATE = 'listener_update'
REQ_TYPE_POOL_CREATE = 'pool_create'
REQ_TYPE_POOL_DELETE = 'pool_delete'
REQ_TYPE_POOL_UPDATE = 'pool_update'
REQ_TYPE_MEMBER_CREATE = 'member_create'
REQ_TYPE_MEMBER_DELETE = 'member_delete'
REQ_TYPE_MEMBER_UPDATE = 'member_update'
REQ_TYPE_EXIT = 'exit'

DISABLED_RESOURCE_SUFFIX = 'D'

LB_EXT_IDS_LS_REFS_KEY = 'ls_refs'
LB_EXT_IDS_LR_REF_KEY = 'lr_ref'
LB_EXT_IDS_POOL_PREFIX = 'pool_'
LB_EXT_IDS_LISTENER_PREFIX = 'listener_'
LB_EXT_IDS_MEMBER_PREFIX = 'member_'
LB_EXT_IDS_VIP_KEY = 'neutron:vip'
LB_EXT_IDS_VIP_PORT_ID_KEY = 'neutron:vip_port_id'

OVN_NATIVE_LB_PROTOCOLS = [constants.PROTOCOL_TCP,
                           constants.PROTOCOL_UDP, ]
OVN_NATIVE_LB_ALGORITHMS = [constants.LB_ALGORITHM_ROUND_ROBIN, ]


def get_network_driver():
    CONF.import_group('controller_worker', 'octavia.common.config')
    return driver.DriverManager(
        namespace='octavia.network.drivers',
        name=CONF.controller_worker.network_driver,
        invoke_on_load=True
    ).driver


class OvnProviderHelper(object):

    ovn_nbdb_api = None

    def __init__(self):
        self.requests = Queue.Queue()
        self.helper_thread = threading.Thread(target=self.request_handler)
        self.helper_thread.daemon = True
        atexit.register(self.shutdown)
        self._octavia_driver_lib = o_driver_lib.DriverLibrary()
        self._init_ovnnb_db_api()
        self._init_lb_actions()
        self.start()

    def _init_lb_actions(self):
        self._lb_request_func_maps = {
            REQ_TYPE_LB_CREATE: self.lb_create,
            REQ_TYPE_LB_DELETE: self.lb_delete,
            REQ_TYPE_LB_UPDATE: self.lb_update,
            REQ_TYPE_LB_FAILOVER: self.lb_failover,
            REQ_TYPE_LISTENER_CREATE: self.listener_create,
            REQ_TYPE_LISTENER_DELETE: self.listener_delete,
            REQ_TYPE_LISTENER_UPDATE: self.listener_update,
            REQ_TYPE_POOL_CREATE: self.pool_create,
            REQ_TYPE_POOL_DELETE: self.pool_delete,
            REQ_TYPE_POOL_UPDATE: self.pool_update,
            REQ_TYPE_MEMBER_CREATE: self.member_create,
            REQ_TYPE_MEMBER_DELETE: self.member_delete,
            REQ_TYPE_MEMBER_UPDATE: self.member_update,
        }

    def _init_ovnnb_db_api(self):
        if OvnProviderHelper.ovn_nbdb_api:
            return

        tables = ('Logical_Switch', 'Load_Balancer', 'Logical_Router',
                  'Logical_Switch_Port', 'Logical_Router_Port')
        conn = ovn_utils.get_ovsdb_connection(
            ovn_cfg.get_ovn_nb_connection(), 'OVN_Northbound',
            ovn_cfg.get_ovn_ovsdb_timeout(), tables=tables)

        # idl_ovn.OvnNbApiIdlImpl.ovsdb_connection is a class variable.
        # So set it to None so that we don't use any old connection object.
        # See ovsdbapp.backend.ovs_idl.Backend class for more details.
        idl_ovn.OvnNbApiIdlImpl.ovsdb_connection = None
        OvnProviderHelper.ovn_nbdb_api = idl_ovn.OvnNbApiIdlImpl(conn)

        priv_key_file = ovn_cfg.get_ovn_nb_private_key()
        cert_file = ovn_cfg.get_ovn_nb_certificate()
        ca_cert_file = ovn_cfg.get_ovn_nb_ca_cert()
        if priv_key_file:
            Stream.ssl_set_private_key_file(priv_key_file)

        if cert_file:
            Stream.ssl_set_certificate_file(cert_file)

        if ca_cert_file:
            Stream.ssl_set_ca_cert_file(ca_cert_file)

    def start(self):
        self.helper_thread.start()

    def request_handler(self):
        while True:
            try:
                request = self.requests.get()
                request_type = request['type']
                if request_type == REQ_TYPE_EXIT:
                    break

                request_handler = self._lb_request_func_maps.get(request_type)
                if request_handler:
                    status = request_handler(request['info'])
                    if status:
                        self._update_status_to_octavia(status)
                self.requests.task_done()
            except Exception:
                # If any unexpected exception happens we don't want the
                # notify_loop to exit.
                LOG.exception('Unexpected exception in request_handler')

    def add_request(self, req):
        self.requests.put(req)

    def shutdown(self):
        self.requests.put({'type': REQ_TYPE_EXIT})

    def _update_status_to_octavia(self, status):
        try:
            self._octavia_driver_lib.update_loadbalancer_status(status)
        except driver_exceptions.UpdateStatusError as e:
            # TODO(numans): Handle the exception properly
            LOG.error('Error while updating the load balancer status: %s',
                      e.fault_string)

    def _find_ovn_lb(self, loadbalancer_id):
        find_condition = ('name', '=', loadbalancer_id)
        ovn_lb = self.ovn_nbdb_api.db_find(
            'Load_Balancer', find_condition, row=True).execute(
                check_error=True)
        if len(ovn_lb) > 1:
            LOG.warning("Two or more load balancer named '%s' "
                        "have been found in the database", loadbalancer_id)
        return ovn_lb[0] if len(ovn_lb) == 1 else None

    def _find_ovn_lb_with_pool_key(self, pool_key):
        lbs = self.ovn_nbdb_api.db_list_rows('Load_Balancer').execute()
        for lb in lbs:
            if pool_key in lb.external_ids:
                return lb

    def _execute_commands(self, commands):
        with self.ovn_nbdb_api.transaction(check_error=True) as txn:
            for command in commands:
                txn.add(command)

    def _update_lb_to_ls_association(self, ovn_lb, network_id=None,
                                     subnet_id=None, associate=True):
        commands = []
        if not network_id and not subnet_id:
            return commands

        if network_id:
            ls_name = ovn_utils.ovn_name(network_id)
        else:
            network_driver = get_network_driver()
            subnet = network_driver.get_subnet(subnet_id)
            ls_name = ovn_utils.ovn_name(subnet.network_id)

        ovn_ls = self.ovn_nbdb_api.ls_get(ls_name).execute(
            check_error=True)
        if not ovn_ls:
            return commands

        ls_refs = ovn_lb.external_ids.get(LB_EXT_IDS_LS_REFS_KEY)
        if ls_refs:
            try:
                ls_refs = jsonutils.loads(ls_refs)
            except ValueError:
                ls_refs = {}
        else:
            ls_refs = {}

        if associate:
            if ls_name in ls_refs:
                ref_ct = ls_refs[ls_name]
                ls_refs[ls_name] = ref_ct + 1
            else:
                ls_refs[ls_name] = 1
                commands.append(self.ovn_nbdb_api.ls_lb_add(
                    ovn_ls.uuid, ovn_lb.uuid, may_exist=True))
        else:
            if ls_name not in ls_refs:
                # Nothing to be done.
                return commands

            ref_ct = ls_refs[ls_name]
            if ref_ct == 1:
                del ls_refs[ls_name]
                commands.append(self.ovn_nbdb_api.ls_lb_del(
                    ovn_ls.uuid, ovn_lb.uuid, if_exists=True))
            else:
                ls_refs[ls_name] = ref_ct - 1

        ls_refs = {LB_EXT_IDS_LS_REFS_KEY: jsonutils.dumps(ls_refs)}
        commands.append(self.ovn_nbdb_api.db_set(
            'Load_Balancer', ovn_lb.uuid,
            ('external_ids', ls_refs)))

        return commands

    def _update_lb_to_lr_association(self, ovn_lb, ovn_lr):
        commands = []
        lr_ref = {LB_EXT_IDS_LR_REF_KEY: ovn_lr.name}
        commands.append(
            self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                     ('external_ids', lr_ref))
        )
        commands.append(
            self.ovn_nbdb_api.lr_lb_add(ovn_lr.uuid, ovn_lb.uuid)
        )

        return commands

    def _find_lr_of_ls(self, ovn_ls):
        lsp_router_port = None
        for port in ovn_ls.ports or []:
            if port.type == 'router':
                lsp_router_port = port
                break
        else:
            return

        lrp_name = lsp_router_port.options.get('router-port')
        if not lrp_name:
            return

        for lr in self.ovn_nbdb_api.tables['Logical_Router'].rows.values():
            for lrp in lr.ports:
                if lrp.name == lrp_name:
                    return lr

    def _get_listener_key(self, listener_id, is_enabled=True):
        listener_key = LB_EXT_IDS_LISTENER_PREFIX + str(listener_id)
        if not is_enabled:
            listener_key += ':' + DISABLED_RESOURCE_SUFFIX
        return listener_key

    def _get_pool_key(self, pool_id, is_enabled=True):
        pool_key = LB_EXT_IDS_POOL_PREFIX + str(pool_id)
        if not is_enabled:
            pool_key += ':' + DISABLED_RESOURCE_SUFFIX
        return pool_key

    def _extract_member_info(self, member):
        mem_info = ''
        if member:
            for mem in member.split(','):
                mem_info += str(mem.split('_')[2]) + ','
        return mem_info[:-1]  # Remove the last ','

    def _get_member_key(self, member):
        member_info = LB_EXT_IDS_MEMBER_PREFIX + member['id'] + "_"
        member_info += member['address'] + ":" + str(member['protocol_port'])
        return member_info

    def _make_listener_key_value(self, listener_port, pool_id):
        return str(listener_port) + ':' + pool_id

    def _extract_listener_key_value(self, listener_value):
        v = listener_value.split(':')
        if len(v) == 2:
            return (v[0], v[1])
        else:
            return (None, None)

    def _is_listener_disabled(self, listener_key):
        v = listener_key.split(':')
        if len(v) == 2 and v[1] == DISABLED_RESOURCE_SUFFIX:
            return True

        return False

    def _get_pool_listeners(self, ovn_lb, pool_key):
        pool_listeners = []
        for k, v in ovn_lb.external_ids.items():
            if LB_EXT_IDS_LISTENER_PREFIX not in k:
                continue
            vip_port, p_key = self._extract_listener_key_value(v)
            if pool_key == p_key:
                pool_listeners.append(k[len(LB_EXT_IDS_LISTENER_PREFIX):])

        return pool_listeners

    def _frame_vip_ips(self, lb_external_ids):
        vip_ips = {}
        # If load balancer is disabled, return
        if lb_external_ids.get('enabled') == 'False':
            return vip_ips

        lb_vip = lb_external_ids[LB_EXT_IDS_VIP_KEY]
        for k, v in lb_external_ids.items():
            if LB_EXT_IDS_LISTENER_PREFIX not in k or (
                self._is_listener_disabled(k)):
                continue

            vip_port, pool_id = self._extract_listener_key_value(v)
            if not vip_port or not pool_id:
                continue

            if pool_id not in lb_external_ids or not lb_external_ids[pool_id]:
                continue

            ips = self._extract_member_info(lb_external_ids[pool_id])
            vip_ips[lb_vip + ':' + vip_port] = ips

        return vip_ips

    def _refresh_lb_vips(self, ovn_lb_uuid, lb_external_ids):
        vip_ips = self._frame_vip_ips(lb_external_ids)
        return [self.ovn_nbdb_api.db_clear('Load_Balancer', ovn_lb_uuid,
                                           'vips'),
                self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb_uuid,
                                         ('vips', vip_ips))]

    def _is_listener_in_lb(self, lb):
        for key in list(lb.external_ids):
            if key.startswith(LB_EXT_IDS_LISTENER_PREFIX):
                return True
        return False

    def check_lb_protocol(self, lb_id, listener_protocol):
        ovn_lb = self._find_ovn_lb(lb_id)
        if not ovn_lb:
            return False
        elif not self._is_listener_in_lb(ovn_lb):
            return True
        else:
            return str(listener_protocol).lower() in ovn_lb.protocol

    def lb_create(self, loadbalancer):
        try:
            # Get the port id of the vip and store it in the external_ids.
            # This is required to delete the port when the loadbalancer is
            # deleted.
            network_driver = get_network_driver()
            ports = network_driver.neutron_client.list_ports(
                network_id=loadbalancer['vip_network_id'])
            port = None
            for p in ports['ports']:
                for ip in p['fixed_ips']:
                    if ip['ip_address'] == loadbalancer['vip_address']:
                        port = p
                        break
            # In case port is not found for the vip_address we will see an
            # exception when port['id'] is accessed.
            self.ovn_nbdb_api.db_create(
                'Load_Balancer', name=loadbalancer['id'], protocol='tcp',
                external_ids={LB_EXT_IDS_VIP_KEY: loadbalancer['vip_address'],
                              LB_EXT_IDS_VIP_PORT_ID_KEY: port['id'],
                              'enabled': str(loadbalancer['admin_state_up'])}
                ).execute(check_error=True)
            ovn_lb = self._find_ovn_lb(loadbalancer['id'])
            commands = self._update_lb_to_ls_association(
                ovn_lb, network_id=loadbalancer['vip_network_id'],
                associate=True)
            ls_name = ovn_utils.ovn_name(loadbalancer['vip_network_id'])
            ovn_ls = self.ovn_nbdb_api.ls_get(ls_name).execute(
                check_error=True)
            ovn_lr = self._find_lr_of_ls(ovn_ls)
            if ovn_lr:
                commands.extend(self._update_lb_to_lr_association(
                    ovn_lb, ovn_lr))
            self._execute_commands(commands)
            operating_status = constants.ONLINE
            if not loadbalancer.get('admin_state_up', True):
                operating_status = constants.OFFLINE
            status = {
                'loadbalancers': [{"id": loadbalancer['id'],
                                   "provisioning_status": constants.ACTIVE,
                                   "operating_status": operating_status}]}
        # If the connection with the OVN NB db server is broken, then
        # ovsdbapp will throw either TimeOutException or RunTimeError.
        # May be we can catch these specific exceptions.
        # It is important to report the status to octavia. We can report
        # immediately or reschedule the lb_create request later.
        # For now lets report immediately.
        except Exception:
            LOG.exception('Unexpected exception during load balancer create')
            # Any Exception set the status to ERROR
            status = {
                'loadbalancers': [{"id": loadbalancer['id'],
                                   "provisioning_status": constants.ERROR,
                                   "operating_status": constants.ERROR}]}
        return status

    def lb_delete(self, loadbalancer):
        try:
            status = {'loadbalancers': [{"id": loadbalancer['id'],
                                         "provisioning_status": "DELETED",
                                         "operating_status": "OFFLINE"}]}
            ovn_lb = self._find_ovn_lb(loadbalancer['id'])
            if not ovn_lb:
                return status

            if loadbalancer['cascade']:
                status['members'] = []
                status['pools'] = []
                status['listeners'] = []
                # Delete all pools
                for key, value in ovn_lb.external_ids.items():
                    if key.startswith(LB_EXT_IDS_POOL_PREFIX):
                        pool_id = key.split('_')[1]
                        # Delete all members in the pool
                        if value and len(value.split(',')) > 0:
                            for mem_info in value.split(','):
                                status['members'].append({
                                    'id': mem_info.split('_')[1],
                                    'provisioning_status': constants.DELETED})
                        status['pools'].append(
                            {"id": pool_id,
                             "provisioning_status": constants.DELETED})

                    if key.startswith(LB_EXT_IDS_LISTENER_PREFIX):
                        status['listeners'].append({
                            'id': key.split('_')[1],
                            'provisioning_status': constants.DELETED,
                            'operating_status': constants.OFFLINE})
                # Clear the status dict of any key having [] value
                # Python 3.6 doesnt allow deleting an element in a
                # dict while iterating over it. So first get a list of keys.
                # https://cito.github.io/blog/never-iterate-a-changing-dict/
                status = {key: value for key, value in status.items() if value}
            ls_refs = ovn_lb.external_ids.get(LB_EXT_IDS_LS_REFS_KEY, {})
            if ls_refs:
                try:
                    ls_refs = jsonutils.loads(ls_refs)
                except ValueError:
                    ls_refs = {}

            commands = []
            for ls_name in ls_refs.keys():
                ovn_ls = self.ovn_nbdb_api.ls_get(ls_name).execute(
                    check_error=True)
                if ovn_ls:
                    commands.append(
                        self.ovn_nbdb_api.ls_lb_del(ovn_ls.uuid, ovn_lb.uuid,
                                                    if_exists=True)
                    )

            lr_ref = ovn_lb.external_ids.get(LB_EXT_IDS_LR_REF_KEY)
            if lr_ref:
                for lr in self.ovn_nbdb_api.tables['Logical_Router'].rows.\
                    values():
                    if lr.name == lr_ref:
                        commands.append(self.ovn_nbdb_api.lr_lb_del(
                            lr.uuid, ovn_lb.uuid))
                        break

            commands.append(self.ovn_nbdb_api.lb_del(ovn_lb.uuid))
            self._execute_commands(commands)

            # We need to delete the vip port
            network_driver = get_network_driver()
            network_driver.neutron_client.delete_port(
                ovn_lb.external_ids[LB_EXT_IDS_VIP_PORT_ID_KEY])
        except Exception:
            LOG.exception('Exception during load balancer delete')
            status = {
                'loadbalancers': [{"id": loadbalancer['id'],
                                   "provisioning_status": constants.ERROR,
                                   "operating_status": constants.ERROR}]}
        return status

    def lb_failover(self, loadbalancer):
        status = {
            'loadbalancers': [{'id': loadbalancer['id'],
                               'provisioning_status': constants.ACTIVE}]}
        return status

    def lb_update(self, loadbalancer):
        try:
            lb_status = {'id': loadbalancer['id'],
                         'provisioning_status': constants.ACTIVE}
            status = {'loadbalancers': [lb_status]}
            if 'admin_state_up' not in loadbalancer:
                return status
            lb_enabled = loadbalancer['admin_state_up']

            ovn_lb = self._find_ovn_lb(loadbalancer['id'])
            if ovn_lb.external_ids['enabled'] != str(lb_enabled):
                commands = []
                enable_info = {'enabled': str(lb_enabled)}
                ovn_lb.external_ids['enabled'] = str(lb_enabled)
                commands.append(
                    self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                             ('external_ids', enable_info))
                )

                commands.extend(
                    self._refresh_lb_vips(ovn_lb.uuid, ovn_lb.external_ids))

                self._execute_commands(commands)
            if lb_enabled:
                operating_status = constants.ONLINE
            else:
                operating_status = constants.OFFLINE
            lb_status['operating_status'] = operating_status
        except Exception:
            LOG.exception('Exception during load balancer delete')
            lb_status['provisioning_status'] = constants.ERROR
            lb_status['operating_status'] = constants.ERROR

        return status

    def listener_create(self, listener):
        try:
            ovn_lb = self._find_ovn_lb(listener['loadbalancer_id'])

            external_ids = copy.deepcopy(ovn_lb.external_ids)
            listener_key = self._get_listener_key(
                listener['id'], is_enabled=listener['admin_state_up'])

            if listener['default_pool_id']:
                pool_key = self._get_pool_key(listener['default_pool_id'])
            else:
                pool_key = ''
            external_ids[listener_key] = self._make_listener_key_value(
                listener['protocol_port'], pool_key)

            listener_info = {listener_key: external_ids[listener_key]}
            commands = []
            commands.append(
                self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                         ('external_ids', listener_info))
            )
            if not self._is_listener_in_lb(ovn_lb):
                commands.append(
                    self.ovn_nbdb_api.db_set(
                        'Load_Balancer', ovn_lb.uuid,
                        ('protocol', str(listener['protocol']).lower()))
                )
            commands.extend(
                self._refresh_lb_vips(ovn_lb.uuid, external_ids)
            )
            self._execute_commands(commands)

            operating_status = constants.ONLINE
            if not listener.get('admin_state_up', True):
                operating_status = constants.OFFLINE
            status = {
                'listeners': [{"id": listener['id'],
                               "provisioning_status": constants.ACTIVE,
                               "operating_status": operating_status}],
                'loadbalancers': [{"id": listener['loadbalancer_id'],
                                   "provisioning_status": constants.ACTIVE}]}
        except Exception:
            LOG.exception('Exception during listener create')
            status = {
                'listeners': [{"id": listener['id'],
                               "provisioning_status": constants.ERROR,
                               "operating_status": constants.ERROR}],
                'loadbalancers': [{"id": listener['loadbalancer_id'],
                                   "provisioning_status": constants.ACTIVE}]}
        return status

    def listener_delete(self, listener):
        try:
            ovn_lb = self._find_ovn_lb(listener['loadbalancer_id'])
            external_ids = copy.deepcopy(ovn_lb.external_ids)
            listener_key = self._get_listener_key(listener['id'])

            if listener_key in external_ids:
                commands = []
                commands.append(
                    self.ovn_nbdb_api.db_remove(
                        'Load_Balancer', ovn_lb.uuid, 'external_ids',
                        (listener_key))
                )

                del external_ids[listener_key]
                commands.extend(
                    self._refresh_lb_vips(ovn_lb.uuid, external_ids)
                )

                self._execute_commands(commands)

            status = {
                'listeners': [{"id": listener['id'],
                               "provisioning_status": constants.DELETED,
                               "operating_status": constants.OFFLINE}],
                'loadbalancers': [{"id": listener['loadbalancer_id'],
                                   "provisioning_status": constants.ACTIVE}]}
        except Exception:
            LOG.exception('Exception during listener create')
            status = {
                'listeners': [{"id": listener['id'],
                               "provisioning_status": constants.ERROR,
                               "operating_status": constants.ERROR}],
                'loadbalancers': [{"id": listener['loadbalancer_id'],
                                   "provisioning_status": constants.ACTIVE}]}
        return status

    def listener_update(self, listener):
        try:
            listener_status = {'id': listener['id'],
                               'provisioning_status': constants.ACTIVE}
            pool_status = []
            status = {
                'listeners': [listener_status],
                'loadbalancers': [{'id': listener['loadbalancer_id'],
                                   'provisioning_status': constants.ACTIVE}],
                'pools': pool_status}

            ovn_lb = self._find_ovn_lb(listener['loadbalancer_id'])
            l_key_when_enabled = self._get_listener_key(listener['id'])
            l_key_when_disabled = self._get_listener_key(
                listener['id'], is_enabled=False)

            external_ids = copy.deepcopy(ovn_lb.external_ids)

            if 'admin_state_up' not in listener and (
                    'default_pool_id' not in listener):
                return status

            l_key_to_add = {}
            if l_key_when_enabled in external_ids:
                present_l_key = l_key_when_enabled
            elif l_key_when_disabled in external_ids:
                present_l_key = l_key_when_disabled
            else:
                # Something is terribly wrong. This cannot happen.
                return status

            commands = []
            new_l_key = None
            l_key_to_remove = None
            if 'admin_state_up' in listener:
                if listener['admin_state_up']:
                    # We need to enable the listener
                    new_l_key = l_key_when_enabled
                    listener_status['operating_status'] = constants.ONLINE
                else:
                    # We need to disable the listener
                    new_l_key = l_key_when_disabled
                    listener_status['operating_status'] = constants.OFFLINE

                if present_l_key != new_l_key:
                    external_ids[new_l_key] = external_ids[present_l_key]
                    l_key_to_add[new_l_key] = external_ids[present_l_key]
                    del external_ids[present_l_key]
                    l_key_to_remove = present_l_key

                if l_key_to_remove:
                    commands.append(
                        self.ovn_nbdb_api.db_remove(
                            'Load_Balancer', ovn_lb.uuid, 'external_ids',
                            (l_key_to_remove))
                    )
            else:
                new_l_key = present_l_key

            if 'default_pool_id' in listener:
                pool_key = self._get_pool_key(listener['default_pool_id'])
                l_key_value = self._make_listener_key_value(
                    listener['protocol_port'], pool_key)
                l_key_to_add[new_l_key] = l_key_value
                external_ids[new_l_key] = l_key_value
                pool_status.append({'id': listener['default_pool_id'],
                                    'provisioning_status': constants.ACTIVE})

            if l_key_to_add:
                commands.append(
                    self.ovn_nbdb_api.db_set(
                        'Load_Balancer', ovn_lb.uuid,
                        ('external_ids', l_key_to_add))
                )

            commands.extend(
                self._refresh_lb_vips(ovn_lb.uuid, external_ids))
            self._execute_commands(commands)
        except Exception:
            LOG.exception('Exception during listener delete')
            status = {
                'listeners': [{'id': listener['id'],
                               'provisioning_status': constants.ERROR}],
                'loadbalancers': [{'id': listener['loadbalancer_id'],
                                   'provisioning_status': constants.ACTIVE}]}

        return status

    def pool_create(self, pool):
        try:
            ovn_lb = self._find_ovn_lb(pool['loadbalancer_id'])
            external_ids = copy.deepcopy(ovn_lb.external_ids)
            pool_key = self._get_pool_key(pool['id'],
                                          is_enabled=pool['admin_state_up'])
            external_ids[pool_key] = ''
            if pool['listener_id']:
                listener_key = self._get_listener_key(pool['listener_id'])
                if listener_key in ovn_lb.external_ids:
                    external_ids[listener_key] = str(
                        external_ids[listener_key]) + str(pool_key)
            self.ovn_nbdb_api.db_set(
                'Load_Balancer', ovn_lb.uuid,
                ('external_ids', external_ids)).execute(check_error=True)
            operating_status = constants.ONLINE
            if not pool.get('admin_state_up', True):
                operating_status = constants.OFFLINE

            status = {
                'pools': [{'id': pool['id'],
                           'provisioning_status': constants.ACTIVE,
                           'operating_status': operating_status}],
                'loadbalancers': [{"id": pool['loadbalancer_id'],
                                   "provisioning_status": constants.ACTIVE}]}
            if pool['listener_id']:
                listener_status = [{'id': pool['listener_id'],
                                    'provisioning_status': constants.ACTIVE}]
                status['listeners'] = listener_status
        except Exception:
            LOG.exception('Exception during pool create')
            status = {
                'pools': [{"id": pool['id'],
                           "provisioning_status": constants.ERROR}],
                'loadbalancers': [{"id": pool['loadbalancer_id'],
                                   "provisioning_status": constants.ACTIVE}]}
            if pool['listener_id']:
                listener_status = [{'id': pool['listener_id'],
                                   'provisioning_status': constants.ACTIVE}]
                status['listeners'] = listener_status

        return status

    def pool_delete(self, pool):
        try:
            ovn_lb = self._find_ovn_lb(pool['loadbalancer_id'])
            pool_key = self._get_pool_key(pool['id'])
            commands = []
            if pool_key in ovn_lb.external_ids:
                commands.append(
                    self.ovn_nbdb_api.db_remove('Load_Balancer', ovn_lb.uuid,
                                                'external_ids', (pool_key))
                )
                external_ids = copy.deepcopy(ovn_lb.external_ids)
                del external_ids[pool_key]
                commands.extend(
                    self._refresh_lb_vips(ovn_lb.uuid, external_ids))
            # Remove Pool from Listener if it is associated
            listener_id = None
            for key, value in ovn_lb.external_ids.items():
                if key.startswith(
                    LB_EXT_IDS_LISTENER_PREFIX) and pool_key in value:
                    external_ids[key] = value.split(':')[0] + ':'
                    commands.append(
                        self.ovn_nbdb_api.db_set(
                            'Load_Balancer', ovn_lb.uuid,
                            ('external_ids', external_ids)))
                    listener_id = key.split('_')[1]

            pool_key_when_disabled = self._get_pool_key(pool['id'],
                                                        is_enabled=False)
            if pool_key_when_disabled in ovn_lb.external_ids:
                commands.append(
                    self.ovn_nbdb_api.db_remove(
                        'Load_Balancer', ovn_lb.uuid,
                        'external_ids', (pool_key_when_disabled))
                )

            self._execute_commands(commands)

            status = {
                'pools': [{"id": pool['id'],
                           "provisioning_status": constants.DELETED}],
                'loadbalancers': [{"id": pool['loadbalancer_id'],
                                   "provisioning_status": constants.ACTIVE}]}
            if listener_id:
                status['listeners'] = [{
                    'id': listener_id,
                    'provisioning_status': constants.ACTIVE}]
        except Exception:
            LOG.exception('Exception during pool delete')
            status = {
                'pools': [{"id": pool['id'],
                           "provisioning_status": constants.ERROR}],
                'loadbalancers': [{"id": pool['loadbalancer_id'],
                                   "provisioning_status": constants.ACTIVE}]}

        return status

    def pool_update(self, pool):
        try:
            pool_status = {'id': pool['id'],
                           'provisioning_status': constants.ACTIVE}
            status = {
                'pools': [pool_status],
                'loadbalancers': [{'id': pool['loadbalancer_id'],
                                   'provisioning_status': constants.ACTIVE}]}
            if 'admin_state_up' not in pool:
                return status

            ovn_lb = self._find_ovn_lb(pool['loadbalancer_id'])
            pool_key = self._get_pool_key(pool['id'])
            p_key_when_disabled = self._get_pool_key(pool['id'],
                                                     is_enabled=False)

            external_ids = copy.deepcopy(ovn_lb.external_ids)
            p_key_to_remove = None
            p_key_to_add = {}
            if pool['admin_state_up']:
                if p_key_when_disabled in external_ids:
                    p_key_to_add[pool_key] = external_ids[p_key_when_disabled]
                    external_ids[pool_key] = external_ids[p_key_when_disabled]
                    del external_ids[p_key_when_disabled]
                    p_key_to_remove = p_key_when_disabled
            else:
                if pool_key in external_ids:
                    p_key_to_add[p_key_when_disabled] = external_ids[pool_key]
                    external_ids[p_key_when_disabled] = external_ids[pool_key]
                    del external_ids[pool_key]
                    p_key_to_remove = pool_key

            if p_key_to_remove:
                commands = []
                commands.append(
                    self.ovn_nbdb_api.db_remove(
                        'Load_Balancer', ovn_lb.uuid, 'external_ids',
                        (p_key_to_remove))
                )

                commands.append(
                    self.ovn_nbdb_api.db_set(
                        'Load_Balancer', ovn_lb.uuid,
                        ('external_ids', p_key_to_add))
                )

                commands.extend(
                    self._refresh_lb_vips(ovn_lb.uuid, external_ids))
                self._execute_commands(commands)
            if pool['admin_state_up']:
                operating_status = constants.ONLINE
            else:
                operating_status = constants.OFFLINE
            pool_status['operating_status'] = operating_status

            pool_listeners = self._get_pool_listeners(ovn_lb,
                                                      pool_key)
            listener_status = []
            for l in pool_listeners:
                listener_status.append(
                    {'id': l,
                     'provisioning_status': constants.ACTIVE})
            status['listeners'] = listener_status
        except Exception:
            LOG.exception('Exception during pool update')
            status = {
                'pools': [{"id": pool['id'],
                           'provisioning_status': constants.ERROR}],
                'loadbalancers': [{"id": pool['loadbalancer_id'],
                                   'provisioning_status': constants.ACTIVE}]}

        return status

    def _add_member(self, member, ovn_lb, pool_key):
        external_ids = copy.deepcopy(ovn_lb.external_ids)
        existing_members = external_ids[pool_key]
        member_info = self._get_member_key(member)
        if member_info in existing_members.split(','):
            # member already present. No need to do anything.
            return

        if existing_members:
            pool_data = {pool_key: existing_members + "," + member_info}
        else:
            pool_data = {pool_key: member_info}

        commands = []
        commands.append(
            self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                     ('external_ids', pool_data))
        )

        external_ids[pool_key] = pool_data[pool_key]
        commands.extend(
            self._refresh_lb_vips(ovn_lb.uuid, external_ids)
        )
        commands.extend(
            self._update_lb_to_ls_association(
                ovn_lb, subnet_id=member['subnet_id'], associate=True)
        )
        self._execute_commands(commands)

    def member_create(self, member):
        try:
            pool_key = self._get_pool_key(member['pool_id'])
            ovn_lb = self._find_ovn_lb_with_pool_key(pool_key)
            if not ovn_lb:
                pool_key = self._get_pool_key(member['pool_id'],
                                              is_enabled=False)
                ovn_lb = self._find_ovn_lb_with_pool_key(pool_key)
            self._add_member(member, ovn_lb, pool_key)
            status = {
                'pools': [{"id": member['pool_id'],
                           "provisioning_status": constants.ACTIVE}],
                'members': [{"id": member['id'],
                             "provisioning_status": constants.ACTIVE}],
                'loadbalancers': [{"id": ovn_lb.name,
                                   "provisioning_status": constants.ACTIVE}]}
            pool_listeners = self._get_pool_listeners(ovn_lb, pool_key)
            listener_status = []
            for l in pool_listeners:
                listener_status.append(
                    {'id': l,
                     'provisioning_status': constants.ACTIVE})
            status['listeners'] = listener_status
        except Exception:
            LOG.exception('Exception during member create')
            status = {
                'pools': [{"id": member['pool_id'],
                           "provisioning_status": constants.ERROR}],
                'members': [{"id": member['id'],
                             "provisioning_status": constants.ACTIVE}],
                'loadbalancers': [{"id": ovn_lb.name,
                                   "provisioning_status": constants.ACTIVE}]}

        return status

    def _remove_member(self, member, ovn_lb, pool_key):
        external_ids = copy.deepcopy(ovn_lb.external_ids)
        existing_members = external_ids[pool_key].split(",")
        member_info = self._get_member_key(member)
        if member_info in existing_members:
            commands = []
            existing_members.remove(member_info)
            pool_data = {pool_key: ",".join(existing_members)}
            commands.append(
                self.ovn_nbdb_api.db_set('Load_Balancer', ovn_lb.uuid,
                                         ('external_ids', pool_data))
            )
            external_ids[pool_key] = ",".join(existing_members)
            commands.extend(
                self._refresh_lb_vips(ovn_lb.uuid, external_ids)
            )

            commands.extend(
                self._update_lb_to_ls_association(
                    ovn_lb, subnet_id=member['subnet_id'], associate=False)
            )
            self._execute_commands(commands)

    def member_delete(self, member):
        try:
            pool_key = self._get_pool_key(member['pool_id'])
            ovn_lb = self._find_ovn_lb_with_pool_key(pool_key)
            if not ovn_lb:
                pool_key = self._get_pool_key(member['pool_id'],
                                              is_enabled=False)
                ovn_lb = self._find_ovn_lb_with_pool_key(pool_key)
            self._remove_member(member, ovn_lb, pool_key)
            status = {
                'pools': [{"id": member['pool_id'],
                           "provisioning_status": constants.ACTIVE}],
                'members': [{"id": member['id'],
                             "provisioning_status": constants.DELETED}],
                'loadbalancers': [{"id": ovn_lb.name,
                                   "provisioning_status": constants.ACTIVE}]}
            pool_listeners = self._get_pool_listeners(ovn_lb, pool_key)
            listener_status = []
            for l in pool_listeners:
                listener_status.append(
                    {'id': l,
                     'provisioning_status': constants.ACTIVE})
            status['listeners'] = listener_status
        except Exception:
            LOG.exception('Exception during member delete')
            status = {
                'pools': [{"id": member['pool_id'],
                           "provisioning_status": constants.ACTIVE}],
                'members': [{"id": member['id'],
                             "provisioning_status": constants.ERROR}],
                'loadbalancers': [{"id": ovn_lb.name,
                                   "provisioning_status": constants.ACTIVE}]}

        return status

    def member_update(self, member):
        try:
            pool_key = self._get_pool_key(member['pool_id'])
            ovn_lb = self._find_ovn_lb_with_pool_key(pool_key)
            status = {
                'pools': [{'id': member['pool_id'],
                           'provisioning_status': constants.ACTIVE}],
                'members': [{'id': member['id'],
                             'provisioning_status': constants.ACTIVE}],
                'loadbalancers': [{'id': ovn_lb.name,
                                   'provisioning_status': constants.ACTIVE}]}
            if not ovn_lb:
                pool_key = self._get_pool_key(member['pool_id'],
                                              is_enabled=False)
                ovn_lb = self._find_ovn_lb_with_pool_key(pool_key)

            if 'admin_state_up' in member:
                if member['admin_state_up']:
                    self._add_member(member, ovn_lb, pool_key)
                    status['members'][0]['operating_status'] = \
                        constants.ONLINE
                else:
                    self._remove_member(member, ovn_lb, pool_key)
                    status['members'][0]['operating_status'] = \
                        constants.OFFLINE

            pool_listeners = self._get_pool_listeners(ovn_lb, pool_key)
            listener_status = []
            for l in pool_listeners:
                listener_status.append(
                    {'id': l,
                     'provisioning_status': constants.ACTIVE})
            status['listeners'] = listener_status
        except Exception:
            status = {
                'pools': [{'id': member['pool_id'],
                           'provisioning_status': constants.ACTIVE}],
                'members': [{'id': member['id'],
                             'provisioning_status': constants.ERROR}],
                'loadbalancers': [{'id': ovn_lb.name,
                                   'provisioning_status': constants.ACTIVE}]}
        return status

    def _get_existing_pool_members(self, pool_id):
        pool_key = self._get_pool_key(pool_id)
        ovn_lb = self._find_ovn_lb_with_pool_key(pool_key)
        if not ovn_lb:
            pool_key = self._get_pool_key(pool_id, is_enabled=False)
            ovn_lb = self._find_ovn_lb_with_pool_key(pool_key)
            if not ovn_lb:
                msg = _("Loadbalancer with pool %s does not exist") % pool_key
                raise driver_exceptions.DriverError(msg)
        external_ids = dict(ovn_lb.external_ids)
        return external_ids[pool_key]

    def get_pool_member_id(self, pool_id, mem_addr_port=None):
        '''Gets Member information

        :param pool_id: ID of the Pool whose member information is reqd.
        :param mem_addr_port: Combination of Member Address+Port. Default=None
        :returns: UUID -- ID of the Member if member exists in pool.
        :returns: None -- if no member exists in the pool
        :raises: Exception if Loadbalancer is not found for a Pool ID
        '''
        existing_members = self._get_existing_pool_members(pool_id)
        # Members are saved in OVN in the form of
        # member1_UUID_IP:Port, member2_UUID_IP:Port
        # Match the IP:Port for all members with the mem_addr_port
        # information and return the UUID.
        for meminf in existing_members.split(','):
            if mem_addr_port == meminf.split('_')[2]:
                return meminf.split('_')[1]

    def get_member_info(self, pool_id):
        '''Gets Member information

        :param pool_id: ID of the Pool whose member information is reqd.
        :param mem_addr_port: Combination of Member Address+Port. Default=None
        :returns: List -- List of Member Address+Pool of all members in pool.
        :returns:[None] -- if no member exists in the pool.
        :raises: Exception if Loadbalancer is not found for a Pool ID
        '''
        existing_members = self._get_existing_pool_members(pool_id)
        # Members are saved in OVN in the form of
        # member1_UUID_IP:Port, member2_UUID_IP:Port
        # Return the list of (UUID,IP:Port) for all members.
        return [(meminf.split('_')[1], meminf.split(
            '_')[2]) for meminf in existing_members.split(',')]

    def create_vip_port(self, project_id, lb_id, vip_d):
        port = {'port': {'name': 'ovn-lb-vip-' + str(lb_id),
                         'network_id': vip_d['vip_network_id'],
                         'fixed_ips': [{'subnet_id': vip_d['vip_subnet_id']}],
                         'admin_state_up': True,
                         'project_id': project_id}}
        network_driver = get_network_driver()
        return network_driver.neutron_client.create_port(port)


class OvnProviderDriver(driver_base.ProviderDriver):
    def __init__(self):
        super(OvnProviderDriver, self).__init__()
        self._ovn_helper = OvnProviderHelper()

    def _check_for_supported_protocols(self, protocol):
        if protocol not in OVN_NATIVE_LB_PROTOCOLS:
            msg = _('OVN provider does not support %s protocol') % protocol
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)

    def _check_for_supported_algorithms(self, algorithm):
        if algorithm not in OVN_NATIVE_LB_ALGORITHMS:
            msg = _('OVN provider does not support %s algorithm') % algorithm
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)

    def loadbalancer_create(self, loadbalancer):
        admin_state_up = loadbalancer.admin_state_up
        if isinstance(admin_state_up, o_datamodels.UnsetType):
            admin_state_up = True
        request_info = {'id': loadbalancer.loadbalancer_id,
                        'vip_address': loadbalancer.vip_address,
                        'vip_network_id': loadbalancer.vip_network_id,
                        'admin_state_up': admin_state_up}

        request = {'type': REQ_TYPE_LB_CREATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def loadbalancer_delete(self, loadbalancer, cascade=False):
        request_info = {'id': loadbalancer.loadbalancer_id,
                        'cascade': cascade}
        request = {'type': REQ_TYPE_LB_DELETE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def loadbalancer_failover(self, loadbalancer_id):
        request_info = {'id': loadbalancer_id}
        request = {'type': REQ_TYPE_LB_FAILOVER,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def loadbalancer_update(self, old_loadbalancer, new_loadbalncer):
        request_info = {'id': new_loadbalncer.loadbalancer_id}
        if not isinstance(
            new_loadbalncer.admin_state_up, o_datamodels.UnsetType):
            request_info['admin_state_up'] = new_loadbalncer.admin_state_up
        request = {'type': REQ_TYPE_LB_UPDATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    # Pool
    def pool_create(self, pool):
        self._check_for_supported_protocols(pool.protocol)
        self._check_for_supported_algorithms(pool.lb_algorithm)
        admin_state_up = pool.admin_state_up
        if isinstance(admin_state_up, o_datamodels.UnsetType):
            admin_state_up = True
        request_info = {'id': pool.pool_id,
                        'loadbalancer_id': pool.loadbalancer_id,
                        'listener_id': pool.listener_id,
                        'admin_state_up': admin_state_up}
        request = {'type': REQ_TYPE_POOL_CREATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def pool_delete(self, pool):
        for member in pool.members:
            self.member_delete(member)

        request_info = {'id': pool.pool_id,
                        'loadbalancer_id': pool.loadbalancer_id}
        request = {'type': REQ_TYPE_POOL_DELETE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def pool_update(self, old_pool, new_pool):
        if not isinstance(new_pool.protocol, o_datamodels.UnsetType):
            self._check_for_supported_protocols(new_pool.protocol)
        if not isinstance(new_pool.lb_algorithm, o_datamodels.UnsetType):
            self._check_for_supported_algorithms(new_pool.lb_algorithm)
        request_info = {'id': new_pool.pool_id,
                        'loadbalancer_id': old_pool.loadbalancer_id}

        if not isinstance(new_pool.admin_state_up, o_datamodels.UnsetType):
            request_info['admin_state_up'] = new_pool.admin_state_up
        request = {'type': REQ_TYPE_POOL_UPDATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    # Listener
    def _check_listener_protocol(self, listener):
        self._check_for_supported_protocols(listener.protocol)
        if not self._ovn_helper.check_lb_protocol(
            listener.loadbalancer_id, listener.protocol):
            msg = (_('The loadbalancer %(lb)s does not support %(proto)s '
                     'protocol') % {
                'lb': listener.loadbalancer_id,
                'proto': listener.protocol})
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)

    def listener_create(self, listener):
        self._check_listener_protocol(listener)
        admin_state_up = listener.admin_state_up
        if isinstance(admin_state_up, o_datamodels.UnsetType):
            admin_state_up = True
        request_info = {'id': listener.listener_id,
                        'protocol': listener.protocol,
                        'loadbalancer_id': listener.loadbalancer_id,
                        'protocol_port': listener.protocol_port,
                        'default_pool_id': listener.default_pool_id,
                        'admin_state_up': admin_state_up}
        request = {'type': REQ_TYPE_LISTENER_CREATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def listener_delete(self, listener):
        request_info = {'id': listener.listener_id,
                        'loadbalancer_id': listener.loadbalancer_id,
                        'protocol_port': listener.protocol_port}
        request = {'type': REQ_TYPE_LISTENER_DELETE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def listener_update(self, old_listener, new_listener):
        if not isinstance(new_listener.protocol, o_datamodels.UnsetType):
            self._check_listener_protocol(new_listener)
        request_info = {'id': new_listener.listener_id,
                        'loadbalancer_id': old_listener.loadbalancer_id,
                        'protocol_port': old_listener.protocol_port}

        if not isinstance(new_listener.admin_state_up, o_datamodels.UnsetType):
            request_info['admin_state_up'] = new_listener.admin_state_up

        if not isinstance(new_listener.default_pool_id,
                          o_datamodels.UnsetType):
            request_info['default_pool_id'] = new_listener.default_pool_id

        request = {'type': REQ_TYPE_LISTENER_UPDATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    # Member
    def member_create(self, member):
        admin_state_up = member.admin_state_up
        if isinstance(member.subnet_id, o_datamodels.UnsetType):
            msg = _('Subnet is required for Member creation'
                    ' with OVN Provider Driver')
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)

        if isinstance(admin_state_up, o_datamodels.UnsetType):
            admin_state_up = True
        request_info = {'id': member.member_id,
                        'address': member.address,
                        'protocol_port': member.protocol_port,
                        'pool_id': member.pool_id,
                        'subnet_id': member.subnet_id,
                        'admin_state_up': admin_state_up}
        request = {'type': REQ_TYPE_MEMBER_CREATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def member_delete(self, member):
        request_info = {'id': member.member_id,
                        'address': member.address,
                        'protocol_port': member.protocol_port,
                        'pool_id': member.pool_id,
                        'subnet_id': member.subnet_id}
        request = {'type': REQ_TYPE_MEMBER_DELETE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def member_update(self, old_member, new_member):
        request_info = {'id': new_member.member_id,
                        'address': old_member.address,
                        'protocol_port': old_member.protocol_port,
                        'pool_id': old_member.pool_id,
                        'subnet_id': old_member.subnet_id}
        if not isinstance(new_member.admin_state_up, o_datamodels.UnsetType):
            request_info['admin_state_up'] = new_member.admin_state_up
        request = {'type': REQ_TYPE_MEMBER_UPDATE,
                   'info': request_info}
        self._ovn_helper.add_request(request)

    def member_batch_update(self, members):
        # Note(rbanerje): all members belong to the same pool.
        request_list = []
        skipped_members = []
        pool_id = None
        try:
            pool_id = members[0].pool_id
        except IndexError:
            msg = (_('No member information has been passed'))
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)
        except AttributeError:
            msg = (_('Member does not have proper pool information'))
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)
        current_members = self._ovn_helper.get_member_info(pool_id)
        # current_members gets a list of tuples (ID, IP:Port) for pool members
        for member in members:
            if member.monitor_address or member.monitor_port:
                skipped_members.append(member.member_id)
                continue
            admin_state_up = member.admin_state_up
            if isinstance(admin_state_up, o_datamodels.UnsetType):
                admin_state_up = True
            mem_addr_port = str(member.address) + ':' + str(
                member.protocol_port)
            if (member.member_id, mem_addr_port) not in current_members:
                req_type = REQ_TYPE_MEMBER_CREATE
            else:
                # If member exists in pool, then Update
                req_type = REQ_TYPE_MEMBER_UPDATE
                current_members.remove((member.member_id, mem_addr_port))
                # Remove all updating members so only deleted ones are left
            request_info = {'id': member.member_id,
                            'address': member.address,
                            'protocol_port': member.protocol_port,
                            'pool_id': member.pool_id,
                            'subnet_id': member.subnet_id,
                            'admin_state_up': admin_state_up}
            request = {'type': req_type,
                       'info': request_info}
            request_list.append(request)
        for cmember in current_members:
            request_info = {'id': cmember[0],
                            'address': cmember[1].split(':')[0],
                            'protocol_port': cmember[1].split(':')[1],
                            'pool_id': pool_id}
            request = {'type': REQ_TYPE_MEMBER_DELETE,
                       'info': request_info}
            request_list.append(request)
        for request in request_list:
            self._ovn_helper.add_request(request)
        if skipped_members:
            msg = (_('OVN provider does not support monitor options, '
                     'so following members skipped: %s') % skipped_members)
            raise driver_exceptions.UnsupportedOptionError(
                user_fault_string=msg,
                operator_fault_string=msg)

    def create_vip_port(self, lb_id, project_id, vip_dict):
        try:
            port = self._ovn_helper.create_vip_port(
                project_id, lb_id, vip_dict)['port']
            vip_dict['vip_port_id'] = port['id']
            vip_dict['vip_address'] = port['fixed_ips'][0]['ip_address']
        except Exception as e:
            raise driver_exceptions.DriverError(e)
        return vip_dict

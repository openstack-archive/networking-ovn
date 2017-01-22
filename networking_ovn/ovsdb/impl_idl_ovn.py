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

from neutron_lib import exceptions as n_exc
from oslo_log import log
import tenacity

from neutron.agent.ovsdb import impl_idl
from neutron.agent.ovsdb.native import idlutils
from neutron_lib.utils import helpers

from networking_ovn._i18n import _, _LI
from networking_ovn.common import config as cfg
from networking_ovn.common import constants as ovn_const
from networking_ovn.common import utils
from networking_ovn.ovsdb import commands as cmd
from networking_ovn.ovsdb import ovn_api
from networking_ovn.ovsdb import ovsdb_monitor
from networking_ovn.ovsdb import vlog


LOG = log.getLogger(__name__)


class OvsdbConnectionUnavailable(n_exc.ServiceUnavailable):
    message = _("OVS database connection to %(db_schema)s failed with error: "
                "'%(error)s'. Verify that the OVS and OVN services are "
                "available and that the 'ovn_nb_connection' and "
                "'ovn_sb_connection' configuration options are correct.")


# Retry forever to get the OVN NB and SB IDLs. Wait 2^x * 1 seconds between
# each retry, up to 180 seconds, then 180 seconds afterwards.
def get_ovn_idls(driver, trigger):
    @tenacity.retry(
        wait=tenacity.wait_exponential(max=180),
        reraise=True)
    def get_ovn_idl_retry(cls, driver, trigger):
        LOG.info(_LI('Getting %(cls)s for %(trigger)s with retry'),
                 {'cls': cls.__name__, 'trigger': trigger.im_class.__name__})
        return cls(driver, trigger)

    vlog.use_oslo_logger()
    nb_ovn_idl = get_ovn_idl_retry(OvsdbNbOvnIdl, driver, trigger)
    sb_ovn_idl = get_ovn_idl_retry(OvsdbSbOvnIdl, driver, trigger)
    return nb_ovn_idl, sb_ovn_idl


def get_connection(db_class, trigger=None):
    # The trigger is the start() method of the NeutronWorker class
    if trigger and trigger.im_class == ovsdb_monitor.OvnWorker:
        cls = ovsdb_monitor.OvnConnection
    else:
        cls = ovsdb_monitor.OvnBaseConnection

    if db_class == OvsdbNbOvnIdl:
        return cls(cfg.get_ovn_nb_connection(),
                   cfg.get_ovn_ovsdb_timeout(), 'OVN_Northbound')
    elif db_class == OvsdbSbOvnIdl:
        return cls(cfg.get_ovn_sb_connection(),
                   cfg.get_ovn_ovsdb_timeout(), 'OVN_Southbound')


class OvsdbNbOvnIdl(ovn_api.API):

    ovsdb_connection = None

    def __init__(self, driver, trigger=None):
        super(OvsdbNbOvnIdl, self).__init__()
        try:
            if OvsdbNbOvnIdl.ovsdb_connection is None:
                OvsdbNbOvnIdl.ovsdb_connection = get_connection(
                    OvsdbNbOvnIdl, trigger)
            if isinstance(OvsdbNbOvnIdl.ovsdb_connection,
                          ovsdb_monitor.OvnConnection):
                OvsdbNbOvnIdl.ovsdb_connection.start(driver)
            else:
                OvsdbNbOvnIdl.ovsdb_connection.start()
            self.idl = OvsdbNbOvnIdl.ovsdb_connection.idl
            self.ovsdb_timeout = cfg.get_ovn_ovsdb_timeout()
        except Exception as e:
            connection_exception = OvsdbConnectionUnavailable(
                db_schema='OVN_Northbound', error=e)
            LOG.exception(connection_exception)
            raise connection_exception

    @property
    def _tables(self):
        return self.idl.tables

    def transaction(self, check_error=False, log_errors=True, **kwargs):
        return impl_idl.Transaction(self,
                                    OvsdbNbOvnIdl.ovsdb_connection,
                                    self.ovsdb_timeout,
                                    check_error, log_errors)

    def create_lswitch(self, lswitch_name, may_exist=True, **columns):
        return cmd.AddLSwitchCommand(self, lswitch_name,
                                     may_exist, **columns)

    def delete_lswitch(self, lswitch_name=None, ext_id=None, if_exists=True):
        if lswitch_name is not None:
            return cmd.DelLSwitchCommand(self, lswitch_name, if_exists)
        else:
            raise RuntimeError(_("Currently only supports delete "
                                 "by lswitch-name"))

    def set_lswitch_ext_id(self, lswitch_id, ext_id, if_exists=True):
        return cmd.LSwitchSetExternalIdCommand(self, lswitch_id,
                                               ext_id[0], ext_id[1],
                                               if_exists)

    def create_lswitch_port(self, lport_name, lswitch_name, may_exist=True,
                            **columns):
        return cmd.AddLSwitchPortCommand(self, lport_name, lswitch_name,
                                         may_exist, **columns)

    def set_lswitch_port(self, lport_name, if_exists=True, **columns):
        return cmd.SetLSwitchPortCommand(self, lport_name,
                                         if_exists, **columns)

    def delete_lswitch_port(self, lport_name=None, lswitch_name=None,
                            ext_id=None, if_exists=True):
        if lport_name is not None:
            return cmd.DelLSwitchPortCommand(self, lport_name,
                                             lswitch_name, if_exists)
        else:
            raise RuntimeError(_("Currently only supports "
                                 "delete by lport-name"))

    def get_all_logical_switches_with_ports(self):
        result = []
        for lswitch in self._tables['Logical_Switch'].rows.values():
            if ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY not in (
                    lswitch.external_ids):
                continue
            ports = []
            for lport in getattr(lswitch, 'ports', []):
                if ovn_const.OVN_PORT_NAME_EXT_ID_KEY in lport.external_ids:
                    ports.append(lport.name)
            result.append({'name': lswitch.name,
                           'ports': ports})
        return result

    def get_all_logical_routers_with_rports(self):
        """Get logical Router ports associated with all logical Routers

        @return: list of dict, each dict has key-value:
                 - 'name': string router_id in neutron.
                 - 'static_routes': list of static routes dict.
                 - 'ports': dict of port_id in neutron (key) and networks on
                            port (value).
        """
        result = []
        for lrouter in self._tables['Logical_Router'].rows.values():
            if ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY not in (
                    lrouter.external_ids):
                continue
            lrports = {lrport.name.replace('lrp-', ''): lrport.networks
                       for lrport in getattr(lrouter, 'ports', [])}
            sroutes = [{'destination': sroute.ip_prefix,
                        'nexthop': sroute.nexthop}
                       for sroute in getattr(lrouter, 'static_routes', [])]
            result.append({'name': lrouter.name.replace('neutron-', ''),
                           'static_routes': sroutes,
                           'ports': lrports})
        return result

    def get_acls_for_lswitches(self, lswitch_names):
        """Get the existing set of acls that belong to the logical switches

        @param lswitch_names: List of logical switch names
        @type lswitch_names: []
        @var acl_values_dict: A dictionary indexed by port_id containing the
                              list of acl values in string format that belong
                              to that port
        @var acl_obj_dict: A dictionary indexed by acl value containing the
                           corresponding acl idl object.
        @var lswitch_ovsdb_dict: A dictionary mapping from logical switch
                                 name to lswitch idl object
        @return: (acl_values_dict, acl_obj_dict, lswitch_ovsdb_dict)
        """
        acl_values_dict = {}
        acl_obj_dict = {}
        lswitch_ovsdb_dict = {}
        for lswitch_name in lswitch_names:
            try:
                lswitch = idlutils.row_by_value(self.idl,
                                                'Logical_Switch',
                                                'name',
                                                utils.ovn_name(lswitch_name))
            except idlutils.RowNotFound:
                # It is possible for the logical switch to be deleted
                # while we are searching for it by name in idl.
                continue
            lswitch_ovsdb_dict[lswitch_name] = lswitch
            acls = getattr(lswitch, 'acls', [])

            # Iterate over each acl in a lswitch and store the acl in
            # a key:value representation for e.g. acl_string. This
            # key:value representation can invoke the code -
            # self._ovn.add_acl(**acl_string)
            for acl in acls:
                ext_ids = getattr(acl, 'external_ids', {})
                port_id = ext_ids.get('neutron:lport')
                acl_list = acl_values_dict.setdefault(port_id, [])
                acl_string = {'lport': port_id,
                              'lswitch': utils.ovn_name(lswitch_name)}
                for acl_key in getattr(acl, "_data", {}):
                    try:
                        acl_string[acl_key] = getattr(acl, acl_key)
                    except AttributeError:
                        pass
                acl_obj_dict[str(acl_string)] = acl
                acl_list.append(acl_string)
        return acl_values_dict, acl_obj_dict, lswitch_ovsdb_dict

    def create_lrouter(self, name, may_exist=True, **columns):
        return cmd.AddLRouterCommand(self, name,
                                     may_exist, **columns)

    def update_lrouter(self, name, if_exists=True, **columns):
        return cmd.UpdateLRouterCommand(self, name,
                                        if_exists, **columns)

    def delete_lrouter(self, name, if_exists=True):
        return cmd.DelLRouterCommand(self, name, if_exists)

    def add_lrouter_port(self, name, lrouter, **columns):
        return cmd.AddLRouterPortCommand(self, name, lrouter, **columns)

    def update_lrouter_port(self, name, lrouter, if_exists=True, **columns):
        return cmd.UpdateLRouterPortCommand(self, name, lrouter,
                                            if_exists, **columns)

    def delete_lrouter_port(self, name, lrouter, if_exists=True):
        return cmd.DelLRouterPortCommand(self, name, lrouter,
                                         if_exists)

    def set_lrouter_port_in_lswitch_port(self, lswitch_port, lrouter_port):
        return cmd.SetLRouterPortInLSwitchPortCommand(self, lswitch_port,
                                                      lrouter_port)

    def add_acl(self, lswitch, lport, **columns):
        return cmd.AddACLCommand(self, lswitch, lport, **columns)

    def delete_acl(self, lswitch, lport, if_exists=True):
        return cmd.DelACLCommand(self, lswitch, lport, if_exists)

    def update_acls(self, lswitch_names, port_list, acl_new_values_dict,
                    need_compare=True, is_add_acl=True):
        return cmd.UpdateACLsCommand(self, lswitch_names,
                                     port_list, acl_new_values_dict,
                                     need_compare=need_compare,
                                     is_add_acl=is_add_acl)

    def add_static_route(self, lrouter, **columns):
        return cmd.AddStaticRouteCommand(self, lrouter, **columns)

    def delete_static_route(self, lrouter, ip_prefix, nexthop, if_exists=True):
        return cmd.DelStaticRouteCommand(self, lrouter, ip_prefix, nexthop,
                                         if_exists)

    def create_address_set(self, name, may_exist=True, **columns):
        return cmd.AddAddrSetCommand(self, name, may_exist, **columns)

    def delete_address_set(self, name, if_exists=True, **columns):
        return cmd.DelAddrSetCommand(self, name, if_exists)

    def update_address_set(self, name, addrs_add, addrs_remove,
                           if_exists=True):
        return cmd.UpdateAddrSetCommand(self, name, addrs_add, addrs_remove,
                                        if_exists)

    def update_address_set_ext_ids(self, name, external_ids, if_exists=True):
        return cmd.UpdateAddrSetExtIdsCommand(self, name, external_ids,
                                              if_exists)

    def get_all_chassis_router_bindings(self, chassis_candidate_list=None):
        chassis_bindings = {}
        for chassis_name in chassis_candidate_list or []:
            chassis_bindings.setdefault(chassis_name, [])
        for lrouter in self._tables['Logical_Router'].rows.values():
            if ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY not in (
                    lrouter.external_ids):
                continue
            chassis_name = lrouter.options.get('chassis')
            if not chassis_name:
                continue
            if (not chassis_candidate_list or
                    chassis_name in chassis_candidate_list):
                routers_hosted = chassis_bindings.setdefault(chassis_name, [])
                routers_hosted.append(lrouter.name)
        return chassis_bindings

    def get_router_chassis_binding(self, router_name):
        try:
            router = idlutils.row_by_value(self.idl,
                                           'Logical_Router',
                                           'name',
                                           router_name)
            chassis_name = router.options.get('chassis')
            if chassis_name == ovn_const.OVN_GATEWAY_INVALID_CHASSIS:
                return None
            else:
                return chassis_name
        except idlutils.RowNotFound:
            return None

    def get_unhosted_routers(self, valid_chassis_list):
        unhosted_routers = {}
        for lrouter in self._tables['Logical_Router'].rows.values():
            if ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY not in (
                    lrouter.external_ids):
                continue
            chassis_name = lrouter.options.get('chassis')
            if not chassis_name:
                # Not a gateway router
                continue
            # TODO(azbiswas): Handle the case when a chassis is no
            # longer valid. This may involve moving conntrack states,
            # so it needs to discussed in the OVN community first.
            if (chassis_name == ovn_const.OVN_GATEWAY_INVALID_CHASSIS or
                    chassis_name not in valid_chassis_list):
                unhosted_routers[lrouter.name] = lrouter.options
        return unhosted_routers

    def add_dhcp_options(self, subnet_id, port_id=None, may_exists=True,
                         **columns):
        return cmd.AddDHCPOptionsCommand(self, subnet_id, port_id=port_id,
                                         may_exists=may_exists, **columns)

    def delete_dhcp_options(self, row_uuid, if_exists=True):
        return cmd.DelDHCPOptionsCommand(self, row_uuid, if_exists=if_exists)

    def get_subnet_dhcp_options(self, subnet_id):
        for row in self._tables['DHCP_Options'].rows.values():
            external_ids = getattr(row, 'external_ids', {})
            port_id = external_ids.get('port_id')
            if subnet_id == external_ids.get('subnet_id') and not port_id:
                return {'cidr': row.cidr, 'options': dict(row.options),
                        'external_ids': dict(external_ids),
                        'uuid': row.uuid}
        return None

    def get_subnets_dhcp_options(self, subnet_ids):
        ret_opts = []
        for row in self._tables['DHCP_Options'].rows.values():
            external_ids = getattr(row, 'external_ids', {})
            if (external_ids.get('subnet_id') in subnet_ids
                    and not external_ids.get('port_id')):
                ret_opts.append({
                    'cidr': row.cidr, 'options': dict(row.options),
                    'external_ids': dict(external_ids),
                    'uuid': row.uuid})
                if len(ret_opts) == len(subnet_ids):
                    break
        return ret_opts

    def get_all_dhcp_options(self):
        dhcp_options = {'subnets': {}, 'ports_v4': {}, 'ports_v6': {}}

        for row in self._tables['DHCP_Options'].rows.values():
            external_ids = getattr(row, 'external_ids', {})
            if not external_ids.get('subnet_id'):
                # This row is not created by OVN ML2 driver. Ignore it.
                continue

            if not external_ids.get('port_id'):
                dhcp_options['subnets'][external_ids['subnet_id']] = {
                    'cidr': row.cidr, 'options': dict(row.options),
                    'external_ids': dict(external_ids),
                    'uuid': row.uuid}
            else:
                port_dict = 'ports_v6' if ':' in row.cidr else 'ports_v4'
                dhcp_options[port_dict][external_ids['port_id']] = {
                    'cidr': row.cidr, 'options': dict(row.options),
                    'external_ids': dict(external_ids),
                    'uuid': row.uuid}

        return dhcp_options

    def compose_dhcp_options_commands(self, subnet_id, **columns):
        # First add the subnet DHCP options.
        commands = [self.add_dhcp_options(subnet_id, **columns)]

        # Check if there are any port DHCP options which
        # belongs to this 'subnet_id' and frame the commands to update them.
        port_dhcp_options = []
        for row in self._tables['DHCP_Options'].rows.values():
            external_ids = getattr(row, 'external_ids', {})
            port_id = external_ids.get('port_id')
            if subnet_id == external_ids.get('subnet_id'):
                if port_id:
                    port_dhcp_options.append({'port_id': port_id,
                                             'port_dhcp_opts': row.options})

        for port_dhcp_opt in port_dhcp_options:
            if columns.get('options'):
                updated_opts = dict(columns['options'])
                updated_opts.update(port_dhcp_opt['port_dhcp_opts'])
            else:
                updated_opts = {}
            commands.append(
                self.add_dhcp_options(subnet_id,
                                      port_id=port_dhcp_opt['port_id'],
                                      options=updated_opts))

        return commands

    def get_address_sets(self):
        address_sets = {}
        for row in self._tables['Address_Set'].rows.values():
            if ovn_const.OVN_SG_NAME_EXT_ID_KEY not in (row.external_ids):
                continue
            name = getattr(row, 'name')
            data = {}
            for row_key in getattr(row, "_data", {}):
                data[row_key] = getattr(row, row_key)
            address_sets[name] = data
        return address_sets

    def get_router_port_options(self, lsp_name):
        try:
            lsp = idlutils.row_by_value(self.idl, 'Logical_Switch_Port',
                                        'name', lsp_name)
            options = getattr(lsp, 'options')
            for key in options.keys():
                if key not in ovn_const.OVN_ROUTER_PORT_OPTION_KEYS:
                    del(options[key])
            return options
        except idlutils.RowNotFound:
            return {}

    def add_nat_rule_in_lrouter(self, lrouter, **columns):
        return cmd.AddNATRuleInLRouterCommand(self, lrouter, **columns)

    def delete_nat_rule_in_lrouter(self, lrouter, type, logical_ip,
                                   external_ip, if_exists=True):
        return cmd.DeleteNATRuleInLRouterCommand(self, lrouter, type,
                                                 logical_ip, external_ip,
                                                 if_exists)

    def get_lrouter_nat_rules(self, lrouter_name):
        try:
            lrouter = idlutils.row_by_value(self.idl, 'Logical_Router',
                                            'name', lrouter_name)
        except idlutils.RowNotFound:
            msg = _("Logical Router %s does not exist") % lrouter_name
            raise RuntimeError(msg)

        nat_rules = []
        for nat_rule in getattr(lrouter, 'nat', []):
            nat_rules.append({'external_ip': nat_rule.external_ip,
                              'logical_ip': nat_rule.logical_ip,
                              'type': nat_rule.type,
                              'uuid': nat_rule.uuid})
        return nat_rules

    def set_nat_rule_in_lrouter(self, lrouter, nat_rule_uuid, **columns):
        return cmd.SetNATRuleInLRouterCommand(self, lrouter, nat_rule_uuid,
                                              **columns)

    def add_nat_ip_to_lrport_peer_options(self, lport, nat_ip):
        return cmd.AddNatIpToLRPortPeerOptionsCommand(self, lport, nat_ip)

    def delete_nat_ip_from_lrport_peer_options(self, lport, nat_ip):
        return cmd.DeleteNatIpFromLRPortPeerOptionsCommand(self, lport, nat_ip)

    # Check for a column match in the table. If not found do a retry with
    # a stop delay of 10 secs. This function would be useful if the caller
    # wants to verify for the presence of a particular row in the table
    # with the column match before doing any transaction.
    # Eg. We can check if Logical_Switch row is present before adding a
    # logical switch port to it.
    @tenacity.retry(retry=tenacity.retry_if_exception_type(RuntimeError),
                    wait=tenacity.wait_exponential(),
                    stop=tenacity.stop_after_delay(10),
                    reraise=True)
    def check_for_row_by_value_and_retry(self, table, column, match):
        try:
            idlutils.row_by_value(self.idl, table, column, match)
        except idlutils.RowNotFound:
            msg = (_("%(match)s does not exist in %(column)s of %(table)s")
                   % {'match': match, 'column': column, 'table': table})
            raise RuntimeError(msg)


class OvsdbSbOvnIdl(ovn_api.SbAPI):

    ovsdb_connection = None

    def __init__(self, driver, trigger=None):
        super(OvsdbSbOvnIdl, self).__init__()
        try:
            if OvsdbSbOvnIdl.ovsdb_connection is None:
                OvsdbSbOvnIdl.ovsdb_connection = get_connection(OvsdbSbOvnIdl,
                                                                trigger)
            if isinstance(OvsdbSbOvnIdl.ovsdb_connection,
                          ovsdb_monitor.OvnConnection):
                # We only need to know the content of Chassis in OVN_Southbound
                OvsdbSbOvnIdl.ovsdb_connection.start(
                    driver, table_name_list=['Chassis'])
            else:
                OvsdbSbOvnIdl.ovsdb_connection.start(
                    table_name_list=['Chassis'])
            self.idl = OvsdbSbOvnIdl.ovsdb_connection.idl
            self.ovsdb_timeout = cfg.get_ovn_ovsdb_timeout()
        except Exception as e:
            connection_exception = OvsdbConnectionUnavailable(
                db_schema='OVN_Southbound', error=e)
            LOG.exception(connection_exception)
            raise connection_exception

    def _get_chassis_physnets(self, chassis):
        bridge_mappings = chassis.external_ids.get('ovn-bridge-mappings', '')
        mapping_dict = helpers.parse_mappings(bridge_mappings.split(','))
        return mapping_dict.keys()

    def chassis_exists(self, hostname):
        try:
            idlutils.row_by_value(self.idl, 'Chassis', 'hostname', hostname)
        except idlutils.RowNotFound:
            return False
        return True

    def get_chassis_hostname_and_physnets(self):
        chassis_info_dict = {}
        for ch in self.idl.tables['Chassis'].rows.values():
            chassis_info_dict[ch.hostname] = self._get_chassis_physnets(ch)
        return chassis_info_dict

    def get_all_chassis(self, chassis_type=None):
        # TODO(azbiswas): Use chassis_type as input once the compute type
        # preference patch (as part of external ids) merges.
        chassis_list = []
        for ch in self.idl.tables['Chassis'].rows.values():
            chassis_list.append(ch.name)
        return chassis_list

    def get_chassis_data_for_ml2_bind_port(self, hostname):
        try:
            chassis = idlutils.row_by_value(self.idl, 'Chassis',
                                            'hostname', hostname)
        except idlutils.RowNotFound:
            msg = _('Chassis with hostname %s does not exist') % hostname
            raise RuntimeError(msg)
        return (chassis.external_ids.get('datapath-type', ''),
                chassis.external_ids.get('iface-types', ''),
                self._get_chassis_physnets(chassis))

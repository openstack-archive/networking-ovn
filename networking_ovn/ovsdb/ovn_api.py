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

import abc

from ovsdbapp import api
import six


@six.add_metaclass(abc.ABCMeta)
class API(api.API):

    @abc.abstractmethod
    def create_lswitch(self, name, may_exist=True, **columns):
        """Create a command to add an OVN lswitch

        :param name:         The id of the lswitch
        :type name:          string
        :param may_exist:    Do not fail if lswitch already exists
        :type may_exist:     bool
        :param columns:      Dictionary of lswitch columns
                             Supported columns: external_ids
        :type columns:       dictionary
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def set_lswitch_ext_id(self, name, ext_id, if_exists=True):
        """Create a command to set OVN lswitch external id

        :param name:      The name of the lswitch
        :type name:       string
        :param ext_id:    The external id to set for the lswitch
        :type ext_id:     pair of <ext_id_key ,ext_id_value>
        :param if_exists: Do not fail if lswitch does not exist
        :type if_exists:  bool
        :returns:        :class:`Command` with no result
        """

    @abc.abstractmethod
    def delete_lswitch(self, name=None, ext_id=None, if_exists=True):
        """Create a command to delete an OVN lswitch

        :param name:      The name of the lswitch
        :type name:       string
        :param ext_id:    The external id of the lswitch
        :type ext_id:     pair of <ext_id_key ,ext_id_value>
        :param if_exists: Do not fail if the lswitch does not exist
        :type if_exists:  bool
        :returns:         :class:`Command` with no result
        """

    @abc.abstractmethod
    def create_lswitch_port(self, lport_name, lswitch_name, may_exist=True,
                            **columns):
        """Create a command to add an OVN logical switch port

        :param lport_name:    The name of the lport
        :type lport_name:     string
        :param lswitch_name:  The name of the lswitch the lport is created on
        :type lswitch_name:   string
        :param may_exist:     Do not fail if lport already exists
        :type may_exist:      bool
        :param columns:       Dictionary of port columns
                              Supported columns: macs, external_ids,
                                                 parent_name, tag, enabled
        :type columns:        dictionary
        :returns:             :class:`Command` with no result
        """

    @abc.abstractmethod
    def set_lswitch_port(self, lport_name, if_exists=True, **columns):
        """Create a command to set OVN logical switch port fields

        :param lport_name:    The name of the lport
        :type lport_name:     string
        :param columns:       Dictionary of port columns
                              Supported columns: macs, external_ids,
                                                 parent_name, tag, enabled
        :param if_exists:     Do not fail if lport does not exist
        :type if_exists:      bool
        :type columns:        dictionary
        :returns:             :class:`Command` with no result
        """

    @abc.abstractmethod
    def delete_lswitch_port(self, lport_name=None, lswitch_name=None,
                            ext_id=None, if_exists=True):
        """Create a command to delete an OVN logical switch port

        :param lport_name:    The name of the lport
        :type lport_name:     string
        :param lswitch_name:  The name of the lswitch
        :type lswitch_name:   string
        :param ext_id:        The external id of the lport
        :type ext_id:         pair of <ext_id_key ,ext_id_value>
        :param if_exists:     Do not fail if the lport does not exist
        :type if_exists:      bool
        :returns:             :class:`Command` with no result
        """

    @abc.abstractmethod
    def create_lrouter(self, name, may_exist=True, **columns):
        """Create a command to add an OVN lrouter

        :param name:         The id of the lrouter
        :type name:          string
        :param may_exist:    Do not fail if lrouter already exists
        :type may_exist:     bool
        :param columns:      Dictionary of lrouter columns
                             Supported columns: external_ids, default_gw, ip
        :type columns:       dictionary
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def update_lrouter(self, name, if_exists=True, **columns):
        """Update a command to add an OVN lrouter

        :param name:         The id of the lrouter
        :type name:          string
        :param if_exists:    Do not fail if the lrouter does not exist
        :type if_exists:     bool
        :param columns:      Dictionary of lrouter columns
                             Supported columns: external_ids, default_gw, ip
        :type columns:       dictionary
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def delete_lrouter(self, name, if_exists=True):
        """Create a command to delete an OVN lrouter

        :param name:         The id of the lrouter
        :type name:          string
        :param if_exists:    Do not fail if the lrouter does not exist
        :type if_exists:     bool
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def add_lrouter_port(self, name, lrouter, if_exists=True,
                         **columns):
        """Create a command to add an OVN lrouter port

        :param name:         The unique name of the lrouter port
        :type name:          string
        :param lrouter:      The unique name of the lrouter
        :type lrouter:       string
        :param lswitch:      The unique name of the lswitch
        :type lswitch:       string
        :param if_exists:    Do not fail if lrouter port already exists
        :type if_exists:     bool
        :param columns:      Dictionary of lrouter columns
                             Supported columns: external_ids, mac, network
        :type columns:       dictionary
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def update_lrouter_port(self, name, if_exists=True, **columns):
        """Update a command to add an OVN lrouter port

        :param name:         The unique name of the lrouter port
        :type name:          string
        :param if_exists:    Do not fail if the lrouter port does not exist
        :type if_exists:     bool
        :param columns:      Dictionary of lrouter columns
                             Supported columns: networks
        :type columns:       dictionary
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def delete_lrouter_port(self, name, lrouter, if_exists=True):
        """Create a command to delete an OVN lrouter port

        :param name:         The unique name of the lport
        :type name:          string
        :param lrouter:      The unique name of the lrouter
        :type lrouter:       string
        :param if_exists:    Do not fail if the lrouter port does not exist
        :type if_exists:     bool
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def set_lrouter_port_in_lswitch_port(self, lswitch_port, lrouter_port,
                                         is_gw_port=False, if_exists=True):
        """Create a command to set lswitch_port as lrouter_port

        :param lswitch_port: The name of logical switch port
        :type lswitch_port:  string
        :param lrouter_port: The name of logical router port
        :type lrouter_port:  string
        :param is_gw_port:   True if logical router port is gw port
        :type is_gw_port:    bool
        :param if_exists:    Do not fail if the lswitch port does not exist
        :type if_exists:     bool
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def add_acl(self, lswitch, lport, **columns):
        """Create an ACL for a logical port.

        :param lswitch:      The logical switch the port is attached to.
        :type lswitch:       string
        :param lport:        The logical port this ACL is associated with.
        :type lport:         string
        :param columns:      Dictionary of ACL columns
                             Supported columns: see ACL table in OVN_Northbound
        :type columns:       dictionary
        """

    @abc.abstractmethod
    def delete_acl(self, lswitch, lport, if_exists=True):
        """Delete all ACLs for a logical port.

        :param lswitch:      The logical switch the port is attached to.
        :type lswitch:       string
        :param lport:        The logical port this ACL is associated with.
        :type lport:         string
        :param if_exists:    Do not fail if the ACL for this lport does not
                             exist
        :type if_exists:     bool
        """

    @abc.abstractmethod
    def update_acls(self, lswitch_names, port_list, acl_new_values_dict,
                    need_compare=True, is_add_acl=True):
        """Update the list of acls on logical switches with new values.

        :param lswitch_names:         List of logical switch names
        :type lswitch_name:           []
        :param port_list:             Iterator of list of ports
        :type port_list:              []
        :param acl_new_values_dict:   Dictionary of acls indexed by port id
        :type acl_new_values_dict:    {}
        :param need_compare:          If acl_new_values_dict need compare
                                      with existing acls
        :type need_compare:           bool
        :is_add_acl:                  If updating is caused by adding acl
        :type is_add_acl:             bool
        """

    @abc.abstractmethod
    def add_static_route(self, lrouter, **columns):
        """Add static route to logical router.

        :param lrouter:      The unique name of the lrouter
        :type lrouter:       string
        :param columns:      Dictionary of static columns
                             Supported columns: prefix, nexthop, valid
        :type columns:       dictionary
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def delete_static_route(self, lrouter, ip_prefix, nexthop, if_exists=True):
        """Delete static route from logical router.

        :param lrouter:      The unique name of the lrouter
        :type lrouter:       string
        :param ip_prefix:    The prefix of the static route
        :type ip_prefix:     string
        :param nexthop:      The nexthop of the static route
        :type nexthop:       string
        :param if_exists:    Do not fail if router does not exist
        :type if_exists:     bool
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def create_address_set(self, name, may_exist=True, **columns):
        """Create an address set

        :param name:        The name of the address set
        :type name:         string
        :param may_exist:   Do not fail if address set already exists
        :type may_exist:    bool
        :param columns:     Dictionary of address set columns
                            Supported columns: external_ids, addresses
        :type columns:      dictionary
        :returns:           :class:`Command` with no result
        """

    @abc.abstractmethod
    def delete_address_set(self, name, if_exists=True):
        """Delete an address set

        :param name:        The name of the address set
        :type name:         string
        :param if_exists:   Do not fail if the address set does not exist
        :type if_exists:    bool
        :returns:           :class:`Command` with no result
        """

    @abc.abstractmethod
    def update_address_set(self, name, addrs_add, addrs_remove,
                           if_exists=True):
        """Updates addresses in an address set

        :param name:            The name of the address set
        :type name:             string
        :param addrs_add:       The addresses to be added
        :type addrs_add:        []
        :param addrs_remove:    The addresses to be removed
        :type addrs_remove:     []
        :param if_exists:       Do not fail if the address set does not exist
        :type if_exists:        bool
        :returns:               :class:`Command` with no result
        """

    @abc.abstractmethod
    def update_address_set_ext_ids(self, name, external_ids, if_exists=True):
        """Update external IDs for an address set

        :param name:          The name of the address set
        :type name:           string
        :param external_ids:  The external IDs for the address set
        :type external_ids:   dict
        :param if_exists:     Do not fail if the address set does not exist
        :type if_exists:      bool
        :returns:             :class:`Command` with no result
        """

    @abc.abstractmethod
    def get_all_chassis_gateway_bindings(self,
                                         chassis_candidate_list=None):
        """Return a dictionary of chassis name:list of gateways

        :param chassis_candidate_list:  List of possible chassis candidates
        :type chassis_candidate_list:   []
        :returns:                       {} of chassis to routers mapping
        """

    @abc.abstractmethod
    def get_gateway_chassis_binding(self, gateway_id):
        """Return the chassis to which the gateway is bound to

        :param gateway_id:     The gateway id
        :type gateway_id:      string
        :returns:              string containing the chassis name
        """

    @abc.abstractmethod
    def get_unhosted_gateways(self, port_physnet_dict, chassis_physnets):
        """Return a list of gateways not hosted on chassis

        :param port_physnet_dict: Dictionary of gateway ports and their physnet
        :param chassis_physnets:  Dictionary of chassis and physnets
        :returns:                 List of gateways not hosted on a valid
                                  chassis
        """

    @abc.abstractmethod
    def add_dhcp_options(self, subnet_id, port_id=None, may_exists=True,
                         **columns):
        """Adds the DHCP options specified in the @columns in DHCP_Options

        If the DHCP options already exist in the DHC_Options table for
        the @subnet_id (and @lsp_name), updates the row, else creates a new
        row.

        :param subnet_id:      The subnet id to which the DHCP options belong
                               to
        :type subnet_id:       string
        :param port_id:        The port id to which the DHCP options belong to
                               if specified
        :type port_id:         string
        :param may_exists:     If true, checks if the DHCP options for
                               subnet_id exists or not. If it already exists,
                               it updates the row with the columns specified.
                               Else creates a new row.
        :type may_exists:      bool
        :type columns:         Dictionary of DHCP_Options columns
                               Supported columns: see DHCP_Options table in
                               OVN_Northbound
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def delete_dhcp_options(self, row_uuid, if_exists=True):
        """Deletes the row in DHCP_Options with the @row_uuid

        :param row_uuid:       The UUID of the row to be deleted.
        :type row_uuid:        string
        :param if_exists:      Do not fail if the DHCP_Options row does not
                               exist
        :type if_exists:       bool
        """

    @abc.abstractmethod
    def get_subnet_dhcp_options(self, subnet_id):
        """Returns the Subnet DHCP options as a dictionary

        :param subnet_id:      The subnet id whose DHCP options are returned
        :type subnet_id:       string
        :returns:              Returns the columns of the DHCP_Options as a
                               dictionary. None is returned if no DHCP options.
        """

    @abc.abstractmethod
    def get_subnets_dhcp_options(self, subnet_ids):
        """Returns the Subnets DHCP options as list of dictionary

        :param subnet_ids:     The subnet ids whose DHCP options are returned
        :type subnet_ids:      list of string
        :returns:              Returns the columns of the DHCP_Options as list
                               of dictionary. Empty list is returned if no
                               DHCP_Options matched found.
        """

    @abc.abstractmethod
    def compose_dhcp_options_commands(self, subnet_id, **columns):
        """Returns a list of 'Command' objects to add the DHCP options in NB DB

        Checks if there are DHCP_Options rows for the logical switch ports
        belonging to the @subnet_id and if found adds into the `Command` list.

        @param subnet_id:     The subnet id to which DHCP Options are to be
                              added
        @type subnet_id:      string
        @type columns:        Dictionary of DHCP_Options columns
        @returns:             List of 'Command' objects returned by
                              'add_dhcp_options'
        """

    @abc.abstractmethod
    def get_address_sets(self):
        """Gets all address sets in the OVN_Northbound DB

        :returns: dictionary indexed by name, DB columns as values
        """

    @abc.abstractmethod
    def get_router_port_options(self, lsp_name):
        """Get options set for lsp of type router

        :returns: router port options
        """

    @abc.abstractmethod
    def add_nat_rule_in_lrouter(self, lrouter, **columns):
        """Add NAT rule in logical router


        :param lrouter:      The unique name of the lrouter
        :type lrouter:       string
        :param columns:      Dictionary of nat columns
                             Supported columns: type, logical_ip, external_ip
        :type columns:       dictionary
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def delete_nat_rule_in_lrouter(self, lrouter, type, logical_ip,
                                   external_ip, if_exists=True):
        """Delete NAT rule in logical router

        :param lrouter:      The unique name of the lrouter
        :type lrouter:       string
        :param type:         Type of nat. Supported values are 'snat', 'dnat'
                             and 'dnat_and_snat'
        :type type:          string
        :param logical_ip:   IP or network that needs to be natted
        :type logical_ip:    string
        :param external_ip:  External IP to be used for nat
        :type external_ip:   string
        :param if_exists:    Do not fail if the Logical_Router row does not
                             exist
        :type if_exists:     bool
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def add_nat_ip_to_lrport_peer_options(self, lport, nat_ip):
        """Add nat address in peer port of lrouter port

        :param lport:   The unique name of the lswitch port
        :type lport:    string
        :param nat_ip:  nat ip to be added
        :type nat_ip:   string
        :returns:       :class:`Command` with no result
        """

    @abc.abstractmethod
    def delete_nat_ip_from_lrport_peer_options(self, lport, nat_ip):
        """Delete nat address from peer port of lrouter port

        :param lport:   The unique name of the lswitch port
        :type lport:    string
        :param nat_ip:  nat ip to be removed
        :type nat_ip:   string
        :returns:       :class:`Command` with no result
        """

    @abc.abstractmethod
    def get_lrouter_nat_rules(self, lrouter):
        """Returns the nat rules of a router

        :param lrouter: The unique name of the router
        :type lrouter:  string
        :returns:       A list of nat rules of the router, with each item
                        as a dict with the keys - 'external_ip', 'logical_ip'
                        'type' and 'uuid' of the row.
        """

    @abc.abstractmethod
    def set_nat_rule_in_lrouter(self, lrouter, nat_rule_uuid, **columns):
        """Sets the NAT rule fields

        :param lrouter: The unique name of the router to which this the
                        NAT rule belongs to.
        :type lrouter:  string
        :param nat_rule_uuid:  The uuid of the NAT rule row to be updated.
        :type nat_rule_uuid:   string
        :type columns:       dictionary
        :returns:            :class:`Command` with no result
        """


@six.add_metaclass(abc.ABCMeta)
class SbAPI(api.API):

    @abc.abstractmethod
    def chassis_exists(self, hostname):
        """Test if chassis for given hostname exists.

        @param hostname:       The hostname of the chassis
        @type hostname:        string
        :returns:              True if the chassis exists, else False.
        """

    @abc.abstractmethod
    def get_chassis_hostname_and_physnets(self):
        """Return a dict contains hostname and physnets mapping.

        Hostname will be dict key, and a list of physnets will be dict
        value. And hostname and physnets are related to the same host.
        """

    @abc.abstractmethod
    def get_chassis_and_physnets(self):
        """Return a dict contains chassis name and physnets mapping.

        Chassis name will be dict key, and a list of physnets will be dict
        value. And chassis name and physnets are related to the same chassis.
        """

    @abc.abstractmethod
    def get_all_chassis(self, chassis_type=None):
        """Return a list of all chassis which match the compute_type

        :param chassis_type:    The type of chassis
        :type chassis_type:     string
        """

    @abc.abstractmethod
    def get_chassis_data_for_ml2_bind_port(self, hostname):
        """Return chassis data for ML2 port binding.

        @param hostname:       The hostname of the chassis
        @type hostname:        string
        :returns:              Tuple containing the chassis datapath type,
                               iface types and physical networks for the
                               OVN bridge mappings.
        :raises:               RuntimeError exception if an OVN chassis
                               does not exist.
        """

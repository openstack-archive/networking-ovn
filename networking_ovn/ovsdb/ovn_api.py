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
import six


@six.add_metaclass(abc.ABCMeta)
class API(object):

    @abc.abstractmethod
    def transaction(self, check_error=False, log_errors=True, **kwargs):
        """Create a transaction

        :param check_error: Allow the transaction to raise an exception?
        :type check_error:  bool
        :param log_errors:  Log an error if the transaction fails?
        :type log_errors:   bool
        :returns: A new transaction
        :rtype: :class:`Transaction`
        """

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
        :param if_exists: Do not fail if the lswitch does not exists
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
        :param if_exists:     Do not fail if the lport does not exists
        :type if_exists:      bool
        :returns:             :class:`Command` with no result
        """

    @abc.abstractmethod
    def get_all_logical_switches_ids(self):
        """Returns all logical switches names and external ids

        :returns: dictionary with lswitch name and ext ids
        """

    @abc.abstractmethod
    def get_logical_switch_ids(self, lswitch_name):
        """Get external_ids for a Logical_Switch.

        :returns: dict of external_ids.
        """

    @abc.abstractmethod
    def get_all_logical_switch_ports_ids(self):
        """Returns all logical switch ports names and external ids

        :returns: dictionary with lsp name and ext ids
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
        :param if_exists:    Do not fail if the lrouter  does not exists
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
        :param if_exists:    Do not fail if the lrouter  does not exists
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
    def delete_lrouter_port(self, name, lrouter, if_exists=True):
        """Create a command to delete an OVN lrouter port

        :param name:         The unique name of the lport
        :type name:          string
        :param lrouter:      The unique name of the lrouter
        :type lrouter:       string
        :param if_exists:    Do not fail if the lrouter port does not exists
        :type if_exists:     bool
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def set_lrouter_port_in_lswitch_port(self, lswitch_port, lrouter_port):
        """Create a command to set lswitch_port as lrouter_port

        :param lswitch_port: The name of logical switch port
        :type lswitch_port:  string
        :param lrouter_port: The name of logical router port
        :type lrouter_port:  string
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


@six.add_metaclass(abc.ABCMeta)
class SbAPI(object):
    @abc.abstractmethod
    def get_chassis_hostname_and_physnets(self):
        """Return a dict contains hostname and physnets mapping.

        Hostname will be dict key, and a list of physnets will be dict
        value. And hostname and physnets are related to the same host.
        """

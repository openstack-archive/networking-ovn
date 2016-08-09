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
#

import copy
import mock
import six
import uuid


class FakeOvsdbNbOvnIdl(object):

    def __init__(self, **kwargs):
        def _fake(*args, **kwargs):
            return mock.MagicMock()
        self.lswitch_table = FakeOvsdbTable.create_one_ovsdb_table()
        self.lsp_table = FakeOvsdbTable.create_one_ovsdb_table()
        self.lrouter_table = FakeOvsdbTable.create_one_ovsdb_table()
        self.lrouter_static_route_table = \
            FakeOvsdbTable.create_one_ovsdb_table()
        self.lrp_table = FakeOvsdbTable.create_one_ovsdb_table()
        self.addrset_table = FakeOvsdbTable.create_one_ovsdb_table()
        self.acl_table = FakeOvsdbTable.create_one_ovsdb_table()
        self.dhcp_options_table = FakeOvsdbTable.create_one_ovsdb_table()
        self._tables = {}
        self._tables['Logical_Switch'] = self.lswitch_table
        self._tables['Logical_Switch_Port'] = self.lsp_table
        self._tables['Logical_Router'] = self.lrouter_table
        self._tables['Logical_Router_Port'] = self.lrp_table
        self._tables['Logical_Router_Static_Route'] = \
            self.lrouter_static_route_table
        self._tables['ACL'] = self.acl_table
        self._tables['Address_Set'] = self.addrset_table
        self._tables['DHCP_Options'] = self.dhcp_options_table
        self.transaction = _fake
        self.create_lswitch = mock.Mock()
        self.set_lswitch_ext_id = mock.Mock()
        self.delete_lswitch = mock.Mock()
        self.create_lswitch_port = mock.Mock()
        self.set_lswitch_port = mock.Mock()
        self.delete_lswitch_port = mock.Mock()
        self.get_all_logical_switches_ids = mock.Mock()
        self.get_logical_switch_ids = mock.Mock()
        self.get_all_logical_switch_ports_ids = mock.Mock()
        self.create_lrouter = mock.Mock()
        self.update_lrouter = mock.Mock()
        self.delete_lrouter = mock.Mock()
        self.add_lrouter_port = mock.Mock()
        self.update_lrouter_port = mock.Mock()
        self.delete_lrouter_port = mock.Mock()
        self.set_lrouter_port_in_lswitch_port = mock.Mock()
        self.add_acl = mock.Mock()
        self.delete_acl = mock.Mock()
        self.update_acls = mock.Mock()
        self.idl = mock.Mock()
        self.add_static_route = mock.Mock()
        self.delete_static_route = mock.Mock()
        self.create_address_set = mock.Mock()
        self.update_address_set_ext_ids = mock.Mock()
        self.delete_address_set = mock.Mock()
        self.update_address_set = mock.Mock()
        self.get_all_chassis_router_bindings = mock.Mock()
        self.get_router_chassis_binding = mock.Mock()
        self.get_unhosted_routers = mock.Mock()
        self.add_dhcp_options = mock.Mock()
        self.delete_dhcp_options = mock.Mock()
        self.get_subnet_dhcp_options = mock.Mock()
        self.get_subnet_dhcp_options.return_value = {}
        self.get_port_dhcp_options = mock.Mock()
        self.get_port_dhcp_options.return_value = {}
        self.compose_dhcp_options_commands = mock.MagicMock()


class FakeOvsdbSbOvnIdl(object):

    def __init__(self, **kwargs):
        self.get_chassis_hostname_and_physnets = mock.Mock()
        self.get_chassis_hostname_and_physnets.return_value = {}
        self.get_all_chassis = mock.Mock()


class FakeOvsdbTransaction(object):
    def __init__(self, **kwargs):
        self.insert = mock.Mock()


class FakePlugin(object):

    def __init__(self, **kwargs):
        self.get_ports = mock.Mock()
        self._get_port_security_group_bindings = mock.Mock()


class FakeResource(object):

    def __init__(self, manager=None, info=None, loaded=False, methods=None):
        """Set attributes and methods for a resource.

        :param manager:
            The resource manager
        :param Dictionary info:
            A dictionary with all attributes
        :param bool loaded:
            True if the resource is loaded in memory
        :param Dictionary methods:
            A dictionary with all methods
        """
        info = info or {}
        methods = methods or {}

        self.__name__ = type(self).__name__
        self.manager = manager
        self._info = info
        self._add_details(info)
        self._add_methods(methods)
        self._loaded = loaded

    def _add_details(self, info):
        for (k, v) in six.iteritems(info):
            setattr(self, k, v)

    def _add_methods(self, methods):
        """Fake methods with MagicMock objects.

        For each <@key, @value> pairs in methods, add an callable MagicMock
        object named @key as an attribute, and set the mock's return_value to
        @value. When users access the attribute with (), @value will be
        returned, which looks like a function call.
        """
        for (name, ret) in six.iteritems(methods):
            method = mock.MagicMock(return_value=ret)
            setattr(self, name, method)

    def __repr__(self):
        reprkeys = sorted(k for k in self.__dict__.keys() if k[0] != '_' and
                          k != 'manager')
        info = ", ".join("%s=%s" % (k, getattr(self, k)) for k in reprkeys)
        return "<%s %s>" % (self.__class__.__name__, info)

    def keys(self):
        return self._info.keys()

    def info(self):
        return self._info


class FakeNetwork(object):
    """Fake one or more networks."""

    @staticmethod
    def create_one_network(attrs=None):
        """Create a fake network.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A FakeResource object faking the network
        """
        attrs = attrs or {}

        # Set default attributes.
        fake_uuid = uuid.uuid4().hex
        network_attrs = {
            'id': 'network-id-' + fake_uuid,
            'name': 'network-name-' + fake_uuid,
            'status': 'ACTIVE',
            'tenant_id': 'project-id-' + fake_uuid,
            'admin_state_up': True,
            'shared': False,
            'subnets': [],
            'provider:network_type': 'geneve',
            'provider:physical_network': None,
            'provider:segmentation_id': 10,
            'router:external': False,
            'availability_zones': [],
            'availability_zone_hints': [],
            'is_default': False,
        }

        # Overwrite default attributes.
        network_attrs.update(attrs)

        return FakeResource(info=copy.deepcopy(network_attrs),
                            loaded=True)


class FakeNetworkContext(object):
    def __init__(self, network, segments):
        self.fake_network = network
        self.fake_segments = segments

    @property
    def current(self):
        return self.fake_network

    @property
    def original(self):
        return None

    @property
    def network_segments(self):
        return self.fake_segments


class FakeOvsdbRow(FakeResource):
    """Fake one or more OVSDB rows."""

    @staticmethod
    def create_one_ovsdb_row(attrs=None, methods=None):
        """Create a fake OVSDB row.

        :param Dictionary attrs:
            A dictionary with all attributes
        :param Dictionary methods:
            A dictionary with all methods
        :return:
            A FakeResource object faking the OVSDB row
        """
        attrs = attrs or {}
        methods = methods or {}

        # Set default attributes.
        fake_uuid = uuid.uuid4().hex
        ovsdb_row_attrs = {
            'uuid': fake_uuid,
            'name': 'name-' + fake_uuid
        }

        # Set default methods.
        ovsdb_row_methods = {
            'delete': None,
            'verify': None,
        }

        # Overwrite default attributes and methods.
        ovsdb_row_attrs.update(attrs)
        ovsdb_row_methods.update(methods)

        return FakeResource(info=copy.deepcopy(ovsdb_row_attrs),
                            loaded=True,
                            methods=copy.deepcopy(ovsdb_row_methods))


class FakeOvsdbTable(FakeResource):
    """Fake one or more OVSDB tables."""

    @staticmethod
    def create_one_ovsdb_table(attrs=None):
        """Create a fake OVSDB table.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A FakeResource object faking the OVSDB table
        """
        attrs = attrs or {}

        # Set default attributes.
        ovsdb_table_attrs = {
            'rows': {},
        }

        # Overwrite default attributes.
        ovsdb_table_attrs.update(attrs)

        return FakeResource(info=copy.deepcopy(ovsdb_table_attrs),
                            loaded=True)


class FakePort(object):
    """Fake one or more ports."""

    @staticmethod
    def create_one_port(attrs=None):
        """Create a fake port.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A FakeResource object faking the port
        """
        attrs = attrs or {}

        # Set default attributes.
        fake_uuid = uuid.uuid4().hex
        port_attrs = {
            'admin_state_up': True,
            'allowed_address_pairs': [{}],
            'binding:host_id': 'binding-host-id-' + fake_uuid,
            'binding:profile': {},
            'binding:vif_details': {},
            'binding:vif_type': 'ovs',
            'binding:vnic_type': 'normal',
            'device_id': 'device-id-' + fake_uuid,
            'device_owner': 'compute:nova',
            'dns_assignment': [{}],
            'dns_name': 'dns-name-' + fake_uuid,
            'extra_dhcp_opts': [{}],
            'fixed_ips': [{'subnet_id': 'subnet-id-' + fake_uuid,
                           'ip_address': '10.10.10.20'}],
            'id': 'port-id-' + fake_uuid,
            'mac_address': 'fa:16:3e:a9:4e:72',
            'name': 'port-name-' + fake_uuid,
            'network_id': 'network-id-' + fake_uuid,
            'port_security_enabled': True,
            'security_groups': [],
            'status': 'ACTIVE',
            'tenant_id': 'project-id-' + fake_uuid,
        }

        # Overwrite default attributes.
        port_attrs.update(attrs)

        return FakeResource(info=copy.deepcopy(port_attrs),
                            loaded=True)


class FakeSecurityGroup(object):
    """Fake one or more security groups."""

    @staticmethod
    def create_one_security_group(attrs=None):
        """Create a fake security group.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A FakeResource object faking the security group
        """
        attrs = attrs or {}

        # Set default attributes.
        fake_uuid = uuid.uuid4().hex
        security_group_attrs = {
            'id': 'security-group-id-' + fake_uuid,
            'name': 'security-group-name-' + fake_uuid,
            'description': 'security-group-description-' + fake_uuid,
            'tenant_id': 'project-id-' + fake_uuid,
            'security_group_rules': [],
        }

        # Overwrite default attributes.
        security_group_attrs.update(attrs)

        return FakeResource(info=copy.deepcopy(security_group_attrs),
                            loaded=True)


class FakeSecurityGroupRule(object):
    """Fake one or more security group rules."""

    @staticmethod
    def create_one_security_group_rule(attrs=None):
        """Create a fake security group rule.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A FakeResource object faking the security group rule
        """
        attrs = attrs or {}

        # Set default attributes.
        fake_uuid = uuid.uuid4().hex
        security_group_rule_attrs = {
            'direction': 'ingress',
            'ethertype': 'IPv4',
            'id': 'security-group-rule-id-' + fake_uuid,
            'port_range_max': 22,
            'port_range_min': 22,
            'protocol': 'tcp',
            'remote_group_id': None,
            'remote_ip_prefix': '0.0.0.0/0',
            'security_group_id': 'security-group-id-' + fake_uuid,
            'tenant_id': 'project-id-' + fake_uuid,
        }

        # Overwrite default attributes.
        security_group_rule_attrs.update(attrs)

        return FakeResource(info=copy.deepcopy(security_group_rule_attrs),
                            loaded=True)


class FakeSegment(object):
    """Fake one or more segments."""

    @staticmethod
    def create_one_segment(attrs=None):
        """Create a fake segment.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A FakeResource object faking the segment
        """
        attrs = attrs or {}

        # Set default attributes.
        segment_attrs = {
            'network_type': 'geneve',
            'physical_network': None,
            'segmentation_id': 10,
        }

        # Overwrite default attributes.
        segment_attrs.update(attrs)

        return FakeResource(info=copy.deepcopy(segment_attrs),
                            loaded=True)


class FakeSubnet(object):
    """Fake one or more subnets."""

    @staticmethod
    def create_one_subnet(attrs=None):
        """Create a fake subnet.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A FakeResource object faking the subnet
        """
        attrs = attrs or {}

        # Set default attributes.
        fake_uuid = uuid.uuid4().hex
        subnet_attrs = {
            'id': 'subnet-id-' + fake_uuid,
            'name': 'subnet-name-' + fake_uuid,
            'network_id': 'network-id-' + fake_uuid,
            'cidr': '10.10.10.0/24',
            'tenant_id': 'project-id-' + fake_uuid,
            'enable_dhcp': True,
            'dns_nameservers': [],
            'allocation_pools': [],
            'host_routes': [],
            'ip_version': 4,
            'gateway_ip': '10.10.10.1',
            'ipv6_address_mode': 'None',
            'ipv6_ra_mode': 'None',
            'subnetpool_id': None,
        }

        # Overwrite default attributes.
        subnet_attrs.update(attrs)

        return FakeResource(info=copy.deepcopy(subnet_attrs),
                            loaded=True)

# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# TODO(salv-orlando): Verify if a single set of operational
# status constants is achievable
NET_STATUS_ACTIVE = 'ACTIVE'
NET_STATUS_BUILD = 'BUILD'
NET_STATUS_DOWN = 'DOWN'
NET_STATUS_ERROR = 'ERROR'

PORT_STATUS_ACTIVE = 'ACTIVE'
PORT_STATUS_BUILD = 'BUILD'
PORT_STATUS_DOWN = 'DOWN'
PORT_STATUS_ERROR = 'ERROR'
PORT_STATUS_NOTAPPLICABLE = 'N/A'

FLOATINGIP_STATUS_ACTIVE = 'ACTIVE'
FLOATINGIP_STATUS_DOWN = 'DOWN'
FLOATINGIP_STATUS_ERROR = 'ERROR'

# Service operation status constants
ACTIVE = "ACTIVE"
DOWN = "DOWN"
CREATED = "CREATED"
PENDING_CREATE = "PENDING_CREATE"
PENDING_UPDATE = "PENDING_UPDATE"
PENDING_DELETE = "PENDING_DELETE"
INACTIVE = "INACTIVE"
ERROR = "ERROR"

DEVICE_OWNER_COMPUTE_PREFIX = "compute:"
DEVICE_OWNER_NETWORK_PREFIX = "network:"
DEVICE_OWNER_NEUTRON_PREFIX = "neutron:"
DEVICE_OWNER_BAREMETAL_PREFIX = "baremetal:"

DEVICE_OWNER_ROUTER_HA_INTF = (DEVICE_OWNER_NETWORK_PREFIX +
                               "router_ha_interface")
DEVICE_OWNER_HA_REPLICATED_INT = (DEVICE_OWNER_NETWORK_PREFIX +
                                  "ha_router_replicated_interface")
DEVICE_OWNER_ROUTER_INTF = DEVICE_OWNER_NETWORK_PREFIX + "router_interface"
DEVICE_OWNER_ROUTER_GW = DEVICE_OWNER_NETWORK_PREFIX + "router_gateway"
DEVICE_OWNER_FLOATINGIP = DEVICE_OWNER_NETWORK_PREFIX + "floatingip"
DEVICE_OWNER_DHCP = DEVICE_OWNER_NETWORK_PREFIX + "dhcp"
DEVICE_OWNER_DVR_INTERFACE = (DEVICE_OWNER_NETWORK_PREFIX +
                              "router_interface_distributed")
DEVICE_OWNER_AGENT_GW = (DEVICE_OWNER_NETWORK_PREFIX +
                         "floatingip_agent_gateway")
DEVICE_OWNER_ROUTER_SNAT = (DEVICE_OWNER_NETWORK_PREFIX +
                            "router_centralized_snat")
DEVICE_OWNER_LOADBALANCER = DEVICE_OWNER_NEUTRON_PREFIX + "LOADBALANCER"
DEVICE_OWNER_LOADBALANCERV2 = DEVICE_OWNER_NEUTRON_PREFIX + "LOADBALANCERV2"

DEVICE_OWNER_PREFIXES = (DEVICE_OWNER_NETWORK_PREFIX,
                         DEVICE_OWNER_NEUTRON_PREFIX)

# Collection used to identify devices owned by router interfaces.
# DEVICE_OWNER_ROUTER_HA_INTF is a special case and so is not included.
ROUTER_INTERFACE_OWNERS = (DEVICE_OWNER_ROUTER_INTF,
                           DEVICE_OWNER_HA_REPLICATED_INT,
                           DEVICE_OWNER_DVR_INTERFACE)
ROUTER_INTERFACE_OWNERS_SNAT = (DEVICE_OWNER_ROUTER_INTF,
                                DEVICE_OWNER_HA_REPLICATED_INT,
                                DEVICE_OWNER_DVR_INTERFACE,
                                DEVICE_OWNER_ROUTER_SNAT)
FLOATINGIP_KEY = '_floatingips'
INTERFACE_KEY = '_interfaces'
HA_INTERFACE_KEY = '_ha_interface'

IPv4 = 'IPv4'
IPv6 = 'IPv6'
IP_VERSION_4 = 4
IP_VERSION_6 = 6
IPv4_BITS = 32
IPv6_BITS = 128

INVALID_MAC_ADDRESSES = ['00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF']

IPv4_ANY = '0.0.0.0/0'
IPv6_ANY = '::/0'
IP_ANY = {IP_VERSION_4: IPv4_ANY, IP_VERSION_6: IPv6_ANY}

IPv6_LLA_PREFIX = 'fe80::/64'

DHCP_RESPONSE_PORT = 68

FLOODING_ENTRY = ('00:00:00:00:00:00', '0.0.0.0')

AGENT_TYPE_DHCP = 'DHCP agent'
AGENT_TYPE_OVS = 'Open vSwitch agent'
AGENT_TYPE_LINUXBRIDGE = 'Linux bridge agent'
AGENT_TYPE_OFA = 'OFA driver agent'
AGENT_TYPE_L3 = 'L3 agent'
AGENT_TYPE_LOADBALANCER = 'Loadbalancer agent'
AGENT_TYPE_METERING = 'Metering agent'
AGENT_TYPE_METADATA = 'Metadata agent'
AGENT_TYPE_NIC_SWITCH = 'NIC Switch agent'
AGENT_TYPE_MACVTAP = 'Macvtap agent'
L2_AGENT_TOPIC = 'N/A'

L3_AGENT_MODE_DVR = 'dvr'
L3_AGENT_MODE_DVR_SNAT = 'dvr_snat'
L3_AGENT_MODE_LEGACY = 'legacy'
L3_AGENT_MODE = 'agent_mode'

PORT_BINDING_EXT_ALIAS = 'binding'
L3_AGENT_SCHEDULER_EXT_ALIAS = 'l3_agent_scheduler'
DHCP_AGENT_SCHEDULER_EXT_ALIAS = 'dhcp_agent_scheduler'
LBAAS_AGENT_SCHEDULER_EXT_ALIAS = 'lbaas_agent_scheduler'
L3_DISTRIBUTED_EXT_ALIAS = 'dvr'
L3_HA_MODE_EXT_ALIAS = 'l3-ha'
SUBNET_ALLOCATION_EXT_ALIAS = 'subnet_allocation'

# Protocol names and numbers for Security Groups/Firewalls
PROTO_NAME_AH = 'ah'
PROTO_NAME_DCCP = 'dccp'
PROTO_NAME_EGP = 'egp'
PROTO_NAME_ESP = 'esp'
PROTO_NAME_GRE = 'gre'
PROTO_NAME_ICMP = 'icmp'
PROTO_NAME_IGMP = 'igmp'
PROTO_NAME_IPV6_ENCAP = 'ipv6-encap'
PROTO_NAME_IPV6_FRAG = 'ipv6-frag'
PROTO_NAME_IPV6_ICMP = 'ipv6-icmp'
# For backward-compatibility of security group rule API, we keep the old value
# for IPv6 ICMP. It should be clean up in the future.
PROTO_NAME_IPV6_ICMP_LEGACY = 'icmpv6'
PROTO_NAME_IPV6_NONXT = 'ipv6-nonxt'
PROTO_NAME_IPV6_OPTS = 'ipv6-opts'
PROTO_NAME_IPV6_ROUTE = 'ipv6-route'
PROTO_NAME_OSPF = 'ospf'
PROTO_NAME_PGM = 'pgm'
PROTO_NAME_RSVP = 'rsvp'
PROTO_NAME_SCTP = 'sctp'
PROTO_NAME_TCP = 'tcp'
PROTO_NAME_UDP = 'udp'
PROTO_NAME_UDPLITE = 'udplite'
PROTO_NAME_VRRP = 'vrrp'

PROTO_NUM_AH = 51
PROTO_NUM_DCCP = 33
PROTO_NUM_EGP = 8
PROTO_NUM_ESP = 50
PROTO_NUM_GRE = 47
PROTO_NUM_ICMP = 1
PROTO_NUM_IGMP = 2
PROTO_NUM_IPV6_ENCAP = 41
PROTO_NUM_IPV6_FRAG = 44
PROTO_NUM_IPV6_ICMP = 58
PROTO_NUM_IPV6_NONXT = 59
PROTO_NUM_IPV6_OPTS = 60
PROTO_NUM_IPV6_ROUTE = 43
PROTO_NUM_OSPF = 89
PROTO_NUM_PGM = 113
PROTO_NUM_RSVP = 46
PROTO_NUM_SCTP = 132
PROTO_NUM_TCP = 6
PROTO_NUM_UDP = 17
PROTO_NUM_UDPLITE = 136
PROTO_NUM_VRRP = 112

IP_PROTOCOL_MAP = {PROTO_NAME_AH: PROTO_NUM_AH,
                   PROTO_NAME_DCCP: PROTO_NUM_DCCP,
                   PROTO_NAME_EGP: PROTO_NUM_EGP,
                   PROTO_NAME_ESP: PROTO_NUM_ESP,
                   PROTO_NAME_GRE: PROTO_NUM_GRE,
                   PROTO_NAME_ICMP: PROTO_NUM_ICMP,
                   PROTO_NAME_IGMP: PROTO_NUM_IGMP,
                   PROTO_NAME_IPV6_ENCAP: PROTO_NUM_IPV6_ENCAP,
                   PROTO_NAME_IPV6_FRAG: PROTO_NUM_IPV6_FRAG,
                   PROTO_NAME_IPV6_ICMP: PROTO_NUM_IPV6_ICMP,
                   # For backward-compatibility of security group rule API
                   PROTO_NAME_IPV6_ICMP_LEGACY: PROTO_NUM_IPV6_ICMP,
                   PROTO_NAME_IPV6_NONXT: PROTO_NUM_IPV6_NONXT,
                   PROTO_NAME_IPV6_OPTS: PROTO_NUM_IPV6_OPTS,
                   PROTO_NAME_IPV6_ROUTE: PROTO_NUM_IPV6_ROUTE,
                   PROTO_NAME_OSPF: PROTO_NUM_OSPF,
                   PROTO_NAME_PGM: PROTO_NUM_PGM,
                   PROTO_NAME_RSVP: PROTO_NUM_RSVP,
                   PROTO_NAME_SCTP: PROTO_NUM_SCTP,
                   PROTO_NAME_TCP: PROTO_NUM_TCP,
                   PROTO_NAME_UDP: PROTO_NUM_UDP,
                   PROTO_NAME_UDPLITE: PROTO_NUM_UDPLITE,
                   PROTO_NAME_VRRP: PROTO_NUM_VRRP}

# ICMPv6 types:
# Destination Unreachable (1)
ICMPV6_TYPE_DEST_UNREACH = 1
# Packet Too Big (2)
ICMPV6_TYPE_PKT_TOOBIG = 2
# Time Exceeded (3)
ICMPV6_TYPE_TIME_EXCEED = 3
# Parameter Problem (4)
ICMPV6_TYPE_PARAMPROB = 4
# Echo Request (128)
ICMPV6_TYPE_ECHO_REQUEST = 128
# Echo Reply (129)
ICMPV6_TYPE_ECHO_REPLY = 129
# Multicast Listener Query (130)
ICMPV6_TYPE_MLD_QUERY = 130
# Multicast Listener Report (131)
ICMPV6_TYPE_MLD_REPORT = 131
# Multicast Listener Done (132)
ICMPV6_TYPE_MLD_DONE = 132
# Router Solicitation (133)
ICMPV6_TYPE_RS = 133
# Router Advertisement (134)
ICMPV6_TYPE_RA = 134
# Neighbor Solicitation (135)
ICMPV6_TYPE_NS = 135
# Neighbor Advertisement (136)
ICMPV6_TYPE_NA = 136
# Multicast Listener v2 Report (143)
ICMPV6_TYPE_MLD2_REPORT = 143

# List of ICMPv6 types that should be allowed from the unspecified address for
# Duplicate Address Detection:
ICMPV6_ALLOWED_UNSPEC_ADDR_TYPES = [ICMPV6_TYPE_MLD_REPORT,
                                    ICMPV6_TYPE_NS,
                                    ICMPV6_TYPE_MLD2_REPORT]

# Human-readable ID to which the subnetpool ID should be set to
# indicate that IPv6 Prefix Delegation is enabled for a given subnetpool
IPV6_PD_POOL_ID = 'prefix_delegation'

# Device names start with "tap"
TAP_DEVICE_PREFIX = 'tap'

# Device names start with "macvtap"
MACVTAP_DEVICE_PREFIX = 'macvtap'

# Linux interface max length
DEVICE_NAME_MAX_LEN = 15

# Time format
ISO8601_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%f'

DHCPV6_STATEFUL = 'dhcpv6-stateful'
DHCPV6_STATELESS = 'dhcpv6-stateless'
IPV6_SLAAC = 'slaac'
IPV6_MODES = [DHCPV6_STATEFUL, DHCPV6_STATELESS, IPV6_SLAAC]


class Sentinel(object):
    """A constant object that does not change even when copied."""
    def __deepcopy__(self, memo):
        # Always return the same object because this is essentially a constant.
        return self

    def __copy__(self):
        # called via copy.copy(x)
        return self


#############################
# Attribute related constants
#############################

ATTR_NOT_SPECIFIED = Sentinel()

HEX_ELEM = '[0-9A-Fa-f]'
UUID_PATTERN = '-'.join([HEX_ELEM + '{8}', HEX_ELEM + '{4}',
                         HEX_ELEM + '{4}', HEX_ELEM + '{4}',
                         HEX_ELEM + '{12}'])


##########################
# Device related constants
##########################
# vhost-user device names start with "vhu"
VHOST_USER_DEVICE_PREFIX = 'vhu'
# The vswitch side of a veth pair for a nova iptables filter setup
VETH_DEVICE_PREFIX = 'qvo'
# prefix for SNAT interface in DVR
SNAT_INT_DEV_PREFIX = 'sg-'

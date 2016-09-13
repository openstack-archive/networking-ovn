.. _features:

Features
========

Open Virtual Network (OVN) offers the following virtual network
services:

* Layer-2 (switching)

  Native implementation. Replaces the conventional Open vSwitch (OVS)
  agent.

* Layer-3 (routing)

  Native implementation or conventional layer-3 agent. The native
  implementation supports distributed routing. However, it currently lacks
  support for floating IP addresses, NAT, and the metadata proxy.

* DHCP

  Native implementation or conventional DHCP agent. The native implementation
  supports distributed DHCP. However, it currently lacks IPv6 support and
  support for the Neutron internal DNS and metadata proxy features.

* Metadata

  Currently uses conventional metadata agent.

* DPDK

  OVN and networking-ovn may be used with OVS using either the Linux kernel
  datapath or the DPDK datapath.

* Trunk driver

  Uses OVN's functionality of parent port and port tagging to support trunk
  service plugin. One has to enable the 'trunk' service plugin in neutron
  configuration files to use this feature.


The following Neutron API extensions are supported with OVN:

+----------------------------------+---------------------------+
| Extension Name                   | Extension Alias           |
+==================================+===========================+
| agent                            | agent                     |
+----------------------------------+---------------------------+
| Address Scopes *                 | address-scope             |
+----------------------------------+---------------------------+
| Allowed Address Pairs            | allowed-address-pairs     |
+----------------------------------+---------------------------+
| Auto Allocated Topology Services | auto-allocated-topology   |
+----------------------------------+---------------------------+
| Availability Zone                | availability_zone         |
+----------------------------------+---------------------------+
| Default Subnetpools              | default-subnetpools       |
+----------------------------------+---------------------------+
| DHCP Agent Scheduler **          | dhcp_agent_scheduler      |
+----------------------------------+---------------------------+
| Distributed Virtual Router *     | dvr                       |
+----------------------------------+---------------------------+
| DNS Integration *                | dns-integration           |
+----------------------------------+---------------------------+
| HA Router extension *            | l3-ha                     |
+----------------------------------+---------------------------+
| L3 Agent Scheduler *             | l3_agent_scheduler        |
+----------------------------------+---------------------------+
| Multi Provider Network           | multi-provider            |
+----------------------------------+---------------------------+
| Network Availability Zone **     | network_availability_zone |
+----------------------------------+---------------------------+
| Network IP Availability          | network-ip-availability   |
+----------------------------------+---------------------------+
| Neutron external network         | external-net              |
+----------------------------------+---------------------------+
| Neutron Extra DHCP opts          | extra_dhcp_opt            |
+----------------------------------+---------------------------+
| Neutron Extra Route              | extraroute                |
+----------------------------------+---------------------------+
| Neutron L3 external gateway *    | ext-gw-mode               |
+----------------------------------+---------------------------+
| Neutron L3 Router                | router                    |
+----------------------------------+---------------------------+
| Network MTU                      | net-mtu                   |
+----------------------------------+---------------------------+
| Port Binding                     | binding                   |
+----------------------------------+---------------------------+
| Port Security                    | port-security             |
+----------------------------------+---------------------------+
| Provider Network                 | provider                  |
+----------------------------------+---------------------------+
| Quality of Service               | qos                       |
+----------------------------------+---------------------------+
| Quota management support         | quotas                    |
+----------------------------------+---------------------------+
| RBAC Policies                    | rbac-policies             |
+----------------------------------+---------------------------+
| Resource revision numbers        | revisions                 |
+----------------------------------+---------------------------+
| Router Availability Zone *       | router_availability_zone  |
+----------------------------------+---------------------------+
| security-group                   | security-group            |
+----------------------------------+---------------------------+
| standard-attr-description        | standard-attr-description |
+----------------------------------+---------------------------+
| Subnet Allocation                | subnet_allocation         |
+----------------------------------+---------------------------+
| Tag support                      | tag                       |
+----------------------------------+---------------------------+
| Time Stamp Fields                | timestamp_core            |
+----------------------------------+---------------------------+


(\*) Only applicable when conventional layer-3 agent enabled.

(\*\*) Only applicable when conventional DHCP agent enabled.

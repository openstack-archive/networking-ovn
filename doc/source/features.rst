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
  support for floating IP addresses and NAT.

* DHCP

  Currently uses conventional DHCP agent which supports availability zones.

* Metadata

  Currently uses conventional metadata agent.

* DPDK

  OVN and networking-ovn may be used with OVS using either the Linux kernel
  datapath or the DPDK datapath.

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
| DHCP Agent Scheduler             | dhcp_agent_scheduler      |
+----------------------------------+---------------------------+
| Distributed Virtual Router *     | dvr                       |
+----------------------------------+---------------------------+
| DNS Integration *                | dns-integration           |
+----------------------------------+---------------------------+
| HA Router extension *            | l3-ha                     |
+----------------------------------+---------------------------+
| L3 Agent Scheduler *             | l3_agent_scheduler        |
+----------------------------------+---------------------------+
| Network Availability Zone        | network_availability_zone |
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

.. _faq:

===
FAQ
===

**Q: Does OVN support DVR or distributed L3 routing?**

DVR (Distributed Virtual Router) is typically used to refer to a specific
implementation of distributed routers provided by the Neutron L3 agent.  The
Neutron L3 agent in DVR mode has never been tested with OVN.  Support for the
Neutron L3 agent is only temporary and will be removed once OVN's native L3
support includes enough functionality.

When using OVN's native L3 support, L3 routing is always distributed.

**Q: Does OVN support integration with physical switches?**

OVN currently integrates with physical switches by optionally using them as
VTEP gateways from logical to physical networks and via integrations provided
by the Neutron ML2 framework, hierarchical port binding.

**Q: What's the status of HA for networking-ovn and OVN?**

Typically, multiple copies of neutron-server are run across multiple servers
and uses a load balancer.  The neutron ML2 mechanism driver provided by
networking-ovn supports this deployment model.  In addition, multiple copies of
neutron-dhcp-agent and neutron-metadata-agent can be run with the option of
configuring neutron-dhcp-agent availability zones.

The network controller portion of OVN is distributed - an instance of the
ovn-controller service runs on every hypervisor.  OVN also includes some
central components for control purposes.

ovn-northd is a centralized service that does some translation between the
northbound and southbound databases in OVN.  Currently, you only run this
service once.  You can manage it in an active/passive HA mode using something
like Pacemaker.  The OVN project plans to allow this service to be horizontally
scaled both for scaling and HA reasons.  This will allow it to be run in an
active/active HA mode.

OVN also makes use of ovsdb-server for the OVN northbound and southbound
databases.  ovsdb-server supports active/passive HA using replication.
For more information, see:

    https://github.com/openvswitch/ovs/blob/master/Documentation/OVSDB-replication.md

A typical deployment would use something like Pacemaker to manage the
active/passive HA process.  Clients would be pointed at a virtual IP
address.  When the HA manager detects a failure of the master, the
virtual IP would be moved and the passive replica would become the
new master.

See :doc:`readme` for links to more details on OVN's architecture.

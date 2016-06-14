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

OVN's northbound and sounthbound databases both reside in an instance of
ovsdb-server.  OVN started out using this database because it already came with
OVS and is used everywhere OVS is used.  If we aren't able to evolve
ovsdb-server to suit our needs, OVN will switch to something else.  Someone is
looking at making ovsdb-server distributed for both scale and HA reasons.  In
the meantime, you can run this instance of ovsdb-server in an active/passive HA
mode.  This requires having the database reside on shared storage.

If you don't want to use shared storage, Neutron is capable of rebuilding the
OVN database after a failure.  This process can be completed without any impact
to the data path, but new resources created via Neutron will not take effect
until the recovery process is complete.  The recovery procedure would be
roughly:

1. Detect that the node running the OVN northbound database has failed.

2. Enable the OVN northbound database on a new host, but prevent ovn-controller
   processes on compute nodes from connecting to the OVN southbound database
   while recovery is in progress. This can be done with either system firewall
   rules, or by removing the configuration of ovsdb-server that tells it to
   listen for connections on an address that ovn-controller instances are able
   to reach (See ovs-vsctl get-manager/set-manager/del-manager commands).

3. Restart ovn-northd pointed at the new database location(s) for the OVN
   northbound and southbound databases.

4. Run ``neutron-ovn-db-sync-util`` with ``--ovn-neutron_sync_mode=repair`` and
   with your neutron server configuration files (for example,
   ``--config-file /etc/neutron/neutron.conf`` and
   ``--config-file /etc/neutron/plugins/ml2/ml2_conf.ini``).  When
   this command completes, the OVN databases will have been restored and
   ovsdb-server can be configured to allow connections from ovn-controller on
   compute hosts (See ovs-vsctl get-manager/set-manager/del-manager commands).

See :doc:`readme` for links to more details on OVN's architecture.

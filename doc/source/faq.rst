.. _faq:

===
FAQ
===

**Q: Why does networking-ovn implement a Neutron core plugin instead of a ML2
mechanism driver?**

The primary benefit of using ML2 is to support multiple mechanism drivers.  OVN
does not currently support a deployment model that would benefit from the use
of ML2.

**Q: Does OVN support DVR or distributed L3 routing?**

DVR (Distributed Virtual Router) is typically used to refer to a specific
implementation of distributed routers provided by the Neutron L3 agent.  The
Neutron L3 agent in DVR mode has never been tested with OVN.  Support for the
Neutron L3 agent is only temporary and will be removed once OVN's native L3
support includes enough functionality.

When using OVN's native L3 support, L3 routing is always distributed.

**Q: Does OVN support integration with physical switches?**

OVN currently integrates with physical switches by optionally using them as
VTEP gateways from logical to physical networks.

OVN does not support using VLANs to implement tenant networks in such a way
that physical switch integration would be needed.  It exclusively uses tunnel
overlays for that purpose.

**Q: What's the status of HA for networking-ovn and OVN?**

Typically, multiple copies of neutron-server are run across multiple servers
and uses a load balancer.  The neutron plugin provided by networking-ovn
supports this deployment model.

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
OVS and is used everywhere OVS is used.  The OVN project has also been clear
from the beginning that if ovsdb-server doesn't work out, we'll switch. Someone
is looking at making ovsdb-server distributed for both scale and HA reasons. In
the meantime, you can run this instance of ovsdb-server in an active/passive HA
mode.  This requires having the database reside on shared storage.

Development in 2015 was largely focused on the initial architecture and
getting the core networking features working through the whole system.  There
is now active work on improving scale and HA, including addressing the issues
discussed here.

See :doc:`readme` for links to more details on OVN's architecture.

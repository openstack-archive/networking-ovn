..
    Convention for heading levels:
    =======  Heading 0 (reserved for the title in a document)
    -------  Heading 1
    ~~~~~~~  Heading 2
    +++++++  Heading 3
    '''''''  Heading 4
    (Avoid deeper levels because they do not render well.)


Deployment Tool Integration
==============================

The networking-ovn git repository includes integration with DevStack, which
enables the creation of simple development and test environments with OVN.  The
use of OVN in a realstic deployment requires integration with OpenStack
deployment tooling.

The purpose of this guide is to document what’s required to integrate OVN into
an OpenStack deployment tool.  It discusses OpenStack nodes of 3 different
types:

* **Controller Node** - A node that runs OpenStack control services such as REST
  APIs and databases.

* **Network Node** - A node that runs the Neutron L3 agent and provides routing
  between tenant networks, as well as connectivity to an external network.
  This node may also be running the Neutron DHCP agent to provide DHCP services
  to tenant networks.

* **Compute Node** - A hypervisor.

New Packages
---------------

The Neutron integration for OVN is an independent package, ``networking-ovn``.

OVN is a part of OVS.  The first release that includes OVN is OVS 2.5, though
OVN is technically experimental in that release.  OVN gets installed
automatically if you install OVS from source.  The OVS RPM includes OVN as a
sub-package called ``openvswitch-ovn``.  The Debian/Ubuntu packaging has not
been updated for OVN yet.

Controller Nodes
-------------------

Controller nodes should have both the ``networking-ovn`` and ``openvswitch-ovn``
packages installed.

ovn-northd and ovsdb-server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

OVN has two databases both managed by ``ovsdb-server``.  It also has a control
service, ``ovn-northd``.

To start both ``ovsdb-server`` and ``ovn-northd``, you can use the ovn-northd
systemd unit::

    $ sudo systemctl start ovn-northd

Or you can start it using the ``ovn-ctl`` script::

    $ sudo /usr/share/openvswitch/scripts/ovn-ctl start_northd

There should only be a single instance of ``ovn-northd`` and ``ovsdb-server``
running. For HA, you can run them in an active/passive mode.  See the HA section
of the networking-ovn :doc:`faq` for more information about the current state
and future plans around HA for the control services.

``ovsdb-server`` must be told to listen via TCP so that compute nodes will be
able to connect to the database.  You can enable that with the following
command::

    $ sudo ovs-appctl -t ovsdb-server ovsdb-server/add-remote ptcp:6640:IP_ADDRESS

``IP_ADDRESS`` should be the address that remote services use to connect to
``ovsdb-server`` running on this node.  TCP port 6640 must be made accessible if a
firewall is in use.

neutron-server
~~~~~~~~~~~~~~~~~

OVN has its own Neutron core plugin.  ``neutron-server`` must be configured to
use this new plugin.  The following settings should be applied to
``/etc/neutron/neutron.conf``::

    [DEFAULT]
    core_plugin = networking_ovn.plugin.OVNPlugin
    service_plugins =

The following options should be set in
``/etc/neutron/plugins/networking-ovn/networking-ovn.ini``::

    [ovn]
    # This setting must always be specified.
    ovsdb_connection = tcp:IP_ADDRESS:6640

    # If running in an active/passive HA mode, you’ll want to add this setting:
    #neutron_sync_mode = repair

    # Set to true if using OVN native L3 support.
    #ovn_l3_mode = true

``IP_ADDRESS`` should match the one used when configuring ``ovsdb-server``
earlier.

Network Nodes
----------------

OVN with OpenStack can currently be used in two different modes.

1. **Neutron L3 Agent** - Use a network node running the Neutron L3 agent to
   provide routing between networks.
2. **OVN native L3** - Use OVN's native distributed L3 routing support.

There's some more detailed commentary about the difference between these two
modes in the ``networking-ovn`` :doc:`faq`.  The critically important feature
gap is that OVN native L3 does not yet support NAT.

In OVN native L3 mode, you don't need network nodes.  L3 routing is fully
distributed among hypervisors.  Connectivity to external networks is provided
either by direct connectivity to each hypervisor as a provider network, or via a
top-of-rack switch acting as an OVN VTEP gateway.

In both modes, you also need to run the Neutron DHCP agent.  That can run on the
network node.  If you're using OVN native L3, you'll need to run the DHCP agent
elsewhere since you won't need a network node.  This is temporary until OVN
native support for DHCP is completed and then the DHCP agent will no longer be
needed.

Compute Nodes
----------------

Every compute node must run OVN's local controller, the ``ovn-controller``
service.  This replaces the use of the Neutron OVS agent.

To start ``ovn-controller`` with systemd, use this command::

    $ sudo systemctl start ovn-controller

If systemd is not in use, you can start it with the ``ovn-ctl`` command.

    $ sudo /usr/share/openvswitch/scripts/ovn-ctl start_controller

``ovn-controller`` requires a few cofiguration values.  The first option,
``ovn-remote``, should be set to point ``ovn-controller`` at the location of the
OVN databases.  This should be the controller node IP address used when setting
up ``ovsdb-server`` earlier.

    ovs-vsctl set open . external-ids:ovn-remote=tcp:IP_ADDRESS:6640

The ``ovn-encap-type`` option should always include ``geneve``.  If an OVN VTEP
gateway is in use, it should be ``geneve,vxlan``.  It should actually be safe to
always set this to ``geneve,vxlan``, even if a VTEP gateway is not in use.

    ovs-vsctl set open . external-ids:ovn-encap-type=geneve,vxlan

The ``ovn-encap-ip`` option is the IP address that other compute nodes should
use for creating Geneve tunnels to this compute node.

    ovs-vsctl set open . external-ids:ovn-encap-ip=LOCAL_IP_ADDRESS

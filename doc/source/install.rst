.. _installation:

Installation
============

The ``networking-ovn`` repository includes integration with DevStack that
enables creation of a simple Open Virtual Network (OVN) development and test
environment. This document discusses what is required for manual installation
or integration into a production OpenStack deployment tool of conventional
architectures that include the following types of nodes:

* Controller - Runs OpenStack control plane services such as REST APIs
  and databases.

* Network - Runs the layer-2, layer-3 (routing), DHCP, and metadata agents
  for the Networking service. Some agents optional. Usually provides
  connectivity between provider (public) and project (private) networks
  via NAT and floating IP addresses.

  .. note::

     Some tools deploy these services on controller nodes.

* Compute - Runs the hypervisor and layer-2 agent for the Networking
  service.

Packaging
---------

Open vSwitch (OVS) includes OVN beginning with version 2.5 and considers
it experimental. The Networking service integration for OVN uses an
independent package, typically ``networking-ovn``.

Building OVS from source automatically installs OVN. For deployment tools
using distribution packages, the ``openvswitch-ovn`` package for RHEL/CentOS
and compatible distributions automatically installs ``openvswitch`` as a
dependency. Ubuntu/Debian includes ``ovn-central``, ``ovn-host``,
``ovn-docker``, and ``ovn-common`` packages that pull in the appropriate Open
vSwitch dependencies as needed.

A ``python-networking-ovn`` RPM may be obtained for Fedora or CentOS from
the RDO project.  A package based on the ``master`` branch of
``networking-ovn`` can be found at http://trunk.rdoproject.org/.

Fedora and CentOS RPM builds of OVS and OVN from the ``master`` branch of
``ovs`` can be found in this COPR repository:
https://copr.fedorainfracloud.org/coprs/leifmadsen/ovs-master/.  If you would
like packages that are built with DPDK integration enabled, you can try this
COPR repository, instead:
https://copr.fedorainfracloud.org/coprs/pmatilai/dpdk-snapshot/.

Controller nodes
----------------

Each controller node runs the OVS service (including dependent services such
as ``ovsdb-server``) and the ``ovn-northd`` service. However, only a single
instance of the ``ovsdb-server`` and ``ovn-northd`` services can operate in
a deployment. However, deployment tools can implement active/passive
high-availability using a management tool that monitors service health
and automatically starts these services on another node after failure of the
primary node. See the :ref:`faq` for more information.

#. Install the ``openvswitch-ovn`` and ``networking-ovn`` packages.

#. Start the OVS service. The central OVS service starts the ``ovsdb-server``
   service that manages OVN databases.

   Using the *systemd* unit:

   .. code-block:: console

      # systemctl start openvswitch

   Using the ``ovs-ctl`` script:

   .. code-block:: console

      # /usr/share/openvswitch/scripts/ovs-ctl start

#. Configure the ``ovsdb-server`` component. By default, the ``ovsdb-server``
   service only permits local access to databases via Unix socket. However,
   OVN services on compute nodes require access to these databases.

   * Permit remote database access.

     .. code-block:: console

        # ovs-appctl -t ovsdb-server ovsdb-server/add-remote ptcp:6640:IP_ADDRESS

     Replace ``IP_ADDRESS`` with the IP address of the management network
     interface on the controller node.

     .. note::

        Permit remote access to TCP port 6640 on any host firewall.

#. Start the ``ovn-northd`` service.

   Using the *systemd* unit:

   .. code-block:: console

      # systemctl start ovn-northd

   Using the ``ovn-ctl`` script:

   .. code-block:: console

      # /usr/share/openvswitch/scripts/ovn-ctl start_northd

   Options for *start_northd*:

   .. code-block:: console

      # /usr/share/openvswitch/scripts/ovn-ctl start_northd --help
      # ...
      # DB_NB_SOCK="/usr/local/etc/openvswitch/nb_db.sock"
      # DB_NB_PID="/usr/local/etc/openvswitch/ovnnb_db.pid"
      # DB_SB_SOCK="usr/local/etc/openvswitch/sb_db.sock"
      # DB_SB_PID="/usr/local/etc/openvswitch/ovnsb_db.pid"
      # ...

#. Configure the Networking server component. The Networking service
   implements OVN as an ML2 driver. Edit the ``/etc/neutron/neutron.conf``
   file:

   * Enable the ML2 core plug-in.

     .. code-block:: ini

        [DEFAULT]
        ...
        core_plugin = neutron.plugins.ml2.plugin.Ml2Plugin

   * If the QoS service is enabled then you also need to enable the OVN QoS
     notification driver.

     .. code-block:: ini

        [qos]
        ...
        notification_drivers = ovn-qos

   * (Optional) Enable the native or conventional layer-3 service.

     .. code-block:: ini

        [DEFAULT]
        ...
        service_plugins = L3_SERVICE

     .. note::

        Replace ``L3_SERVICE`` with
        ``networking_ovn.l3.l3_ovn.OVNL3RouterPlugin``
        to enable the native layer-3 service or with
        ``neutron.services.l3_router.l3_router_plugin.L3RouterPlugin``
        to enable the conventional layer-3 service.
        See :ref:`features` and :ref:`faq` for more information.

#. Configure the ML2 plug-in. Edit the
   ``/etc/neutron/plugins/ml2/ml2_conf.ini`` file:

   * Configure the OVN mechanism driver, network type drivers, self-service
     (tenant) network types, and enable the port security extension.

     .. code-block:: ini

        [ml2]
        ...
        mechanism_drivers = ovn
        type_drivers = local,flat,vlan,geneve
        tenant_network_types = geneve
        extension_drivers = port_security
        overlay_ip_version = 4

    .. note::

       To enable VLAN self-service networks, add ``vlan`` to the
       ``tenant_network_types`` option. The first network type
       in the list becomes the default self-service network type.

       To use IPv6 for all overlay (tunnel) network endpoints,
       set the ``overlay_ip_version`` option to ``6``.

   * Configure the Geneve ID range and maximum header size. The IP version
     overhead (20 bytes for IPv4 (default) or 40 bytes for IPv6) is added
     to the maximum header size based on the ML2 ``overlay_ip_version``
     option.

     .. code-block:: ini

        [ml2_type_geneve]
        ...
        vni_ranges = 1:65536
        max_header_size = 38

     .. note::

        The Networking service uses the ``vni_ranges`` option to allocate
        network segments. However, OVN ignores the actual values. Thus, the ID
        range only determines the quantity of Geneve networks in the
        environment. For example, a range of ``5001:6000`` defines a maximum
        of 1000 Geneve networks.

   * Optionally, enable support for VLAN provider and self-service
     networks on one or more physical networks. If you specify only
     the physical network, only administrative (privileged) users can
     manage VLAN networks. Additionally specifying a VLAN ID range for
     a physical network enables regular (non-privileged) users to
     manage VLAN networks. The Networking service allocates the VLAN ID
     for each self-service network using the VLAN ID range for the
     physical network.

     .. code-block:: ini

        [ml2_type_vlan]
        ...
        network_vlan_ranges = PHYSICAL_NETWORK:MIN_VLAN_ID:MAX_VLAN_ID

     Replace ``PHYSICAL_NETWORK`` with the physical network name and
     optionally define the minimum and maximum VLAN IDs. Use a comma
     to separate each physical network.

     For example, to enable support for administrative VLAN networks
     on the ``physnet1`` network and self-service VLAN networks on
     the ``physnet2`` network using VLAN IDs 1001 to 2000:

     .. code-block:: ini

        network_vlan_ranges = physnet1,physnet2:1001:2000

   * Enable security groups.

     .. code-block:: ini

        [securitygroup]
        ...
        enable_security_group = true

     .. note::

        The ``firewall_driver`` option under ``[securitygroup]`` is ignored
        since the OVN ML2 driver itself handles security groups.

   * Configure OVS database access, the OVN L3 mode and scheduler, and
     the OVN DHCP mode

     .. code-block:: ini

        [ovn]
        ...
        ovn_nb_connection = tcp:IP_ADDRESS:6641
        ovn_sb_connection = tcp:IP_ADDRESS:6642
        ovn_l3_mode = OVN_L3_MODE
        ovn_l3_scheduler = OVN_L3_SCHEDULER
        ovn_native_dhcp = OVN_NATIVE_DHCP

     .. note::

        Replace ``IP_ADDRESS`` with the IP address of the controller node
        that runs the ``ovsdb-server`` service. Replace ``OVN_L3_MODE``
        with ``True`` if you enabled the native layer-3 service in
        ``/etc/neutron/neutron.conf`` else ``False``. The ovn_l3_scheduler
        value is only valid if ovn_l3_mode is set to ``True``. Replace
        ``OVN_L3_SCHEDULER`` with ``leastloaded`` if you want the scheduler
        to select a compute node with the least number of gateway routers
        or ``chance`` if you want the scheduler to randomly select a compute
        node from the available list of compute nodes. And finally, replace
        ``OVN_NATIVE_DHCP`` with ``True`` if you want to enable the native
        DHCP service else ``False`` to use the conventional DHCP agent.

#. Start the ``neutron-server`` service.

Network nodes
-------------

Deployments using OVN native layer-3 and DHCP services do not require
conventional network nodes because connectivity to external networks
(including VTEP gateways) and routing occurs on compute nodes.
OVN currently relies on the conventional metadata agent that typically
operates on network nodes. However, you can deploy this agent on
controller or compute nodes.

Compute nodes
-------------

Each compute node runs the OVS and ``ovn-controller`` services. The
``ovn-controller`` service replaces the conventional OVS layer-2 agent.

#. Install the ``openvswitch-ovn`` and ``networking-ovn`` packages.

#. Start the OVS service.

   Using the *systemd* unit:

   .. code-block:: console

      # systemctl start openvswitch

   Using the ``ovs-ctl`` script:

   .. code-block:: console

      # /usr/share/openvswitch/scripts/ovs-ctl start

#. Configure the OVS service.

   * Use OVS databases on the controller node.

     .. code-block:: console

        # ovs-vsctl set open . external-ids:ovn-remote=tcp:IP_ADDRESS:6642

     Replace ``IP_ADDRESS`` with the IP address of the controller node
     that runs the ``ovsdb-server`` service.

   * Enable one or more overlay network protocols. At a minimum, OVN requires
     enabling the ``geneve`` protocol. Deployments using VTEP gateways should
     also enable the ``vxlan`` protocol.

     .. code-block:: console

        # ovs-vsctl set open . external-ids:ovn-encap-type=geneve,vxlan

     .. note::

        Deployments without VTEP gateways can safely enable both protocols.

     .. note::

        Overlay network protocols generally require reducing MTU on VM
        interfaces to account for additional packet overhead. See the
        DHCP agent configuration in the
        `Installation Guide <http://docs.openstack.org/liberty/install-guide-ubuntu/neutron-controller-install-option2.html>`_
        for more information.

   * Configure the overlay network local endpoint IP address.

     .. code-block:: console

        # ovs-vsctl set open . external-ids:ovn-encap-ip=IP_ADDRESS

     Replace ``IP_ADDRESS`` with the IP address of the overlay network
     interface on the compute node.

#. Start the ``ovn-controller`` service.

   Using the *systemd* unit:

   .. code-block:: console

      # systemctl start ovn-controller

   Using the ``ovn-ctl`` script:

   .. code-block:: console

      # /usr/share/openvswitch/scripts/ovn-ctl start_controller

Verify operation
----------------

#. Each compute node should contain an ``ovn-controller`` instance.

   .. code-block:: console

      # ovn-sbctl show
        <output>

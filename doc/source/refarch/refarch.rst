======================
Reference architecture
======================

The reference architecture defines the minimum environment necessary
for a basic evaluation of OpenStack with Open Virtual Network (OVN)
integration for the Networking service. You can deploy this environment
manually using the :ref:`Installation Guide <installation>` or using
`Vagrant <https://github.com/openstack/networking-ovn/tree/master/vagrant>`_.
Any scaling or performance evaluations should use bare metal instead of
virtual machines.

Layout
------

The minimum environment includes four nodes.

The controller node contains the following components that provide enough
functionality to launch basic instances:

* One network interface for management
* Identity service
* Image service
* Networking management with ML2 mechanism driver for OVN (control plane)
* Compute management (control plane)

The database node contains the following components:

* One network interface for management
* OVN northbound service (``ovn-northd``)
* Open vSwitch (OVS) database service (``ovsdb-server``) for the OVN
  northbound database (``ovnnb.db``)
* Open vSwitch (OVS) database service (``ovsdb-server``) for the OVN
  southbound database (``ovnsb.db``)

The two compute nodes contain the following components:

* Three network interfaces for management, overlay networks, and provider
  networks
* Compute management (hypervisor)
* Hypervisor (KVM)
* OVN controller service (``ovn-controller``)
* OVS data plane service (``ovs-vswitchd``)
* OVS database service (``ovsdb-server``) with OVS local configuration
  (``conf.db``) database
* Networking DHCP agent
* Networking metadata agent

.. note::

   By default, deploying DHCP and metadata agents on two compute nodes
   provides basic redundancy for these services. For larger environments,
   consider deploying the agents on a fraction of the compute nodes to
   minimize control plane traffic.

.. image:: figures/ovn-hw.png
   :alt: Hardware layout
   :align: center

.. image:: figures/ovn-services.png
   :alt: Service layout
   :align: center

Networking service with OVN integration
---------------------------------------

The reference architecture deploys the Networking service with OVN
integration as follows:

.. image:: figures/ovn-architecture1.png
   :alt: Architecture for Networking service with OVN integration
   :align: center

Each compute node contains the following network components:

.. image:: figures/ovn-compute1.png
   :alt: Compute node network components
   :align: center

.. note::

   The Networking service creates a unique network namespace for each
   virtual subnet that enables the DHCP service.

.. _refarch_database-access:

Accessing OVN database content
------------------------------

OVN stores configuration data in a collection of OVS database tables.
The following commands show the contents of the most common database
tables in the northbound and southbound databases. The example database
output in this section uses these commands with various output filters.

.. code-block:: console

   $ ovn-nbctl list Logical_Switch
   $ ovn-nbctl list Logical_Switch_Port
   $ ovn-nbctl list ACL
   $ ovn-nbctl list Logical_Router
   $ ovn-nbctl list Logical_Router_Port

   $ ovn-sbctl list Chassis
   $ ovn-sbctl list Encap
   $ ovn-sbctl list Logical_Flow
   $ ovn-sbctl list Multicast_Group
   $ ovn-sbctl list Datapath_Binding
   $ ovn-sbctl list Port_Binding
   $ ovn-sbctl list MAC_Binding

.. _refarch-adding-compute-node:

Adding a compute node
---------------------

When you add a compute node to the environment, the OVN controller
service on it connects to the OVN southbound database and registers
the node as a chassis.

.. code-block:: console

   _uuid               : 9be8639d-1d0b-4e3d-9070-03a655073871
   encaps              : [2fcefdf4-a5e7-43ed-b7b2-62039cc7e32e]
   external_ids        : {ovn-bridge-mappings=""}
   hostname            : "compute1"
   name                : "410ee302-850b-4277-8610-fa675d620cb7"
   vtep_logical_switches: []

The ``encaps`` field value refers to tunnel endpoint information
for the compute node.

.. code-block:: console

   _uuid               : 2fcefdf4-a5e7-43ed-b7b2-62039cc7e32e
   ip                  : "10.0.0.32"
   options             : {}
   type                : geneve

Networks
--------

.. toctree::
   :maxdepth: 1

   provider-networks
   selfservice-networks

Routers
-------

.. toctree::
   :maxdepth: 1

   routers

.. note::

   Currently, OVN lacks support for routing between self-service (private)
   and provider networks. However, it supports routing between
   self-service networks.

Instances
---------

Launching an instance causes the same series of operations regardless
of the network. The following example uses the ``provider`` provider
network, ``cirros`` image, ``m1.tiny`` flavor, ``default`` security
group, and ``mykey`` key.

.. toctree::
   :maxdepth: 1

   launch-instance-provider-network
   launch-instance-selfservice-network

.. todo: Add north-south when OVN gains support for it.

   Traffic flows
   -------------

   East-west for instances on the same provider network
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

   East-west for instances on different provider networks
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

   East-west for instances on the same self-service network
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

   East-west for instances on different self-service networks
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

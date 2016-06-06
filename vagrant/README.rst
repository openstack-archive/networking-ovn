=================================================
Automatic deployment using Vagrant and VirtualBox
=================================================

The Vagrant scripts deploy OpenStack with Open Virtual Network (OVN)
using four nodes to implement a minimal variant of the reference
architecture:

#. Database node containing the OVN northbound (NB) and southbound (SB)
   databases via the Open vSwitch (OVS) database and ``ovn-northd`` services.
#. Controller node containing the Identity service, Image service, control
   plane portion of the Compute service, control plane portion of the
   Networking service including the ``networking-ovn`` ML2 driver, and the
   dashboard. In addition, the controller node is configured as an NFS
   server to support instance live migration between the two compute nodes.
#. Two compute nodes containing the Compute hypervisor, ``ovn-controller``
   service for OVN, DHCP and metadata agents for the Networking service,
   OVS services. In addition, the compute nodes are configured as NFS
   clients to support instance live migration between them.
#. Optionally a node to run the HW VTEP simulator. This node is not
   started by default but can be started by running "vagrant up ovn-vtep"
   after doing a normal "vagrant up".

During deployment, Vagrant creates three VirtualBox networks:

#. Vagrant management network for deployment and VM access to external
   networks such as the Internet. Becomes the VM ``eth0`` network interface.
#. OpenStack management network for the OpenStack control plane, OVN
   control plane, and OVN overlay networks. Becomes the VM ``eth1`` network
   interface.
#. OVN provider network that connects OpenStack instances to external networks
   such as the Internet. Becomes the VM ``eth2`` network interface.

Requirements
------------

The default configuration requires approximately 12 GB of RAM and supports
launching approximately four OpenStack instances using the ``m1.tiny``
flavor. You can change the amount of resources for each VM in the
``virtualbox.conf.yml`` file.

Deployment
----------

#. Install `VirtualBox <https://www.virtualbox.org/wiki/Downloads>`_ and
   `Vagrant <https://www.vagrantup.com/downloads.html>`_.

#. Clone the ``networking-ovn`` repository into your home directory and
   change to the ``vagrant`` directory::

     $ git clone https://git.openstack.org/openstack/networking-ovn.git
     $ cd networking-ovn/vagrant

#. Install plug-ins for Vagrant::

     $ vagrant plugin install vagrant-cachier
     $ vagrant plugin install vagrant-vbguest

#. If necessary, adjust any configuration in the ``virtualbox.conf.yml`` file.

   * If you change any IP addresses or networks, avoid conflicts with the
     host.
   * For evaluating large MTUs, adjust the ``mtu`` option. You must also
     change the MTU on the equivalent ``vboxnet`` interfaces on the host
     to the same value after Vagrant creates them. For example::

       # ip link set dev vboxnet0 mtu 9000
       # ip link set dev vboxnet1 mtu 9000

#. Launch the VMs and grab some coffee::

     $ vagrant up

#. After the process completes, you can use the ``vagrant status`` command
   to determine the VM status::

     $ vagrant status
     Current machine states:

     ovn-db                    running (virtualbox)
     ovn-controller            running (virtualbox)
     ovn-vtep                  running (virtualbox)
     ovn-compute1              running (virtualbox)
     ovn-compute2              running (virtualbox)

#. You can access the VMs using the following commands::

     $ vagrant ssh ovn-db
     $ vagrant ssh ovn-controller
     $ vagrant ssh ovn-vtep
     $ vagrant ssh ovn-compute1
     $ vagrant ssh ovn-compute2

   Note: If you prefer to use the VM console, the password for the ``root``
         account is ``vagrant``. Since ovn-controller is set as the primary
         in the Vagrantfile, the command ``vagrant ssh`` (without specifying
         the name) will connect ssh to that virtual machine.

#. Access OpenStack services via command-line tools on the ``ovn-controller``
   node or via the dashboard from the host by pointing a web browser at the
   IP address of the ``ovn-controller`` node.

   Note: By default, OpenStack includes two accounts: ``admin`` and ``demo``,
         both using password ``password``.

#. On Linux hosts, you can enable instances to access external networks such
   as the Internet by enabling IP forwarding and configuring SNAT from the IP
   address range of the provider network interface (typically vboxnet1) on
   the host to the external network interface on the host. For example, if
   the ``eth0`` network interface on the host provides external network
   connectivity::

     # sysctl -w net.ipv4.ip_forward=1
     # sysctl -p
     # iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o eth0 -j MASQUERADE

   Note: These commands do not persist after rebooting the host.

#. After completing your tasks, you can destroy the VMs::

     $ vagrant destroy

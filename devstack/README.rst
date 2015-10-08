======================
 Enabling in Devstack
======================

1. Download devstack and networking-ovn

     git clone http://git.openstack.org/openstack-dev/devstack.git
     git clone http://git.openstack.org/openstack/networking-ovn.git

2. Add networking-ovn to devstack.  The minimal set of critical local.conf
   additions are the following::

     cd devstack
     cat << EOF >> local.conf
     > enable_plugin networking-ovn http://git.openstack.org/openstack/networking-ovn
     > enable_service ovn
     > EOF

You can also use the provided example local.conf, or look at its contents to add
to your own::

     cd devstack
     cp ../networking-ovn/devstack/local.conf.sample local.conf

3. run devstack::

     ./stack.sh

============================================
 Automated setup using Vagrant + Virtualbox
============================================

Automate the setup described here
http://docs.openstack.org/developer/networking-ovn/testing.html#single-node-test-environment.

This will create a 2 nodes devstack (controller + compute), where OVN is used as
the Open vSwitch backend.

Vagrant allows to configure the provider on which the virtual machines are
created. Virtualbox is the default provider used to launch the VM's on a
developer computer, but other providers can be used: VMWare, AWS, Openstack,
containers stuff, ...

Quick Start
-----------

1. Install Virtualbox (https://www.virtualbox.org/wiki/Downloads) and Vagrant
   (http://downloads.vagrantup.com).

2. Configure

::

    git clone https://git.openstack.org/openstack/networking-ovn
    cd networking-ovn
    vagrant plugin install vagrant-cachier
    vagrant plugin install vagrant-vbguest

3. Adjust the settings in `devstack/vagrant.conf.yml` if needed (5GB RAM is the
   minimum to get 1 VM running on the controller node)

4. Launch the VM's: `vagrant up`

... This may take a while, once it is finished:

* you can ssh into the virtual machines: `vagrant ssh devstack_controller` or
  `vagrant ssh devstack_compute`

* you can access the horizon dashboard at http://controller.devstack.dev

* the networking-ovn folder is shared between the host and the two nodes (at
  /home/vagrant/networking-ovn)

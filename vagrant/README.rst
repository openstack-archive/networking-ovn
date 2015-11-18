============================================
 Automated setup using Vagrant + Virtualbox
============================================

Automate the setup described here
http://docs.openstack.org/developer/networking-ovn/testing.html.

This will create a 3-node devstack (1 controller node + 2 compute nodes), where
OVN is used as the OpenStack Neutron backend.

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
    cd networking-ovn/vagrant
    vagrant plugin install vagrant-cachier
    vagrant plugin install vagrant-vbguest

3. Adjust the settings in `virtualbox.conf.yml` if needed. Notice that
   5GB RAM is the minimum to get 1 VM running on the controller node.
   If other provider is used, then you will need to create a conf file
   similar to virtualbox.conf.yml, then adjusted the file Vagrantfile
   to load that file. In virtualbox.conf.yml file, make sure that the
   IP addresses for the VMs fall into your VirtualBox Host-Only network
   IP range, if not, the script most likely will fail when it tries to
   access the VMs.

4. Launch the VM's: `vagrant up`

... This may take a while (one hour or so), once it is finished:

* you can ssh into the virtual machines: `vagrant ssh devstack_controller` or
  `vagrant ssh devstack_compute` or if you like to log in from the console of
  the VMs, then the password will be vagrant for root user.

* you can access the horizon dashboard at http://controller.devstack.dev. Use
  admin/password to log in to horizon dashboard if you did not changed the
  devstack settings in file networking-ovn/devstack/local.conf.sample.

* the networking-ovn folder is shared between the host and the two nodes (at
  /home/vagrant/networking-ovn)

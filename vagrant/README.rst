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

2. Configure::

    git clone https://git.openstack.org/openstack/networking-ovn
    cd networking-ovn/vagrant
    vagrant plugin install vagrant-cachier
    vagrant plugin install vagrant-vbguest

3. Adjust the settings in `virtualbox.conf.yml` if needed. Notice that
   5GB RAM is the minimum to get 1 VM running on the controller node.
   If other provider is used, then you will need to create a conf file
   similar to `virtualbox.conf.yml`, then adjusted the file Vagrantfile
   to load that file. In `virtualbox.conf.yml` file, make sure that the
   IP addresses for the VMs fall into your VirtualBox Host-Only network
   IP range, if not, the script most likely will fail when it tries to
   access the VMs.

   For evaluating large MTUs, set the 'mtu' option for each VM to the
   appropriate value. You must also set the MTU on the equivalent
   ``vboxnet`` interfaces on the host to the same value after Vagrant
   creates them. For example, using a 9000 MTU::

    ip link set dev vboxnet0 mtu 9000
    ip link set dev vboxnet1 mtu 9000

4. Build up three VirtualBox VMs using vagrant, the process can take
   one hour::

    vagrant up

5. Once the process is done successfully, you can use vagrant status and
   ssh command to see VM status and ssh to each of the VMs::

    vagrant status

   The above command will show vagrant project VMs and status, you may see
   things like the following::

    Current machine states:

    ovn-controller            running (virtualbox)
    ovn-compute1              running (virtualbox)
    ovn-compute2              running (virtualbox)
    ...

   You can now ssh to these machines by using the following command::

    vagrant ssh ovn-controller
    vagrant ssh ovn-compute1
    vagrant ssh ovn-compute2

   If you like to log in from the console of the VMs, the password for the
   root user is vagrant.

   You can point your browser to `http://<<ovn-controller ip address>>` to
   access the horizon dashboard. By default the ip address of ovn-controller
   was set to 192.168.33.12 in `provisioning/virtualbox.conf.yml` file. Use
   admin/password to log in once you see the Horizon login screen. You can
   certainly change the user name and password in file
   `networking-ovn/devstack/local.conf.sample` before you run vagrant up if
   you want different user name and password.

6. The networking-ovn folder is shared between the host and the three nodes
   (at /home/vagrant/networking-ovn).

7. On Linux hosts, you can enable instances to access external networks such
   as the Internet by enabling IP forwarding and configuring SNAT from the IP
   address range of the provider network interface (typically vboxnet1) on
   the host to the external network interface on the host. For example, if
   the ``eth0`` network interface on the host provides external network
   connectivity::

    # sysctl -w net.ipv4.ip_forward=1
    # iptables -t nat -A POSTROUTING -s 192.168.66.0/24 -o eth0 -j MASQUERADE

8. After you finished your work with the VMs, you can choose to destroy,
   suspend and later resume the VMs by using the following commands:

    vagrant suspend
    vagrant resume
    vagrant destroy

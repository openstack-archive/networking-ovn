Testing with DevStack
=====================

This document describes how to test OpenStack with OVN using DevStack.  We will
start by describing how to test on a single host.

Single Node Test Environment
----------------------------

1. Create a test system.

It's best to use a throwaway dev system for running DevStack.  In this example
I'm using a Fedora 21 VM with 4 GB of RAM.  You should be able to use any
distribution that is supported by DevStack.  So far, networking-ovn is being
tested on Fedora 21 and Ubuntu 14.04.

Create a user and grant it sudo access.  Install git.

2. Get DevStack and networking-ovn.

::

     $ git clone http://git.openstack.org/openstack-dev/devstack.git
     $ git clone http://git.openstack.org/openstack/networking-ovn.git

3. Configure DevStack to use networking-ovn.

networking-ovn comes with a sample DevStack configuration file you can start
with.  For example, you may want to set some values for the various PASSWORD
variables in that file so DevStack doesn't have to prompt you for them.  Feel
free to edit it if you'd like, but it should work as-is.

::

    $ cd devstack
    $ cp ../networking-ovn/devstack/local.conf.sample local.conf

4. Run DevStack.

This is going to take a while.  It installs a bunch of packages, clones a bunch
of git repos, and installs everything from these git repos.

::

    $ ./stack.sh

Once DevStack completes successfully, you should see output that looks something
like this::

    This is your host ip: 192.168.122.8
    Horizon is now available at http://192.168.122.8/
    Keystone is serving at http://192.168.122.8:5000/
    The default users are: admin and demo
    The password: password
    2015-04-30 22:02:40.220 | stack.sh completed in 515 seconds.

Environment Variables
---------------------

Once DevStack finishes successfully, we're ready to start interacting with
OpenStack APIs.  OpenStack provides a set of command line tools for interacting
with these APIs.  DevStack provides a file you can source to set up the right
environment variables to make the OpenStack command line tools work.

::
    $ . openrc

If you're curious what environment variables are set, they generally start with
an OS prefix::

    $ env | grep OS
    OS_REGION_NAME=RegionOne
    OS_IDENTITY_API_VERSION=2.0
    OS_PASSWORD=password
    OS_AUTH_URL=http://192.168.122.8:5000/v2.0
    OS_USERNAME=demo
    OS_TENANT_NAME=demo
    OS_VOLUME_API_VERSION=2
    OS_CACERT=/opt/stack/data/CA/int-ca/ca-chain.pem
    OS_NO_CACHE=1

Default Network Configuration
-----------------------------

DevStack creates two networks by default, called ``public`` and ``private``.
Run the following command to see the two default networks::

    $ neutron net-list
    +--------------------------------------+---------+----------------------------------------------------------+
    | id                                   | name    | subnets                                                  |
    +--------------------------------------+---------+----------------------------------------------------------+
    | c1f33146-1b82-48fb-aad6-493d08fbe492 | public  | f4542319-516e-4d16-af1d-289b9ca999f0                     |
    |                                      |         | 6ae7ac12-f353-4e86-a948-e43a6a94c6aa                     |
    | 266371ca-904e-4433-b653-866f9204d22e | private | 64bc14c2-52a6-4188-aaeb-d24922125c2c fde5:95da:6b50::/64 |
    |                                      |         | 299d182b-2f2c-44e2-9bc9-d094b9ea317b 10.0.0.0/24         |
    +--------------------------------------+---------+----------------------------------------------------------+

A Neutron network is implemented as an OVN logical switch.  networking-ovn
creates logical switches with a name in the format neutron-<network UUID>.  So,
we can use ``ovn-nbctl`` to list the configured logical switches and see that
their names correlate with the output from ``neutron net-list``::

    $ ovn-nbctl lswitch-list
    c628c46a-372f-412b-8edf-eb3408b021ca (neutron-266371ca-904e-4433-b653-866f9204d22e)
    f4e6e393-a8a3-4066-b6c5-eb1ac253d02f (neutron-c1f33146-1b82-48fb-aad6-493d08fbe492)

    $ ovn-nbctl lswitch-get-external-id neutron-266371ca-904e-4433-b653-866f9204d22e
    neutron:network_name=private

    $ ovn-nbctl lswitch-get-external-id neutron-c1f33146-1b82-48fb-aad6-493d08fbe492
    neutron:network_name=public

Some Neutron ports are created by default, as well.  These ports are actually an
implementation detail of the Neutron DHCP and L3 agents that are currently in
use.

::

    $ neutron port-list
    +--------------------------------------+------+-------------------+-------------------------------------------------------------------------------------------------------------+
    | id                                   | name | mac_address       | fixed_ips |
    +--------------------------------------+------+-------------------+-------------------------------------------------------------------------------------------------------------+
    | 23c42fca-fa51-4e06-9d4e-2bf2888604eb |      | fa:16:3e:ba:f3:0c | {"subnet_id": "64bc14c2-52a6-4188-aaeb-d24922125c2c", "ip_address": "fde5:95da:6b50::1"}                    |
    | 51f98e51-143b-4968-a7a9-e2d8d419b246 |      | fa:16:3e:6e:63:b1 | {"subnet_id": "299d182b-2f2c-44e2-9bc9-d094b9ea317b", "ip_address": "10.0.0.2"}                             |
    |                                      |      |                   | {"subnet_id": "64bc14c2-52a6-4188-aaeb-d24922125c2c", "ip_address": "fde5:95da:6b50:0:f816:3eff:fe6e:63b1"} |
    | 9920b86a-a7fe-4fd5-a162-9a619d79c2d8 |      | fa:16:3e:4f:d2:c7 | {"subnet_id": "299d182b-2f2c-44e2-9bc9-d094b9ea317b", "ip_address": "10.0.0.1"}                             |
    +--------------------------------------+------+-------------------+-------------------------------------------------------------------------------------------------------------+

..
    TODO Go into more detail about the DHCP and L3 agents and how to figure out
    which ports are associated with which.

Booting VMs
-----------

In this section we'll go through the steps to create two VMs that have a virtual
NIC attached to the ``private`` Neutron network.  

DevStack uses libvirt as the Nova backend by default.  If KVM is available, it
will be used.  Otherwise, it will just run qemu emulated guests.  This is
perfectly fine for our testing, as we only need these VMs to be able to send and
receive a small amount of traffic so performance is not very important.

1. Get the Network UUID.

Start by getting the UUID for the ``private`` network from the output of
``neutron net-list`` from earlier and save it off::

    $ PRIVATE_NET_ID=266371ca-904e-4433-b653-866f9204d22e

2. Create an SSH keypair.

Next create an SSH keypair in Nova.  Later, when we boot a VM, we'll ask that
the public key be put in the VM so we can SSH into it.

::

    $ nova keypair-add demo > id_rsa_demo
    $ chmod 600 id_rsa_demo

3. Choose a flavor.

We need minimal resources for these test VMs, so the ``m1.nano`` flavor is sufficient.

::

    $ nova flavor-list
    +----+-----------+-----------+------+-----------+------+-------+-------------+-----------+
    | ID | Name      | Memory_MB | Disk | Ephemeral | Swap | VCPUs | RXTX_Factor | Is_Public |
    +----+-----------+-----------+------+-----------+------+-------+-------------+-----------+
    | 1  | m1.tiny   | 512       | 1    | 0         |      | 1     | 1.0         | True      |
    | 2  | m1.small  | 2048      | 20   | 0         |      | 1     | 1.0         | True      |
    | 3  | m1.medium | 4096      | 40   | 0         |      | 2     | 1.0         | True      |
    | 4  | m1.large  | 8192      | 80   | 0         |      | 4     | 1.0         | True      |
    | 42 | m1.nano   | 64        | 0    | 0         |      | 1     | 1.0         | True      |
    | 5  | m1.xlarge | 16384     | 160  | 0         |      | 8     | 1.0         | True      |
    | 84 | m1.micro  | 128       | 0    | 0         |      | 1     | 1.0         | True      |
    +----+-----------+-----------+------+-----------+------+-------+-------------+-----------+

    $ FLAVOR_ID=42

4. Choose an image.

DevStack imports the CirrOS image by default, which is perfect for our testing.
It's a very small test image.

::

    $ glance image-list
    +--------------------------------------+---------------------------------+-------------+------------------+----------+--------+
    | ID                                   | Name                            | Disk Format | Container Format | Size     | Status |
    +--------------------------------------+---------------------------------+-------------+------------------+----------+--------+
    | 2698bd5b-e493-4ea7-8d4a-e30c14df5c80 | cirros-0.3.2-x86_64-uec         | ami         | ami              | 25165824 | active |
    | 498648c1-6778-47cb-a16d-245b6905a9e8 | cirros-0.3.2-x86_64-uec-kernel  | aki         | aki              | 4969360  | active |
    | 40f13663-142c-4e6c-ac1f-5df5ebe090c0 | cirros-0.3.2-x86_64-uec-ramdisk | ari         | ari              | 3723817  | active |
    +--------------------------------------+---------------------------------+-------------+------------------+----------+--------+

    $ IMAGE_ID=2698bd5b-e493-4ea7-8d4a-e30c14df5c80

5. Boot some VMs.

Now we will boot two VMs.  We'll name them ``test1`` and ``test2``.

::

    $ nova boot --nic net-id=$PRIVATE_NET_ID --flavor $FLAVOR_ID --image $IMAGE_ID --key-name demo test1
    +--------------------------------------+----------------------------------------------------------------+
    | Property                             | Value                                                          |
    +--------------------------------------+----------------------------------------------------------------+
    | OS-DCF:diskConfig                    | MANUAL                                                         |
    | OS-EXT-AZ:availability_zone          | nova                                                           |
    | OS-EXT-STS:power_state               | 0                                                              |
    | OS-EXT-STS:task_state                | scheduling                                                     |
    | OS-EXT-STS:vm_state                  | building                                                       |
    | OS-SRV-USG:launched_at               | -                                                              |
    | OS-SRV-USG:terminated_at             | -                                                              |
    | accessIPv4                           |                                                                |
    | accessIPv6                           |                                                                |
    | adminPass                            | aQJMqi8vAWJP                                                   |
    | config_drive                         |                                                                |
    | created                              | 2015-05-01T01:55:27Z                                           |
    | flavor                               | m1.nano (42)                                                   |
    | hostId                               |                                                                |
    | id                                   | 571f622e-8f65-4617-9b39-6a04438f394f                           |
    | image                                | cirros-0.3.2-x86_64-uec (2698bd5b-e493-4ea7-8d4a-e30c14df5c80) |
    | key_name                             | demo                                                           |
    | metadata                             | {}                                                             |
    | name                                 | test1                                                          |
    | os-extended-volumes:volumes_attached | []                                                             |
    | progress                             | 0                                                              |
    | security_groups                      | default                                                        |
    | status                               | BUILD                                                          |
    | tenant_id                            | c41f413079aa4389b7a41932cd8a6be6                               |
    | updated                              | 2015-05-01T01:55:27Z                                           |
    | user_id                              | 98978389ceb3433cb1db3f64da217ee0                               |
    +--------------------------------------+----------------------------------------------------------------+

    $ nova boot --nic net-id=$PRIVATE_NET_ID --flavor $FLAVOR_ID --image $IMAGE_ID --key-name demo test2
    +--------------------------------------+----------------------------------------------------------------+
    | Property                             | Value                                                          |
    +--------------------------------------+----------------------------------------------------------------+
    | OS-DCF:diskConfig                    | MANUAL                                                         |
    | OS-EXT-AZ:availability_zone          | nova                                                           |
    | OS-EXT-STS:power_state               | 0                                                              |
    | OS-EXT-STS:task_state                | scheduling                                                     |
    | OS-EXT-STS:vm_state                  | building                                                       |
    | OS-SRV-USG:launched_at               | -                                                              |
    | OS-SRV-USG:terminated_at             | -                                                              |
    | accessIPv4                           |                                                                |
    | accessIPv6                           |                                                                |
    | adminPass                            | HxAQk8pSi53d                                                   |
    | config_drive                         |                                                                |
    | created                              | 2015-05-01T01:55:33Z                                           |
    | flavor                               | m1.nano (42)                                                   |
    | hostId                               |                                                                |
    | id                                   | 7a8c12da-54b3-4adf-bba5-74df9fd2e907                           |
    | image                                | cirros-0.3.2-x86_64-uec (2698bd5b-e493-4ea7-8d4a-e30c14df5c80) |
    | key_name                             | demo                                                           |
    | metadata                             | {}                                                             |
    | name                                 | test2                                                          |
    | os-extended-volumes:volumes_attached | []                                                             |
    | progress                             | 0                                                              |
    | security_groups                      | default                                                        |
    | status                               | BUILD                                                          |
    | tenant_id                            | c41f413079aa4389b7a41932cd8a6be6                               |
    | updated                              | 2015-05-01T01:55:33Z                                           |
    | user_id                              | 98978389ceb3433cb1db3f64da217ee0                               |
    +--------------------------------------+----------------------------------------------------------------+

Once both VMs have been started, they will have a status of ``ACTIVE``::

    $ nova list
    +--------------------------------------+-------+--------+------------+-------------+--------------------------------------------------------+
    | ID                                   | Name  | Status | Task State | Power State | Networks                                               |
    +--------------------------------------+-------+--------+------------+-------------+--------------------------------------------------------+
    | 571f622e-8f65-4617-9b39-6a04438f394f | test1 | ACTIVE | -          | Running     | private=fde5:95da:6b50:0:f816:3eff:fe92:579a, 10.0.0.3 |
    | 7a8c12da-54b3-4adf-bba5-74df9fd2e907 | test2 | ACTIVE | -          | Running     | private=fde5:95da:6b50:0:f816:3eff:fe42:cbc7, 10.0.0.4 |
    +--------------------------------------+-------+--------+------------+-------------+--------------------------------------------------------+

SSH into one VM and ping the other::

    $ ssh -i id_rsa_demo cirros@10.0.0.3

    (cirros)$ ping 10.0.0.4
    PING 10.0.0.4 (10.0.0.4): 56 data bytes
    64 bytes from 10.0.0.4: seq=0 ttl=64 time=0.803 ms

If we look at the console log of one of the VMs, we can see that it got its
address using DHCP::

    $ nova console-log test1
    ...
    Starting network...
    udhcpc (v1.20.1) started
    Sending discover...
    Sending select for 10.0.0.3...
    Lease of 10.0.0.3 obtained, lease time 86400
    deleting routers
    adding dns 10.0.0.2
    ...

Our two VMs have addresses of ``10.0.0.3`` and ``10.0.0.4``.  If we list Neutron
ports again, there are two new ports with these addresses associated with the::

    $ neutron port-list
    +--------------------------------------+------+-------------------+-------------------------------------------------------------------------------------------------------------+
    | id                                   | name | mac_address       | fixed_ips                                                                                                   |
    +--------------------------------------+------+-------------------+-------------------------------------------------------------------------------------------------------------+
    | 23c42fca-fa51-4e06-9d4e-2bf2888604eb |      | fa:16:3e:ba:f3:0c | {"subnet_id": "64bc14c2-52a6-4188-aaeb-d24922125c2c", "ip_address": "fde5:95da:6b50::1"}                    |
    | 51f98e51-143b-4968-a7a9-e2d8d419b246 |      | fa:16:3e:6e:63:b1 | {"subnet_id": "299d182b-2f2c-44e2-9bc9-d094b9ea317b", "ip_address": "10.0.0.2"}                             |
    |                                      |      |                   | {"subnet_id": "64bc14c2-52a6-4188-aaeb-d24922125c2c", "ip_address": "fde5:95da:6b50:0:f816:3eff:fe6e:63b1"} |
    | 9920b86a-a7fe-4fd5-a162-9a619d79c2d8 |      | fa:16:3e:4f:d2:c7 | {"subnet_id": "299d182b-2f2c-44e2-9bc9-d094b9ea317b", "ip_address": "10.0.0.1"}                             |
    | d660a917-5095-4bd0-92c5-d0abdffb600b |      | fa:16:3e:42:cb:c7 | {"subnet_id": "299d182b-2f2c-44e2-9bc9-d094b9ea317b", "ip_address": "10.0.0.4"}                             |
    |                                      |      |                   | {"subnet_id": "64bc14c2-52a6-4188-aaeb-d24922125c2c", "ip_address": "fde5:95da:6b50:0:f816:3eff:fe42:cbc7"} |
    | e3800c90-24d4-49ad-abb2-041a2e3dd259 |      | fa:16:3e:92:57:9a | {"subnet_id": "299d182b-2f2c-44e2-9bc9-d094b9ea317b", "ip_address": "10.0.0.3"}                             |
    |                                      |      |                   | {"subnet_id": "64bc14c2-52a6-4188-aaeb-d24922125c2c", "ip_address": "fde5:95da:6b50:0:f816:3eff:fe92:579a"} |
    +--------------------------------------+------+-------------------+-------------------------------------------------------------------------------------------------------------+

    $ TEST1_PORT_ID=e3800c90-24d4-49ad-abb2-041a2e3dd259
    $ TEST2_PORT_ID=d660a917-5095-4bd0-92c5-d0abdffb600b

Now we can look at OVN using ``ovn-nbctl`` to see the logical ports that were
created for these two Neutron ports.  The first part of the output is the OVN
logical port UUID.  The second part in parentheses is the logical port name.
Neutron sets the logical port name equal to the Neutron port ID.

::

    $ ovn-nbctl lport-list neutron-$PRIVATE_NET_ID
    1117ac4e-1c83-4fd5-bb16-6c9c11150446 (e3800c90-24d4-49ad-abb2-041a2e3dd259)
    e8ceb496-c2ee-4f9d-81d5-4c06a9754ed3 (9920b86a-a7fe-4fd5-a162-9a619d79c2d8)
    baa38f9a-b5e4-46d7-8a5d-f264ccfa28f7 (23c42fca-fa51-4e06-9d4e-2bf2888604eb)
    9be0ab27-1565-4b92-b2d2-c4578e90c46d (d660a917-5095-4bd0-92c5-d0abdffb600b)
    1e81abcf-574b-4533-8202-da182491724c (51f98e51-143b-4968-a7a9-e2d8d419b246)

We noted before that the default network setup created 3 ports.  2 more ports
have been added after we booted our two test VMs::

    1117ac4e-1c83-4fd5-bb16-6c9c11150446 (e3800c90-24d4-49ad-abb2-041a2e3dd259)
    9be0ab27-1565-4b92-b2d2-c4578e90c46d (d660a917-5095-4bd0-92c5-d0abdffb600b)

..
    TODO: Show how to look at the corresponding configuration of OVS.

Adding Another Compute Node
---------------------------

After completing the earlier instructions for setting up devstack, you can use a
second VM to emulate an additional compute node.  This is important for OVN
testing as it exercises the tunnels created by OVN between the hypervisors.

Just as before, create a throwaway VM.  Create a user with sudo access and
install git.

::

     $ git clone http://git.openstack.org/openstack-dev/devstack.git
     $ git clone http://git.openstack.org/openstack/networking-ovn.git

networking-ovn comes with another sample configuration file that can be used for
this::

     $ cd devstack
     $ cp ../networking-ovn/devstack/computenode-local.conf.sample local.conf

You must set SERVICE_HOST in local.conf.  The value should be the IP address of
the main DevStack host.  See the text in the sample configuration file for more
information.  Once that is complete, run DevStack::

    $ cd devstack
    $ ./stack.sh

This should complete in less time than before, as it's only running a single
OpenStack service (nova-compute) along with OVN (ovn-controller, ovs-vswitchd,
ovsdb-server).  The final output will look something like this::

    This is your host ip: 172.16.189.10
    2015-05-09 01:21:49.565 | stack.sh completed in 308 seconds.

Now go back to your main DevStack host.  You can use admin credentials to verify
that the additional hypervisor has been added to the deployment::

    $ cd devstack
    $ . openrc admin

    $ nova hypervisor-list
    +----+------------------------------------+-------+---------+
    | ID | Hypervisor hostname                | State | Status  |
    +----+------------------------------------+-------+---------+
    | 1  | ovn-devstack-1                     | up    | enabled |
    | 2  | ovn-devstack-2                     | up    | enabled |
    +----+------------------------------------+-------+---------+

You can also look at OVN and OVS to see that the second host has shown up.  For
example, there will be a second entry in the Chassis table of the OVN_Southbound
database::

    $ ovsdb-client dump OVN_Southbound

    ...

    Chassis table
    _uuid                                encaps                                 gateway_ports name
    ------------------------------------ -------------------------------------- ------------- --------------------------------------
    68933e4a-7a1e-4a41-af77-6cd1bfdc953a [e3a766c2-bec0-4f65-b9d7-72a89df87e95] {}            "719834e5-dd0f-482f-985d-442aca51180f"
    518702e9-ffc2-4e27-8057-8ebd155ea436 [b8793b59-195c-4e8e-8898-399f52139870] {}            "ac780a06-76a3-4b85-859a-450de7170201"

    ...

You can also see a tunnel created to the other compute node::

    $ ovs-vsctl show

    ...

    Bridge br-int
        fail_mode: secure
        Port "ovn-90b4d4-0"
            Interface "ovn-90b4d4-0"
                type: geneve
                options: {key=flow, remote_ip="172.16.189.10"}

    ...

Provider Networks
-----------------

Neutron has a "provider networks" API extension that lets you specify
some additional attributes on a network.  These attributes let you
map a Neutron network to a physical network in your environment.
The OVN plugin is adding support for this API extension.  It currently
supports "flat" and "vlan" networks.

Here is how you can test it:

First you must create an OVS bridge that provides connectivity to the
provider network on every host running ovn-controller.  For trivial
testing this could just be a dummy bridge.  In a real environment, you
would want to add a local network interface to the bridge, as well.

::

    $ ovs-vsctl add-br br-provider

ovn-controller on each host must be configured with a mapping between
a network name and the bridge that provides connectivity to that network.
In this case we'll create a mapping from the network name "providernet"
to the bridge 'br-provider".

::

    $ ovs-vsctl set open . \
    external-ids:ovn-bridge-mappings=providernet:br-provider

At this point you should be able to observe that ovn-controller
automatically created patch ports between br-int and br-provider.

::

    $ ovs-vsctl show
    ...
    Bridge br-provider
        Port br-provider
            Interface br-provider
                type: internal
        Port patch-br-provider-to-br-int
            Interface patch-br-provider-to-br-int
                type: patch
                options: {peer=patch-br-int-to-br-provider}
    Bridge br-int
        ...
        Port patch-br-int-to-br-provider
            Interface patch-br-int-to-br-provider
                type: patch
                options: {peer=patch-br-provider-to-br-int}
        ...


Now create a Neutron provider network.

::

    $ neutron net-create provider --shared \
    --provider:physical_network providernet \
    --provider:network_type flat

Alternatively, you can define connectivity to a VLAN instead of a flat network:

::

    $ neutron net-create provider-101 --shared \
    --provider:physical_network providernet \
    --provider:network_type vlan \
    --provider:segmentation_id 101

Finally, create a Neutron port on the provider network.

::

    $ neutron port-create provider

or if you followed the VLAN example, it would be:

::

    $ neutron port-create provider-101

Observe that the OVN plugin created a special logical switch that models
the connection between this port and the provider network.

::

    $ ovn-nbctl show
    ...
     lswitch 5bbccbbd-f5ca-411b-bad9-01095d6f1316 (neutron-729dbbee-db84-4a3d-afc3-82c0b3701074)
         lport provnet-729dbbee-db84-4a3d-afc3-82c0b3701074
             macs: unknown
         lport 729dbbee-db84-4a3d-afc3-82c0b3701074
             macs: fa:16:3e:20:38:d1
    ...

    $ ovn-nbctl lport-get-type provnet-729dbbee-db84-4a3d-afc3-82c0b3701074
    localnet

    $ ovn-nbctl lport-get-options provnet-729dbbee-db84-4a3d-afc3-82c0b3701074
    network_name=providernet

Troubleshooting
---------------

If you run into any problems, take a look at our troubleshooting_ page.

Additional Resources
--------------------

These resources may also help with testing out and understanding OVN:

* http://blog.russellbryant.net/2015/04/08/ovn-and-openstack-integration-development-update/
* http://blog.russellbryant.net/2015/04/21/ovn-and-openstack-status-2015-04-21/
* http://galsagie.github.io/sdn/openstack/ovs/2015/04/26/ovn-containers/
* http://blog.russellbryant.net/2015/05/14/an-ez-bake-ovn-for-openstack/
* http://galsagie.github.io/sdn/openstack/ovs/2015/05/30/ovn-deep-dive/

OVN architecture documents and DB schema explanations:

* http://benpfaff.org/~blp/dist-docs/ovn-architecture.7.html
* http://benpfaff.org/~blp/dist-docs/ovn-nb.5.html
* http://benpfaff.org/~blp/dist-docs/ovn.5.html

..
    TODO: multi-node testing

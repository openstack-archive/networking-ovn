Container Integration with OVN
=================================

OVN supports virtual networking for both VMs and containers.  There are two
modes OVN can operate in with respect to containers.  The first mode looks just
like it does with VMs.  If you're running a bunch of containers in a cluster of
VMs, OVN can be used to provide a virtual networking overlay for those
containers to use.

The second mode is very interesting in the context of OpenStack.  OVN makes
special accommodation for running containers inside of VMs when the networking
for those VMs is already being managed by OVN.  You can create a special type
of port in OVN for these containers and have them directly connected to virtual
networks managed by OVN.  There are two major benefits of this:

* It allows containers to use virtual networks without creating another layer
  of overlay networks.  This reduces networking complexity and increases
  performance.

* It allows arbitrary connections between any VMs and any containers running
  inside VMs.

Creating a Container Port
------------------------------

A container port has two additional attributes that do not exist with a normal
Neutron port.  First, you must specify the parent port that the VM is using.
Second, you must specify a tag.  This tag is a VLAN ID today, though that may
change in the future.  Traffic from the container must be tagged with this VLAN
ID by open vSwitch running inside the VM.  Traffic destined for the container
will arrive on the parent VM port with this VLAN ID.  Open vSwitch inside the
VM will forward this traffic to the container.

These two attributes are not currently supported in the Neutron API.  As a
result, we are initially allowing these attributes to be set in the
'binding:profile' extension for ports.  If this approach gains traction and
more general support, we will revisit making this a real extension to the
Neutron API.

Note that the default /etc/neutron/policy.json does not allow a regular user
to set a 'binding:profile'.  If you want to allow this, you must update
policy.json.  To do so, change::

    "create_port:binding:profile": "rule:admin_only",

to::

    "create_port:binding:profile": "",

Here is an example of creating a port for a VM, and then creating a port for a
container that runs inside of that VM::

    $ neutron port-create private
    Created a new port:
    +-----------------------+---------------------------------------------------------------------------------+
    | Field                 | Value                                                                           |
    +-----------------------+---------------------------------------------------------------------------------+
    | admin_state_up        | True                                                                            |
    | allowed_address_pairs |                                                                                 |
    | binding:vnic_type     | normal                                                                          |
    | device_id             |                                                                                 |
    | device_owner          |                                                                                 |
    | fixed_ips             | {"subnet_id": "ce5e0d61-10a1-44be-b917-f628616d686a", "ip_address": "10.0.0.3"} |
    | id                    | 74e43404-f3c2-4f13-aeec-934db4e2de35                                            |
    | mac_address           | fa:16:3e:c5:a9:74                                                               |
    | name                  |                                                                                 |
    | network_id            | f654265f-baa6-4351-9d76-b5693521c521                                            |
    | security_groups       | fe25592f-3610-48b9-a114-4ec834c52349                                            |
    | status                | DOWN                                                                            |
    | tenant_id             | db75dd6671ef4858a7fed450f1f8e995                                                |
    +-----------------------+---------------------------------------------------------------------------------+

    $ neutron port-create --binding-profile '{"parent_name":"74e43404-f3c2-4f13-aeec-934db4e2de35","tag":42}' private
    Created a new port:
    +-----------------------+---------------------------------------------------------------------------------+
    | Field                 | Value                                                                           |
    +-----------------------+---------------------------------------------------------------------------------+
    | admin_state_up        | True                                                                            |
    | allowed_address_pairs |                                                                                 |
    | binding:vnic_type     | normal                                                                          |
    | device_id             |                                                                                 |
    | device_owner          |                                                                                 |
    | fixed_ips             | {"subnet_id": "ce5e0d61-10a1-44be-b917-f628616d686a", "ip_address": "10.0.0.4"} |
    | id                    | be155d07-ecd9-4ad7-91e5-5be60684572a                                            |
    | mac_address           | fa:16:3e:74:ef:82                                                               |
    | name                  |                                                                                 |
    | network_id            | f654265f-baa6-4351-9d76-b5693521c521                                            |
    | security_groups       | fe25592f-3610-48b9-a114-4ec834c52349                                            |
    | status                | DOWN                                                                            |
    | tenant_id             | db75dd6671ef4858a7fed450f1f8e995                                                |
    +-----------------------+---------------------------------------------------------------------------------+

Now we can look at the corresponding logical switch ports in OVN to see that
the parent and tag were set as expected::

    $ ovn-nbctl lsp-get-parent be155d07-ecd9-4ad7-91e5-5be60684572a
    74e43404-f3c2-4f13-aeec-934db4e2de35

    $ ovn-nbctl lsp-get-tag be155d07-ecd9-4ad7-91e5-5be60684572a
    42

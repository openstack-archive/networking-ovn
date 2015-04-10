Mapping between Neutron and OVN data models
========================================================

The primary job of the OVN ML2 mechanism driver is to translate requests for
resources into OVN's data model.  Resources are created in OVN by updating the
appropriate tables in the OVN northbound database (an ovsdb database).  This
document looks at the mappings between the data that exists in Neutron and what
the resulting entries in the OVN northbound DB would look like.


Network
----------

::

    Neutron Network:
        id
        name
        subnets
        admin_state_up
        status
        tenant_id

Once a network is created, we should create an entry in the Logical Switch table.

::

    OVN northbound DB Logical Switch:
        external_ids: {
            'neutron:network_id': network.id,
            'neutron:network_name': network.name
        }


Subnet
---------

::

    Neutron Subnet:
        id
        name
        ip_version
        network_id
        cidr
        gateway_ip
        allocation_pools
        dns_nameservers
        host_routers
        tenant_id
        enable_dhcp
        ipv6_ra_mode
        ipv6_address_mode

Nothing is needed here for now.  When OVN supports DHCP, we will need to feed
this info into OVN.


Port
-------

::

    Neutron Port:
        id
        name
        network_id
        admin_state_up
        mac_address
        fixed_ips
        device_id
        device_owner
        tenant_id
        status

When a port is created, we should create an entry in the Logical Switch Ports
table in the OVN northbound DB.

::

    OVN Northbound DB Logical Switch Port:
        switch: reference to OVN Logical Switch
        router_port: (empty)
        name: port.id
        up: (read-only)
        macs: [port.mac_address]
        port_security:
        external_ids: {'neutron:port_name': port.name}


Router
----------

::

    Neutron Router:
        id
        name
        admin_state_up
        status
        tenant_id
        external_gw_info:
            network_id
            external_fixed_ips: list of dicts
                ip_address
                subnet_id

...

::

    OVN Northbound DB Logical Router:
        ip:
        default_gw:
        external_ids:


Router Port
--------------

...

::

    OVN Northbound DB Logical Router Port:
        router: (reference to Logical Router)
        network: (refernce to network this port is connected to)
        mac:
        external_ids:

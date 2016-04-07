# Utility functions that create subnets, networks, routers, etc
# These were copied mostly from devstack's neutron-legacy script
# so they could be used by the networking-ovn devstack plugin

function create_public_subnet_v4 {
    # Create public IPv4 subnet
    # This function is copied directly from the devstack neutron-legacy script
    local subnet_params+="--ip_version 4 "
    subnet_params+="${Q_FLOATING_ALLOCATION_POOL:+--allocation-pool $Q_FLOATING_ALLOCATION_POOL} "
    subnet_params+="--gateway $PUBLIC_NETWORK_GATEWAY "
    subnet_params+="--name $PUBLIC_SUBNET_NAME "
    subnet_params+="$EXT_NET_ID $FLOATING_RANGE "
    subnet_params+="-- --enable_dhcp=False"
    local id_and_ext_gw_ip
    id_and_ext_gw_ip=$(neutron subnet-create $subnet_params | grep -e 'gateway_ip' -e ' id ')
    die_if_not_set $LINENO id_and_ext_gw_ip "Failure creating public IPv4 subnet"
    echo $id_and_ext_gw_ip
}

function create_public_subnet_v6 {
    # Create public IPv6 subnet
    # This function is copied directly from the devstack neutron-legacy script
    local subnet_params="--ip_version 6 "
    subnet_params+="--gateway $IPV6_PUBLIC_NETWORK_GATEWAY "
    subnet_params+="--name $IPV6_PUBLIC_SUBNET_NAME "
    subnet_params+="$EXT_NET_ID $IPV6_PUBLIC_RANGE "
    subnet_params+="-- --enable_dhcp=False"
    local ipv6_id_and_ext_gw_ip
    ipv6_id_and_ext_gw_ip=$(neutron subnet-create $subnet_params | grep -e 'gateway_ip' -e ' id ')
    die_if_not_set $LINENO ipv6_id_and_ext_gw_ip "Failure creating an IPv6 public subnet"
    echo $ipv6_id_and_ext_gw_ip
}

function add_net_subnet_router {
    # Create the public network, subnet(s) and router
    # This is based on the devstack neutron-legacy
    # create_neutron_initial_network function
    project_id=$(openstack project list | grep " demo " | get_field 1)
    die_if_not_set $LINENO project_id "Failure retrieving project_id for demo"

    # Create a router, and add the private subnet as one of its interfaces
    if [[ "$Q_L3_ROUTER_PER_TENANT" == "True" ]]; then
        # create a tenant-owned router.
        ROUTER_ID=$(neutron router-create --tenant-id $project_id $Q_ROUTER_NAME | grep ' id ' | get_field 2)
        die_if_not_set $LINENO ROUTER_ID "Failure creating ROUTER_ID for $project_id $Q_ROUTER_NAME"
    else
        # Plugin only supports creating a single router, which should be admin owned.
        ROUTER_ID=$(neutron router-create $Q_ROUTER_NAME | grep ' id ' | get_field 2)
        die_if_not_set $LINENO ROUTER_ID "Failure creating ROUTER_ID for $Q_ROUTER_NAME"
    fi

    # if the extension is available, then mark the external
    # network as default, and provision default subnetpools
    EXTERNAL_NETWORK_FLAGS="--router:external"
    if [[ -n $AUTO_ALLOCATE_EXT && -n $SUBNETPOOL_EXT ]]; then
        EXTERNAL_NETWORK_FLAGS="$EXTERNAL_NETWORK_FLAGS --is-default"
        if [[ "$IP_VERSION" =~ 4.* ]]; then
            SUBNETPOOL_V4_ID=$(neutron subnetpool-create $SUBNETPOOL_NAME --default-prefixlen $SUBNETPOOL_SIZE_V4 --pool-prefix $SUBNETPOOL_PREFIX_V4 --shared --is-default=True | grep ' id ' | get_field 2)
        fi
        if [[ "$IP_VERSION" =~ .*6 ]]; then
            SUBNETPOOL_V6_ID=$(neutron subnetpool-create $SUBNETPOOL_NAME --default-prefixlen $SUBNETPOOL_SIZE_V6 --pool-prefix $SUBNETPOOL_PREFIX_V6 --shared --is-default=True | grep ' id ' | get_field 2)
        fi
    fi
    # Create an external network, and a subnet. Configure the external network as router gw
    if [ "$Q_USE_PROVIDERNET_FOR_PUBLIC" = "True" ]; then
        EXT_NET_ID=$(neutron net-create "$PUBLIC_NETWORK_NAME" -- $EXTERNAL_NETWORK_FLAGS --provider:network_type=flat --provider:physical_network=${PUBLIC_PHYSICAL_NETWORK} | grep ' id ' | get_field 2)
    else
        EXT_NET_ID=$(neutron net-create "$PUBLIC_NETWORK_NAME" -- $EXTERNAL_NETWORK_FLAGS | grep ' id ' | get_field 2)
    fi
    die_if_not_set $LINENO EXT_NET_ID "Failure creating EXT_NET_ID for $PUBLIC_NETWORK_NAME"

    if [[ "$IP_VERSION" =~ 4.* ]]; then
        # Configure router for IPv4 public access
        #_neutron_configure_router_v4
        neutron router-interface-add $ROUTER_ID $SUBNET_ID
        # Create a public subnet on the external network
        local id_and_ext_gw_ip
        id_and_ext_gw_ip=$(create_public_subnet_v4 $EXT_NET_ID)
        local ext_gw_ip
        ext_gw_ip=$(echo $id_and_ext_gw_ip  | get_field 2)
        PUB_SUBNET_ID=$(echo $id_and_ext_gw_ip | get_field 5)
        # Configure the external network as the default router gateway
        neutron router-gateway-set $ROUTER_ID $EXT_NET_ID
    fi

    if [[ "$IP_VERSION" =~ .*6 ]]; then
        # Configure router for IPv6 public access
        #_neutron_configure_router_v6
        neutron router-interface-add $ROUTER_ID $IPV6_SUBNET_ID
        # Create a public subnet on the external network
        local ipv6_id_and_ext_gw_ip
        ipv6_id_and_ext_gw_ip=$(create_public_subnet_v6 $EXT_NET_ID)
        local ipv6_ext_gw_ip
        ipv6_ext_gw_ip=$(echo $ipv6_id_and_ext_gw_ip | get_field 2)
        local ipv6_pub_subnet_id
        ipv6_pub_subnet_id=$(echo $ipv6_id_and_ext_gw_ip | get_field 5)

        # If the external network has not already been set as the default router
        # gateway when configuring an IPv4 public subnet, do so now
        if [[ "$IP_VERSION" == "6" ]]; then
            neutron router-gateway-set $ROUTER_ID $EXT_NET_ID
        fi
    fi
}

function get_ext_gw_interface {
    # Get ext_gw_interface depending on value of Q_USE_PUBLIC_VETH
    # This function is copied directly from the devstack neutron-legacy script
    if [[ "$Q_USE_PUBLIC_VETH" == "True" ]]; then
        echo $Q_PUBLIC_VETH_EX
    else
        # Disable in-band as we are going to use local port
        # to communicate with VMs
        sudo ovs-vsctl set Bridge $PUBLIC_BRIDGE \
            other_config:disable-in-band=true
        echo $PUBLIC_BRIDGE
    fi
}

function add_public_network_id_to_tempest_conf {
    # Put the public network id into the tempest config file
    # This is taken from the devstack lib/tempest configure_tempest function
    public_net_id=$(neutron net-list | grep $PUBLIC_NETWORK_NAME | \
            awk '{print $2}')
    iniset $TEMPEST_CONFIG network public_network_id "$public_net_id"
}

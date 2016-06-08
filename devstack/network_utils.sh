# Network utility functions that were copied mostly from
# devstack's neutron-legacy script so they could be used
# by the networking-ovn devstack plugin

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

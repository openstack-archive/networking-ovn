#!/bin/bash

function provider_setup {
    sudo ovs-vsctl --may-exist add-br br-provider -- set bridge br-provider protocols=OpenFlow13
    sudo ovs-vsctl set open . external-ids:ovn-bridge-mappings=provider:br-provider

    # Save the existing address from eth2 and add it to br-provider
    PROVADDR=$(ip -4 addr show eth2 | grep -oP "(?<=inet ).*(?= brd)")
    if [ -n "$PROVADDR" ]; then
        sudo ip addr flush dev eth2
        sudo ip addr add $PROVADDR dev br-provider
        sudo ip link set br-provider up
        sudo ovs-vsctl --may-exist add-port br-provider eth2
    fi
}

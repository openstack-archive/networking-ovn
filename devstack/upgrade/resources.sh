#!/bin/bash

set -o errexit

source $GRENADE_DIR/grenaderc
source $GRENADE_DIR/functions

source $TOP_DIR/openrc admin admin

OVN_TEST_NETWORK=ovn-test-net

function early_create {
    :
}

function create {
    local net_id
    net_id=$(openstack network create $OVN_TEST_NETWORK -f value -c id)
    resource_save ovn net_id $net_id
}

function verify_noapi {
    :
}

function verify {
    local net_id
    net_id=$(resource_get ovn net_id)
    # verifiy will be called in base stage as well. But ovn-nbctl will be
    # installed only during the target stage.
    [ -z $(which ovn-nbctl || true) ] || ovn-nbctl list Logical_Switch neutron-$net_id
}

function destroy {
    local net_id
    net_id=$(resource_get ovn net_id)

    openstack network delete $net_id
}

case $1 in
    "early_create")
        early_create
        ;;
    "create")
        create
        ;;
    "verify_noapi")
        verify_noapi
        ;;
    "verify")
        verify
        ;;
    "destroy")
        destroy
        ;;
    "force_destroy")
        set +o errexit
        destroy
        ;;
esac

#!/usr/bin/env bash

set -ex

VENV=${1:-"dsvm-functional"}

GATE_DEST=$BASE/new
NEUTRON_PATH=$GATE_DEST/neutron
DEVSTACK_PATH=$GATE_DEST/devstack

case $VENV in
"dsvm-functional")
    source $DEVSTACK_PATH/functions
    source $NEUTRON_PATH/devstack/lib/ovs

    # In order to run functional tests, we want to compile OVS
    # from sources and installed. We don't need to start ovs services.
    remove_ovs_packages
    # compile_ovs expects "DEST" to be defined
    DEST=$GATE_DEST
    compile_ovs True /usr/local /var

    # Make the workspace owned by the stack user
    sudo chown -R stack:stack $BASE
    ;;

*)
    echo "Unrecognized environment $VENV".
    exit 1
esac

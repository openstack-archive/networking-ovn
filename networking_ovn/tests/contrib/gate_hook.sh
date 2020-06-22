#!/usr/bin/env bash

set -ex

VENV=${1:-"dsvm-functional"}

GATE_DEST=$BASE/new
NEUTRON_PATH=$GATE_DEST/neutron
DEVSTACK_PATH=$GATE_DEST/devstack
NETWORKING_OVN_PATH=$GATE_DEST/networking-ovn
GATE_STACK_USER=stack

case $VENV in
"dsvm-functional"|"dsvm-functional-py27")
    # The logic to set YUM or DNF as the package manager lives in stackrc,
    # let's source it so it gets applied
    source $DEVSTACK_PATH/stackrc
    source $DEVSTACK_PATH/functions
    source $NEUTRON_PATH/devstack/lib/ovs

    # NOTE(numans) Functional tests after upgrade to xenial in
    # the CI are breaking because of missing six package.
    # Installing the package for now as a workaround
    # https://bugs.launchpad.net/networking-ovn/+bug/1648670
    if python3_enabled; then
        install_package python3-six python3-tox
    else
        install_package python-six python-tox
    fi
    # Install SSL dependencies here for now as a workaround
    # https://bugs.launchpad.net/networking-ovn/+bug/1696713
    if is_fedora ; then
        install_package openssl-devel
    elif is_ubuntu ; then
        install_package libssl-dev
    fi
    # In order to run functional tests, we want to compile OVS
    # from sources and installed. We don't need to start ovs services.
    remove_ovs_packages
    # compile_ovs expects "DEST" to be defined
    DEST=$GATE_DEST
    compile_ovs False /usr/local /var

    # Make the workspace owned by GATE_STACK_USER
    sudo chown -R $GATE_STACK_USER:$GATE_STACK_USER $BASE

    source $NETWORKING_OVN_PATH/tools/configure_for_func_testing.sh

    configure_host_for_func_testing
    ;;

*)
    echo "Unrecognized environment $VENV".
    exit 1
esac

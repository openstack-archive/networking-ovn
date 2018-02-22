#!/usr/bin/env bash

set -ex

VENV=${1:-"dsvm-functional"}

GATE_DEST=$BASE/new
NEUTRON_PATH=$GATE_DEST/neutron
DEVSTACK_PATH=$GATE_DEST/devstack
GATE_STACK_USER=stack

case $VENV in
"dsvm-functional"|"dsvm-functional-py35")
    source $DEVSTACK_PATH/functions
    source $NEUTRON_PATH/devstack/lib/ovs

    # NOTE(numans) Functional tests after upgrade to xenial in
    # the CI are breaking because of missing six package.
    # Installing the package for now as a workaround
    # https://bugs.launchpad.net/networking-ovn/+bug/1648670
    sudo pip install six
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
    # The commit 8bf332225d4a73f359c806ad907bcb78ad2a6087
    # - "ovn-northd: Reduce amount of flow hashing." and the other patches
    # of the series in ovs master has caused regressions because of which
    # functional tests are failing. So use commit -
    # 8b70d82461ea104858ebd7d397ec004f6974240b.
    # We can revert back to master, once the regressions are addressed.
    OVS_BRANCH=8b70d82461ea104858ebd7d397ec004f6974240b
    compile_ovs True /usr/local /var

    # Make the workspace owned by GATE_STACK_USER
    sudo chown -R $GATE_STACK_USER:$GATE_STACK_USER $BASE
    ;;

*)
    echo "Unrecognized environment $VENV".
    exit 1
esac

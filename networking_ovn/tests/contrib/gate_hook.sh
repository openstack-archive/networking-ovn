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
    # Recent OVN DB changes in ACL table has broken the functional tests
    # job. So shifting to OVS 2.7 branch for now, until we handle the
    # DB changes properly in networking-ovn since we want to support both
    # OVS master and the latest OVS branch.
    # TODO (numans) - Revisit it to either shift to master
    # or to pick the latest branch instead of hardcoding it.
    # The other option is to have jobs to run functional tests on both
    # master (may be as non voting) and latest branch.
    OVS_BRANCH=branch-2.7
    compile_ovs True /usr/local /var

    # Make the workspace owned by GATE_STACK_USER
    sudo chown -R $GATE_STACK_USER:$GATE_STACK_USER $BASE
    ;;

*)
    echo "Unrecognized environment $VENV".
    exit 1
esac

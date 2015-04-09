#!/bin/bash
#
# devstack/plugin.sh
# Functions to control the configuration and operation of the OVN service

# Dependencies:
#
# ``functions`` file
# ``DEST`` must be defined
# ``STACK_USER`` must be defined

# ``stack.sh`` calls the entry points in this order:
#
# - install_ovn
# - configure_ovn
# - configure_ovn_plugin
# - init_ovn
# - start_ovn
# - stop_ovn
# - cleanup_ovn

# Save trace setting
XTRACE=$(set +o | grep xtrace)
set +o xtrace


# Defaults
# --------

# The git repo to use
OVN_REPO=${OVN_REPO:-http://github.com/openvswitch/ovs.git}

# The branch to use from $OVN_REPO
OVN_BRANCH=${OVN_BRANCH:-origin/ovn}


# Entry Points
# ------------

# cleanup_ovn() - Remove residual data files, anything left over from previous
# runs that a clean run would need to clean up
function cleanup_ovn {
    :
}

# configure_ovn() - Set config files, create data dirs, etc
function configure_ovn {
    echo "Configuring OVN"
    :
}

function configure_ovn_plugin {
    echo "Configuring Neutron for OVN"

    # TODO: The changes in setup.cfg should have this installed automatically
    # but doesn't seem to be working
    sudo cp $DEST/networking-ovn/etc/ovn.filters /etc/neutron/rootwrap.d/.

    # ovs is installed with a prefix of /usr/local, so neutron-rootwrap needs to
    # be allowed to find the tools installed in /usr/local/bin.
    iniset /etc/neutron/rootwrap.conf DEFAULT exec_dirs \
        "$(iniget /etc/neutron/rootwrap.conf DEFAULT exec_dirs),/usr/local/bin"
}

# init_ovn() - Initialize databases, etc.
function init_ovn {
    # clean up from previous (possibly aborted) runs
    # create required data files

    # Assumption: this is a dedicated test system and there is nothing important
    # in the ovn, ovn-nb, or ovs databases.  We're going to trash them and
    # create new ones on each devstack run.

    base_dir=$DATA_DIR/ovs
    mkdir -p $base_dir

    for db in conf.db ovn.db ovnnb.db ; do
        if [ -f $base_dir/$db ] ; then
            rm -f $base_dir/$db
        fi
    done
    rm -f $base_dir/.*.db.~lock~

    echo "Creating OVS, OVN-Southbound and OVN-Northbound Databases"
    ovsdb-tool create $base_dir/ovn.db $DEST/ovs/ovn/ovn-sb.ovsschema
    ovsdb-tool create $base_dir/ovnnb.db $DEST/ovs/ovn/ovn-nb.ovsschema
    ovsdb-tool create $base_dir/conf.db $DEST/ovs/vswitchd/vswitch.ovsschema
}

# install_ovn() - Collect source and prepare
function install_ovn {
    local _pwd=$(pwd)
    echo "Installing OVN and dependent packages"

    # If OVS is already installed, remove it, because we're about to re-install
    # it from source.
    for package in openvswitch openvswitch-switch openvswitch-common; do
        if is_package_installed $package ; then
            uninstall_package $package
        fi
    done

    setup_develop $DEST/networking-ovn

    REPO_BASE="$(basename $OVN_REPO | cut -f1 -d'.')"
    if [ ! -d $REPO_BASE ] ; then
        git clone $OVN_REPO
        cd $REPO_BASE
        git checkout $OVN_BRANCH
    else
        cd $REPO_BASE
    fi

    # TODO: Can you create package list files like you can inside devstack?
    install_package autoconf automake libtool gcc patch

    if [ ! -f configure ] ; then
        ./boot.sh
    fi
    ./configure
    make -j$[$(nproc) + 1]
    sudo make install
    sudo chown $(whoami) /usr/local/var/run/openvswitch

    cd $_pwd
}

# start_ovn() - Start running processes, including screen
function start_ovn {
    echo "Starting OVN"

    local _pwd=$(pwd)
    cd $DATA_DIR/ovs

    ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
                 --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
                 --remote=ptcp:6640:127.0.0.1 \
                 --pidfile --detach conf.db ovn.db ovnnb.db

    ovs-vsctl --no-wait init

    sudo ovs-vswitchd --pidfile --detach

    cd $_pwd
}

# stop_ovn() - Stop running processes (non-screen)
function stop_ovn {
    sudo killall ovsdb-server
    sudo killall ovs-vswitchd
}

# main loop
if is_service_enabled ovn; then
    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        if [[ "$OFFLINE" != "True" ]]; then
            install_ovn
        fi
        configure_ovn
        init_ovn
        # We have to start at install time, because Neutron's post-config
        # phase runs ovs-vsctl.
        start_ovn
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        configure_ovn_plugin

        if is_service_enabled nova; then
            create_nova_conf_neutron
        fi
    fi

    if [[ "$1" == "unstack" ]]; then
        stop_ovn
        cleanup_ovn
    fi
fi

# Restore xtrace
$XTRACE

# Tell emacs to use shell-script-mode
## Local variables:
## mode: shell-script
## End:

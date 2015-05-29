#!/bin/bash

#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

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
OVN_REPO_NAME=$(basename ${OVN_REPO} | cut -f1 -d'.')

# The branch to use from $OVN_REPO
OVN_BRANCH=${OVN_BRANCH:-origin/ovn}

# How to connect to ovsdb-server hosting the OVN databases.
OVN_REMOTE=${OVN_REMOTE:-tcp:$HOST_IP:6640}

# A UUID to uniquely identify this system.  If one is not specified, a random
# one will be generated.  A randomly generated UUID will be saved in a file
# 'ovn-uuid' so that the same one will be re-used if you re-run DevStack.
OVN_UUID=${OVN_UUID:-}


# Utility Functions
# -----------------

function is_ovn_service_enabled {
    ovn_service=$1
    is_service_enabled ovn && return 0
    is_service_enabled $ovn_service && return 0
    return 1
}


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

    if [ -z "$OVN_UUID" ] ; then
        if [ -f ./ovn-uuid ] ; then
            OVN_UUID=$(cat ovn-uuid)
        else
            OVN_UUID=$(uuidgen)
            echo $OVN_UUID > ovn-uuid
        fi
    fi
}

function configure_ovn_plugin {
    echo "Configuring Neutron for OVN"

    if is_service_enabled q-svc ; then
        NEUTRON_CONF=/etc/neutron/neutron.conf
        iniset $NEUTRON_CONF ovn ovsdb_connection "$OVN_REMOTE"
    fi
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

    for db in conf.db ovnsb.db ovnnb.db ; do
        if [ -f $base_dir/$db ] ; then
            rm -f $base_dir/$db
        fi
    done
    rm -f $base_dir/.*.db.~lock~

    echo "Creating OVS, OVN-Southbound and OVN-Northbound Databases"
    ovsdb-tool create $base_dir/conf.db $DEST/$OVN_REPO_NAME/vswitchd/vswitch.ovsschema
    if is_ovn_service_enabled ovn-northd ; then
        ovsdb-tool create $base_dir/ovnsb.db $DEST/$OVN_REPO_NAME/ovn/ovn-sb.ovsschema
        ovsdb-tool create $base_dir/ovnnb.db $DEST/$OVN_REPO_NAME/ovn/ovn-nb.ovsschema
    fi
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

    if ! is_neutron_enabled ; then
        # networking-ovn depends on neutron, so ensure it at least gets
        # installed.
        install_neutron
    fi

    setup_develop $DEST/networking-ovn

    cd $DEST
    if [ ! -d $OVN_REPO_NAME ] ; then
        git clone $OVN_REPO
        cd $OVN_REPO_NAME
        git checkout $OVN_BRANCH
    else
        cd $OVN_REPO_NAME
    fi

    # TODO: Can you create package list files like you can inside devstack?
    install_package autoconf automake libtool gcc patch

    if [ ! -f configure ] ; then
        ./boot.sh
    fi
    if [ ! -f config.status ] || [ configure -nt config.status ] ; then
        ./configure
    fi
    make -j$[$(nproc) + 1]
    sudo make install
    sudo chown $(whoami) /usr/local/var/run/openvswitch
    sudo chown $(whoami) /usr/local/var/log/openvswitch

    cd $_pwd
}

function start_ovs {
    echo "Starting OVS"

    local _pwd=$(pwd)
    cd $DATA_DIR/ovs

    EXTRA_DBS=""
    OVSDB_REMOTE=""
    if is_ovn_service_enabled ovn-northd ; then
        EXTRA_DBS="ovnsb.db ovnnb.db"
        OVSDB_REMOTE="--remote=ptcp:6640:$HOST_IP"
    fi

    ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
                 --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
                 --pidfile --detach -vconsole:off --log-file $OVSDB_REMOTE \
                 conf.db ${EXTRA_DBS}

    echo -n "Waiting for ovsdb-server to start ... "
    while ! test -e /usr/local/var/run/openvswitch/db.sock ; do
        sleep 1
    done
    echo "done."
    ovs-vsctl --no-wait init
    ovs-vsctl --no-wait set open_vswitch . system-type="devstack"
    ovs-vsctl --no-wait set open_vswitch . external-ids:system-id="$OVN_UUID"
    if is_ovn_service_enabled ovn-controller ; then
        sudo modprobe openvswitch || die $LINENO "Failed to load openvswitch module"
        # TODO This needs to be a fatal error when doing multi-node testing, but
        # breaks testing in OpenStack CI where geneve isn't available.
        #sudo modprobe geneve || die $LINENO "Failed to load geneve module"
        sudo modprobe geneve || true
        #sudo modprobe vport_geneve || die $LINENO "Failed to load vport_geneve module"
        sudo modprobe vport_geneve || true

        ovs-vsctl --no-wait set open_vswitch . external-ids:ovn-remote="$OVN_REMOTE"
        ovs-vsctl --no-wait set open_vswitch . external-ids:ovn-bridge="br-int"
        ovs-vsctl --no-wait set open_vswitch . external-ids:ovn-encap-type="geneve"
        ovs-vsctl --no-wait set open_vswitch . external-ids:ovn-encap-ip="$HOST_IP"

        _neutron_ovs_base_setup_bridge br-int
        ovs-vsctl --no-wait set bridge br-int fail-mode=secure other-config:disable-in-band=true

        sudo ovs-vswitchd --pidfile --detach -vconsole:off --log-file
    fi

    cd $_pwd
}

# start_ovn() - Start running processes, including screen
function start_ovn {
    echo "Starting OVN"

    if is_ovn_service_enabled ovn-controller ; then
        run_process ovn-controller "sudo ovn-controller --log-file unix:/usr/local/var/run/openvswitch/db.sock"
    fi

    if is_ovn_service_enabled ovn-northd ; then
        run_process ovn-northd "ovn-northd --log-file"
    fi
}

# stop_ovn() - Stop running processes (non-screen)
function stop_ovn {
    if is_ovn_service_enabled ovn-controller ; then
        stop_process ovn-controller
        sudo killall ovs-vswitchd
    fi
    if is_ovn_service_enabled ovn-northd ; then
        stop_process ovn-northd
    fi
    sudo killall ovsdb-server
}

# main loop
if is_ovn_service_enabled ovn-northd || is_ovn_service_enabled ovn-controller; then
    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        if [[ "$OFFLINE" != "True" ]]; then
            install_ovn
        fi
        configure_ovn
        init_ovn
        # We have to start at install time, because Neutron's post-config
        # phase runs ovs-vsctl.
        start_ovs
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        configure_ovn_plugin

        if is_service_enabled nova; then
            create_nova_conf_neutron
        fi

        start_ovn
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

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
# - is_ovn_enabled
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

# Entry Points
# ------------

# Test if OVN is enabled
# is_ovn_enabled
function is_ovn_enabled {
    [[ ,${ENABLED_SERVICES} =~ ,"ovn" ]] && return 0
    return 1
}

# cleanup_ovn() - Remove residual data files, anything left over from previous
# runs that a clean run would need to clean up
function cleanup_ovn {
    :
}

# configure_ovn() - Set config files, create data dirs, etc
function configure_ovn {
    echo "Configuring OVN"

    # Configure OVN
}

function configure_ovn_plugin {
    echo "Configuring Neutron for OVN"

    # OVN plugin configuration information goes here
}

# init_ovn() - Initialize databases, etc.
function init_ovn {
    # clean up from previous (possibly aborted) runs
    # create required data files
    :
}

# install_ovn() - Collect source and prepare
function install_ovn {
    local _pwd=$(pwd)
    echo "Installing OVN and dependent packages"

    # Do some awesome stuff to install OVN
}

# start_ovn() - Start running processes, including screen
function start_ovn {
    echo "Starting OPVN"

    # Start OVN up
}

# stop_ovn() - Stop running processes (non-screen)
function stop_ovn {
    stop_process ovn
}

# main loop
if is_service_enabled ovn; then
    if [[ "$1" == "source" ]]; then
        # no-op
        :
    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        if [[ "$OFFLINE" != "True" ]]; then
            install_ovn
        fi
        configure_ovn
        init_ovn
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        configure_ovn_plugin
        # This has to start before Neutron
        start_ovn

        if is_service_enabled nova; then
            create_nova_conf_neutron
        fi
    elif [[ "$1" == "stack" && "$2" == "post-extra" ]]; then
        # no-op
        :
    fi

    if [[ "$1" == "unstack" ]]; then
        stop_ovn
        cleanup_ovn
    fi

    if [[ "$1" == "clean" ]]; then
        # no-op
        :
    fi
fi

# Restore xtrace
$XTRACE

# Tell emacs to use shell-script-mode
## Local variables:
## mode: shell-script
## End:

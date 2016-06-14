echo "*********************************************************************"
echo "Begin $0"
echo "*********************************************************************"

# Clean up any resources that may be in use
cleanup() {
    set +o errexit

    echo "*********************************************************************"
    echo "ERROR: Abort $0"
    echo "*********************************************************************"

    # Kill ourselves to signal any calling process
    trap 2; kill -2 $$
}

trap cleanup SIGHUP SIGINT SIGTERM

# Keep track of the grenade directory
RUN_DIR=$(cd $(dirname "$0") && pwd)

source $GRENADE_DIR/grenaderc
source $GRENADE_DIR/functions

set -o errexit

source $TARGET_DEVSTACK_DIR/stackrc

NW_OVN_DEVSTACK_DIR=$(dirname "$0")/..
source $NW_OVN_DEVSTACK_DIR/lib/networking-ovn
set -o xtrace

export OVN_NEUTRON_SYNC_MODE=repair
export OVN_L3_MODE=True

install_ovn
configure_ovn
init_ovn
start_ovs
disable_libvirt_apparmor

upgrade_project ovn $RUN_DIR $BASE_DEVSTACK_BRANCH $TARGET_DEVSTACK_BRANCH

configure_ovn_plugin

if is_service_enabled nova; then
    create_nova_conf_neutron
fi
start_ovn

ensure_services_started ovn-controller ovn-northd

set +o xtrace
echo "*********************************************************************"
echo "SUCCESS: End $0"
echo "*********************************************************************"

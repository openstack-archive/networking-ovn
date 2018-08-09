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

# Source params
source $GRENADE_DIR/grenaderc

# Import common functions
source $GRENADE_DIR/functions

set -o errexit

# Upgrade networking-ovn
# ======================

source $TARGET_DEVSTACK_DIR/stackrc
source $TARGET_DEVSTACK_DIR/functions-common

NW_OVN_DEVSTACK_DIR=$(dirname "$0")/..
source $NW_OVN_DEVSTACK_DIR/lib/networking-ovn
source $TARGET_RELEASE_DIR/neutron/devstack/lib/ovs
[[ -r $TARGET_DEVSTACK_DIR/lib/neutron ]] && source $TARGET_DEVSTACK_DIR/lib/neutron
source $TARGET_DEVSTACK_DIR/lib/neutron-legacy

# Upgrade networking-ovn
setup_develop $TARGET_RELEASE_DIR/networking-ovn

# Stop OVN services
stop_ovn

# FIXME(lucasagomes): Workaround, still investigating. Apparently if
# the PID file exist but the process is not running ovn-northd doesn't get
# started for some reason. By deleting the remaining PID files after calling
# stop_ovn (which stops the OVSDBs) we workaround that problem. Apparently
# it must be something to do with the ovn-ctl script.
rm -rf $OVS_RUNDIR/ovnnb_db.pid
rm -rf $OVS_RUNDIR/ovnsb_db.pid

# FIXME(lucasagomes): Workaround, stop_ovn should have stopped those!? It
# seems to not get stopped because both ovs-vswitchd and ovsdb-server
# are not part of the ENABLED_SERVICES list. These unit files are created
# within networking-ovn's DevStack plugin.
sudo systemctl stop devstack@ovs-vswitchd.service
sudo systemctl stop devstack@ovsdb-server.service

# Stop OVS datapath
stop_ovs_dp

# Uninstall OVN
cleanup_ovn $BASE_RELEASE_DIR/ovs

# Compile and install a new version of OVS
compile_ovs $OVN_BUILD_MODULES

# Use the same OVSDB system-id, this UUID will be used by the start_ovs
# function
OVN_UUID=`cat $BASE_DEVSTACK_DIR/ovn-uuid`
export OVN_UUID

# Start OVS
start_ovs

# We need to reconfigure br-ex because stop_ovs_dp removed the ovs kernel
# module thereby removing the br-ex interface. The start_ovs method must
# have recreated the br-ex interface.
sudo ip addr add $PUBLIC_NETWORK_GATEWAY/${FLOATING_RANGE#*/} dev br-ex
sudo ip link set br-ex up

# Reset the openflow protocol in the vswitchd Bridge tables
for br in br-int br-ex; do
    ovs-vsctl set Bridge $br protocols=[] || true
done

# Start OVN services
start_ovn_services

ensure_services_started ovn-controller ovn-northd

set +x
set +o xtrace
echo "*********************************************************************"
echo "SUCCESS: End $0"
echo "*********************************************************************"

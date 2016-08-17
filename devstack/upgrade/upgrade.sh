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
set -o xtrace

# Set for DevStack compatibility

source $GRENADE_DIR/grenaderc
source $GRENADE_DIR/functions
source $TARGET_DEVSTACK_DIR/stackrc

set -o errexit
TOP_DIR=$TARGET_DEVSTACK_DIR

# Get functions from current DevStack
source $TARGET_DEVSTACK_DIR/lib/apache
source $TARGET_DEVSTACK_DIR/lib/tls
source $TARGET_DEVSTACK_DIR/lib/keystone
[[ -r $TARGET_DEVSTACK_DIR/lib/neutron ]] && source $TARGET_DEVSTACK_DIR/lib/neutron
source $TARGET_DEVSTACK_DIR/lib/neutron-legacy
source $TARGET_DEVSTACK_DIR/lib/neutron_plugins/services/l3
source $TARGET_DEVSTACK_DIR/lib/database
source $TARGET_DEVSTACK_DIR/lib/nova

NW_OVN_DEVSTACK_DIR=$(dirname "$0")/..
source $NW_OVN_DEVSTACK_DIR/lib/networking-ovn

export OVN_NEUTRON_SYNC_MODE=repair
# Use neutron l3 as there is a check in nova upgrade, which 
# verifies an instance can be reached with its floating ip even
# after upgrade
export OVN_L3_MODE=False

set -x

# Restart rabbitmq. Without this, the tempest test cases on the upgraded stack
# fails randomly due to rabbitmq connection problems.
sudo service rabbitmq-server restart

# We are no more starting OVS agent, delete the dead agents from neutron
dead_agents=$(neutron --os-cloud devstack-admin agent-list --alive False -f value -c id || /bin/true)
for agent in $dead_agents; do
    neutron --os-cloud devstack-admin agent-delete $agent || /bin/true
done

# stop neutron and its agents as the neutron configuration file is going to
# be modified now
stop_neutron || /bin/true

#Re use the exisiting vswitch db
ovs_db_file=$(/usr/share/openvswitch/scripts/ovs-ctl --help | grep DBDIR | awk '{gsub(/\:/, ""); printf $2"/"$1"\n"}')
mkdir -p $DATA_DIR/ovs
cp $ovs_db_file $DATA_DIR/ovs/conf.db

install_ovn

#uprade the db to the latest ovsschema
OVS_SHARE_ROOT=/usr/local/share/openvswitch/
/bin/bash -c ". $OVS_SHARE_ROOT/scripts/ovs-lib; upgrade_db $DATA_DIR/ovs/conf.db $OVS_SHARE_ROOT/vswitch.ovsschema"

configure_ovn
start_ovs

# We need to reconfigure br-ex because install_ovn must have removed the
# ovs kernel module thereby removing the br-ex interface. start_ovs
# must have recreated the br-ex interface.
sudo ip addr add $PUBLIC_NETWORK_GATEWAY/${FLOATING_RANGE#*/} dev br-ex
sudo ip link set br-ex up

# Reset the openflow protocol in the vswitchd Bridge tables
for br in br-int br-ex br-tun; do
ovs-vsctl set Bridge $br protocols=[] || /bin/true
done

disable_libvirt_apparmor

upgrade_project ovn $RUN_DIR $BASE_DEVSTACK_BRANCH $TARGET_DEVSTACK_BRANCH

neutron_plugin_configure_common
Q_PLUGIN_CONF_FILE=$Q_PLUGIN_CONF_PATH/$Q_PLUGIN_CONF_FILENAME
Q_ML2_PLUGIN_MECHANISM_DRIVERS=ovn,logger
Q_ML2_PLUGIN_TYPE_DRIVERS=local,flat,vlan,geneve,vxlan
Q_ML2_TENANT_NETWORK_TYPE="geneve"
neutron_plugin_configure_service

configure_ovn_plugin

if is_service_enabled nova; then
    create_nova_conf_neutron
fi
start_ovn

ensure_services_started ovn-controller ovn-northd

start_neutron_service_and_check
start_neutron_agents

set +x
set +o xtrace
echo "*********************************************************************"
echo "SUCCESS: End $0"
echo "*********************************************************************"

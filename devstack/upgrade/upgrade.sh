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

setup_develop $TARGET_RELEASE_DIR/networking-ovn

# TODO(lucasagomes): I believe that apart from upgrading the
# networking-ovn ML2 driver we would also want to upgrade OVN itself. This
# will present its own challenges and we need to investigate more, maybe
# we can set the OVN_BRANCH to 2.9 or whatever stable release in the base
# DevStack localrc (see the settings file for that) and as part of the
# upgrade we recompile it as master and restart all the services. Food
# for thought.

set +x
set +o xtrace
echo "*********************************************************************"
echo "SUCCESS: End $0"
echo "*********************************************************************"

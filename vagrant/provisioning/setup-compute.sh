#!/usr/bin/env bash
cp networking-ovn/devstack/computenode-local.conf.sample devstack/local.conf
if [ "$1" != "" ]; then
    sed -i -e 's/<IP address of host running everything else>/'$1'/g' devstack/local.conf
fi
if [ "$2" != "" ]; then
    ovnip=$2
fi


# Get the IP address
ipaddress=$(ip -4 addr show eth1 | grep -oP "(?<=inet ).*(?=/)")

# Fixup HOST_IP with the local IP address
sed -i -e 's/<IP address of current host>/'$ipaddress'/g' devstack/local.conf

# Adjust some things in local.conf
cat << DEVSTACKEOF >> devstack/local.conf

# Set this to the address of the main DevStack host running the rest of the
# OpenStack services.
Q_HOST=$1
HOSTNAME=$(hostname)
OVN_REMOTE=tcp:$ovnip:6640
enable_service q-dhcp q-meta
DEVSTACKEOF

# Using a separate 'cat' with single quotes around EOF to prevent
# interpretation of variables such as $Q_DHCP_CONF_FILE.

cat << 'DEVSTACKEOF' >> devstack/local.conf

[[post-config|/$Q_DHCP_CONF_FILE]]
[DEFAULT]
enable_isolated_metadata = True
DEVSTACKEOF

devstack/stack.sh

# Setup the provider network
source /vagrant/provisioning/provider-setup.sh

provider_setup

# Set the OVN_*_DB variables to enable OVN commands using a remote database.
echo -e "\n# Enable OVN commands using a remote database.
export OVN_NB_DB=$OVN_REMOTE
export OVN_SB_DB=$OVN_REMOTE" >> ~/.bash_profile

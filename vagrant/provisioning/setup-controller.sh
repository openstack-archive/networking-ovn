#!/usr/bin/env bash
cp networking-ovn/devstack/local.conf.sample devstack/local.conf

if [ "$1" != "" ]; then
    ovnip=$1
fi

# Get the IP address
ipaddress=$(ip -4 addr show eth1 | grep -oP "(?<=inet ).*(?=/)")

# Adjust some things in local.conf
cat << DEVSTACKEOF >> devstack/local.conf

# Adjust this in case we're running on a cloud which may use 10.0.0.x
# for VM IP addresses
NETWORK_GATEWAY=10.100.100.100
FIXED_RANGE=10.100.100.0/24

# Good to set these
HOST_IP=$ipaddress
HOSTNAME=$(hostname)
SERVICE_HOST_NAME=${HOST_NAME}
SERVICE_HOST=$ipaddress
OVN_REMOTE=tcp:$ovnip:6640
disable_service ovn-northd
DEVSTACKEOF

devstack/stack.sh

# Setup the provider network
source /vagrant/provisioning/provider-setup.sh

provider_setup

# Actually create the provider network
# FIXME(mestery): Make the subnet-create parameters configurable via virtualbox.conf.yml.
source devstack/openrc admin admin
neutron net-create provider --shared --provider:physical_network providernet --provider:network_type flat
neutron subnet-create provider 192.168.66.0/24 --name provider-subnet --gateway 192.168.66.1 --allocation-pool start=192.168.66.20,end=192.168.66.99 --ip-version 4

# Set the OVN_*_DB variables to enable OVN commands using a remote database.
echo -e "\n# Enable OVN commands using a remote database.
export OVN_NB_DB=$OVN_REMOTE
export OVN_SB_DB=$OVN_REMOTE" >> ~/.bash_profile

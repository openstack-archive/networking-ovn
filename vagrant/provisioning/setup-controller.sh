#!/usr/bin/env bash
cp networking-ovn/devstack/local.conf.sample devstack/local.conf

if [ "$1" != "" ]; then
    ovnip=$1
fi

# Get the IP address
ipaddress=$(ip -4 addr show eth1 | grep -oP "(?<=inet ).*(?=/)")

# Adjust some things in local.conf
cat << DEVSTACKEOF >> devstack/local.conf

# Until OVN supports NAT, the private network IP address range
# must not conflict with IP address ranges on the host. Change
# as necessary for your environment.
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
neutron net-create provider --shared --router:external --provider:physical_network provider --provider:network_type flat
neutron subnet-create provider --name provider-subnet-v4 --gateway 192.168.66.102 --allocation-pool start=192.168.66.20,end=192.168.66.99 --ip-version 4 192.168.66.0/24

# Create a router for the private network.
source devstack/openrc demo demo
neutron router-create router
neutron router-interface-add router private-subnet
neutron router-gateway-set router provider

# Add host route for private network, at least until the native L3 agent
# supports NAT.
# FIXME(mkassawara): Add support for IPv6.
source devstack/openrc admin admin
ROUTER_GATEWAY=`neutron port-list -c fixed_ips -c device_owner | grep router_gateway | awk -F'ip_address'  '{ print $2 }' | cut -f3 -d\"`
sudo ip route add $FIXED_RANGE via $ROUTER_GATEWAY

# Set the OVN_*_DB variables to enable OVN commands using a remote database.
echo -e "\n# Enable OVN commands using a remote database.
export OVN_NB_DB=$OVN_REMOTE
export OVN_SB_DB=$OVN_REMOTE" >> ~/.bash_profile

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
NETWORK_GATEWAY=172.16.1.1
FIXED_RANGE=172.16.1.0/24

# Good to set these
HOST_IP=$ipaddress
HOSTNAME=$(hostname)
SERVICE_HOST_NAME=${HOST_NAME}
SERVICE_HOST=$ipaddress
OVN_REMOTE=tcp:$ovnip:6640
disable_service ovn-northd
disable_service c-api c-sch c-vol n-cpu q-dhcp q-meta tempest
DEVSTACKEOF

# Using a separate 'cat' with single quotes around EOF to prevent
# interpretation of variables such as $NEUTRON_CONF.

cat << 'DEVSTACKEOF' >> devstack/local.conf

[[post-config|/$NEUTRON_CONF]]
[DEFAULT]
dhcp_agents_per_network = 2
DEVSTACKEOF

devstack/stack.sh

# Setup the provider network
source /vagrant/provisioning/provider-setup.sh

provider_setup

# Actually create the provider network
# FIXME(mestery): Make the subnet-create parameters configurable via virtualbox.conf.yml.
source devstack/openrc admin admin
neutron net-create provider --shared --router:external --provider:physical_network provider --provider:network_type flat

# Provider network allocation pool defaults to values from upstream
# documentation. Change as necessary for your environment, exercising
# caution to avoid interference with existing IP addresses on the network.
neutron subnet-create provider --name provider-v4 --ip-version 4 --allocation-pool start=192.168.66.101,end=192.168.66.200 --gateway 192.168.66.1 192.168.66.0/24

# Create a router for the private network.
source devstack/openrc demo demo
neutron router-create router
neutron router-interface-add router private-subnet
neutron router-gateway-set router provider

# Add host route for the private network, at least until the native L3 agent
# supports NAT.
# FIXME(mkassawara): Add support for IPv6.
source devstack/openrc admin admin
ROUTER_GATEWAY=`neutron port-list -c fixed_ips -c device_owner | grep router_gateway | awk -F'ip_address'  '{ print $2 }' | cut -f3 -d\"`
sudo ip route add $FIXED_RANGE via $ROUTER_GATEWAY

# Set the OVN_*_DB variables to enable OVN commands using a remote database.
echo -e "\n# Enable OVN commands using a remote database.
export OVN_NB_DB=$OVN_REMOTE
export OVN_SB_DB=$OVN_REMOTE" >> ~/.bash_profile

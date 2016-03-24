#!/usr/bin/env bash

# Script Arguments:
# $1 - ovn-db IP address
# $2 - provider network starting IP address
# $3 - provider network ending IP address
# $4 - provider network gateway
# $5 - provider network network
# $6 - ovn vm subnet
ovnip=$1
start_ip=$2
end_ip=$3
gateway=$4
network=$5
ovn_vm_subnet=$6

cp networking-ovn/devstack/local.conf.sample devstack/local.conf

# Get the IP address
ipaddress=$(ip -4 addr show eth1 | grep -oP "(?<=inet ).*(?=/)")

# Adjust some things in local.conf
cat << DEVSTACKEOF >> devstack/local.conf

# Good to set these
HOST_IP=$ipaddress
HOSTNAME=$(hostname)
SERVICE_HOST_NAME=${HOST_NAME}
SERVICE_HOST=$ipaddress
OVN_SB_REMOTE=tcp:$ovnip:6642
OVN_NB_REMOTE=tcp:$ovnip:6641

# Enable logging to files.
LOGFILE=/opt/stack/log/stack.sh.log
SCREEN_LOGDIR=/opt/stack/log/data

# Disable the ovn-northd service on the controller node because the
# architecture includes a separate OVN database server.
disable_service ovn-northd

# Disable the ovn-controller service because the architecture lacks services
# on the controller node that depend on it.
disable_service ovn-controller

# Disable the DHCP and metadata services on the controller node because the
# architecture only deploys them on separate compute nodes.
disable_service q-dhcp q-meta

# Disable the nova compute service on the controller node because the
# architecture only deploys it on separate compute nodes.
disable_service n-cpu

# Disable cinder services and tempest to reduce deployment time.
disable_service c-api c-sch c-vol tempest

# Until OVN supports NAT, the private network IP address range
# must not conflict with IP address ranges on the host. Change
# as necessary for your environment.
NETWORK_GATEWAY=172.16.1.1
FIXED_RANGE=172.16.1.0/24
DEVSTACKEOF

# Add unique post-config for DevStack here using a separate 'cat' with
# single quotes around EOF to prevent interpretation of variables such
# as $NEUTRON_CONF.

cat << 'DEVSTACKEOF' >> devstack/local.conf

# Enable two DHCP agents per neutron subnet with support for availability
# zones. Requires two or more compute nodes.

[[post-config|/$NEUTRON_CONF]]
[DEFAULT]
network_scheduler_driver = neutron.scheduler.dhcp_agent_scheduler.AZAwareWeightScheduler
dhcp_load_type = networks
dhcp_agents_per_network = 2
DEVSTACKEOF

devstack/stack.sh

# Create the provider network with one IPv4 subnet.
source devstack/openrc admin admin
neutron net-create provider --shared --router:external --provider:physical_network provider --provider:network_type flat
neutron subnet-create provider --name provider-v4 --ip-version 4 --allocation-pool start=$start_ip,end=$end_ip --gateway $gateway $network

# Create a router.
source devstack/openrc demo demo
neutron router-create router

# Attach the private network IPv4 subnet that DevStack creates to the router.
neutron router-interface-add router private-subnet

# Set the gateway for the router as the provider network.
neutron router-gateway-set router provider

# NFS server setup
sudo apt-get update
sudo apt-get install -y nfs-kernel-server nfs-common
sudo mkdir -p /opt/stack/data/nova/instances
sudo touch /etc/exports
sudo sh -c "echo \"/opt/stack/data/nova/instances $ovn_vm_subnet(rw,sync,fsid=0,no_root_squash)\" >> /etc/exports"
sudo service nfs-kernel-server restart
sudo service idmapd restart

# Set the OVN_*_DB variables to enable OVN commands using a remote database.
echo -e "\n# Enable OVN commands using a remote database.
export OVN_NB_DB=$OVN_NB_REMOTE
export OVN_SB_DB=$OVN_SB_REMOTE" >> ~/.bash_profile


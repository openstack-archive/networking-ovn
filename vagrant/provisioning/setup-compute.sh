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

# Enable logging to files.
LOGFILE=/opt/stack/log/stack.sh.log
SCREEN_LOGDIR=/opt/stack/log/data

# Enable the DHCP and metadata services on the compute node.
enable_service q-dhcp q-meta

# Until OVN supports NAT, the private network IP address range
# must not conflict with IP address ranges on the host. Change
# as necessary for your environment.
NETWORK_GATEWAY=172.16.1.1
FIXED_RANGE=172.16.1.0/24
DEVSTACKEOF

# Add unique post-config for DevStack here using a separate 'cat' with
# single quotes around EOF to prevent interpretation of variables such
# as $Q_DHCP_CONF_FILE.

cat << 'DEVSTACKEOF' >> devstack/local.conf

# Set the availablity zone name (default is nova) for the DHCP service.
[[post-config|$Q_DHCP_CONF_FILE]]
[AGENT]
availability_zone = nova
DEVSTACKEOF

devstack/stack.sh

# Build the provider network in OVN. You can enable instances to access
# external networks such as the Internet by using the IP address of the host
# vboxnet interface for the provider network (typically vboxnet1) as the
# gateway for the subnet on the neutron provider network. Also requires
# enabling IP forwarding and configuring SNAT on the host. See the README for
# more information.

source /vagrant/provisioning/provider-setup.sh

provider_setup

# Add host route for the private network, at least until the native L3 agent
# supports NAT.
# FIXME(mkassawara): Add support for IPv6.
source devstack/openrc admin admin
ROUTER_GATEWAY=`neutron port-list -c fixed_ips -c device_owner | grep router_gateway | awk -F'ip_address'  '{ print $2 }' | cut -f3 -d\"`
sudo ip route add $FIXED_RANGE via $ROUTER_GATEWAY

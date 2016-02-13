#!/usr/bin/env bash
cp networking-ovn/devstack/db-local.conf.sample devstack/local.conf
if [ "$1" != "" ]; then
    sed -i -e 's/<IP address of host running everything else>/'$1'/g' devstack/local.conf
fi

# Get the IP address
ipaddress=$(ip -4 addr show eth1 | grep -oP "(?<=inet ).*(?=/)")

# Adjust some things in local.conf
cat << DEVSTACKEOF >> devstack/local.conf

# Set this to the address of the main DevStack host running the rest of the
# OpenStack services.
Q_HOST=$1
HOST_IP=$ipaddress
HOSTNAME=$(hostname)

# Enable logging to files.
LOGFILE=/opt/stack/log/stack.sh.log
SCREEN_LOGDIR=/opt/stack/log/data
DEVSTACKEOF

devstack/stack.sh

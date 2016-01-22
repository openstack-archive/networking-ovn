#!/bin/sh
DEBIAN_FRONTEND=noninteractive sudo apt-get -qqy update
DEBIAN_FRONTEND=noninteractive sudo apt-get install -qqy git
DEBIAN_FRONTEND=noninteractive sudo apt-get install -qqy bridge-utils
DEBIAN_FRONTEND=noninteractive sudo apt-get install -qqy ebtables
DEBIAN_FRONTEND=noninteractive sudo apt-get install -qqy python-pip
DEBIAN_FRONTEND=noninteractive sudo apt-get install -qqy python-dev
DEBIAN_FRONTEND=noninteractive sudo apt-get install -qqy build-essential
echo export LC_ALL=en_US.UTF-8 >> ~/.bash_profile
echo export LANG=en_US.UTF-8 >> ~/.bash_profile
# FIXME(mestery): Remove once Vagrant boxes allow apt-get to work again
sudo rm -rf /var/lib/apt/lists/*
sudo apt-get install -y git
if [ ! -d "devstack" ]; then
    git clone https://github.com/openstack-dev/devstack
fi
# for a local deployment, this repo folder is shared between the host and the guests
if [ ! -d "networking-ovn" ]; then
    git clone http://git.openstack.org/openstack/networking-ovn.git
fi

# We need swap space to do any sort of scale testing with the Vagrant config.
# Without this, we quickly run out of RAM and the kernel starts whacking things.
sudo rm -f /swapfile1
sudo dd if=/dev/zero of=/swapfile1 bs=1024 count=8388608
sudo chown root:root /swapfile1
sudo chmod 0600 /swapfile1
sudo mkswap /swapfile1
sudo swapon /swapfile1

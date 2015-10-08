#!/usr/bin/env bash
cp networking-ovn/devstack/computenode-local.conf.sample devstack/local.conf
if [ "$1" != "" ]; then
    sed -i -e 's/<IP address of host running everything else>/'$1'/g' devstack/local.conf
fi
devstack/stack.sh
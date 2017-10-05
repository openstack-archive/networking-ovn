#!/bin/bash

# Copyright 2018 Red Hat, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# With LANG set to everything else than C completely undercipherable errors
# like "file not found" and decoding errors will start to appear during scripts
# or even ansible modules
LANG=C

# Complete stackrc file path.
: ${STACKRC_FILE:=~/stackrc}

# Complete overcloudrc file path.
: ${OVERCLOUDRC_FILE:=~/overcloudrc}

# overcloud deploy script for OVN migration.
: ${OVERCLOUD_OVN_DEPLOY_SCRIPT:=~/overcloud-deploy-ovn.sh}

# Is the present deployment DVR or HA. Lets assume it's HA
: ${IS_DVR_ENABLED:=False}
: ${OPT_WORKDIR:=$PWD}
: ${PUBLIC_NETWORK_NAME:=public}
: ${IMAGE_NAME:=cirros}
: ${SERVER_USER_NAME:=cirros}
: ${IS_CONTAINER_DEPLOYMENT:=False}
: ${VALIDATE_MIGRATION:=True}

# Check if the neutron networks MTU has been updated to geneve MTU size or not.
# We donot want to proceed if the MTUs are not updated.
oc_check_network_mtu() {
    source $OVERCLOUDRC_FILE
    python network_mtu.py verify mtu
    if [ "$?" != "0" ]
    then
        echo "Please update the tenant network MTU by running 'python network_mtu.py update mtu' before starting migration"
        exit 1
    fi
}

generate_ansible_hosts_file() {
    source $STACKRC_FILE
    echo "[ovn-dbs]"  > hosts_for_migration
    ovn_central=True
    CONTROLLERS=`openstack server list -c Name -c Networks | grep controller | awk  '{ split($4, net, "="); print net[2] }'`
    for node_ip in $CONTROLLERS
    do
        if [ "$ovn_central" == "True" ]
        then
            ovn_central=False
            node_ip="$node_ip ovn_central=true"
        fi
        echo $node_ip ansible_ssh_user=heat-admin ansible_become=true >> hosts_for_migration
    done

    echo "" >> hosts_for_migration
    echo "[ovn-controllers]" >> hosts_for_migration
    for node_ip in $CONTROLLERS
    do
        echo $node_ip ansible_ssh_user=heat-admin ansible_become=true >> hosts_for_migration
    done

    for node_ip in `openstack server list -c Name -c Networks | grep compute | awk  '{ split($4, net, "="); print net[2] }'`
    do
        echo $node_ip ansible_ssh_user=heat-admin ansible_become=true >> hosts_for_migration
    done

    echo "" >> hosts_for_migration

    cat >> hosts_for_migration << EOF
[overcloud:children]
ovn-controllers
ovn-dbs

[overcloud:vars]
remote_user=heat-admin
dvr_setup=$IS_DVR_ENABLED
public_network_name=$PUBLIC_NETWORK_NAME
image_name=$IMAGE_NAME
working_dir=$OPT_WORKDIR
server_user_name=$SERVER_USER_NAME
container_deployment=$IS_CONTAINER_DEPLOYMENT
validate_migration=$VALIDATE_MIGRATION
overcloud_ovn_deploy_script=$OVERCLOUD_OVN_DEPLOY_SCRIPT
overcloudrc=$OVERCLOUDRC_FILE
EOF
}

# Step 1. Check if the user has generated overcloud-deploy-ovn.sh file
# If it is not generated. Exit
if [ ! -e $OVERCLOUD_OVN_DEPLOY_SCRIPT ]
then
    echo "overcloud deploy migration script : $OVERCLOUD_OVN_DEPLOY_SCRIPT is not present. Please make sure you generate that file before running this"
    exit 1
fi

echo "Check if jq and sshpass commands are available or not"

which jq
if [ "$?" != "0" ]
then
    echo "Please install jq as it is required during migration"
    exit 1
fi

which sshpass
if [ "$?" != "0" ]
then
    echo "Please install sshpass as it is required during migration"
    exit 1
fi

echo "Checking the tenant network mtu values"
oc_check_network_mtu

echo "MTU is fine"

cat $OVERCLOUD_OVN_DEPLOY_SCRIPT  | grep  $HOME/ovn-extras.yaml
if [ "$?" == "1" ]
then
    echo "ovn-extras.yaml file is missing in $OVERCLOUD_OVN_DEPLOY_SCRIPT. Please add it"
    exit 1
fi

# Generate the hosts file for ansible migration playbook.
echo "Generating the hosts file for ansible-playbook"
generate_ansible_hosts_file

# Lets kick start the ansible playbook.
echo "Starting the Migration"
ansible-playbook  $OPT_WORKDIR/playbooks/ovn-migration.yml \
    -i hosts_for_migration -e working_dir=$OPT_WORKDIR \
    -e public_network_name=$PUBLIC_NETWORK_NAME \
    -e image_name=$IMAGE_NAME \
    -e overcloud_ovn_deploy_script=$OVERCLOUD_OVN_DEPLOY_SCRIPT \
    -e server_user_name=$SERVER_USER_NAME        \
    -e overcloudrc=$OVERCLOUDRC_FILE             \
    -e container_deployment=$IS_CONTAINER_DEPLOYMENT \
    -e validate_migration=$VALIDATE_MIGRATION

echo "Migration complete !!!"

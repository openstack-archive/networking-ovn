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

: ${OPT_WORKDIR:=$PWD}
: ${STACK_NAME:=overcloud}
: ${PUBLIC_NETWORK_NAME:=public}
: ${IMAGE_NAME:=cirros}
: ${SERVER_USER_NAME:=cirros}
: ${VALIDATE_MIGRATION:=True}
: ${DHCP_RENEWAL_TIME:=30}


check_for_necessary_files() {
    if [ ! -e hosts_for_migration ]
    then
        echo "hosts_for_migration ansible inventory file not present"
        echo "Please run ./ovn_migration.sh generate-inventory"
        exit 1
    fi

    # Check if the user has generated overcloud-deploy-ovn.sh file
    # If it is not generated. Exit
    if [ ! -e $OVERCLOUD_OVN_DEPLOY_SCRIPT ]
    then
        echo "overcloud deploy migration script : $OVERCLOUD_OVN_DEPLOY_SCRIPT\
 is not present. Please make sure you generate that file before running this"
        exit 1
    fi

    cat $OVERCLOUD_OVN_DEPLOY_SCRIPT  | grep  neutron-ovn >/dev/null
    if [ "$?" == "1" ]
    then
        echo "OVN t-h-t environment file seems to be missing in \
$OVERCLOUD_OVN_DEPLOY_SCRIPT. Please check the $OVERCLOUD_OVN_DEPLOY_SCRIPT \
file again."
        exit 1
    fi

    cat $OVERCLOUD_OVN_DEPLOY_SCRIPT | grep \$HOME/ovn-extras.yaml >/dev/null
    check1=$?
    cat $OVERCLOUD_OVN_DEPLOY_SCRIPT | grep $HOME/ovn-extras.yaml >/dev/null
    check2=$?

    if [[ "$check1" == "1" && "$check2" == "1" ]]
    then
        echo "ovn-extras.yaml file is missing in $OVERCLOUD_OVN_DEPLOY_SCRIPT.\
 Please add it as \" -e \$HOME/ovn-extras.yaml\""
        exit 1
    fi
}

get_host_ip() {
    inventory_file=$1
    host_name=$2
    host_vars=$(ansible-inventory -i "$inventory_file" --host "$host_name" 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        echo "$host_vars" | jq -r \.ansible_host
    else
        echo $host_name
    fi
}

get_group_hosts() {
    inventory_file=$1
    group_name=$2
    group_graph=$(ansible-inventory -i "$inventory_file" --graph "$group_name" 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        echo "$group_graph" | sed -ne 's/^[ \t|]\+--\([a-z0-9\-]\+\)$/\1/p'
    else
        echo ""
    fi
}

# Generate the ansible.cfg file
generate_ansible_config_file() {

  cat > ansible.cfg <<-EOF
[defaults]
forks=50
become=True
callback_whitelist = profile_tasks
host_key_checking = False
gathering = smart
fact_caching = jsonfile
fact_caching_connection = ./ansible_facts_cache
fact_caching_timeout = 0

#roles_path = roles:...

[ssh_connection]
control_path = %(directory)s/%%h-%%r
ssh_args = -o ControlMaster=auto -o ControlPersist=270s -o ServerAliveInterval=30 -o GSSAPIAuthentication=no
retries = 3

EOF
}

# Generate the inventory file for ansible migration playbook.
generate_ansible_inventory_file() {
    echo "Generating the inventory file for ansible-playbook"
    source $STACKRC_FILE
    echo "[ovn-dbs]"  > hosts_for_migration
    ovn_central=True
    inventory_file=$(mktemp --tmpdir ansible-inventory-XXXXXXXX.yaml)
    /usr/bin/tripleo-ansible-inventory --stack $STACK_NAME --static-yaml-inventory "$inventory_file"
    # We want to run ovn_dbs where neutron_api is running
    OVN_DBS=$(get_group_hosts "$inventory_file" neutron_api)
    for node_name in $OVN_DBS
    do
        node_ip=$(get_host_ip "$inventory_file" $node_name)
        node="$node_name ansible_host=$node_ip"
        if [ "$ovn_central" == "True" ]; then
            ovn_central=False
            node="$node_name ansible_host=$node_ip ovn_central=true"
        fi
        echo $node ansible_ssh_user=heat-admin ansible_become=true >> hosts_for_migration
    done

    echo "" >> hosts_for_migration
    echo "[ovn-controllers]" >> hosts_for_migration

    # We want to run ovn-controller where OVS agent was running before the migration
    OVN_CONTROLLERS=$(get_group_hosts "$inventory_file" neutron_ovs_agent)
    for node_name in $OVN_CONTROLLERS
    do
        node_ip=$(get_host_ip "$inventory_file" $node_name)
        echo $node_name ansible_host=$node_ip ansible_ssh_user=heat-admin ansible_become=true ovn_controller=true >> hosts_for_migration
    done
    rm -f "$inventory_file"
    echo "" >> hosts_for_migration

    cat >> hosts_for_migration << EOF

[overcloud-controllers:children]
ovn-dbs

[overcloud:children]
ovn-controllers
ovn-dbs

EOF
    add_group_vars() {

    cat >> hosts_for_migration << EOF

[$1:vars]
remote_user=heat-admin
public_network_name=$PUBLIC_NETWORK_NAME
image_name=$IMAGE_NAME
working_dir=$OPT_WORKDIR
server_user_name=$SERVER_USER_NAME
validate_migration=$VALIDATE_MIGRATION
overcloud_ovn_deploy_script=$OVERCLOUD_OVN_DEPLOY_SCRIPT
overcloudrc=$OVERCLOUDRC_FILE
ovn_migration_backups=/var/lib/ovn-migration-backup
EOF
    }

    add_group_vars overcloud
    add_group_vars overcloud-controllers


    echo "***************************************"
    cat hosts_for_migration
    echo "***************************************"
    echo "Generated the inventory file - hosts_for_migration"
    echo "Please review the file before running the next command - setup-mtu-t1"
}

# Check if the stack exists
function check_stack {
    source $STACKRC_FILE
    openstack stack show $STACK_NAME 1> /dev/null || {
        echo "ERROR: STACK_NAME=${STACK_NAME} does not exist. Please provide the stack name or its ID "
        echo "       via STACK_NAME environment variable."
        exit 1
    }
}

# Check if the public network exists, and if it has floating ips available

oc_check_public_network() {

    source $OVERCLOUDRC_FILE
    openstack network show $PUBLIC_NETWORK_NAME 1>/dev/null || {
        echo "ERROR: PUBLIC_NETWORK_NAME=${PUBLIC_NETWORK_NAME} can't be accessed by the"
        echo "       admin user, please fix that before continuing."
        exit 1
    }

    ID=$(openstack floating ip create $PUBLIC_NETWORK_NAME -c id -f value) || {
        echo "ERROR: PUBLIC_NETWORK_NAME=${PUBLIC_NETWORK_NAME} doesn't have available"
        echo "       floating ips. Make sure that your public network has at least one"
        echo "       floating ip available for the admin user."
        exit 1
    }

    openstack floating ip delete $ID 2>/dev/null 1>/dev/null
    return $?
}


# Check if the neutron networks MTU has been updated to geneve MTU size or not.
# We donot want to proceed if the MTUs are not updated.
oc_check_network_mtu() {
    source $OVERCLOUDRC_FILE
    networking-ovn-migration-mtu verify mtu
    return $?
}

setup_mtu_t1() {
    # Run the ansible playbook to reduce the DHCP T1 parameter in
    # dhcp_agent.ini in all the overcloud nodes where dhcp agent is running.
    ansible-playbook  -vv $OPT_WORKDIR/playbooks/reduce-dhcp-renewal-time.yml \
        -i hosts_for_migration -e working_dir=$OPT_WORKDIR \
        -e renewal_time=$DHCP_RENEWAL_TIME
    rc=$?
    return $rc
}

reduce_network_mtu () {
    source $OVERCLOUDRC_FILE
    oc_check_network_mtu
    if [ "$?" != "0" ]
    then
        # Reduce the network mtu
        networking-ovn-migration-mtu update mtu
        rc=$?

        if [ "$rc" != "0" ]
        then
            echo "Reducing the network mtu's failed. Exiting."
            exit 1
        fi
    fi

    return $rc
}

start_migration() {
    source $STACKRC_FILE
    echo "Starting the Migration"
    ansible-playbook  -vv $OPT_WORKDIR/playbooks/ovn-migration.yml \
    -i hosts_for_migration -e working_dir=$OPT_WORKDIR \
    -e public_network_name=$PUBLIC_NETWORK_NAME \
    -e image_name=$IMAGE_NAME \
    -e overcloud_ovn_deploy_script=$OVERCLOUD_OVN_DEPLOY_SCRIPT \
    -e server_user_name=$SERVER_USER_NAME        \
    -e overcloudrc=$OVERCLOUDRC_FILE             \
    -e validate_migration=$VALIDATE_MIGRATION $*

    rc=$?
    return $rc
}

print_usage() {

cat << EOF

Usage:

  Before running this script, please refer to the migration guide for
complete details. This script needs to be run in 5 steps.

 Step 1 -> ovn_migration.sh generate-inventory

           Generates the inventory file

 Step 2 -> ovn_migration.sh setup-mtu-t1

           Sets the DHCP renewal T1 to 30 seconds. After this step you will
           need to wait at least 24h for the change to be propagated to all
           VMs. This step is only necessary for VXLAN or GRE based tenant
           networking.

 Step 3 -> You need to wait at least 24h based on the default configuration
           of neutron for the DHCP T1 parameter to be propagated, please
           refer to documentation. WARNING: this is very important if you
           are using VXLAN or GRE tenant networks.

 Step 4 -> ovn_migration.sh reduce-mtu

           Reduces the MTU of the neutron tenant networks networks. This
           step is only necessary for VXLAN or GRE based tenant networking.

 Step 5 -> ovn_migration.sh start-migration

           Starts the migration to OVN.

EOF

}

command=$1

ret_val=0
case $command in
    generate-inventory)
        check_stack
        oc_check_public_network
        generate_ansible_inventory_file
        generate_ansible_config_file
        ret_val=$?
        ;;

    setup-mtu-t1)
        check_for_necessary_files
        setup_mtu_t1
        ret_val=$?;;

    reduce-mtu)
        check_for_necessary_files
        reduce_network_mtu
        ret_val=$?;;

    start-migration)
        oc_check_public_network
        check_for_necessary_files
        shift
        start_migration $*
        ret_val=$?
        ;;

    *)
        print_usage;;
esac

exit $ret_val

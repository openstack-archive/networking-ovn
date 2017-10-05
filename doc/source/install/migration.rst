.. _migration:

Migration Strategy
==================

This document details an in-place migration strategy from ML2/OVS in either
ovs-firewall, or ovs-hybrid mode in a TripleO OpenStack deployment.

For non TripleO deployments, please refer to the file ``migration/README.rst``
and the ansible playbook ``migration/migrate-to-ovn.yml``.

Overview
--------
The migration would be accomplished by following the steps:

a. Administrator steps:

    * Updating to the latest openstack/neutron version

    * Reducing the DHCP T1 parameter on dhcp_agent.ini beforehand, which
      is controlled by the dhcp_renewal_time of /etc/neutron/dhcp_agent.ini

      Somewhere around 30 seconds would be enough (TODO: Data and calculations
      to back this value with precise information).

    * Waiting for at least dhcp_lease_duration (see /etc/neutron/neutron.conf
      or /etc/neutron/dhcp_agent.ini) time (default is 86400 seconds =
      24hours), that way all instances will grab the new new lease renewal time
      and start checking with the dhcp server periodically based on the T1
      parameter.

    * Lowering the MTU of all vxlan or gre based networks down to
      make sure geneve works (a tool will be provided for that). The mtu
      must be set to "max_tunneling_network_mtu - ovn_geneve_overhead", that's
      generally "1500 - ovn_geneve_overhead", unless your network and any
      intermediate router hop between compute and network nodes is jumboframe
      capable). ovn_geneve_overhead is 58 bytes. VXLAN overhead is 50 bytes. So
      for the typical 1500 MTU tunneling network, we may need to assign 1442.

      The migration tool provides a python script `network_mtu.py``. To lower
      the MTU, run ``python network_mtu.py update mtu``.


b. Automated steps (via ansible)

    * Create pre-migration resources (network and VM) to validate final
      migration.

    * Update the overcloud stack (in the case of TripleO) to deploy OVN
      alongside reference implementation services using a temporary bridge
      "br-migration" instead of br-int.

    * Start the migration process:

      1. generate the OVN north db by running neutron-ovn-db-sync util
      2. re-assign ovn-controller to br-int instead of br-migration
      3. cleanup network namespaces (fip, snat, qrouter, qdhcp),
      4. remove any unnecessary patch ports on br-int
      5. remove br-tun and br-migration ovs bridges
      6. delete qr-*, ha-* and qg-* ports from br-int

    * Delete neutron agents and neutron HA internal networks

    * Validate connectivity on pre-migration resources.

    * Delete pre-migration resources.

    * Create post-migration resources.

    * Validate connectivity on post-migration resources.

    * Cleanup post-migration resources.

    * Re-run deployment tool to update OVN on br-int.


Steps for migration
-------------------
Carryout the below steps in the undercloud:

1.  Run ``python network_mtu.py update mtu`` to lower the mtu of the pre
    migration vxlan networks.

2. Create ``overcloud-deploy-ovn.sh`` script  in /home/stack. Make sure the
   below environment files are added in the order mentioned below

* -e /usr/share/openstack-triple-heat-templates/environments/docker.yaml
* -e /usr/share/openstack-triple-heat-templates/environments/docker-ha.yaml
* -e /usr/share/openstack-tripleo-heat-templates/environments/services-docker/
  neutron-ovn-ha.yaml
* -e /home/stack/ovn-extras.yaml

    If compute nodes have external connectivity, then you can use the
    environment file - environments/services-docker/neutron-ovn-dvr-ha.yaml

3. Configure 'dhcp_renewal_time' in
   /var/lib/config-data/puppet-generated/neutron/etc/neutron/dhcp_agent.ini
   in all the nodes where DHCP agent is configured.

4. Wait till the new MTU values are propagated to all the pre migration VMs.

5. Check the script ``ovn_migration.sh`` and override the environment variables
   if desired.

   Below are the environment variables

    * IS_DVR_ENABLED - If the existing ML2/OVS has DVR enabled, set it to True.
      Default value is False.

    * PUBLIC_NETWORK_NAME - Name of the public network. Default value is
      'public'.

    * IMAGE_NAME - Name/ID of the glance image to us for booting a test server.
      Default value is 'cirros'.

    * VALIDATE_MIGRATION - Create migration resources to validate the
      migration.
      The migration script, before starting the migration, boots a server and
      validates that the server is reachable after the migration.
      Default value is True.

    * SERVER_USER_NAME - User name to use for logging to the migration server.
      Default value is 'cirros'.

6. Set the below tripleo heat template parameters to point to the proper
   OVN docker images in appropriate environment file

    * DockerOvnControllerConfigImage
    * DockerOvnControllerImage
    * DockerOvnNorthdImage
    * DockerNeutronApiImage
    * DockerNeutronConfigImage
    * DockerOvnDbsImage
    * DockerOvnDbsConfigImage

   Eg: Run ``openstack overcloud container image prepare ..
   --env-file=/home/stack/docker-images.yaml
   -e /usr/share/openstack-tripleo-heat-templates/environments/services-docker
   /neutron-ovn-ha.yaml``.

7. Run the script ``ovn_migration.sh``.

Migration is complete !!!

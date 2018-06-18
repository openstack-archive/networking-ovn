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
      24 hours), that way all instances will grab the new new lease renewal
      time and start checking with the dhcp server periodically based on the
      T1 parameter.

    * Lowering the MTU of all VXLAN or GRE based networks down to
      make sure geneve works (a tool will be provided for that). The mtu
      must be set to "max_tunneling_network_mtu - ovn_geneve_overhead", that's
      generally "1500 - ovn_geneve_overhead", unless your network and any
      intermediate router hop between compute and network nodes is jumboframe
      capable). ovn_geneve_overhead is 58 bytes. VXLAN overhead is 50 bytes. So
      for the typical 1500 MTU tunneling network, we may need to assign 1442.

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

1. Create ``overcloud-deploy-ovn.sh`` script  in /home/stack. Make sure the
   below environment files are added in the order mentioned below

  .. code-block:: console

     -e /usr/share/openstack-tripleo-heat-templates/environments/docker-ha.yaml \
     -e /usr/share/openstack-tripleo-heat-templates/environments/services/neutron-ovn-ha.yaml \
     -e /home/stack/ovn-extras.yaml

    If compute nodes have external connectivity, then you can use the
    environment file - environments/services-docker/neutron-ovn-dvr-ha.yaml

2. Check the script ``ovn_migration.sh`` and override the environment variables
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

    * DHCP_RENEWAL_TIME - DHCP renewal time to configure in dhcp agent
      configuration file. The default value is 30 seconds.

2. Run ``./ovn_migration.sh generate-inventory`` to generate the inventory
   file - hosts_for_migration. Please review this file for correctness and
   modify it if desired.

4. Run ``./ovn_migration.sh setup-mtu-t1``. This lowers the T1 parameter
   of the internal neutron DHCP servers configuring the ‘dhcp_renewal_time’ in
   /var/lib/config-data/puppet-generated/neutron/etc/neutron/dhcp_agent.ini
   in all the nodes where DHCP agent is running.

5. After the previous step we need to wait at least 24h before continuing
   if you are using VXLAN or GRE tenant networking. This will allow VMs to
   catch up with the new MTU size of the next step.

    .. warning::

        This step is very important, never skip it if you are using VXLAN
        or GRE tenant networks. If you are using VLAN tenant networks you don't
        need to wait.

    .. warning::

        If you have any instance with static IP assignation on VXLAN or
        GRE tenant networks, you will need to manually modify the
        configuration of those instances to configure the new geneve MTU,
        which is current VXLAN MTU minus 8 bytes, that is 1442 when VXLAN
        based MTU was 1450.

    .. note::

        24h is the time based on default configuration, it actually depends on
        /var/lib/config-data/puppet-generated/neutron/etc/neutron/dhcp_agent.ini
        dhcp_renewal_time and
        /var/lib/config-data/puppet-generated/neutron/etc/neutron/neutron.conf
        dhcp_lease_duration parameters. (defaults to 86400 seconds)

    .. note::

        Please note that migrating a VLAN deployment is not recommended at
        this time because of a bug in core ovn, full support is being worked
        out here:
        https://mail.openvswitch.org/pipermail/ovs-dev/2018-May/347594.html

   One way of verifying that the T1 parameter has propated to existing VMs
   is going to one of the compute nodes, and run tcpdump over one of the
   VM taps attached to a tenant network,  we should see that requests happen
   around every 30 seconds.

    .. code-block:: console

        [heat-admin@overcloud-novacompute-0 ~]$ sudo tcpdump -i tap52e872c2-e6 port 67 or port 68 -n
        tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
        listening on tap52e872c2-e6, link-type EN10MB (Ethernet), capture size 262144 bytes
        13:17:28.954675 IP 192.168.99.5.bootpc > 192.168.99.3.bootps: BOOTP/DHCP, Request from fa:16:3e:6b:41:3d, length 300
        13:17:28.961321 IP 192.168.99.3.bootps > 192.168.99.5.bootpc: BOOTP/DHCP, Reply, length 355
        13:17:56.241156 IP 192.168.99.5.bootpc > 192.168.99.3.bootps: BOOTP/DHCP, Request from fa:16:3e:6b:41:3d, length 300
        13:17:56.249899 IP 192.168.99.3.bootps > 192.168.99.5.bootpc: BOOTP/DHCP, Reply, length 355

    .. note::

        This verification is not possible with cirros VMs, due to cirros
        udhcpc implementation which won't obey DHCP option 58 (T1), if you have
        any cirros based instances you will need to reboot them.

6. Run ``./ovn_migration.sh reduce-mtu``. This lowers the MTU of the pre
   migration VXLAN and GRE networks. You can skip this step if you use VLAN
   tenant networks. It will be safe to execute in such case, because the
   tool will ignore non-VXLAN/GRE networks.

7. Set the below tripleo heat template parameters to point to the proper
   OVN docker images in appropriate environment file

    * DockerOvnControllerConfigImage
    * DockerOvnControllerImage
    * DockerOvnNorthdImage
    * DockerNeutronApiImage
    * DockerNeutronConfigImage
    * DockerOvnDbsImage
    * DockerOvnDbsConfigImage

   This can be done running the next command:

   .. code-block:: console

       PREPARE_ARGS="-e /usr/share/openstack-tripleo-heat-templates/environments/docker.yaml \
                     -e /usr/share/openstack-tripleo-heat-templates/environments/services/neutron-ovn-ha.yaml" \
          ~/overcloud-prep-containers.sh

8. Run ``./ovn_migration.sh start-migration`` to kick start the migration
   process.

Migration is complete !!!

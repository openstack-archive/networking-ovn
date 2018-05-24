Migration from ML2/OVS to ML2/OVN in a tripleo deployment
=========================================================

To migrate your existing ML2/OVS deployment to ML2/OVN, run the
script ``ovn_migration.sh``` in the undercloud.

This script does in place migration from ML2/OVS to ML2/OVN i.e the VMs
hosted on the compute nodes are not migrated to other compute hosts, instead
the ovn-controller service manages the OVS integration bridge by the end of
migration.

Steps for migration
-------------------

1. Run ``python network_mtu.py update mtu`` to lower the mtu of the pre migration
   vxlan networks. Since OVN uses geneve tunnels, the mtu has to be lowered.

2. Create ``overcloud-deploy-ovn.sh`` script  in /home/stack. Make sure the
   below environment files are added in the order mentioned below
     * -e /usr/share/openstack-triple-heat-templates/environments/docker.yaml
     * -e /usr/share/openstack-triple-heat-templates/environments/docker-ha.yaml
     * -e /usr/share/openstack-tripleo-heat-templates/environments/services-docker/neutron-ovn-ha.yaml
     * -e /home/stack/ovn-extras.yaml

3. Wait till the new MTU values are propagated to all the pre migration VMs

4. Check the script ``ovn_migration.sh`` and override the environment variables if desired.
   Below are the environment variables

    * IS_DVR_ENABLED - If the existing ML2/OVS has DVR enabled, set it to True.
      Default value is False.

    * PUBLIC_NETWORK_NAME - Name of the public network. Default value is 'public'.

    * IMAGE_NAME - Name/ID of the glance image to us for booting a test server.
      Default value is 'cirros'.

    * VALIDATE_MIGRATION - Create migration resources to validate the migration.
      The migration script, before starting the migration, boots a server and
      validates that the server is reachable after the migration.
      Default value is True.

    * SERVER_USER_NAME - User name to use for logging to the migration server.
      Default value is 'cirros'.

5. Run the script ``ovn_migration.sh``.

Migration is complete !!!

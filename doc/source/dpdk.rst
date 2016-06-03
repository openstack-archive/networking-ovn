DPDK Support in OVN
===================

Configuration Settings
----------------------

The following are the configuration parameters which need to be set in
the Neutron configuration file under the 'ovn' section to enable DPDK support.

**vif_type**
    Valid values are one of ["ovs", "vhostuser"]. The default value is "ovs".
    To enable DPDK, this has to be set to "vhostuser". If it is set to
    "vhostuser", the OVN ML2 driver assumes that OVS on every node has been
    configured to use the DPDK datapath.

**vhost_sock_dir**
    This is the directory path in which vswitch daemon in all the compute
    nodes creates the virtio socket. Follow the instructions in
    INSTALL.DPDK.md in openvswitch source tree to know how to configure DPDK
    support in vswitch daemons.

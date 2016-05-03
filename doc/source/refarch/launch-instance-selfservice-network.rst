.. _refarch-launch-instance-selfservice-network:

Launch an instance on a self-service network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To launch an instance on a self-service network, follow the same steps as
:ref:`launching an instance on the provider network
<refarch-launch-instance-provider-network>`, but using the UUID of the
self-service network.

OVN operations
^^^^^^^^^^^^^^

The OVN mechanism driver and OVN perform the following operations when
launching an instance.

#. The OVN mechanism driver creates a logical port for the instance.

   .. code-block:: console

      _uuid               : c754d1d2-a7fb-4dd0-b14c-c076962b06b9
      addresses           : ["fa:16:3e:15:7d:13 192.168.1.5"]
      enabled             : true
      external_ids        : {"neutron:port_name"=""}
      name                : "eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"
      options             : {}
      parent_name         : []
      port_security       : ["fa:16:3e:15:7d:13 192.168.1.5"]
      tag                 : []
      type                : ""
      up                  : true

#. The OVN mechanism driver creates ACL entries for this port and
   any other ports in the project.

   .. code-block:: console

      _uuid               : 00ecbe8f-c82a-4e18-b688-af2a1941cff7
      action              : allow
      direction           : from-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "inport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip4 && (ip4.dst == 255.255.255.255 || ip4.dst == 192.168.1.0/24) && udp && udp.src == 68 && udp.dst == 67"
      priority            : 1002

      _uuid               : 2bf5b7ed-008e-4676-bba5-71fe58897886
      action              : allow-related
      direction           : from-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "inport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip4"
      priority            : 1002

      _uuid               : 330b4e27-074f-446a-849b-9ab0018b65c5
      action              : allow
      direction           : to-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "outport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip4 && ip4.src == 192.168.1.0/24 && udp && udp.src == 67 && udp.dst == 68"
      priority            : 1002

      _uuid               : 683f52f2-4be6-4bd7-a195-6c782daa7840
      action              : allow-related
      direction           : from-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "inport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip6"
      priority            : 1002

      _uuid               : 8160f0b4-b344-43d5-bbd4-ca63a71aa4fc
      action              : drop
      direction           : to-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "outport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip"
      priority            : 1001

      _uuid               : 97c6b8ca-14ea-4812-8571-95d640a88f4f
      action              : allow-related
      direction           : to-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "outport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip6"
      priority            : 1002

      _uuid               : 9cfd8eb5-5daa-422e-8fe8-bd22fd7fa826
      action              : allow-related
      direction           : to-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "outport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip4 && ip4.src == 0.0.0.0/0 && icmp4"
      priority            : 1002

      _uuid               : f72c2431-7a64-4cea-b84a-118bdc761be2
      action              : drop
      direction           : from-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "inport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip"
      priority            : 1001

      _uuid               : f94133fa-ed27-4d5e-a806-0d528e539cb3
      action              : allow-related
      direction           : to-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "outport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip4 && (ip4.src == 203.0.113.103)"
      priority            : 1002

#. The OVN mechanism driver updates the logical switch information with
   the UUIDs of these objects.

   .. code-block:: console

      _uuid               : 15e2c80b-1461-4003-9869-80416cd97de5
      acls                : [00ecbe8f-c82a-4e18-b688-af2a1941cff7,
                             2bf5b7ed-008e-4676-bba5-71fe58897886,
                             330b4e27-074f-446a-849b-9ab0018b65c5,
                             683f52f2-4be6-4bd7-a195-6c782daa7840,
                             8160f0b4-b344-43d5-bbd4-ca63a71aa4fc,
                             97c6b8ca-14ea-4812-8571-95d640a88f4f,
                             9cfd8eb5-5daa-422e-8fe8-bd22fd7fa826,
                             f72c2431-7a64-4cea-b84a-118bdc761be2,
                             f94133fa-ed27-4d5e-a806-0d528e539cb3]
      external_ids        : {"neutron:network_name"="selfservice"}
      name                : "neutron-6cc81cae-8c5f-4c09-aaf2-35d0aa95c084"
      ports               : [2df457a5-f71c-4a2f-b9ab-d9e488653872,
                             67c2737c-b380-492b-883b-438048b48e56,
                             c754d1d2-a7fb-4dd0-b14c-c076962b06b9]

#. If the project contains instances on another network that use the same
   security group and that security group contains a ``remote_group_id``
   value, the OVN mechanism driver creates ACLs to handle communication among
   those instances and updates the provider network logical switch record
   because the driver cannot determine whether external means connect the
   networks.

   * Access control lists

     .. code-block:: console

        _uuid               : 7ca6ec49-f0a0-45d4-a839-dd1c9a9b8203
        action              : allow-related
        direction           : to-lport
        external_ids        : {"neutron:lport"="cafd4862-c69c-46e4-b3d2-6141ce06b205"}
        log                 : false
        match               : "outport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip4 && (ip4.src == 192.168.1.5)"
        priority            : 1002

        _uuid               : a012e647-da2f-4ca7-8344-5cf15bd2f257
        action              : allow-related
        direction           : to-lport
        external_ids        : {"neutron:lport"="cafd4862-c69c-46e4-b3d2-6141ce06b205"}
        log                 : false
        match               : "outport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip6"
        priority            : 1002

   * Logical ports

     .. code-block:: console

        _uuid               : 924500c4-8580-4d5f-a7ad-8769f6e58ff5
        acls                : [05a92f66-be48-461e-a7f1-b07bfbd3e667,
                               36dbb1b1-cd30-4454-a0bf-923646eb7c3f,
                               37f18377-d6c3-4c44-9e4d-2170710e50ff,
                               7b3f63b8-e69a-476c-ad3d-37de043232b2,
                               7ca6ec49-f0a0-45d4-a839-dd1c9a9b8203,
                               a012e647-da2f-4ca7-8344-5cf15bd2f257,
                               a5a787b8-7040-4b63-a20a-551bd73eb3d1,
                               a61d0068-b1aa-4900-9882-e0671d1fc131,
                               f8d27bfc-4d74-4e73-8fac-c84585443efd]
        external_ids        : {"neutron:network_name"=provider}
        name                : "neutron-670efade-7cd0-4d87-8a04-27f366eb8941"
        ports               : [38cf8b52-47c4-4e93-be8d-06bf71f6a7c9,
                               5e144ab9-3e08-4910-b936-869bbbf254c8,
                               a576b812-9c3e-4cfb-9752-5d8500b3adf9,
                               cc891503-1259-47a1-9349-1c0293876664]

#. The OVN controller service on each compute node translates these objects
   into flows on the integration bridge ``br-int``. Exact flows depend on
   whether the compute node containing the instance also contains a DHCP agent
   on the subnet.

   * On the compute node containing the instance, the Compute service creates
     a port that connects the instance to the integration bridge and OVN
     creates the following flows:

     .. code-block:: console

        # ovs-ofctl show br-int
        OFPT_FEATURES_REPLY (xid=0x2): dpid:000022024a1dc045
        n_tables:254, n_buffers:256
        capabilities: FLOW_STATS TABLE_STATS PORT_STATS QUEUE_STATS ARP_MATCH_IP
        actions: output enqueue set_vlan_vid set_vlan_pcp strip_vlan mod_dl_src mod_dl_dst mod_nw_src mod_nw_dst mod_nw_tos mod_tp_src mod_tp_dst
         12(tapeaf36f62-56): addr:fe:16:3e:15:7d:13
             config:     0
             state:      0
             current:    10MB-FD COPPER

     .. code-block:: console

        cookie=0x0, duration=179.460s, table=0, n_packets=122, n_bytes=10556,
            idle_age=1, priority=100,in_port=12
            actions=load:0x4->NXM_NX_REG5[],load:0x5->OXM_OF_METADATA[],
                load:0x3->NXM_NX_REG6[],resubmit(,16)
        cookie=0x0, duration=187.408s, table=16, n_packets=122, n_bytes=10556,
            idle_age=1, priority=50,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13 actions=resubmit(,17)
        cookie=0x0, duration=187.408s, table=17, n_packets=2, n_bytes=684,
            idle_age=84, priority=90,udp,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13,nw_src=0.0.0.0,nw_dst=255.255.255.255,
                tp_src=68,tp_dst=67 actions=resubmit(,18)
        cookie=0x0, duration=187.408s, table=17, n_packets=98, n_bytes=8276,
            idle_age=1, priority=90,ip,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13,nw_src=192.168.1.5
            actions=resubmit(,18)
        cookie=0x0, duration=187.408s, table=17, n_packets=17, n_bytes=1386,
            idle_age=55, priority=80,ipv6,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13 actions=drop
        cookie=0x0, duration=187.408s, table=17, n_packets=0, n_bytes=0,
            idle_age=187, priority=80,ip,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13 actions=drop
        cookie=0x0, duration=187.408s, table=18, n_packets=5, n_bytes=210,
            idle_age=10, priority=90,arp,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13,arp_spa=192.168.1.5,
            arp_sha=fa:16:3e:15:7d:13 actions=resubmit(,19)
        cookie=0x0, duration=187.408s, table=18, n_packets=0, n_bytes=0,
            idle_age=187, priority=80,icmp6,reg6=0x3,metadata=0x5,
                icmp_type=135,icmp_code=0 actions=drop
        cookie=0x0, duration=187.408s, table=18, n_packets=0, n_bytes=0,
            idle_age=187, priority=80,icmp6,reg6=0x3,metadata=0x5,
                icmp_type=136,icmp_code=0 actions=drop
        cookie=0x0, duration=187.408s, table=18, n_packets=0, n_bytes=0,
            idle_age=187, priority=80,arp,reg6=0x3,metadata=0x5 actions=drop
        cookie=0x0, duration=187.408s, table=19, n_packets=0, n_bytes=0,
            idle_age=187, priority=100,ipv6,metadata=0x5
            actions=ct(table=20,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=187.408s, table=19, n_packets=150, n_bytes=13766,
            idle_age=1, priority=100,ip,metadata=0x5
            actions=ct(table=20,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=187.408s, table=20, n_packets=100, n_bytes=8450,
            idle_age=1, priority=65535,ct_state=-new+est-rel-inv+trk,
                metadata=0x5 actions=resubmit(,21)
        cookie=0x0, duration=187.408s, table=20, n_packets=0, n_bytes=0,
            idle_age=187, priority=2002,udp,reg6=0x3,metadata=0x5,
                nw_dst=192.168.1.0/24,tp_src=68,tp_dst=67
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=476.272s, table=20, n_packets=0, n_bytes=0,
            idle_age=476, priority=2002,ct_state=+new+trk,ip,reg6=0x4,
                metadata=0x4
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=187.408s, table=20, n_packets=0, n_bytes=0,
            idle_age=187, priority=65535,ct_state=-new-est+rel-inv+trk,
                metadata=0x5 actions=resubmit(,21)
        cookie=0x0, duration=187.408s, table=20, n_packets=0, n_bytes=0,
            idle_age=187, priority=65535,ct_state=+inv+trk,metadata=0x5
            actions=drop
        cookie=0x0, duration=476.272s, table=20, n_packets=0, n_bytes=0,
            idle_age=476, priority=2002,udp,reg6=0x4,metadata=0x4,
                nw_dst=255.255.255.255,tp_src=68,tp_dst=67
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=187.408s, table=20, n_packets=0, n_bytes=0,
            idle_age=187, priority=2002,udp,reg6=0x3,metadata=0x5,
                nw_dst=255.255.255.255,tp_src=68,tp_dst=67
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=476.273s, table=20, n_packets=0, n_bytes=0,
            idle_age=476, priority=2001,ipv6,reg6=0x4,metadata=0x4
            actions=drop
        cookie=0x0, duration=476.272s, table=20, n_packets=0, n_bytes=0,
            idle_age=476, priority=2001,ip,reg6=0x4,metadata=0x4 actions=drop
        cookie=0x0, duration=187.408s, table=20, n_packets=0, n_bytes=0,
            idle_age=187, priority=2001,ip,reg6=0x3,metadata=0x5 actions=drop
        cookie=0x0, duration=187.408s, table=20, n_packets=0, n_bytes=0,
            idle_age=187, priority=2001,ipv6,reg6=0x3,metadata=0x5 actions=drop
        cookie=0x0, duration=476.273s, table=20, n_packets=0, n_bytes=0,
            idle_age=476, priority=1,ipv6,metadata=0x4
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=187.408s, table=20, n_packets=0, n_bytes=0,
            idle_age=187, priority=1,ipv6,metadata=0x5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=187.408s, table=20, n_packets=2, n_bytes=766,
            idle_age=84, priority=1,ip,metadata=0x5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=179.457s, table=21, n_packets=2, n_bytes=84,
            idle_age=33, priority=50,arp,metadata=0x5,arp_tpa=192.168.1.5,
                arp_op=1
            actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],
                mod_dl_src:fa:16:3e:15:7d:13,load:0x2->NXM_OF_ARP_OP[],
                move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],
                load:0xfa163e157d13->NXM_NX_ARP_SHA[],
                move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],
                load:0xc0a80105->NXM_OF_ARP_SPA[],
                move:NXM_NX_REG6[]->NXM_NX_REG7[],
                load:0->NXM_NX_REG6[],load:0->NXM_OF_IN_PORT[],resubmit(,32)
        cookie=0x0, duration=187.408s, table=22, n_packets=50, n_bytes=4806,
            idle_age=1, priority=50,metadata=0x5,dl_dst=fa:16:3e:15:7d:13
            actions=load:0x3->NXM_NX_REG7[],resubmit(,32)
        cookie=0x0, duration=469.575s, table=33, n_packets=74, n_bytes=7040,
            idle_age=305, priority=100,reg7=0x4,metadata=0x4
            actions=load:0x1->NXM_NX_REG7[],resubmit(,33)
        cookie=0x0, duration=51424.070s, table=33, n_packets=18, n_bytes=1980,
            idle_age=84, hard_age=179, priority=100,reg7=0xffff,metadata=0x5
            actions=load:0x3->NXM_NX_REG5[],load:0x2->NXM_NX_REG7[],
                resubmit(,34),load:0x4->NXM_NX_REG5[],load:0x3->NXM_NX_REG7[],
                resubmit(,34),load:0xffff->NXM_NX_REG7[]
        cookie=0x0, duration=179.460s, table=34, n_packets=2, n_bytes=684,
            idle_age=84, priority=100,reg6=0x3,reg7=0x3,metadata=0x5
            actions=drop
        cookie=0x0, duration=187.408s, table=48, n_packets=161, n_bytes=15137,
            idle_age=1, priority=100,ip,metadata=0x5
            actions=ct(table=49,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=187.408s, table=48, n_packets=0, n_bytes=0,
            idle_age=187, priority=100,ipv6,metadata=0x5
            actions=ct(table=49,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=187.408s, table=49, n_packets=0, n_bytes=0,
            idle_age=187, priority=65535,ct_state=-new-est+rel-inv+trk,
                metadata=0x5 actions=resubmit(,50)
        cookie=0x0, duration=187.408s, table=49, n_packets=124, n_bytes=10473,
            idle_age=1, priority=65535,ct_state=-new+est-rel-inv+trk,
                metadata=0x5 actions=resubmit(,50)
        cookie=0x0, duration=187.408s, table=49, n_packets=0, n_bytes=0,
            idle_age=187, priority=65535,ct_state=+inv+trk,metadata=0x5
            actions=drop
        cookie=0x0, duration=476.273s, table=49, n_packets=0, n_bytes=0,
            idle_age=476, priority=2002,udp,reg7=0x4,metadata=0x4,
                nw_src=203.0.113.0/24,tp_src=67,tp_dst=68
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=187.408s, table=49, n_packets=3, n_bytes=1140,
            idle_age=84, priority=2002,udp,reg7=0x3,metadata=0x5,
                nw_src=192.168.1.0/24,tp_src=67,tp_dst=68
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=348.014s, table=49, n_packets=0, n_bytes=0,
            idle_age=348, priority=2002,ct_state=+new+trk,icmp,reg7=0x4,
                metadata=0x4
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=187.408s, table=49, n_packets=12, n_bytes=1176,
            idle_age=41, priority=2002,ct_state=+new+trk,icmp,reg7=0x3,
                metadata=0x5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=187.408s, table=49, n_packets=0, n_bytes=0,
            idle_age=187, priority=2002,ct_state=+new+trk,ip,reg7=0x3,
                metadata=0x5,nw_src=203.0.113.103
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=187.236s, table=49, n_packets=0, n_bytes=0,
            idle_age=187, priority=2002,ct_state=+new+trk,ip,reg7=0x4,
                metadata=0x4,nw_src=192.168.1.5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=187.408s, table=49, n_packets=0, n_bytes=0,
            idle_age=187, priority=2002,ct_state=+new+trk,ipv6,reg7=0x3,
                metadata=0x5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=187.408s, table=49, n_packets=0, n_bytes=0,
            idle_age=187, priority=2001,ipv6,reg7=0x3,metadata=0x5
            actions=drop
        cookie=0x0, duration=187.408s, table=49, n_packets=0, n_bytes=0,
            idle_age=187, priority=2001,ip,reg7=0x3,metadata=0x5 actions=drop
        cookie=0x0, duration=187.408s, table=49, n_packets=22, n_bytes=2348,
            idle_age=1, priority=1,ip,metadata=0x5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=187.408s, table=49, n_packets=0, n_bytes=0,
            idle_age=187, priority=1,ipv6,metadata=0x5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=187.408s, table=50, n_packets=0, n_bytes=0,
            idle_age=187, priority=90,ip,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13,nw_dst=224.0.0.0/4
            actions=resubmit(,51)
        cookie=0x0, duration=187.408s, table=50, n_packets=111, n_bytes=10413,
            idle_age=1, priority=90,ip,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13,nw_dst=192.168.1.5
            actions=resubmit(,51)
        cookie=0x0, duration=187.408s, table=50, n_packets=0, n_bytes=0,
            idle_age=187, priority=90,ip,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13,nw_dst=255.255.255.255
            actions=resubmit(,51)
        cookie=0x0, duration=187.408s, table=50, n_packets=0, n_bytes=0,
            idle_age=187, priority=80,ipv6,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13 actions=drop
        cookie=0x0, duration=187.408s, table=50, n_packets=0, n_bytes=0,
            idle_age=187, priority=80,ip,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13 actions=drop
        cookie=0x0, duration=187.408s, table=51, n_packets=116, n_bytes=10623,
            idle_age=1, priority=50,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13 actions=resubmit(,64)
        cookie=0x0, duration=179.460s, table=64, n_packets=116, n_bytes=10623,
            idle_age=1, priority=100,reg7=0x3,metadata=0x5 actions=output:12

   * For each compute node that only contains a DHCP agent on the subnet,
     OVN creates the following flows:

     .. code-block:: console

        cookie=0x0, duration=192.587s, table=16, n_packets=0, n_bytes=0,
            idle_age=192, priority=50,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13 actions=resubmit(,17)
        cookie=0x0, duration=192.587s, table=17, n_packets=0, n_bytes=0,
            idle_age=192, priority=90,ip,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13,nw_src=192.168.1.5
            actions=resubmit(,18)
        cookie=0x0, duration=192.587s, table=17, n_packets=0, n_bytes=0,
            idle_age=192, priority=90,udp,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13,nw_src=0.0.0.0,
                nw_dst=255.255.255.255,tp_src=68,tp_dst=67
            actions=resubmit(,18)
        cookie=0x0, duration=192.587s, table=17, n_packets=0, n_bytes=0,
            idle_age=192, priority=80,ipv6,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13 actions=drop
        cookie=0x0, duration=192.587s, table=17, n_packets=0, n_bytes=0,
            idle_age=192, priority=80,ip,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13 actions=drop
        cookie=0x0, duration=192.587s, table=18, n_packets=0, n_bytes=0,
            idle_age=192, priority=90,arp,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13,arp_spa=192.168.1.5,
                arp_sha=fa:16:3e:15:7d:13 actions=resubmit(,19)
        cookie=0x0, duration=192.587s, table=18, n_packets=0, n_bytes=0,
            idle_age=192, priority=80,arp,reg6=0x3,metadata=0x5 actions=drop
        cookie=0x0, duration=192.587s, table=18, n_packets=0, n_bytes=0,
            idle_age=192, priority=80,icmp6,reg6=0x3,metadata=0x5,
                icmp_type=135,icmp_code=0 actions=drop
        cookie=0x0, duration=192.587s, table=18, n_packets=0, n_bytes=0,
            idle_age=192, priority=80,icmp6,reg6=0x3,metadata=0x5,
                icmp_type=136,icmp_code=0 actions=drop
        cookie=0x0, duration=192.587s, table=19, n_packets=0, n_bytes=0,
            idle_age=192, priority=100,ipv6,metadata=0x5
            actions=ct(table=20,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=192.587s, table=19, n_packets=61, n_bytes=5607,
            idle_age=6, priority=100,ip,metadata=0x5
            actions=ct(table=20,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=192.587s, table=20, n_packets=48, n_bytes=4057,
            idle_age=6, priority=65535,ct_state=-new+est-rel-inv+trk,
                metadata=0x5 actions=resubmit(,21)
        cookie=0x0, duration=192.587s, table=20, n_packets=0, n_bytes=0,
            idle_age=192, priority=65535,ct_state=-new-est+rel-inv+trk,
                metadata=0x5 actions=resubmit(,21)
        cookie=0x0, duration=192.587s, table=20, n_packets=0, n_bytes=0,
            idle_age=192, priority=65535,ct_state=+inv+trk,metadata=0x5
            actions=drop
        cookie=0x0, duration=192.587s, table=20, n_packets=0, n_bytes=0,
            idle_age=192, priority=2002,ct_state=+new+trk,ipv6,reg6=0x3,
                metadata=0x5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=192.587s, table=20, n_packets=0, n_bytes=0,
            idle_age=192, priority=2002,ct_state=+new+trk,ip,reg6=0x3,
                metadata=0x5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=192.587s, table=20, n_packets=0, n_bytes=0,
            idle_age=192, priority=2002,udp,reg6=0x3,metadata=0x5,
                nw_dst=192.168.1.0/24,tp_src=68,tp_dst=67
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=192.587s, table=20, n_packets=0, n_bytes=0,
            idle_age=192, priority=2002,udp,reg6=0x3,metadata=0x5,
                nw_dst=255.255.255.255,tp_src=68,tp_dst=67
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=192.587s, table=20, n_packets=0, n_bytes=0,
            idle_age=192, priority=2001,ip,reg6=0x3,metadata=0x5 actions=drop
        cookie=0x0, duration=192.587s, table=20, n_packets=0, n_bytes=0,
            idle_age=192, priority=2001,ipv6,reg6=0x3,metadata=0x5 actions=drop
        cookie=0x0, duration=192.587s, table=20, n_packets=0, n_bytes=0,
            idle_age=192, priority=1,ipv6,metadata=0x5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=192.587s, table=20, n_packets=13, n_bytes=1550,
            idle_age=46, priority=1,ip,metadata=0x5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=184.638s, table=21, n_packets=4, n_bytes=168,
            idle_age=1, priority=50,arp,metadata=0x5,arp_tpa=192.168.1.5,
                arp_op=1
            actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],
                mod_dl_src:fa:16:3e:15:7d:13,load:0x2->NXM_OF_ARP_OP[],
                move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],
                load:0xfa163e157d13->NXM_NX_ARP_SHA[],
                move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],
                load:0xc0a80105->NXM_OF_ARP_SPA[],
                move:NXM_NX_REG6[]->NXM_NX_REG7[],
                load:0->NXM_NX_REG6[],load:0->NXM_OF_IN_PORT[],resubmit(,32)
        cookie=0x0, duration=192.587s, table=22, n_packets=61, n_bytes=5607,
            idle_age=6, priority=50,metadata=0x5,dl_dst=fa:16:3e:15:7d:13
            actions=load:0x3->NXM_NX_REG7[],resubmit(,32)
        cookie=0x0, duration=184.640s, table=32, n_packets=61, n_bytes=5607,
            idle_age=6, priority=100,reg7=0x3,metadata=0x5
            actions=load:0x5->NXM_NX_TUN_ID[0..23],
                set_field:0x3/0xffffffff->tun_metadata0,
                move:NXM_NX_REG6[0..14]->NXM_NX_TUN_METADATA0[16..30],output:4
        cookie=0x0, duration=192.587s, table=48, n_packets=0, n_bytes=0,
            idle_age=192, priority=100,ipv6,metadata=0x5
            actions=ct(table=49,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=192.587s, table=48, n_packets=52, n_bytes=4920,
            idle_age=6, priority=100,ip,metadata=0x5
            actions=ct(table=49,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=192.587s, table=49, n_packets=0, n_bytes=0,
            idle_age=192, priority=65535,ct_state=+inv+trk,
                metadata=0x5 actions=drop
        cookie=0x0, duration=192.587s, table=49, n_packets=0, n_bytes=0,
            idle_age=192, priority=65535,ct_state=-new-est+rel-inv+trk,
                metadata=0x5 actions=resubmit(,50)
        cookie=0x0, duration=192.587s, table=49, n_packets=27, n_bytes=2316,
            idle_age=6, priority=65535,ct_state=-new+est-rel-inv+trk,
                metadata=0x5 actions=resubmit(,50)
        cookie=0x0, duration=192.587s, table=49, n_packets=0, n_bytes=0,
            idle_age=192, priority=2002,ct_state=+new+trk,icmp,reg7=0x3,
                metadata=0x5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=192.587s, table=49, n_packets=0, n_bytes=0,
            idle_age=192, priority=2002,ct_state=+new+trk,ipv6,reg7=0x3,
                metadata=0x5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=192.587s, table=49, n_packets=0, n_bytes=0,
            idle_age=192, priority=2002,udp,reg7=0x3,metadata=0x5,
                nw_src=192.168.1.0/24,tp_src=67,tp_dst=68
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=192.587s, table=49, n_packets=0, n_bytes=0,
            idle_age=192, priority=2002,ct_state=+new+trk,ip,reg7=0x3,
                metadata=0x5,nw_src=203.0.113.103
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=192.587s, table=49, n_packets=0, n_bytes=0,
            idle_age=192, priority=2001,ip,reg7=0x3,metadata=0x5 actions=drop
        cookie=0x0, duration=192.587s, table=49, n_packets=0, n_bytes=0,
            idle_age=192, priority=2001,ipv6,reg7=0x3,metadata=0x5 actions=drop
        cookie=0x0, duration=192.587s, table=49, n_packets=25, n_bytes=2604,
            idle_age=6, priority=1,ip,metadata=0x5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=192.587s, table=49, n_packets=0, n_bytes=0,
            idle_age=192, priority=1,ipv6,metadata=0x5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=192.587s, table=50, n_packets=0, n_bytes=0,
            idle_age=192, priority=90,ip,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13,nw_dst=224.0.0.0/4
            actions=resubmit(,51)
        cookie=0x0, duration=192.587s, table=50, n_packets=0, n_bytes=0,
            idle_age=192, priority=90,ip,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13,nw_dst=255.255.255.255
            actions=resubmit(,51)
        cookie=0x0, duration=192.587s, table=50, n_packets=0, n_bytes=0,
            idle_age=192, priority=90,ip,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13,nw_dst=192.168.1.5
            actions=resubmit(,51)
        cookie=0x0, duration=192.587s, table=50, n_packets=0, n_bytes=0,
            idle_age=192, priority=80,ipv6,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13 actions=drop
        cookie=0x0, duration=192.587s, table=50, n_packets=0, n_bytes=0,
            idle_age=192, priority=80,ip,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13 actions=drop
        cookie=0x0, duration=192.587s, table=51, n_packets=0, n_bytes=0,
            idle_age=192, priority=50,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13 actions=resubmit(,64)

   * For each compute node that contains neither the instance nor a DHCP
     agent on the subnet, OVN creates the following flows:

     .. code-block:: console

        cookie=0x0, duration=189.763s, table=49, n_packets=0, n_bytes=0,
            idle_age=189, priority=2002,ct_state=+new+trk,ipv6,reg7=0x4,
                metadata=0x4
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=189.763s, table=49, n_packets=0, n_bytes=0,
            idle_age=189, priority=2002,ct_state=+new+trk,ip,reg7=0x4,
                metadata=0x4,nw_src=192.168.1.5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)

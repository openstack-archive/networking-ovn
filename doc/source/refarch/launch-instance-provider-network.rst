.. _refarch-launch-instance-provider-network:

Launch an instance on a provider network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. On the controller node, source the credentials for a regular
   (non-privileged) project. The following example uses the ``demo``
   project.

#. On the controller node, launch an instance using the UUID of the
   provider network.

   .. code-block:: console

      $ openstack server create --flavor m1.tiny --image cirros \
        --nic net-id=0243277b-4aa8-46d8-9e10-5c9ad5e01521 \
        --security-group default --key-name mykey provider-instance
      +--------------------------------------+-----------------------------------------------+
      | Property                             | Value                                         |
      +--------------------------------------+-----------------------------------------------+
      | OS-DCF:diskConfig                    | MANUAL                                        |
      | OS-EXT-AZ:availability_zone          | nova                                          |
      | OS-EXT-STS:power_state               | 0                                             |
      | OS-EXT-STS:task_state                | scheduling                                    |
      | OS-EXT-STS:vm_state                  | building                                      |
      | OS-SRV-USG:launched_at               | -                                             |
      | OS-SRV-USG:terminated_at             | -                                             |
      | accessIPv4                           |                                               |
      | accessIPv6                           |                                               |
      | adminPass                            | hdF4LMQqC5PB                                  |
      | config_drive                         |                                               |
      | created                              | 2015-09-17T21:58:18Z                          |
      | flavor                               | m1.tiny (1)                                   |
      | hostId                               |                                               |
      | id                                   | 181c52ba-aebc-4c32-a97d-2e8e82e4eaaf          |
      | image                                | cirros (38047887-61a7-41ea-9b49-27987d5e8bb9) |
      | key_name                             | mykey                                         |
      | metadata                             | {}                                            |
      | name                                 | provider-instance                             |
      | os-extended-volumes:volumes_attached | []                                            |
      | progress                             | 0                                             |
      | security_groups                      | default                                       |
      | status                               | BUILD                                         |
      | tenant_id                            | f5b2ccaa75ac413591f12fcaa096aa5c              |
      | updated                              | 2015-09-17T21:58:18Z                          |
      | user_id                              | 684286a9079845359882afc3aa5011fb              |
      +--------------------------------------+-----------------------------------------------+

OVN operations
^^^^^^^^^^^^^^

The OVN mechanism driver and OVN perform the following operations when
launching an instance.

#. The OVN mechanism driver creates a logical port for the instance.

   .. code-block:: console

      _uuid               : cc891503-1259-47a1-9349-1c0293876664
      addresses           : ["fa:16:3e:1c:ca:6a 203.0.113.103"]
      enabled             : true
      external_ids        : {"neutron:port_name"=""}
      name                : "cafd4862-c69c-46e4-b3d2-6141ce06b205"
      options             : {}
      parent_name         : []
      port_security       : ["fa:16:3e:1c:ca:6a 203.0.113.103"]
      tag                 : []
      type                : ""
      up                  : true

#. The OVN mechanism driver creates ACL entries for this port and
   any other ports in the project.

   .. code-block:: console

      _uuid               : f8d27bfc-4d74-4e73-8fac-c84585443efd
      action              : drop
      direction           : from-lport
      external_ids        : {"neutron:lport"="cafd4862-c69c-46e4-b3d2-6141ce06b205"}
      log                 : false
      match               : "inport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip"
      priority            : 1001

      _uuid               : a61d0068-b1aa-4900-9882-e0671d1fc131
      action              : allow
      direction           : to-lport
      external_ids        : {"neutron:lport"="cafd4862-c69c-46e4-b3d2-6141ce06b205"}
      log                 : false
      match               : "outport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip4 && ip4.src == 203.0.113.0/24 && udp && udp.src == 67 && udp.dst == 68"
      priority            : 1002

      _uuid               : a5a787b8-7040-4b63-a20a-551bd73eb3d1
      action              : allow-related
      direction           : from-lport
      external_ids        : {"neutron:lport"="cafd4862-c69c-46e4-b3d2-6141ce06b205"}
      log                 : false
      match               : "inport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip6"
      priority            : 1002

      _uuid               : 7b3f63b8-e69a-476c-ad3d-37de043232b2
      action              : allow-related
      direction           : to-lport
      external_ids        : {"neutron:lport"="cafd4862-c69c-46e4-b3d2-6141ce06b205"}
      log                 : false
      match               : "outport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip4 && ip4.src == 0.0.0.0/0 && icmp4"
      priority            : 1002

      _uuid               : 36dbb1b1-cd30-4454-a0bf-923646eb7c3f
      action              : allow
      direction           : from-lport
      external_ids        : {"neutron:lport"="cafd4862-c69c-46e4-b3d2-6141ce06b205"}
      log                 : false
      match               : "inport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip4 && (ip4.dst == 255.255.255.255 || ip4.dst == 203.0.113.0/24) && udp && udp.src == 68 && udp.dst == 67"
      priority            : 1002

      _uuid               : 05a92f66-be48-461e-a7f1-b07bfbd3e667
      action              : allow-related
      direction           : from-lport
      external_ids        : {"neutron:lport"="cafd4862-c69c-46e4-b3d2-6141ce06b205"}
      log                 : false
      match               : "inport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip4"
      priority            : 1002

      _uuid               : 37f18377-d6c3-4c44-9e4d-2170710e50ff
      action              : drop
      direction           : to-lport
      external_ids        : {"neutron:lport"="cafd4862-c69c-46e4-b3d2-6141ce06b205"}
      log                 : false
      match               : "outport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip"
      priority            : 1001

#. The OVN mechanism driver updates the logical switch information with
   the UUIDs of these objects.

   .. code-block:: console

      _uuid               : 924500c4-8580-4d5f-a7ad-8769f6e58ff5
      acls                : [05a92f66-be48-461e-a7f1-b07bfbd3e667,
                             36dbb1b1-cd30-4454-a0bf-923646eb7c3f,
                             37f18377-d6c3-4c44-9e4d-2170710e50ff,
                             7b3f63b8-e69a-476c-ad3d-37de043232b2,
                             a5a787b8-7040-4b63-a20a-551bd73eb3d1,
                             a61d0068-b1aa-4900-9882-e0671d1fc131,
                             f8d27bfc-4d74-4e73-8fac-c84585443efd]
      external_ids        : {"neutron:network_name"=provider}
      name                : "neutron-670efade-7cd0-4d87-8a04-27f366eb8941"
      ports               : [38cf8b52-47c4-4e93-be8d-06bf71f6a7c9,
                             5e144ab9-3e08-4910-b936-869bbbf254c8,
                             a576b812-9c3e-4cfb-9752-5d8500b3adf9,
                             cc891503-1259-47a1-9349-1c0293876664]

#. The OVN northbound service creates port bindings for the logical
   ports and adds them to the appropriate multicast group.

   * Port bindings

     .. code-block:: console

        _uuid               : e73e3fcd-316a-4418-bbd5-a8a42032b1c3
        chassis             : fc5ab9e7-bc28-40e8-ad52-2949358cc088
        datapath            : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
        logical_port        : "cafd4862-c69c-46e4-b3d2-6141ce06b205"
        mac                 : ["fa:16:3e:1c:ca:6a 203.0.113.103"]
        options             : {}
        parent_port         : []
        tag                 : []
        tunnel_key          : 4
        type                : ""

   * Multicast groups

     .. code-block:: console

        _uuid               : 39b32ccd-fa49-4046-9527-13318842461e
        datapath            : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
        name                : _MC_flood
        ports               : [030024f4-61c3-4807-859b-07727447c427,
                               904c3108-234d-41c0-b93c-116b7e352a75,
                               cc5bcd19-bcae-4e29-8cee-3ec8a8a75d46,
                               e73e3fcd-316a-4418-bbd5-a8a42032b1c3]
        tunnel_key          : 65535

#. The OVN northbound service translates the ACL and logical port objects
   into logical flows in the OVN southbound database.

   .. code-block:: console

      _uuid               : c0796be7-4638-4881-be76-4a8f825b13ee
      actions             : "next;"
      external_ids        : {stage-name="ls_in_port_sec_l2"}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "inport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && eth.src == {fa:16:3e:1c:ca:6a}"
      pipeline            : ingress
      priority            : 50
      table_id            : 0

      _uuid               : 5cd409a5-e393-4a55-a7ec-5dc44e1815e0
      actions             : "next;"
      external_ids        : {stage-name=ls_in_port_sec_ip}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "inport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && eth.src == fa:16:3e:1c:ca:6a && ip4.src == {203.0.113.103}"
      pipeline            : ingress
      priority            : 90
      table_id            : 1

      _uuid               : b28927b9-ed03-4269-8f03-0f86e798e1ea
      actions             : "next;"
      external_ids        : {stage-name=ls_in_port_sec_ip}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "inport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && eth.src == fa:16:3e:1c:ca:6a && ip4.src == 0.0.0.0 && ip4.dst == 255.255.255.255 && udp.src == 68 && udp.dst == 67"
      pipeline            : ingress
      priority            : 90
      table_id            : 1

      _uuid               : 809f59f9-97bb-48e3-82bf-b9afa6b5347e
      actions             : "drop;"
      external_ids        : {stage-name=ls_in_port_sec_ip}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "inport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && eth.src == fa:16:3e:1c:ca:6a && ip"
      pipeline            : ingress
      priority            : 80
      table_id            : 1

      _uuid               : 9ceb90b0-a672-4343-9a42-37b1d5fc5849
      actions             : "next;"
      external_ids        : {stage-name=ls_in_port_sec_nd}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "inport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && eth.src == fa:16:3e:1c:ca:6a && arp.sha == fa:16:3e:1c:ca:6a && (arp.spa == 203.0.113.103 )"
      pipeline            : ingress
      priority            : 90
      table_id            : 2

      _uuid               : be53cd1e-d56b-4820-bad6-0e92e8413970
      actions             : "drop;"
      external_ids        : {stage-name=ls_in_port_sec_nd}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "inport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && (arp || nd)"
      pipeline            : ingress
      priority            : 80
      table_id            : 2

      _uuid               : 671a9d40-70b2-4ff6-b630-332de60625c5
      actions             : "ct_next;"
      external_ids        : {stage-name=ls_in_pre_acl}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : ip
      pipeline            : ingress
      priority            : 100
      table_id            : 3

      _uuid               : 883b9568-81b2-4c70-9ac9-8c11d9058ae6
      actions             : "next;"
      external_ids        : {stage-name=ls_in_acl}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "ct.est && !ct.rel && !ct.new && !ct.inv"
      pipeline            : ingress
      priority            : 65535
      table_id            : 4

      _uuid               : a6451b1e-d9c8-49de-9761-168561c3bcf4
      actions             : "drop;"
      external_ids        : {stage-name=ls_in_acl}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : ct.inv
      pipeline            : ingress
      priority            : 65535
      table_id            : 4

      _uuid               : 511d2033-ecf4-4fde-9c86-13f83448eef5
      actions             : "next;"
      external_ids        : {stage-name=ls_in_acl}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "!ct.est && ct.rel && !ct.new && !ct.inv"
      pipeline            : ingress
      priority            : 65535
      table_id            : 4

      _uuid               : d4769e30-15a7-470c-afb0-60b42be53441
      actions             : "ct_commit; next;"
      external_ids        : {stage-name=ls_in_acl}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "ct.new && (inport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip4)"
      pipeline            : ingress
      priority            : 2002
      table_id            : 4

      _uuid               : 892d63d0-9c11-4d03-b0fc-3847e6187da9
      actions             : "ct_commit; next;"
      external_ids        : {stage-name=ls_in_acl}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "inport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip4 && (ip4.dst == 255.255.255.255 || ip4.dst == 203.0.113.0/24) && udp && udp.src == 68 && udp.dst == 67"
      pipeline            : ingress
      priority            : 2002
      table_id            : 4

      _uuid               : c4b680d5-7bd2-47bc-b79f-949395579e99
      actions             : "ct_commit; next;"
      external_ids        : {stage-name=ls_in_acl}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "ct.new && (inport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip6)"
      pipeline            : ingress
      priority            : 2002
      table_id            : 4

      _uuid               : f727c1f8-1284-4bec-b099-f85e1000a6e3
      actions             : "drop;"
      external_ids        : {stage-name=ls_in_acl}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "inport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip"
      pipeline            : ingress
      priority            : 2001
      table_id            : 4

      _uuid               : 3b16933b-f3a4-44e9-ba3b-421ba4af7557
      actions             : "ct_commit; next;"
      external_ids        : {stage-name=ls_in_acl}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : ip
      pipeline            : ingressk
      priority            : 1
      table_id            : 4

      _uuid               : 6a15e881-87cd-40a6-b2a1-d609b25617c5
      actions             : "eth.dst = eth.src; eth.src = fa:16:3e:1c:ca:6a; arp.op = 2; /* ARP reply \*/ arp.tha = arp.sha; arp.sha = fa:16:3e:1c:ca:6a; arp.tpa = arp.spa; arp.spa = 203.0.113.103; outport = inport; inport = \"\"; /* Allow sending out inport. \*/ output;"
      external_ids        : {stage-name=ls_in_arp_rsp}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "arp.tpa == 203.0.113.103 && arp.op == 1"
      pipeline            : ingress
      priority            : 50
      table_id            : 5

      _uuid               : 77f563d1-a249-4e54-a01e-f150ac83aeaf
      actions             : "outport = \"cafd4862-c69c-46e4-b3d2-6141ce06b205\"; output;"
      external_ids        : {stage-name="ls_in_l2_lkup"}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "eth.dst == fa:16:3e:1c:ca:6a"
      pipeline            : ingress
      priority            : 50
      table_id            : 6

      _uuid               : 074a6af5-93c4-4d65-b0a4-589e2f17efb0
      actions             : "ct_next;"
      external_ids        : {stage-name=ls_out_pre_acl}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : ip
      pipeline            : egress
      priority            : 100
      table_id            : 0

      _uuid               : e620ec59-7595-4673-9d1b-8b5d36b873fc
      actions             : "next;"
      external_ids        : {stage-name=ls_out_acl}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "!ct.est && ct.rel && !ct.new && !ct.inv"
      pipeline            : egress
      priority            : 65535
      table_id            : 1

      _uuid               : 90931328-8b6d-437d-b122-3e61b4a434dd
      actions             : "next;"
      external_ids        : {stage-name=ls_out_acl}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "ct.est && !ct.rel && !ct.new && !ct.inv"
      pipeline            : egress
      priority            : 65535
      table_id            : 1

      _uuid               : 0eeb89b0-1180-4476-aa8c-49fb880c2daa
      actions             : "drop;"
      external_ids        : {stage-name=ls_out_acl}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : ct.inv
      pipeline            : egress
      priority            : 65535
      table_id            : 1

      _uuid               : ace32153-664e-45fc-ae94-3a1ed7a1153a
      actions             : "ct_commit; next;"
      external_ids        : {stage-name=ls_out_acl}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "ct.new && (outport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip4 && ip4.src == 0.0.0.0/0 && icmp4)"
      pipeline            : egress
      priority            : 2002
      table_id            : 1

      _uuid               : 51b8139c-867e-4581-af09-121cec56beb9
      actions             : "ct_commit; next;"
      external_ids        : {stage-name=ls_out_acl}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "outport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip4 && ip4.src == 203.0.113.0/24 && udp && udp.src == 67 && udp.dst == 68"
      pipeline            : egress
      priority            : 2002
      table_id            : 1

      _uuid               : 9d9d9f97-82ef-444a-a4e7-15a11d939650
      actions             : "drop;"
      external_ids        : {stage-name=ls_out_acl}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "outport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip"
      pipeline            : egress
      priority            : 2001
      table_id            : 1

      _uuid               : dce378f9-ae6b-40f1-9baa-1b853ac0138d
      actions             : "ct_commit; next;"
      external_ids        : {stage-name=ls_out_acl}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : ip
      pipeline            : egress
      priority            : 1
      table_id            : 1

      _uuid               : 8f2fca0c-25f2-4043-8b54-075e4e559996
      actions             : "next;"
      external_ids        : {stage-name=ls_out_port_sec_ip}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "outport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && eth.dst == fa:16:3e:1c:ca:6a && ip4.dst == {255.255.255.255, 224.0.0.0/4, 203.0.113.103}"
      pipeline            : egress
      priority            : 90
      table_id            : 2

      _uuid               : cf700de1-053a-4ca9-a94a-f1b1889fd6a8
      actions             : "drop;"
      external_ids        : {stage-name=ls_out_port_sec_ip}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "outport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && eth.dst == fa:16:3e:1c:ca:6a && ip"
      pipeline            : egress
      priority            : 80
      table_id            : 2

      _uuid               : 8866a2b9-426d-444f-94dd-f36f0f79eda5
      actions             : "output;"
      external_ids        : {stage-name="ls_out_port_sec_l2"}
      logical_datapath    : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
      match               : "outport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && eth.dst == {fa:16:3e:1c:ca:6a}"
      pipeline            : egress
      priority            : 50
      table_id            : 3

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
         9(tapcafd4862-c6): addr:fe:16:3e:1c:ca:6a
             config:     0
             state:      0
             current:    10MB-FD COPPER
             speed: 10 Mbps now, 0 Mbps max

     .. code-block:: console

        cookie=0x0, duration=184.992s, table=0, n_packets=175, n_bytes=15270,
            idle_age=15, priority=100,in_port=9
            actions=load:0x3->NXM_NX_REG5[],load:0x4->OXM_OF_METADATA[],
                load:0x4->NXM_NX_REG6[],resubmit(,16)
        cookie=0x0, duration=191.687s, table=16, n_packets=175, n_bytes=15270,
            idle_age=15, priority=50,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a actions=resubmit(,17)
        cookie=0x0, duration=191.687s, table=17, n_packets=2, n_bytes=684,
            idle_age=112, priority=90,udp,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a,nw_src=0.0.0.0,
                nw_dst=255.255.255.255,tp_src=68,tp_dst=67
            actions=resubmit(,18)
        cookie=0x0, duration=191.687s, table=17, n_packets=146, n_bytes=12780,
            idle_age=20, priority=90,ip,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a,nw_src=203.0.113.103
            actions=resubmit(,18)
        cookie=0x0, duration=191.687s, table=17, n_packets=17, n_bytes=1386,
            idle_age=92, priority=80,ipv6,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a actions=drop
        cookie=0x0, duration=191.687s, table=17, n_packets=0, n_bytes=0,
            idle_age=191, priority=80,ip,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a actions=drop
        cookie=0x0, duration=191.687s, table=18, n_packets=10, n_bytes=420,
            idle_age=15, priority=90,arp,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a,arp_spa=203.0.113.103,
                arp_sha=fa:16:3e:1c:ca:6a actions=resubmit(,19)
        cookie=0x0, duration=191.687s, table=18, n_packets=0, n_bytes=0,
            idle_age=191, priority=80,icmp6,reg6=0x4,metadata=0x4,
                icmp_type=136,icmp_code=0 actions=drop
        cookie=0x0, duration=191.687s, table=18, n_packets=0, n_bytes=0,
            idle_age=191, priority=80,icmp6,reg6=0x4,metadata=0x4,
                icmp_type=135,icmp_code=0 actions=drop
        cookie=0x0, duration=191.687s, table=18, n_packets=0, n_bytes=0,
            idle_age=191, priority=80,arp,reg6=0x4,metadata=0x4 actions=drop
        cookie=0x0, duration=191.688s, table=19, n_packets=0, n_bytes=0,
            idle_age=191, priority=100,ipv6,metadata=0x4
            actions=ct(table=20,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=191.687s, table=19, n_packets=300, n_bytes=28534,
            idle_age=20, priority=100,ip,metadata=0x4
            actions=ct(table=20,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=191.688s, table=20, n_packets=0, n_bytes=0,
            idle_age=191, priority=65535,ct_state=-new-est+rel-inv+trk,
                metadata=0x4 actions=resubmit(,21)
        cookie=0x0, duration=191.687s, table=20, n_packets=221, n_bytes=19426,
            idle_age=20, priority=65535,ct_state=-new+est-rel-inv+trk,
                metadata=0x4 actions=resubmit(,21)
        cookie=0x0, duration=191.687s, table=20, n_packets=0, n_bytes=0,
            idle_age=191, priority=65535,ct_state=+inv+trk,metadata=0x4
            actions=drop
        cookie=0x0, duration=191.688s, table=20, n_packets=0, n_bytes=0,
            idle_age=191, priority=2002,udp,reg6=0x4,metadata=0x4,
                nw_dst=203.0.113.0/24,tp_src=68,tp_dst=67
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=191.687s, table=20, n_packets=0, n_bytes=0,
            idle_age=191, priority=2002,ct_state=+new+trk,ipv6,reg6=0x4,
                metadata=0x4
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=191.687s, table=20, n_packets=69, n_bytes=6494,
            idle_age=20, priority=2002,ct_state=+new+trk,ip,reg6=0x4,
                metadata=0x4
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=191.687s, table=20, n_packets=0, n_bytes=0,
            idle_age=191, priority=2002,udp,reg6=0x4,metadata=0x4,
                nw_dst=255.255.255.255,tp_src=68,tp_dst=67
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=191.688s, table=20, n_packets=0, n_bytes=0,
            idle_age=191, priority=2001,ipv6,reg6=0x4,metadata=0x4
            actions=drop
        cookie=0x0, duration=191.687s, table=20, n_packets=0, n_bytes=0,
            idle_age=191, priority=2001,ip,reg6=0x4,metadata=0x4 actions=drop
        cookie=0x0, duration=191.687s, table=20, n_packets=0, n_bytes=0,
            idle_age=191, priority=1,ipv6,metadata=0x4
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=191.687s, table=20, n_packets=10, n_bytes=2614,
            idle_age=54, priority=1,ip,metadata=0x4
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=184.990s, table=21, n_packets=3, n_bytes=126,
            idle_age=41, priority=50,arp,metadata=0x4,
                arp_tpa=203.0.113.103,arp_op=1
            actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],
                mod_dl_src:fa:16:3e:1c:ca:6a,load:0x2->NXM_OF_ARP_OP[],
                move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],
                load:0xfa163e1cca6a->NXM_NX_ARP_SHA[],
                move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],
                load:0xc0a8126c->NXM_OF_ARP_SPA[],
                move:NXM_NX_REG6[]->NXM_NX_REG7[],
                load:0->NXM_NX_REG6[],load:0->NXM_OF_IN_PORT[],resubmit(,32)
        cookie=0x0, duration=191.687s, table=22, n_packets=152, n_bytes=14506,
            idle_age=20, priority=50,metadata=0x4,dl_dst=fa:16:3e:1c:ca:6a
            actions=load:0x4->NXM_NX_REG7[],resubmit(,32)
        cookie=0x0, duration=221031.310s, table=33, n_packets=72, n_bytes=6292,
            idle_age=20, hard_age=65534, priority=100,reg7=0x3,metadata=0x4
            actions=load:0x1->NXM_NX_REG7[],resubmit(,33)
        cookie=0x0, duration=184.992s, table=34, n_packets=2, n_bytes=684,
            idle_age=112, priority=100,reg6=0x4,reg7=0x4,metadata=0x4
            actions=drop
        cookie=0x0, duration=191.688s, table=48, n_packets=0, n_bytes=0,
            idle_age=191, priority=100,ipv6,metadata=0x4
            actions=ct(table=49,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=191.687s, table=48, n_packets=304, n_bytes=29902,
            idle_age=20, priority=100,ip,metadata=0x4
            actions=ct(table=49,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=191.688s, table=49, n_packets=221, n_bytes=19426,
            idle_age=20, priority=65535,ct_state=-new+est-rel-inv+trk,
                metadata=0x4 actions=resubmit(,50)
        cookie=0x0, duration=191.687s, table=49, n_packets=0, n_bytes=0,
            idle_age=191, priority=65535,ct_state=-new-est+rel-inv+trk,
                metadata=0x4 actions=resubmit(,50)
        cookie=0x0, duration=191.687s, table=49, n_packets=0, n_bytes=0,
            idle_age=191, priority=65535,ct_state=+inv+trk,metadata=0x4
            actions=drop
        cookie=0x0, duration=191.688s, table=49, n_packets=4, n_bytes=1538,
            idle_age=112, priority=2002,udp,reg7=0x4,metadata=0x4,
                nw_src=203.0.113.0/24,tp_src=67,tp_dst=68
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=63.430s, table=49, n_packets=1, n_bytes=98,
            idle_age=54, priority=2002,ct_state=+new+trk,icmp,reg7=0x4,
                metadata=0x4
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=191.687s, table=49, n_packets=5, n_bytes=978,
            idle_age=89, priority=2001,ip,reg7=0x4,metadata=0x4 actions=drop
        cookie=0x0, duration=191.687s, table=49, n_packets=0, n_bytes=0,
            idle_age=191, priority=2001,ipv6,reg7=0x4,metadata=0x4 actions=drop
        cookie=0x0, duration=191.687s, table=49, n_packets=73, n_bytes=7862,
            idle_age=20, priority=1,ip,metadata=0x4
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=191.687s, table=49, n_packets=0, n_bytes=0,
            idle_age=191, priority=1,ipv6,metadata=0x4
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=191.688s, table=50, n_packets=0, n_bytes=0,
            idle_age=191, priority=90,ip,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a,nw_dst=224.0.0.0/4
            actions=resubmit(,51)
        cookie=0x0, duration=191.687s, table=50, n_packets=147, n_bytes=14092,
            idle_age=20, priority=90,ip,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a,nw_dst=203.0.113.103
            actions=resubmit(,51)
        cookie=0x0, duration=191.687s, table=50, n_packets=0, n_bytes=0,
            idle_age=191, priority=90,ip,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a,nw_dst=255.255.255.255
            actions=resubmit(,51)
        cookie=0x0, duration=191.687s, table=50, n_packets=0, n_bytes=0,
            idle_age=191, priority=80,ipv6,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a actions=drop
        cookie=0x0, duration=191.687s, table=50, n_packets=0, n_bytes=0,
            idle_age=191, priority=80,ip,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a actions=drop
        cookie=0x0, duration=191.687s, table=51, n_packets=157, n_bytes=14548,
            idle_age=15, priority=50,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a actions=resubmit(,64)
        cookie=0x0, duration=184.992s, table=64, n_packets=166, n_bytes=15088,
            idle_age=15, priority=100,reg7=0x4,metadata=0x4 actions=output:9

   * For each compute node that only contains a DHCP agent on the subnet, OVN
     creates the following flows:

     .. code-block:: console

        cookie=0x0, duration=189.649s, table=16, n_packets=0, n_bytes=0,
            idle_age=189, priority=50,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a actions=resubmit(,17)
        cookie=0x0, duration=189.650s, table=17, n_packets=0, n_bytes=0,
            idle_age=189, priority=90,udp,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a,nw_src=0.0.0.0,
                nw_dst=255.255.255.255,tp_src=68,tp_dst=67
            actions=resubmit(,18)
        cookie=0x0, duration=189.649s, table=17, n_packets=0, n_bytes=0,
            idle_age=189, priority=90,ip,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a,nw_src=203.0.113.103
            actions=resubmit(,18)
        cookie=0x0, duration=189.650s, table=17, n_packets=0, n_bytes=0,
            idle_age=189, priority=80,ipv6,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a actions=drop
        cookie=0x0, duration=189.650s, table=17, n_packets=0, n_bytes=0,
            idle_age=189, priority=80,ip,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a actions=drop
        cookie=0x0, duration=189.650s, table=18, n_packets=0, n_bytes=0,
            idle_age=189, priority=90,arp,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a,arp_spa=203.0.113.103,
                arp_sha=fa:16:3e:1c:ca:6a actions=resubmit(,19)
        cookie=0x0, duration=189.650s, table=18, n_packets=0, n_bytes=0,
            idle_age=189, priority=80,icmp6,reg6=0x4,metadata=0x4,
                icmp_type=136,icmp_code=0 actions=drop
        cookie=0x0, duration=189.650s, table=18, n_packets=0, n_bytes=0,
            idle_age=189, priority=80,icmp6,reg6=0x4,metadata=0x4,
                icmp_type=135,icmp_code=0 actions=drop
        cookie=0x0, duration=189.649s, table=18, n_packets=0, n_bytes=0,
            idle_age=189, priority=80,arp,reg6=0x4,metadata=0x4 actions=drop
        cookie=0x0, duration=189.650s, table=19, n_packets=0, n_bytes=0,
            idle_age=189, priority=100,ipv6,metadata=0x4
            actions=ct(table=20,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=189.649s, table=19, n_packets=150, n_bytes=14700,
            idle_age=18, priority=100,ip,metadata=0x4
            actions=ct(table=20,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=189.650s, table=20, n_packets=0, n_bytes=0,
            idle_age=189, priority=65535,ct_state=-new-est+rel-inv+trk,
                metadata=0x4 actions=resubmit(,21)
        cookie=0x0, duration=189.650s, table=20, n_packets=106, n_bytes=9293,
            idle_age=18, priority=65535,ct_state=-new+est-rel-inv+trk,
                metadata=0x4 actions=resubmit(,21)
        cookie=0x0, duration=189.650s, table=20, n_packets=0, n_bytes=0,
            idle_age=189, priority=65535,ct_state=+inv+trk,metadata=0x4
            actions=drop
        cookie=0x0, duration=189.650s, table=20, n_packets=0, n_bytes=0,
            idle_age=189, priority=2002,udp,reg6=0x4,metadata=0x4,
                nw_dst=203.0.113.0/24,tp_src=68,tp_dst=67
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=189.649s, table=20, n_packets=0, n_bytes=0,
            idle_age=189, priority=2002,ct_state=+new+trk,ipv6,reg6=0x4,
                metadata=0x4
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=189.649s, table=20, n_packets=0, n_bytes=0,
            idle_age=189, priority=2002,ct_state=+new+trk,ip,reg6=0x4,
                metadata=0x4
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=189.649s, table=20, n_packets=0, n_bytes=0,
            idle_age=189, priority=2002,udp,reg6=0x4,metadata=0x4,
                nw_dst=255.255.255.255,tp_src=68,tp_dst=67
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=189.650s, table=20, n_packets=0, n_bytes=0,
            idle_age=189, priority=2001,ipv6,reg6=0x4,metadata=0x4
            actions=drop
        cookie=0x0, duration=189.649s, table=20, n_packets=0, n_bytes=0,
            idle_age=189, priority=2001,ip,reg6=0x4,metadata=0x4 actions=drop
        cookie=0x0, duration=189.650s, table=20, n_packets=0, n_bytes=0,
            idle_age=189, priority=1,ipv6,metadata=0x4
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=189.650s, table=20, n_packets=44, n_bytes=5407,
            idle_age=18, priority=1,ip,metadata=0x4
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
        cookie=0x0, duration=182.951s, table=21, n_packets=3, n_bytes=126,
            idle_age=13, priority=50,arp,metadata=0x4,arp_tpa=203.0.113.103,
                arp_op=1
            actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],
                mod_dl_src:fa:16:3e:1c:ca:6a,
                load:0x2->NXM_OF_ARP_OP[],
                move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],
                load:0xfa163e1cca6a->NXM_NX_ARP_SHA[],
                move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],
                load:0xc0a8126c->NXM_OF_ARP_SPA[],
                move:NXM_NX_REG6[]->NXM_NX_REG7[],load:0->NXM_NX_REG6[],
                load:0->NXM_OF_IN_PORT[],resubmit(,32)
        cookie=0x0, duration=189.649s, table=22, n_packets=74, n_bytes=7040,
            idle_age=18, priority=50,metadata=0x4,dl_dst=fa:16:3e:1c:ca:6a
            actions=load:0x4->NXM_NX_REG7[],resubmit(,32)
        cookie=0x0, duration=182.952s, table=33, n_packets=74, n_bytes=7040,
            idle_age=18, priority=100,reg7=0x4,metadata=0x4
            actions=load:0x1->NXM_NX_REG7[],resubmit(,33)
        cookie=0x0, duration=189.650s, table=48, n_packets=0, n_bytes=0,
            idle_age=189, priority=100,ipv6,metadata=0x4
            actions=ct(table=49,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=189.649s, table=48, n_packets=150, n_bytes=14700,
            idle_age=18, priority=100,ip,metadata=0x4
            actions=ct(table=49,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=189.650s, table=49, n_packets=106, n_bytes=9293,
            idle_age=18, priority=65535,ct_state=-new+est-rel-inv+trk,
                metadata=0x4 actions=resubmit(,50)
        cookie=0x0, duration=189.649s, table=49, n_packets=0, n_bytes=0,
            idle_age=189, priority=65535,ct_state=-new-est+rel-inv+trk,
                metadata=0x4 actions=resubmit(,50)
        cookie=0x0, duration=189.649s, table=49, n_packets=0, n_bytes=0,
            idle_age=189, priority=65535,ct_state=+inv+trk,metadata=0x4
            actions=drop
        cookie=0x0, duration=189.650s, table=49, n_packets=0, n_bytes=0,
            idle_age=189, priority=2002,udp,reg7=0x4,metadata=0x4,
                nw_src=203.0.113.0/24,tp_src=67,tp_dst=68
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=61.391s, table=49, n_packets=0, n_bytes=0,
            idle_age=61, priority=2002,ct_state=+new+trk,icmp,reg7=0x4,
                metadata=0x4
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=189.650s, table=49, n_packets=0, n_bytes=0,
            idle_age=189, priority=2001,ip,reg7=0x4,metadata=0x4 actions=drop
        cookie=0x0, duration=189.649s, table=49, n_packets=0, n_bytes=0,
            idle_age=189, priority=2001,ipv6,reg7=0x4,metadata=0x4 actions=drop
        cookie=0x0, duration=189.650s, table=49, n_packets=44, n_bytes=5407,
            idle_age=18, priority=1,ip,metadata=0x4
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=189.650s, table=49, n_packets=0, n_bytes=0,
            idle_age=189, priority=1,ipv6,metadata=0x4
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
        cookie=0x0, duration=189.650s, table=50, n_packets=0, n_bytes=0,
            idle_age=189, priority=90,ip,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a,nw_dst=224.0.0.0/4
            actions=resubmit(,51)
        cookie=0x0, duration=189.650s, table=50, n_packets=0, n_bytes=0,
            idle_age=189, priority=90,ip,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a,nw_dst=203.0.113.103
            actions=resubmit(,51)
        cookie=0x0, duration=189.649s, table=50, n_packets=0, n_bytes=0,
            idle_age=189, priority=90,ip,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a,nw_dst=255.255.255.255
            actions=resubmit(,51)
        cookie=0x0, duration=189.650s, table=50, n_packets=0, n_bytes=0,
            idle_age=189, priority=80,ipv6,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a actions=drop
        cookie=0x0, duration=189.650s, table=50, n_packets=0, n_bytes=0,
            idle_age=189, priority=80,ip,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a actions=drop
        cookie=0x0, duration=189.649s, table=51, n_packets=0, n_bytes=0,
            idle_age=189, priority=50,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a actions=resubmit(,64)

.. _refarch-routers:

Routers
-------

Routers pass traffic between layer-3 networks.

.. note::

   Currently, OVN lacks support for routing between self-service (private)
   and provider networks. However, it supports routing between
   self-service networks.

Create a router
~~~~~~~~~~~~~~~

#. On the controller node, source the credentials for a regular
   (non-privileged) project. The following example uses the ``demo``
   project.

#. On the controller node, create router in the Networking service.

   .. code-block:: console

      $ openstack router create router
      +-----------------------+--------------------------------------+
      | Field                 | Value                                |
      +-----------------------+--------------------------------------+
      | admin_state_up        | UP                                   |
      | description           |                                      |
      | external_gateway_info | null                                 |
      | headers               |                                      |
      | id                    | 24addfcd-5506-405d-a59f-003644c3d16a |
      | name                  | router                               |
      | project_id            | b1ebf33664df402693f729090cfab861     |
      | routes                |                                      |
      | status                | ACTIVE                               |
      +-----------------------+--------------------------------------+

OVN operations
^^^^^^^^^^^^^^

The OVN mechanism driver and OVN perform the following operations when
creating a router.

#. The OVN mechanism driver translates the router into a logical
   router object in the OVN northbound database.

  .. code-block:: console

     _uuid               : 1c2e340d-dac9-496b-9e86-1065f9dab752
     default_gw          : []
     enabled             : []
     external_ids        : {"neutron:router_name"="router"}
     name                : "neutron-a24fd760-1a99-4eec-9f02-24bb284ff708"
     ports               : []
     static_routes       : []

#. The OVN northbound service translates this object into logical flows
   and datapath bindings in the OVN southbound database.

   * Logical flows

     .. code-block:: console

        _uuid               : 5b17b9c7-97f5-40be-b432-77a5873d136b
        actions             : "next;"
        external_ids        : {stage-name=lr_in_ip_input}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "1"
        pipeline            : ingress
        priority            : 0
        table_id            : 1

        _uuid               : cea49509-2bc7-4b60-bc39-06ffc0afb91a
        actions             : "put_arp(inport, arp.spa, arp.sha);"
        external_ids        : {stage-name=lr_in_ip_input}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "arp.op == 2"
        pipeline            : ingress
        priority            : 90
        table_id            : 1

        _uuid               : 8f1c640b-2fc6-4c8a-a4fb-c0ecbfd7e20c
        actions             : "output;"
        external_ids        : {stage-name=lr_in_arp_request}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "1"
        pipeline            : ingress
        priority            : 0
        table_id            : 4

        _uuid               : 9fab764b-e8e0-4c50-9ea9-3ed8f105fea1
        actions             : "arp { eth.dst = ff:ff:ff:ff:ff:ff; arp.spa = reg1; arp.op = 1; output; };"
        external_ids        : {stage-name=lr_in_arp_request}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "eth.dst == 00:00:00:00:00:00"
        pipeline            : ingress
        priority            : 100
        table_id            : 4

        _uuid               : 22e651d8-d6b9-449c-8fd3-2adb7e2f7db3
        actions             : "drop;"
        external_ids        : {stage-name=lr_in_ip_input}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : eth.bcast
        pipeline            : ingress
        priority            : 50
        table_id            : 1

        _uuid               : 464ee259-6c48-4087-afd3-9774e3e6e069
        actions             : "drop;"
        external_ids        : {stage-name=lr_in_ip_input}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "ip4.mcast || ip4.src == 255.255.255.255 || ip4.src == 127.0.0.0/8 || ip4.dst == 127.0.0.0/8 || ip4.src == 0.0.0.0/8 || ip4.dst == 0.0.0.0/8"
        pipeline            : ingress
        priority            : 100
        table_id            : 1

        _uuid               : 3771f9da-b698-4202-9c25-4fabdfbc5c99
        actions             : "get_arp(outport, reg0); next;"
        external_ids        : {stage-name=lr_in_arp_resolve}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "1"
        pipeline            : ingress
        priority            : 0
        table_id            : 3

        _uuid               : c2192d9d-a87b-48d2-baa4-8aad579af962
        actions             : "drop;"
        external_ids        : {stage-name=lr_in_ip_input}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "ip4.mcast"
        pipeline            : ingress
        priority            : 50
        table_id            : 1

        _uuid               : 2ca628e3-645b-423c-ba92-c8fa13f4b349
        actions             : "drop;"
        external_ids        : {stage-name=lr_in_admission}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "vlan.present || eth.src[40]"
        pipeline            : ingress
        priority            : 100
        table_id            : 0

        _uuid               : c55f72ac-b5aa-4ef1-b38a-3820a42c3be3
        actions             : "drop;"
        external_ids        : {stage-name=lr_in_ip_input}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "ip4 && ip.ttl == {0, 1}"
        pipeline            : ingress
        priority            : 30
        table_id            : 1

   * Datapath bindings

     .. code-block:: console

        _uuid               : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        external_ids        : {logical-router="1c2e340d-dac9-496b-9e86-1065f9dab752"}
        tunnel_key          : 3

#. The OVN controller service on each compute node translates these objects
   into flows on the integration bridge ``br-int``.

   .. code-block:: console

      # ovs-ofctl dump-flows br-int
      cookie=0x0, duration=6.402s, table=16, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,metadata=0x5,vlan_tci=0x1000/0x1000
          actions=drop
      cookie=0x0, duration=6.402s, table=16, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,metadata=0x5,
          dl_src=01:00:00:00:00:00/01:00:00:00:00:00 actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,metadata=0x5,nw_dst=127.0.0.0/8
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,metadata=0x5,nw_dst=0.0.0.0/8
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,metadata=0x5,nw_dst=224.0.0.0/4
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,ip,metadata=0x5,nw_dst=224.0.0.0/4
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,metadata=0x5,nw_src=255.255.255.255
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,metadata=0x5,nw_src=127.0.0.0/8
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,metadata=0x5,nw_src=0.0.0.0/8
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=90,arp,metadata=0x5,arp_op=2
          actions=push:NXM_NX_REG0[],push:NXM_OF_ETH_SRC[],
              push:NXM_NX_ARP_SHA[],push:NXM_OF_ARP_SPA[],
              pop:NXM_NX_REG0[],pop:NXM_OF_ETH_SRC[],
              controller(userdata=00.00.00.01.00.00.00.00),
              pop:NXM_OF_ETH_SRC[],pop:NXM_NX_REG0[]
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,metadata=0x5,dl_dst=ff:ff:ff:ff:ff:ff
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=30,ip,metadata=0x5,nw_ttl=0 actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=30,ip,metadata=0x5,nw_ttl=1 actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x5 actions=resubmit(,18)
      cookie=0x0, duration=6.402s, table=19, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x5
          actions=mod_dl_dst:00:00:00:00:00:00,resubmit(,65),resubmit(,20)
      cookie=0x0, duration=6.402s, table=20, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,metadata=0x5,dl_dst=00:00:00:00:00:00
          actions=controller(userdata=00.00.00.00.00.00.00.00.00.19.00.10.80.00.06.06.ff.ff.ff.ff.ff.ff.00.00.ff.ff.00.18.00.00.23.20.00.06.00.20.00.00.00.00.00.01.02.04.00.00.20.04.00.19.00.10.80.00.2a.02.00.01.00.00.00.00.00.00.ff.ff.00.10.00.00.23.20.00.0e.ff.f8.20.00.00.00)
      cookie=0x0, duration=6.402s, table=20, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x5 actions=resubmit(,32)

Attach a self-service network to the router
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Self-service networks, particularly subnets, must interface with a
router to enable connectivity with other self-service and provider
networks.

#. On the controller node, add the self-service network subnet
   ``selfservice-v4`` to the router ``router``.

   .. code-block:: console

      $ openstack router add subnet router selfservice-v4

   .. note::

      This command provides no output.

OVN operations
^^^^^^^^^^^^^^

The OVN mechanism driver and OVN perform the following operations when
adding a subnet as an interface on a router.

#. The OVN mechanism driver translates the operation into logical
   objects and devices in the OVN northbound database and performs a
   series of operations on them.

   * Create a logical port.

     .. code-block:: console

        _uuid               : 4c9e70b1-fff0-4d0d-af8e-42d3896eb76f
        addresses           : ["fa:16:3e:0c:55:62 192.168.1.1"]
        enabled             : true
        external_ids        : {"neutron:port_name"=""}
        name                : "5b72d278-5b16-44a6-9aa0-9e513a429506"
        options             : {router-port="lrp-5b72d278-5b16-44a6-9aa0-9e513a429506"}
        parent_name         : []
        port_security       : []
        tag                 : []
        type                : router
        up                  : false

   * Add the logical port to logical switch.

.. todo: Router interfaces are usually subnets, not networks. Does OVN
         still reference the network name?

     .. code-block:: console

        _uuid               : 0ab40684-7cf8-4d6c-ae8b-9d9143762d37
        acls                : []
        external_ids        : {"neutron:network_name"="selfservice-v4"}
        name                : "neutron-d5aadceb-d8d6-41c8-9252-c5e0fe6c26a5"
        ports               : [1ed7c28b-dc69-42b8-bed6-46477bb8b539,
                               4c9e70b1-fff0-4d0d-af8e-42d3896eb76f,
                               ae10a5e0-db25-4108-b06a-d2d5c127d9c4]

   * Create a logical router port object.

     .. code-block:: console

        _uuid               : f60ccb93-7b3d-4713-922c-37104b7055dc
        enabled             : []
        external_ids        : {}
        mac                 : "fa:16:3e:0c:55:62"
        name                : "lrp-5b72d278-5b16-44a6-9aa0-9e513a429506"
        network             : "192.168.1.1/24"
        peer                : []

   * Add the logical router port to the logical router object.

     .. code-block:: console

        _uuid               : 1c2e340d-dac9-496b-9e86-1065f9dab752
        default_gw          : []
        enabled             : []
        external_ids        : {"neutron:router_name"="router"}
        name                : "neutron-a24fd760-1a99-4eec-9f02-24bb284ff708"
        ports               : [f60ccb93-7b3d-4713-922c-37104b7055dc]
        static_routes       : []

#. The OVN northbound service translates these objects into logical flows,
   datapath bindings, and the appropriate multicast groups in the OVN
   southbound database.

   * Logical flows

     .. code-block:: console

        _uuid               : 27cc1784-077f-4543-8eb2-8d4d52d85800
        actions             : "ip.ttl--; reg0 = ip4.dst; reg1 = 192.168.1.1; eth.src = fa:16:3e:0c:55:62; outport = \"lrp-5b72d278-5b16-44a6-9aa0-9e513a429506\"; next;"
        external_ids        : {stage-name=lr_in_ip_routing}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "ip4.dst == 192.168.1.0/255.255.255.0"
        pipeline            : ingress
        priority            : 24
        table_id            : 2

        _uuid               : c58a3b04-6e35-43c8-9983-0a7d060a02fc
        actions             : "next;"
        external_ids        : {stage-name=lr_in_admission}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "(eth.mcast || eth.dst == fa:16:3e:0c:55:62) && inport == \"lrp-5b72d278-5b16-44a6-9aa0-9e513a429506\""
        pipeline            : ingress
        priority            : 50
        table_id            : 0

        _uuid               : 5ef30c51-1718-4241-866f-4cabd64ccd7e
        actions             : "ip4.dst = ip4.src; ip4.src = 192.168.1.1; ip.ttl = 255; icmp4.type = 0; inport = \"\"; /* Allow sending out inport. \*/ next; "
        external_ids        : {stage-name=lr_in_ip_input}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "inport == \"lrp-5b72d278-5b16-44a6-9aa0-9e513a429506\" && (ip4.dst == 192.168.1.1 || ip4.dst == 192.168.1.255) && icmp4.type == 8 && icmp4.code == 0"
        pipeline            : ingress
        priority            : 90
        table_id            : 1

        _uuid               : ffcde1a4-3cb6-4441-b469-31640926072a
        actions             : "eth.dst = eth.src; eth.src = fa:16:3e:0c:55:62; arp.op = 2; /* ARP reply \*/ arp.tha = arp.sha; arp.sha = fa:16:3e:0c:55:62; arp.tpa = arp.spa; arp.spa = 192.168.1.1; outport = inport; inport = \"\"; /* Allow sending out inport. \*/ output;"
        external_ids        : {stage-name=ls_in_arp_rsp}
        logical_datapath    : 4aef86e4-e54a-4c83-bb27-d65c670d4b51
        match               : "arp.tpa == 192.168.1.1 && arp.op == 1"
        pipeline            : ingress
        priority            : 50
        table_id            : 5

        _uuid               : 3584bce5-feb7-4a8d-88ea-bdbf34acc233
        actions             : "output;"
        external_ids        : {stage-name=lr_out_delivery}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "outport == \"lrp-5b72d278-5b16-44a6-9aa0-9e513a429506\""
        pipeline            : egress
        priority            : 100
        table_id            : 0

        _uuid               : b7b5dd69-c91d-4f71-9bbe-882bec0ed07d
        actions             : "eth.dst = eth.src; eth.src = fa:16:3e:0c:55:62; arp.op = 2; /* ARP reply \*/ arp.tha = arp.sha; arp.sha = fa:16:3e:0c:55:62; arp.tpa = arp.spa; arp.spa = 192.168.1.1; outport = \"lrp-5b72d278-5b16-44a6-9aa0-9e513a429506\"; inport = \"\"; /* Allow sending out inport. \*/ output;"
        external_ids        : {stage-name=lr_in_ip_input}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "inport == \"lrp-5b72d278-5b16-44a6-9aa0-9e513a429506\" && arp.tpa == 192.168.1.1 && arp.op == 1"
        pipeline            : ingress
        priority            : 90
        table_id            : 1

        _uuid               : e9cbd06b-32a9-4c7f-aaf2-797a4c94e44f
        actions             : "drop;"
        external_ids        : {stage-name=lr_in_ip_input}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "ip4.dst == 192.168.1.1"
        pipeline            : ingress
        priority            : 60
        table_id            : 1

        _uuid               : ca4dd46c-74a9-48e0-986e-a96a96a7a7bf
        actions             : "eth.dst = fa:16:3e:90:bd:f1; next;"
        external_ids        : {stage-name=lr_in_arp_resolve}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "outport == \"lrp-5b72d278-5b16-44a6-9aa0-9e513a429506\" && reg0 == 192.168.1.3"
        pipeline            : ingress
        priority            : 100
        table_id            : 3

        _uuid               : 121d432f-8e5b-41c2-8e38-55e1fb71c67c
        actions             : "drop;"
        external_ids        : {stage-name=lr_in_ip_input}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "ip4.src == {192.168.1.1, 192.168.1.255}"
        pipeline            : ingress
        priority            : 100
        table_id            : 1

        _uuid               : 467aeab1-4f88-4959-b932-b9eaff41a78f
        actions             : "eth.dst = fa:16:3e:94:db:5e; next;"
        external_ids        : {stage-name=lr_in_arp_resolve}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "outport == \"lrp-5b72d278-5b16-44a6-9aa0-9e513a429506\" && reg0 == 192.168.1.2"
        pipeline            : ingress
        priority            : 100
        table_id            : 3

        _uuid               : 284e7b7f-06c9-4f14-a473-541134175de7
        actions             : "eth.dst = fa:16:3e:0c:55:62; next;"
        external_ids        : {stage-name=lr_in_arp_resolve}
        logical_datapath    : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        match               : "outport == \"lrp-5b72d278-5b16-44a6-9aa0-9e513a429506\" && reg0 == 192.168.1.1"
        pipeline            : ingress
        priority            : 100
        table_id            : 3

   * Port bindings

     .. code-block:: console

        _uuid               : 0f86395b-a0d8-40fd-b22c-4c9e238a7880
        chassis             : []
        datapath            : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        logical_port        : "lrp-5b72d278-5b16-44a6-9aa0-9e513a429506"
        mac                 : []
        options             : {peer="5b72d278-5b16-44a6-9aa0-9e513a429506"}
        parent_port         : []
        tag                 : []
        tunnel_key          : 1
        type                : patch

        _uuid               : 8d95ab8c-c2ea-4231-9729-7ecbfc2cd676
        chassis             : []
        datapath            : 4aef86e4-e54a-4c83-bb27-d65c670d4b51
        logical_port        : "5b72d278-5b16-44a6-9aa0-9e513a429506"
        mac                 : ["fa:16:3e:0c:55:62 192.168.1.1"]
        options             : {peer="lrp-5b72d278-5b16-44a6-9aa0-9e513a429506"}
        parent_port         : []
        tag                 : []
        tunnel_key          : 3
        type                : patch

   * Multicast groups

     .. code-block:: console

        _uuid               : 4a6191aa-d8ac-4e93-8306-b0d8fbbe4e35
        datapath            : 4aef86e4-e54a-4c83-bb27-d65c670d4b51
        name                : _MC_flood
        ports               : [8d95ab8c-c2ea-4231-9729-7ecbfc2cd676,
                               be71fac3-9f04-41c9-9951-f3f7f1fa1ec5,
                               da5c1269-90b7-4df2-8d76-d4575754b02d]
        tunnel_key          : 65535

#. The OVN controller service on each compute node translates these objects
   into flows on the integration bridge ``br-int``.

   .. code-block:: console

      # ovs-ofctl dump-flows br-int
      cookie=0x0, duration=11.576s, table=0, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,in_port=1
          actions=load:0x1->OXM_OF_METADATA[],
              load:0x2->NXM_NX_REG6[],resubmit(,16)
      cookie=0x0, duration=11.575s, table=0, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,in_port=2
          actions=load:0x2->OXM_OF_METADATA[],load:0x1->NXM_NX_REG6[],
              resubmit(,16)
      cookie=0x0, duration=11.574s, table=0, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,in_port=6
          actions=load:0x4->OXM_OF_METADATA[],load:0x3->NXM_NX_REG6[],
              resubmit(,16)
      cookie=0x0, duration=11.574s, table=0, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,in_port=7
          actions=load:0x5->OXM_OF_METADATA[],load:0x1->NXM_NX_REG6[],
              resubmit(,16)
      cookie=0x0, duration=11.576s, table=16, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,metadata=0x1,vlan_tci=0x1000/0x1000
          actions=drop
      cookie=0x0, duration=11.576s, table=16, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,metadata=0x4,vlan_tci=0x1000/0x1000
          actions=drop
      cookie=0x0, duration=11.576s, table=16, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,metadata=0x4,
              dl_src=01:00:00:00:00:00/01:00:00:00:00:00 actions=drop
      cookie=0x0, duration=11.575s, table=16, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,metadata=0x1,
              dl_src=01:00:00:00:00:00/01:00:00:00:00:00 actions=drop
      cookie=0x0, duration=11.579s, table=16, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,reg6=0x1,metadata=0x5,
              dl_dst=01:00:00:00:00:00/01:00:00:00:00:00
          actions=resubmit(,17)
      cookie=0x0, duration=11.579s, table=16, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,reg6=0x1,metadata=0x5,
              dl_dst=fa:16:3e:3c:ea:be actions=resubmit(,17)
      cookie=0x0, duration=11.576s, table=16, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,reg6=0x1,metadata=0x1 actions=resubmit(,17)
      cookie=0x0, duration=11.576s, table=16, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,reg6=0x2,metadata=0x4 actions=resubmit(,17)
      cookie=0x0, duration=11.576s, table=16, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,reg6=0x1,metadata=0x4 actions=resubmit(,17)
      cookie=0x0, duration=11.576s, table=16, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,reg6=0x3,metadata=0x4 actions=resubmit(,17)
      cookie=0x0, duration=11.575s, table=16, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,reg6=0x2,metadata=0x1 actions=resubmit(,17)
      cookie=0x0, duration=11.575s, table=16, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,reg6=0x3,metadata=0x1 actions=resubmit(,17)
      cookie=0x0, duration=11.575s, table=16, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,reg6=0x4,metadata=0x1 actions=resubmit(,17)
      cookie=0x0, duration=11.575s, table=16, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,reg6=0x5,metadata=0x1,
              dl_src=fa:16:3e:3a:9c:fe actions=resubmit(,17)
      cookie=0x0, duration=11.579s, table=17, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,ip,metadata=0x5,nw_src=192.168.1.255
              actions=drop
      cookie=0x0, duration=11.579s, table=17, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,ip,metadata=0x5,nw_src=192.168.1.1
              actions=drop
      cookie=0x0, duration=11.579s, table=17, n_packets=0, n_bytes=0,
          idle_age=11, priority=90,icmp,metadata=0x5,nw_dst=192.168.1.255
              icmp_type=8,icmp_code=0
          actions=move:NXM_OF_IP_SRC[]->NXM_OF_IP_DST[],mod_nw_src:192.168.1.1,
              load:0xff->NXM_NX_IP_TTL[],load:0->NXM_OF_ICMP_TYPE[],
              load:0->NXM_NX_REG6[],load:0->NXM_OF_IN_PORT[],resubmit(,18)
      cookie=0x0, duration=11.579s, table=17, n_packets=0, n_bytes=0,
          idle_age=11, priority=90,icmp,metadata=0x5,nw_dst=192.168.1.1,
              icmp_type=8,icmp_code=0
              actions=move:NXM_OF_IP_SRC[]->NXM_OF_IP_DST[],
                  mod_nw_src:192.168.1.1,load:0xff->NXM_NX_IP_TTL[],
                  load:0->NXM_OF_ICMP_TYPE[],load:0->NXM_NX_REG6[],
                  load:0->NXM_OF_IN_PORT[],resubmit(,18)
      cookie=0x0, duration=11.579s, table=17, n_packets=0, n_bytes=0,
          idle_age=11, priority=90,arp,reg6=0x1,metadata=0x5,
              arp_tpa=192.168.1.1,arp_op=1
              actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],
                 mod_dl_src:fa:16:3e:3c:ea:be,load:0x2->NXM_OF_ARP_OP[],
                 move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],
                 load:0xfa163e3ceabe->NXM_NX_ARP_SHA[],
                 move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],
                 load:0xa0a0a01->NXM_OF_ARP_SPA[],load:0x1->NXM_NX_REG7[],
                 load:0->NXM_NX_REG6[],load:0->NXM_OF_IN_PORT[],resubmit(,32)
      cookie=0x0, duration=11.576s, table=17, n_packets=0, n_bytes=0,
          idle_age=11, priority=90,udp,reg6=0x5,metadata=0x1,
              dl_src=fa:16:3e:3a:9c:fe,nw_src=0.0.0.0,
              nw_dst=255.255.255.255,tp_src=68,tp_dst=67 actions=resubmit(,18)
      cookie=0x0, duration=11.576s, table=17, n_packets=0, n_bytes=0,
          idle_age=11, priority=80,ip,reg6=0x5,metadata=0x1,
              dl_src=fa:16:3e:3a:9c:fe actions=drop
      cookie=0x0, duration=11.575s, table=17, n_packets=0, n_bytes=0,
          idle_age=11, priority=80,ipv6,reg6=0x5,metadata=0x1,
              dl_src=fa:16:3e:3a:9c:fe actions=drop
      cookie=0x0, duration=11.579s, table=17, n_packets=0, n_bytes=0,
          idle_age=11, priority=60,ip,metadata=0x5,nw_dst=192.168.1.1
              actions=drop
      cookie=0x0, duration=11.575s, table=17, n_packets=0, n_bytes=0,
          idle_age=11, priority=0,metadata=0x1 actions=resubmit(,18)
      cookie=0x0, duration=11.575s, table=17, n_packets=0, n_bytes=0,
          idle_age=11, priority=0,metadata=0x4 actions=resubmit(,18)
      cookie=0x0, duration=11.575s, table=18, n_packets=0, n_bytes=0,
          idle_age=11, priority=80,arp,reg6=0x5,metadata=0x1 actions=drop
      cookie=0x0, duration=11.575s, table=18, n_packets=0, n_bytes=0,
          idle_age=11, priority=80,icmp6,reg6=0x5,metadata=0x1,
              icmp_type=135,icmp_code=0 actions=drop
      cookie=0x0, duration=11.575s, table=18, n_packets=0, n_bytes=0,
          idle_age=11, priority=80,icmp6,reg6=0x5,metadata=0x1,
              icmp_type=136,icmp_code=0 actions=drop
      cookie=0x0, duration=11.579s, table=18, n_packets=0, n_bytes=0,
          idle_age=11, priority=24,ip,metadata=0x5,nw_dst=192.168.1.0/24
          actions=dec_ttl(),move:NXM_OF_IP_DST[]->NXM_NX_REG0[],
             load:0xa0a0a01->NXM_NX_REG1[],mod_dl_src:fa:16:3e:3c:ea:be,
             load:0x1->NXM_NX_REG7[],resubmit(,19)
      cookie=0x0, duration=11.575s, table=18, n_packets=0, n_bytes=0,
          idle_age=11, priority=0,metadata=0x1 actions=resubmit(,19)
      cookie=0x0, duration=11.575s, table=18, n_packets=0, n_bytes=0,
          idle_age=11, priority=0,metadata=0x4 actions=resubmit(,19)
      cookie=0x0, duration=11.576s, table=19, n_packets=0, n_bytes=0,
          idle_age=11, priority=110,ipv6,reg6=0x2,metadata=0x1
          actions=resubmit(,20)
      cookie=0x0, duration=11.575s, table=19, n_packets=0, n_bytes=0,
          idle_age=11, priority=110,ip,reg6=0x2,metadata=0x1
          actions=resubmit(,20)
      cookie=0x0, duration=11.579s, table=19, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg0=0xa0a0a15,reg7=0x1,
          metadata=0x5 actions=mod_dl_dst:fa:16:3e:33:66:2f,resubmit(,20)
      cookie=0x0, duration=11.579s, table=19, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg0=0xa0a0a16,reg7=0x1,metadata=0x5
          actions=mod_dl_dst:fa:16:3e:6e:a2:a0,resubmit(,20)
      cookie=0x0, duration=11.576s, table=19, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,ip,metadata=0x1
          actions=ct(table=20,zone=NXM_NX_REG5[0..15])
      cookie=0x0, duration=11.575s, table=19, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,ipv6,metadata=0x1
          actions=ct(table=20,zone=NXM_NX_REG5[0..15])
      cookie=0x0, duration=11.576s, table=19, n_packets=0, n_bytes=0,
          idle_age=11, priority=0,metadata=0x1 actions=resubmit(,20)
      cookie=0x0, duration=11.575s, table=19, n_packets=0, n_bytes=0,
          idle_age=11, priority=0,metadata=0x4 actions=resubmit(,20)
      cookie=0x0, duration=11.576s, table=20, n_packets=0, n_bytes=0,
          idle_age=11, priority=65535,ct_state=-new-est+rel-inv+trk,
          metadata=0x1 actions=resubmit(,21)
      cookie=0x0, duration=11.576s, table=20, n_packets=0, n_bytes=0,
          idle_age=11, priority=65535,ct_state=-new+est-rel-inv+trk,
          metadata=0x1 actions=resubmit(,21)
      cookie=0x0, duration=11.575s, table=20, n_packets=0, n_bytes=0,
          idle_age=11, priority=65535,ct_state=+inv+trk,metadata=0x1 actions=drop
      cookie=0x0, duration=11.576s, table=20, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,ip,reg6=0x5,
          metadata=0x1 actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
      cookie=0x0, duration=11.575s, table=20, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,ipv6,reg6=0x5,
          metadata=0x1 actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
      cookie=0x0, duration=11.575s, table=20, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,udp,reg6=0x5,metadata=0x1,
          nw_dst=255.255.255.255,tp_src=68,tp_dst=67
          actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
      cookie=0x0, duration=11.576s, table=20, n_packets=0, n_bytes=0,
          idle_age=11, priority=2001,ip,reg6=0x5,metadata=0x1 actions=drop
      cookie=0x0, duration=11.575s, table=20, n_packets=0, n_bytes=0,
          idle_age=11, priority=2001,ipv6,reg6=0x5,metadata=0x1 actions=drop
      cookie=0x0, duration=11.575s, table=20, n_packets=0, n_bytes=0,
          idle_age=11, priority=1,ipv6,metadata=0x1
          actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
      cookie=0x0, duration=11.575s, table=20, n_packets=0, n_bytes=0,
          idle_age=11, priority=1,ip,metadata=0x1
          actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,21)
      cookie=0x0, duration=11.576s, table=20, n_packets=0, n_bytes=0,
          idle_age=11, priority=0,metadata=0x1 actions=resubmit(,21)
      cookie=0x0, duration=11.575s, table=20, n_packets=0, n_bytes=0,
          idle_age=11, priority=0,metadata=0x4 actions=resubmit(,21)
      cookie=0x0, duration=11.576s, table=21, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg6=0x1,metadata=0x1 actions=resubmit(,22)
      cookie=0x0, duration=11.576s, table=21, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,arp,metadata=0x4,arp_tpa=192.168.1.3,
              arp_op=1 actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],
              mod_dl_src:fa:16:3e:33:66:2f,load:0x2->NXM_OF_ARP_OP[],
              move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],
              load:0xfa163e33662f->NXM_NX_ARP_SHA[],
              move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],
              load:0xa0a0a15->NXM_OF_ARP_SPA[],
              move:NXM_NX_REG6[]->NXM_NX_REG7[],load:0->NXM_NX_REG6[],
              load:0->NXM_OF_IN_PORT[],resubmit(,32)
      cookie=0x0, duration=11.576s, table=21, n_packets=0, n_bytes=0,
          idle_age=11, priority=0,metadata=0x1 actions=resubmit(,22)
      cookie=0x0, duration=11.576s, table=21, n_packets=0, n_bytes=0,
          idle_age=11, priority=0,metadata=0x4 actions=resubmit(,22)
      cookie=0x0, duration=11.575s, table=22, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,metadata=0x1,
          dl_dst=01:00:00:00:00:00/01:00:00:00:00:00
          actions=load:0xffff->NXM_NX_REG7[],resubmit(,32)
      cookie=0x0, duration=11.575s, table=22, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,metadata=0x4,
          dl_dst=01:00:00:00:00:00/01:00:00:00:00:00
          actions=load:0xffff->NXM_NX_REG7[],resubmit(,32)
      cookie=0x0, duration=11.576s, table=22, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,metadata=0x4,dl_dst=fa:16:3e:33:66:2f
          actions=load:0x1->NXM_NX_REG7[],resubmit(,32)
      cookie=0x0, duration=11.575s, table=22, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,metadata=0x4,dl_dst=fa:16:3e:3c:ea:be
          actions=load:0x3->NXM_NX_REG7[],resubmit(,32)
      cookie=0x0, duration=11.575s, table=22, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,metadata=0x1,dl_dst=fa:16:3e:3a:9c:fe
          actions=load:0x5->NXM_NX_REG7[],resubmit(,32)
      cookie=0x0, duration=11.575s, table=22, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,metadata=0x1,dl_dst=fa:16:3e:82:ab:d7
          actions=load:0x4->NXM_NX_REG7[],resubmit(,32)
      cookie=0x0, duration=11.575s, table=22, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,metadata=0x1,dl_dst=fa:16:3e:90:c0:ba
          actions=load:0x3->NXM_NX_REG7[],resubmit(,32)
      cookie=0x0, duration=11.575s, table=22, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,metadata=0x4,dl_dst=fa:16:3e:6e:a2:a0
          actions=load:0x2->NXM_NX_REG7[],resubmit(,32)
      cookie=0x0, duration=11.575s, table=22, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,metadata=0x1,dl_dst=fa:16:3e:09:e0:b0
          actions=load:0x2->NXM_NX_REG7[],resubmit(,32)
      cookie=0x0, duration=11.576s, table=22, n_packets=0, n_bytes=0,
          idle_age=11, priority=0,metadata=0x1
          actions=load:0xfffe->NXM_NX_REG7[],resubmit(,32)
      cookie=0x0, duration=11.576s, table=32, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg7=0x2,metadata=0x4
          actions=load:0x4->NXM_NX_TUN_ID[0..23],
          set_field:0x2/0xffffffff->tun_metadata0,
          move:NXM_NX_REG6[0..14]->NXM_NX_TUN_METADATA0[16..30],output:5
      cookie=0x0, duration=11.576s, table=32, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg7=0x3,metadata=0x1
          actions=load:0x1->NXM_NX_TUN_ID[0..23],
          set_field:0x3/0xffffffff->tun_metadata0,
          move:NXM_NX_REG6[0..14]->NXM_NX_TUN_METADATA0[16..30],output:3
      cookie=0x0, duration=11.575s, table=32, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg7=0x1,metadata=0x4
          actions=load:0x4->NXM_NX_TUN_ID[0..23],
          set_field:0x1/0xffffffff->tun_metadata0,
          move:NXM_NX_REG6[0..14]->NXM_NX_TUN_METADATA0[16..30],output:3
      cookie=0x0, duration=11.575s, table=32, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg7=0x4,metadata=0x1
          actions=load:0x1->NXM_NX_TUN_ID[0..23],
          set_field:0x4/0xffffffff->tun_metadata0,
          move:NXM_NX_REG6[0..14]->NXM_NX_TUN_METADATA0[16..30],output:4
      cookie=0x0, duration=11.575s, table=32, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg7=0x5,metadata=0x1
          actions=load:0x1->NXM_NX_TUN_ID[0..23],
          set_field:0x5/0xffffffff->tun_metadata0,
          move:NXM_NX_REG6[0..14]->NXM_NX_TUN_METADATA0[16..30],output:5
      cookie=0x0, duration=11.576s, table=33, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg7=0x1,metadata=0x2 actions=resubmit(,34)
      cookie=0x0, duration=11.575s, table=33, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg7=0x2,metadata=0x1 actions=resubmit(,34)
      cookie=0x0, duration=11.574s, table=33, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg7=0x1,metadata=0x5 actions=resubmit(,34)
      cookie=0x0, duration=11.574s, table=33, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg7=0x3,metadata=0x4 actions=resubmit(,34)
      cookie=0x0, duration=11.575s, table=34, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg6=0x2,reg7=0x2,metadata=0x1 actions=drop
      cookie=0x0, duration=11.575s, table=34, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg6=0x1,reg7=0x1,metadata=0x2 actions=drop
      cookie=0x0, duration=11.574s, table=34, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg6=0x3,reg7=0x3,metadata=0x4 actions=drop
      cookie=0x0, duration=11.574s, table=34, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg6=0x1,reg7=0x1,metadata=0x5 actions=drop
      cookie=0x0, duration=11.575s, table=48, n_packets=0, n_bytes=0,
          idle_age=11, priority=110,ip,reg7=0x2,metadata=0x1 actions=resubmit(,49)
      cookie=0x0, duration=11.575s, table=48, n_packets=0, n_bytes=0,
          idle_age=11, priority=110,ipv6,reg7=0x2,metadata=0x1
          actions=resubmit(,49)
      cookie=0x0, duration=11.579s, table=48, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg7=0x1,metadata=0x5 actions=resubmit(,64)
      cookie=0x0, duration=11.576s, table=48, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,ipv6,metadata=0x1
          actions=ct(table=49,zone=NXM_NX_REG5[0..15])
      cookie=0x0, duration=11.575s, table=48, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,ip,metadata=0x1
          actions=ct(table=49,zone=NXM_NX_REG5[0..15])
      cookie=0x0, duration=11.576s, table=48, n_packets=0, n_bytes=0,
          idle_age=11, priority=0,metadata=0x1 actions=resubmit(,49)
      cookie=0x0, duration=11.576s, table=48, n_packets=0, n_bytes=0,
          idle_age=11, priority=0,metadata=0x4 actions=resubmit(,49)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=65535,ct_state=-new+est-rel-inv+trk,metadata=0x1
          actions=resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=65535,ct_state=-new-est+rel-inv+trk,metadata=0x1
          actions=resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=65535,ct_state=+inv+trk,metadata=0x1 actions=drop
      cookie=0x0, duration=11.576s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0x800/0xf800 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0xf000/0xf800 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.576s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0xff00/0xff80 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.576s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0x80/0xff80 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.576s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0x8/0xfff8 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0xfff0/0xfff8 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.576s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0x100/0xff00 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.576s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0xfe00/0xff00 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.576s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0x2/0xfffe actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0xfffc/0xfffe actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.576s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0xfff8/0xfffc actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0x4/0xfffc actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.576s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0xffc0/0xffe0 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0x20/0xffe0 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.576s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=65534 actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
      cookie=0x0, duration=11.576s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=65535 actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=1 actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
      cookie=0x0, duration=11.576s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0x400/0xfc00 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0xf800/0xfc00 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.576s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0x8000/0xc000 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0x4000/0xc000 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.576s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0x200/0xfe00 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0xfc00/0xfe00 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,icmp,reg7=0x5,metadata=0x1
          actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0x1000/0xf000 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0xe000/0xf000 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0x2000/0xe000 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0xc000/0xe000 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0xff80/0xffc0 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0x40/0xffc0 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0x10/0xfff0 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2002,ct_state=+new+trk,tcp,reg7=0x5,metadata=0x1,
          tp_dst=0xffe0/0xfff0 actions=ct(commit,zone=NXM_NX_REG5[0..15]),
          resubmit(,50)
      cookie=0x0, duration=11.576s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2001,ipv6,reg7=0x5,metadata=0x1 actions=drop
      cookie=0x0, duration=11.576s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=2001,ip,reg7=0x5,metadata=0x1 actions=drop
      cookie=0x0, duration=11.576s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=1,ipv6,metadata=0x1
          actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=1,ip,metadata=0x1
          actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=0,metadata=0x1 actions=resubmit(,50)
      cookie=0x0, duration=11.575s, table=49, n_packets=0, n_bytes=0,
          idle_age=11, priority=0,metadata=0x4 actions=resubmit(,50)
      cookie=0x0, duration=11.576s, table=50, n_packets=0, n_bytes=0,
          idle_age=11, priority=90,ip,reg7=0x5,metadata=0x1,
          dl_dst=fa:16:3e:3a:9c:fe,nw_dst=255.255.255.255 actions=resubmit(,51)
      cookie=0x0, duration=11.575s, table=50, n_packets=0, n_bytes=0,
          idle_age=11, priority=90,ip,reg7=0x5,metadata=0x1,
          dl_dst=fa:16:3e:3a:9c:fe,nw_dst=224.0.0.0/4 actions=resubmit(,51)
      cookie=0x0, duration=11.575s, table=50, n_packets=0, n_bytes=0,
          idle_age=11, priority=80,ip,reg7=0x5,metadata=0x1,
          dl_dst=fa:16:3e:3a:9c:fe actions=drop
      cookie=0x0, duration=11.575s, table=50, n_packets=0, n_bytes=0,
          idle_age=11, priority=80,ipv6,reg7=0x5,metadata=0x1,
          dl_dst=fa:16:3e:3a:9c:fe actions=drop
      cookie=0x0, duration=11.576s, table=50, n_packets=0, n_bytes=0,
          idle_age=11, priority=0,metadata=0x4 actions=resubmit(,51)
      cookie=0x0, duration=11.576s, table=50, n_packets=0, n_bytes=0,
          idle_age=11, priority=0,metadata=0x1 actions=resubmit(,51)
      cookie=0x0, duration=11.575s, table=51, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,metadata=0x1,
          dl_dst=01:00:00:00:00:00/01:00:00:00:00:00 actions=resubmit(,64)
      cookie=0x0, duration=11.575s, table=51, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,metadata=0x4,
          dl_dst=01:00:00:00:00:00/01:00:00:00:00:00 actions=resubmit(,64)
      cookie=0x0, duration=11.576s, table=51, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,reg7=0x1,metadata=0x1 actions=resubmit(,64)
      cookie=0x0, duration=11.576s, table=51, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,reg7=0x3,metadata=0x1 actions=resubmit(,64)
      cookie=0x0, duration=11.576s, table=51, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,reg7=0x1,metadata=0x4 actions=resubmit(,64)
      cookie=0x0, duration=11.575s, table=51, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,reg7=0x3,metadata=0x4 actions=resubmit(,64)
      cookie=0x0, duration=11.575s, table=51, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,reg7=0x4,metadata=0x1 actions=resubmit(,64)
      cookie=0x0, duration=11.575s, table=51, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,reg7=0x2,metadata=0x1 actions=resubmit(,64)
      cookie=0x0, duration=11.575s, table=51, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,reg7=0x2,metadata=0x4 actions=resubmit(,64)
      cookie=0x0, duration=11.575s, table=51, n_packets=0, n_bytes=0,
          idle_age=11, priority=50,reg7=0x5,metadata=0x1,
          dl_dst=fa:16:3e:3a:9c:fe actions=resubmit(,64)
      cookie=0x0, duration=11.575s, table=64, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg7=0x1,metadata=0x2 actions=output:2
      cookie=0x0, duration=11.575s, table=64, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg7=0x2,metadata=0x1 actions=output:1
      cookie=0x0, duration=11.574s, table=64, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg7=0x3,metadata=0x4 actions=output:6
      cookie=0x0, duration=11.574s, table=64, n_packets=0, n_bytes=0,
          idle_age=11, priority=100,reg7=0x1,metadata=0x5 actions=output:7

.. todo: Add after NAT patches merge.

   Attach the router to an external network
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

OVN as Provider Driver for Octavia
==================================

Octavia has integrated support for provider drivers where any third party
Load Balancer driver can be integrated with Octavia. Functionality related
to this has been developed in OVN and now OVN can now be supported as a
provider driver for Octavia.

OVN Provider driver has few advantages when used a provider driver for Octavia
over Amphora, like:

* OVN can be deployed without VMs. So there is no additional overhead of VMs as
  is required currently in Octavia when using the default Amphora driver.

* OVN Load Balancers can be deployed faster than default Load Balancers in
  Octavia (which use Amphora currently) because of no additional deployment
  requirement.

* Since OVN supports virtual networking for both VMs and containers, OVN as a
  Load Balancer driver can be used succesfully with Kuryr Kubernetes[1].

Limitations of OVN Provider Driver
----------------------------------

OVN has its own set of limitations when considered as an Load Balancer driver.
These include:

* OVN currently supports TCP and UDP. So Layer-7 based Load Balancing is not
  possible with OVN. However, once Layer-7 support is integrated in OVN, this
  issue can be resolved.

* There are no *Health Monitors* currently in OVN's Driver for Load Balancer.
  Therefore Health Checking is not possible with OVN.

* Currently, OVN driver supports a 1:1 protocol mapping between Listeners
  and associated Pools i.e. Listener which can handle TCP protocol can only be
  associated with pools associated to TCP protocol. Pools handling UDP protocol
  cannot be linked with TCP based Listeners. This limitation will be
  handled in the upcoming core OVN release.

Creating OVN based Load Balancer
--------------------------------

OVN provider driver can be tested out on DevStack using the configuration
options in:

.. literalinclude:: ../../../devstack/ovn-octavia-provider.conf.sample

Kindly note that the configuration here shows only OVN provider driver but
in theory, user can create Load Balancers of both Amphora and OVN types by
enabling the correct configuration settings.

Once the DevStack run is complete, the user can create a load balancer
in Openstack::

    $ openstack loadbalancer create --vip-network-id public --provider ovn
    +---------------------+--------------------------------------+
    | Field               | Value                                |
    +---------------------+--------------------------------------+
    | admin_state_up      | True                                 |
    | created_at          | 2018-12-13T09:08:14                  |
    | description         |                                      |
    | flavor              |                                      |
    | id                  | 94e7c431-912b-496c-a247-d52875d44ac7 |
    | listeners           |                                      |
    | name                |                                      |
    | operating_status    | OFFLINE                              |
    | pools               |                                      |
    | project_id          | af820b57868c4864957d523fb32ccfba     |
    | provider            | ovn                                  |
    | provisioning_status | PENDING_CREATE                       |
    | updated_at          | None                                 |
    | vip_address         | 172.24.4.9                           |
    | vip_network_id      | ee97665d-69d0-4995-a275-27855359956a |
    | vip_port_id         | c98e52d0-5965-4b22-8a17-a374f4399193 |
    | vip_qos_policy_id   | None                                 |
    | vip_subnet_id       | 3eed0c05-6527-400e-bb80-df6e59d248f1 |
    +---------------------+--------------------------------------+

If both Amphora and OVN drivers are enabled, then the user can create
different types of loadbalancers with their associated providers which
would be visible as shown below::

    +--------------------------------------+------+----------------------------------+-------------+---------------------+----------+
    | id                                   | name | project_id                       | vip_address | provisioning_status | provider |
    +--------------------------------------+------+----------------------------------+-------------+---------------------+----------+
    | c5f2070c-d51d-46f0-bec6-dd05e7c19370 |      | af820b57868c4864957d523fb32ccfba | 172.24.4.10 | ACTIVE              | amphora  |
    | 94e7c431-912b-496c-a247-d52875d44ac7 |      | af820b57868c4864957d523fb32ccfba | 172.24.4.9  | ACTIVE              | ovn      |
    +--------------------------------------+------+----------------------------------+-------------+---------------------+----------+

Now we can see that OVN will show the load balancer in its *loadbalancer*
table::

    $ ovn-nbctl list load_balancer
    _uuid               : c72de15e-5c2e-4c1b-a21b-8e9a6721193c
    external_ids        : {enabled=True,
                           lr_ref="neutron-3d2a873b-b5b4-4d14-ac24-47a835fd47b2",
                           ls_refs="{\"neutron-ee97665d-69d0-4995-a275-27855359956a\": 1}",
                           "neutron:vip"="172.24.4.9",
                           "neutron:vip_port_id"="c98e52d0-5965-4b22-8a17-a374f4399193"}
    name                : "94e7c431-912b-496c-a247-d52875d44ac7"
    protocol            : tcp
    vips                : {}

Next, a Listener can be created for the associated Load Balancer::

    $ openstack loadbalancer listener create --protocol TCP --protocol-port /
      64015 94e7c431-912b-496c-a247-d52875d44ac7
    +---------------------------+--------------------------------------+
    | Field                     | Value                                |
    +---------------------------+--------------------------------------+
    | admin_state_up            | True                                 |
    | connection_limit          | -1                                   |
    | created_at                | 2018-12-13T09:14:51                  |
    | default_pool_id           | None                                 |
    | default_tls_container_ref | None                                 |
    | description               |                                      |
    | id                        | 21e77cde-854f-4c3e-bd8c-9536ae0443bc |
    | insert_headers            | None                                 |
    | l7policies                |                                      |
    | loadbalancers             | 94e7c431-912b-496c-a247-d52875d44ac7 |
    | name                      |                                      |
    | operating_status          | OFFLINE                              |
    | project_id                | af820b57868c4864957d523fb32ccfba     |
    | protocol                  | TCP                                  |
    | protocol_port             | 64015                                |
    | provisioning_status       | PENDING_CREATE                       |
    | sni_container_refs        | []                                   |
    | timeout_client_data       | 50000                                |
    | timeout_member_connect    | 5000                                 |
    | timeout_member_data       | 50000                                |
    | timeout_tcp_inspect       | 0                                    |
    | updated_at                | None                                 |
    +---------------------------+--------------------------------------+

OVN updates the Listener information in the Load Balancer table::

    $ ovn-nbctl list load_balancer
    _uuid               : c72de15e-5c2e-4c1b-a21b-8e9a6721193c
    external_ids        : {enabled=True, "listener_21e77cde-854f-4c3e-bd8c-9536ae0443bc"="64015:", lr_ref="neutron-3d2a873b-b5b4-4d14-ac24-47a835fd47b2", ls_refs="{\"neutron-ee97665d-69d0-4995-a275-27855359956a\": 1}", "neutron:vip"="172.24.4.9", "neutron:vip_port_id"="c98e52d0-5965-4b22-8a17-a374f4399193"}
    name                : "94e7c431-912b-496c-a247-d52875d44ac7"
    protocol            : tcp
    vips                : {}

Next, a Pool is associated with the Listener::

    $ openstack loadbalancer pool create --protocol TCP --lb-algorithm /
    SOURCE_IP_PORT --listener 21e77cde-854f-4c3e-bd8c-9536ae0443bc
    +---------------------+--------------------------------------+
    | Field               | Value                                |
    +---------------------+--------------------------------------+
    | admin_state_up      | True                                 |
    | created_at          | 2018-12-13T09:21:37                  |
    | description         |                                      |
    | healthmonitor_id    |                                      |
    | id                  | 898be8a2-5185-4f3b-8658-a56457f595a9 |
    | lb_algorithm        | SOURCE_IP_PORT                       |
    | listeners           | 21e77cde-854f-4c3e-bd8c-9536ae0443bc |
    | loadbalancers       | 94e7c431-912b-496c-a247-d52875d44ac7 |
    | members             |                                      |
    | name                |                                      |
    | operating_status    | OFFLINE                              |
    | project_id          | af820b57868c4864957d523fb32ccfba     |
    | protocol            | TCP                                  |
    | provisioning_status | PENDING_CREATE                       |
    | session_persistence | None                                 |
    | updated_at          | None                                 |
    +---------------------+--------------------------------------+

OVN's Load Balancer table is modified as below::

    $ ovn-nbctl list load_balancer
    _uuid               : c72de15e-5c2e-4c1b-a21b-8e9a6721193c
    external_ids        : {enabled=True, "listener_21e77cde-854f-4c3e-bd8c-9536ae0443bc"="64015:", lr_ref="neutron-3d2a873b-b5b4-4d14-ac24-47a835fd47b2", ls_refs="{\"neutron-ee97665d-69d0-4995-a275-27855359956a\": 1}", "neutron:vip"="172.24.4.9", "neutron:vip_port_id"="c98e52d0-5965-4b22-8a17-a374f4399193", "pool_898be8a2-5185-4f3b-8658-a56457f595a9"=""}
    name                : "94e7c431-912b-496c-a247-d52875d44ac7"
    protocol            : tcp
    vips                : {}

Lastly, when a member is created, OVN's Load Balancer table is complete::

    $ openstack loadbalancer member create --address 10.10.10.10 /
    --protocol-port 63015 898be8a2-5185-4f3b-8658-a56457f595a9
    +---------------------+--------------------------------------+
    | Field               | Value                                |
    +---------------------+--------------------------------------+
    | address             | 10.10.10.10                          |
    | admin_state_up      | True                                 |
    | created_at          | 2018-12-13T09:26:05                  |
    | id                  | adf55e70-3d50-4e62-99fd-dd77eababb1c |
    | name                |                                      |
    | operating_status    | NO_MONITOR                           |
    | project_id          | af820b57868c4864957d523fb32ccfba     |
    | protocol_port       | 63015                                |
    | provisioning_status | PENDING_CREATE                       |
    | subnet_id           | None                                 |
    | updated_at          | None                                 |
    | weight              | 1                                    |
    | monitor_port        | None                                 |
    | monitor_address     | None                                 |
    | backup              | False                                |
    +---------------------+--------------------------------------+
    $ ovn-nbctl list load_balancer
    _uuid               : c72de15e-5c2e-4c1b-a21b-8e9a6721193c
    external_ids        : {enabled=True, "listener_21e77cde-854f-4c3e-bd8c-9536ae0443bc"="64015:pool_898be8a2-5185-4f3b-8658-a56457f595a9", lr_ref="neutron-3d2a873b-b5b4-4d14-ac24-47a835fd47b2", ls_refs="{\"neutron-ee97665d-69d0-4995-a275-27855359956a\": 1}", "neutron:vip"="172.24.4.9", "neutron:vip_port_id"="c98e52d0-5965-4b22-8a17-a374f4399193", "pool_898be8a2-5185-4f3b-8658-a56457f595a9"="member_adf55e70-3d50-4e62-99fd-dd77eababb1c_10.10.10.10:63015"}
    name                : "94e7c431-912b-496c-a247-d52875d44ac7"
    protocol            : tcp
    vips                : {"172.24.4.9:64015"="10.10.10.10:63015"}


[1]: https://docs.openstack.org/kuryr-kubernetes/rocky/installation/services.html


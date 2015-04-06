TODO
=====================


ML2 Driver
---------------------

* Convert ML2 driver to use ovsdb Python bindings instead of executing the
  ovn-nbctl tool.

* Add sync functionality to ensure that the OVN northbound DB reflects the
  current state of the world according to Neutron.

* Set Neutron port state when OVN logical port 'up' state changes to true so
  that Nova will get notified that the port is ready.

* Add support for container sub-interfaces.  For more info, see the container
  related additions to the OVN design described here:
  https://github.com/openvswitch/ovs/commit/9fb4636f6c587060713ea0abf60ed6bcbe4f11f4

L3
---------------------

* Create L3 service plugin once L3 design is completed for OVN.


Devstack and Testing
---------------------

* Add jenkins job that uses devstack integration.  Until we're able to test with
  OVN itself, this job can at least ensure that Neutron can start properly with
  this driver enabled.

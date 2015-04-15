TODO
=====================

This document is used to keep track of what we know needs to be worked on.  We
also keep notes about who is working on what.  If you'd like to help with
something with a name attached, please still feel free to reach out to them to
see if there's anything you can do to help.

ML2 Driver
---------------------

* Convert ML2 driver to use ovsdb Python bindings instead of executing the
  ovn-nbctl tool.

  * Assignee: Gal Sagie

* Set Neutron port state when OVN logical port 'up' state changes to true so
  that Nova will get notified that the port is ready.

  * Assignee: Terry Wilson

* Security groups

  * Update the data_model docs to describe the mapping of Neutron security
    groups to OVN northbound db contents.

    * Assignee: Gal Sagie

  * Implementation is currently blocked on
    https://bugs.launchpad.net/networking-ovn/+bug/1444112

* Add support for container sub-interfaces.  For more info, see the container
  related additions to the OVN design described here:
  https://github.com/openvswitch/ovs/commit/9fb4636f6c587060713ea0abf60ed6bcbe4f11f4

  * Assignee: Russell Bryant

* Add sync functionality to ensure that the OVN northbound DB reflects the
  current state of the world according to Neutron.

  * Assignee: Gal Sagie

L3
---------------------

* Create L3 service plugin once L3 design is completed for OVN.


Devstack and Testing
---------------------

* Add jenkins job that uses devstack integration.  Until we're able to test with
  OVN itself, this job can at least ensure that Neutron can start properly with
  this driver enabled.

  * Assignee: Kyle Mestery

* Add gate_hook to install python-openvswitch for the unit test jobs.

* Add unit tests.

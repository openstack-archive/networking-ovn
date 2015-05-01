TODO
=====================

This document is used to keep track of what we know needs to be worked on.  We
also keep notes about who is working on what.  If you'd like to help with
something with a name attached, please still feel free to reach out to them to
see if there's anything you can do to help.

ML2 Driver
---------------------

* Set Neutron port state when OVN logical port 'up' state changes to true so
  that Nova will get notified that the port is ready.

  * Assignee: Terry Wilson

* Security groups

  * Update the data_model docs to describe the mapping of Neutron security
    groups to OVN northbound db contents.

    * Assignee: Gal Sagie

  * Implementation of creating ACL entries for security groups.

* Add sync functionality to ensure that the OVN northbound DB reflects the
  current state of the world according to Neutron.

  * Assignee: Gal Sagie

* Convert ml2 mech driver to perform entire operations inside a single ovsdb
  transaction.

  * Assignee: Gal Sagie

L3
---------------------

* Create L3 service plugin once L3 design is completed for OVN.


Devstack and Testing
---------------------

* Get python-openvswitch installed for unit test jobs.

  * Related ovs-dev thread:
    http://openvswitch.org/pipermail/dev/2015-April/053692.html

* Add unit tests.

TODO
=====================

* Document mappings between Neutron data model and the OVN northbound DB

* Add implementation of creating/deleting resources in the OVN northbound DB

** Create ML2 MechanismDriver

** Create L3 service plugin

* Add sync functionality to ensure that the OVN northbound DB reflects the
  current state of the world according to Neutron.

* Add devstack integration

* Add jenkins job that uses devstack integration.  Until we're able to test with
  OVN itself, this job can at least ensure that Neutron can start properly with
  this driver enabled.

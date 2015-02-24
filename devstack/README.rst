======================
 Enabling in Devstack
======================

1. Download DevStack

2. Add this repo as an external repository::

     > cat local.conf
     [[local|localrc]]
     enable_plugin networking-ovn http://git.openstack.org/stackforge/networking-ovn
     enable_service ovn

3. run ``stack.sh``

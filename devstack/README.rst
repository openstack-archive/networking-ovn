======================
 Enabling in Devstack
======================

1. Download devstack and networking-ovn::

     git clone http://git.openstack.org/openstack-dev/devstack.git
     git clone http://git.openstack.org/openstack/networking-ovn.git

2. Add networking-ovn to devstack.  The minimal set of critical local.conf
   additions are the following::

     cd devstack
     cat << EOF >> local.conf
     > enable_plugin networking-ovn http://git.openstack.org/openstack/networking-ovn
     > enable_service ovn
     > EOF

You can also use the provided example local.conf, or look at its contents to
add to your own::

     cd devstack
     cp ../networking-ovn/devstack/local.conf.sample local.conf

3. run devstack::

     ./stack.sh

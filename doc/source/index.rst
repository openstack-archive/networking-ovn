=======================================================
networking-ovn - OpenStack Neutron integration with OVN
=======================================================

.. NOTE(amotoki): Use a project badge only in HTML doc.
   The badge filename matches the repository name.
   In the PDF doc build, SVG file is converted into PDF file in advance.
   We use the repository name as the generated PDF doc, so the badge
   converted into PDF conflicts with the generated PDF doc.
   This causes PDF build failure.

.. only:: html

   .. image:: https://governance.openstack.org/tc/badges/networking-ovn.svg
       :target: https://governance.openstack.org/tc/reference/tags/index.html

OVN provides virtual networking for Open vSwitch and is a component of the
Open vSwitch project. This project provides integration between OpenStack
Neutron and OVN.

If you want to know about the key differences with ml2/ovs please have a look
on the FAQ (Frequently Asked Questions) section.

Contents
--------

.. toctree::
   :maxdepth: 2

   faq/index
   admin/index
   install/index
   install/migration
   configuration/index
   contributor/index

Links
-----
* Free software: Apache license
* Source: https://opendev.org/openstack/networking-ovn
* Design documents: https://docs.openstack.org/networking-ovn/latest/contributor/design/index.html
* Bugs: https://bugs.launchpad.net/networking-ovn
* Mailing list:
  http://lists.openstack.org/cgi-bin/mailman/listinfo/openstack-discuss
* IRC: #openstack-neutron-ovn on Freenode.
* Docs: https://docs.openstack.org/networking-ovn/latest

.. only:: html

   .. rubric:: Indices and tables

   * :ref:`genindex`
   * :ref:`search`

..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


      Convention for heading levels in OVN devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)

.. _testing_networking_ovn:

Testing OVN
===========

Why Should You Care
-------------------
There's two ways to approach testing:

1) Write unit tests because they're required to get your patch merged.
   This typically involves mock heavy tests that assert that your code is as
   written.
2) Putting as much thought into your testing strategy as you do to the rest
   of your code. Use different layers of testing as appropriate to provide
   high *quality* coverage. Are you touching an agent? Test it against an
   actual system! Are you adding a new API? Test it for race conditions
   against a real database! Are you adding a new cross-cutting feature?
   Test that it does what it's supposed to do when run on a real cloud!

Do you feel the need to verify your change manually? If so, the next few
sections attempt to guide you through OVN's different test infrastructures
to help you make intelligent decisions and best exploit OVN's test
offerings.

Definitions
-----------
We will talk about three classes of tests: unit, functional and integration.
Each respective category typically targets a larger scope of code. Other than
that broad categorization, here are a few more characteristic:

* Unit tests - Should be able to run on your laptop, directly following a
  'git clone' of the project. The underlying system must not be mutated,
  mocks can be used to achieve this. A unit test typically targets a function
  or class.
* Functional tests - Run against a pre-configured environment
  (tools/configure_for_func_testing.sh). Typically test a component
  such as an agent using no mocks.
* Integration tests - Run against a running cloud, often target the API level,
  but also 'scenarios' or 'user stories'. You may find such tests in
  the Tempest, Rally and
  neutron-tempest-plugin(neutron_tempest_plugin/api|scenario) projects.

Tests in the OVN tree are typically organized by the testing infrastructure
used, and not by the scope of the test. For example, many tests under the
'unit' directory invoke an API call and assert that the expected output was
received. The scope of such a test is the entire OVN server stack,
and clearly not a specific function such as in a typical unit test.

Testing Frameworks
------------------

The different frameworks are listed below. The intent is to list the
capabilities of each testing framework as to help the reader understand when
should each tool be used. Remember that when adding code that touches many
areas of OVN, each area should be tested with the appropriate framework.
Overlap between different test layers is often desirable and encouraged.

Unit Tests
~~~~~~~~~~

Unit tests (networking_ovn/tests/unit/) are meant to cover as much code as
possible. They are designed to test the various pieces of the OVN tree to
make sure any new changes don't break existing functionality. Unit tests have
no requirements nor make changes to the system they are running on. They use
an in-memory sqlite database to test DB interaction.

At the start of each test run:

* RPC listeners are mocked away.
* The fake Oslo messaging driver is used.

At the end of each test run:

* Mocks are automatically reverted.
* The in-memory database is cleared of content, but its schema is maintained.
* The global Oslo configuration object is reset.

The unit testing framework can be used to effectively test database interaction,
for example, OVN supports code to bump object revision numbers.
Its test looks like this:

.. code-block:: python

    def test_bump_revision(self):
        db_rev.create_initial_revision(self.net['id'], constants.TYPE_NETWORKS,
                                       self.session)
        self.net['revision_number'] = 123
        db_rev.bump_revision(self.net, constants.TYPE_NETWORKS)
        row = db_rev.get_revision_row(self.net['id'])
        self.assertEqual(123, row.revision_number)

It creates a network with an initial revision number, invokes the method under
test to change the revision number, and asserts it has changed. The test has
many things going for it:

* It targets the method under test correctly, not taking on a larger scope
  than is necessary.
* It does not use mocks to assert that methods were called, it simply
  invokes the method and asserts its output (In this case, that the get
  method returns the object).

This is allowed by the fact that the method was built to be testable -
The method has clear input and output with no side effects.

You can get oslo.db to generate a file-based sqlite database by setting
OS_TEST_DBAPI_ADMIN_CONNECTION to a file based URL as described in `this
mailing list post`__. This file will be created but (confusingly) won't be the
actual file used for the database. To find the actual file, set a break point
in your test method and inspect self.engine.url.

__ file-based-sqlite_

.. code-block:: shell

    $ OS_TEST_DBAPI_ADMIN_CONNECTION=sqlite:///sqlite.db .tox/py27/bin/python -m \
        testtools.run networking_ovn.tests.unit...
    ...
    (Pdb) self.engine.url
    sqlite:////tmp/iwbgvhbshp.db

Now, you can inspect this file using sqlite3.

.. code-block:: shell

    $ sqlite3 /tmp/iwbgvhbshp.db

Functional Tests
~~~~~~~~~~~~~~~~

Functional tests (networking_ovn/tests/functional/) are intended to
validate actual system interaction. Mocks should be used sparingly,
if at all. Care should be taken to ensure that existing system
resources are not modified and that resources created in tests are
properly cleaned up both on test success and failure.

Let's examine the benefits of the functional testing framework.
Neutron offers a library called 'ip_lib' that wraps around the 'ip' binary.
One of its methods is called 'device_exists' which accepts a device name
and a namespace and returns True if the device exists in the given namespace.
It's easy building a test that targets the method directly, and such a test
would be considered a 'unit' test. However, what framework should such a test
use? A test using the unit tests framework could not mutate state on the system,
and so could not actually create a device and assert that it now exists. Such
a test would look roughly like this:

* It would mock 'execute', a method that executes shell commands against the
  system to return an IP device named 'foo'.
* It would then assert that when 'device_exists' is called with 'foo', it
  returns True, but when called with a different device name it returns False.
* It would most likely assert that 'execute' was called using something like:
  'ip link show foo'.

The value of such a test is arguable. Remember that new tests are not free,
they need to be maintained. Code is often refactored, reimplemented and
optimized.

* There are other ways to find out if a device exists (Such as
  by looking at '/sys/class/net'), and in such a case the test would have
  to be updated.
* Methods are mocked using their name. When methods are renamed, moved or
  removed, their mocks must be updated. This slows down development for
  avoidable reasons.
* Most importantly, the test does not assert the behavior of the method. It
  merely asserts that the code is as written.

When adding a functional test for 'device_exists', several framework level
methods were added. These methods may now be used by other tests as well.
One such method creates a virtual device in a namespace,
and ensures that both the namespace and the device are cleaned up at the
end of the test run regardless of success or failure using the 'addCleanup'
method. The test generates details for a temporary device, asserts that
a device by that name does not exist, creates that device, asserts that
it now exists, deletes it, and asserts that it no longer exists.
Such a test avoids all three issues mentioned above if it were written
using the unit testing framework.

Functional tests are also used to target larger scope, such as agents.
Many good examples exist: See the OVS, L3 and DHCP agents functional tests.
Such tests target a top level agent method and assert that the system
interaction that was supposed to be performed was indeed performed.
For example, to test the DHCP agent's top level method that accepts network
attributes and configures dnsmasq for that network, the test:

* Instantiates an instance of the DHCP agent class (But does not start its
  process).
* Calls its top level function with prepared data.
* Creates a temporary namespace and device, and calls 'dhclient' from that
  namespace.
* Assert that the device successfully obtained the expected IP address.

Test exceptions
+++++++++++++++

Test networking_ovn.tests.functional.test_ovn_db_resources.TestPortSecurity.\
test_port_security_port_group is currently skipped if port groups are not
supported in the northbound API.  If the API meets the test requirement then
the test is triggered normally.

API Tests
~~~~~~~~~

API tests (neutron-tempest-plugin/neutron_tempest_plugin/api/) are
intended to ensure the function
and stability of the Neutron API. As much as possible, changes to
this path should not be made at the same time as changes to the code
to limit the potential for introducing backwards-incompatible changes,
although the same patch that introduces a new API should include an API
test.

Since API tests target a deployed OVN daemon that is not test-managed,
they should not depend on controlling the runtime configuration
of the target daemon. API tests should be black-box - no assumptions should
be made about implementation. Only the contract defined by Neutron's REST API
should be validated, and all interaction with the daemon should be via
a REST client.

The neutron-tempest-plugin/neutron_tempest_plugin directory was copied from the
Tempest project around the Kilo timeframe. At the time, there was an overlap of
tests between the Tempest and Neutron repositories. This overlap was then
eliminated by carving out a subset of resources that belong to Tempest, with
the rest in Neutron.

API tests that belong to Tempest deal with a subset of OVN's resources:

* Port
* Network
* Subnet
* Security Group
* Router
* Floating IP

These resources were chosen for their ubiquity. They are found in most
Neutron deployments regardless of plugin, and are directly involved in the
networking and security of an instance. Together, they form the bare minimum
needed by Neutron.

This is excluding extensions to these resources (For example: Extra DHCP
options to subnets, or snat_gateway mode to routers) that are not mandatory
in the majority of cases.

Tests for other resources should be contributed to the Neutron repository.
Scenario tests should be similarly split up between Tempest and Neutron
according to the API they're targeting.

To create an API test, the testing class must at least inherit from
neutron_tempest_plugin.api.base.BaseNetworkTest base class. As some of tests
may require certain extensions to be enabled, the base class provides
``required_extensions`` class attribute which can be used by subclasses to
define a list of required extensions for particular test class.

Scenario Tests
~~~~~~~~~~~~~~

Scenario tests (neutron-tempest-plugin/neutron_tempest_plugin/scenario), like
API tests, use the Tempest test infrastructure and have the same requirements.
Guidelines for writing a good scenario test may be found at the Tempest
developer guide:
https://docs.openstack.org/tempest/latest/field_guide/scenario.html

Scenario tests, like API tests, are split between the Tempest and Neutron
repositories according to the Neutron API the test is targeting.

Some scenario tests require advanced ``Glance`` images (for example, ``Ubuntu``
or ``CentOS``) in order to pass. Those tests are skipped by default. To enable
them, include the following in ``tempest.conf``:

.. code-block:: ini

   [compute]
   image_ref = <uuid of advanced image>
   [neutron_plugin_options]
   image_is_advanced = True

Specific test requirements for advanced images are:

#. ``test_trunk`` requires ``802.11q`` kernel module loaded.

Rally Tests
~~~~~~~~~~~

Rally tests (rally-jobs/plugins) use the `rally <http://rally.readthedocs.io/>`_
infrastructure to exercise an OVN deployment. Guidelines for writing a
good rally test can be found in the
`rally plugin documentation <http://rally.readthedocs.io/en/latest/plugins/>`_.
There are also some examples in tree; the process for adding rally plugins to
OVN requires three steps:

1) write a plugin and place it under rally-jobs/plugins/. This is your rally
   scenario;
2) (optional) add a setup file under rally-jobs/extra/. This is any devstack
   configuration required to make sure your environment can successfully
   process your scenario requests;
3) edit ovn.yaml. This is your scenario 'contract' or SLA.

Development Process
-------------------

It is expected that any new changes that are proposed for merge
come with tests for that feature or code area. Any bugs
fixes that are submitted must also have tests to prove that they stay
fixed! In addition, before proposing for merge, all of the
current tests should be passing.

Structure of the Unit Test Tree
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The structure of the unit test tree should match the structure of the
code tree, e.g. ::

 - target module: networking_ovn.agent.metadata.agent

 - test module: networking_ovn.tests.unit.agent.metadata.test_agent

Unit test modules should have the same path under networking_ovn/tests/unit/
as the module they target has under networking_ovn/, and their name should be
the name of the target module prefixed by `test_`. This requirement
is intended to make it easier for developers to find the unit tests
for a given module.

The following command can be used to validate whether the unit test
tree is structured according to the above requirements: ::

    ./tools/check_unit_test_structure.sh

Where appropriate, exceptions can be added to the above script. If
code is not part of the OVN namespace, for example, it's probably
reasonable to exclude their unit tests from the check.


.. note ::

   At no time should the production code import anything from testing subtree
   (networking_ovn.tests). There are distributions that split out
   networking_ovn.tests modules in a separate package that is not installed by
   default, making any code that relies on presence of the modules to fail.
   For example, RDO is one of those distributions.

Running Tests
-------------

Before submitting a patch for review you should always ensure all tests pass; a
tox run is triggered by the jenkins gate executed on gerrit for each patch
pushed for review.

OVN, like other OpenStack projects, uses `tox`_ for managing the virtual
environments for running test cases. It uses `Testr`_ for managing the running
of the test cases.

Tox handles the creation of a series of `virtualenvs`_ that target specific
versions of Python.

Testr handles the parallel execution of series of test cases as well as
the tracking of long-running tests and other things.

For more information on the standard Tox-based test infrastructure used by
OpenStack and how to do some common test/debugging procedures with Testr,
see this wiki page: https://wiki.openstack.org/wiki/Testr

.. _Testr: https://wiki.openstack.org/wiki/Testr
.. _tox: http://tox.readthedocs.org/en/latest/
.. _virtualenvs: https://pypi.org/project/virtualenv

PEP8 and Unit Tests
~~~~~~~~~~~~~~~~~~~

Running pep8 and unit tests is as easy as executing this in the root
directory of the OVN source code::

    tox

To run only pep8::

    tox -e pep8

Since pep8 includes running pylint on all files, it can take quite some time
to run. To restrict the pylint check to only the files altered by the latest
patch changes::

    tox -e pep8 HEAD~1

To run only pep8, but using the latest code from the upstream neutron
repository instead of the pip installed version from requirements.txt::

    tox -e pep8-dev

To run only the unit tests::

    tox -e py27

To run only the unit tests, but using the latest code from the upstream
neutron repository instead of the pip installed version from requirements.txt::

    tox -e py3-dev

Many changes span across both the OVN and neutron-lib repos, and tox will
always build the test environment using the published module versions specified
in requirements.txt. To run tox tests against a different version of
neutron-lib, use the TOX_ENV_SRC_MODULES environment variable to point at a
local package repo.

For example, to run against the 'master' branch of neutron-lib::

    cd $SRC
    git clone https://git.openstack.org/openstack/neutron-lib
    cd $OVN_DIR
    env TOX_ENV_SRC_MODULES=$SRC/neutron-lib tox -r -e pep8,py27

To run against a change of your own, repeat the same steps, but use the
directory with your changes, not a fresh clone.

To run against a particular gerrit change of the lib (substituting the
desired gerrit refs for this example)::

    cd $SRC
    git clone https://git.openstack.org/openstack/neutron-lib
    cd neutron-lib
    git fetch https://git.openstack.org/openstack/neutron-lib refs/changes/13/635313/6 && git checkout FETCH_HEAD
    cd $OVN_DIR
    env TOX_ENV_SRC_MODULES=$SRC/neutron-lib tox -r -e pep8,py27

Note that the '-r' is needed to re-create the tox virtual envs, and will also
be needed to restore them to standard when not using this method.

Any pip installable package can be overriden with this environment variable,
not just neutron-lib. To specify multiple packages to override, specify them
as a space separated list to TOX_ENV_SRC_MODULES. For example, to override
both neutron and oslo.db::

    env TOX_ENV_SRC_MODULES="$SRC/neutron-lib $SRC/neutron $SRC/oslo.db" tox -r -e pep8,py27

Functional Tests
~~~~~~~~~~~~~~~~

To run functional tests that do not require sudo privileges or
specific-system dependencies::

    tox -e functional

To run all the functional tests, including those requiring sudo
privileges and system-specific dependencies, the procedure defined by
tools/configure_for_func_testing.sh should be followed.

IMPORTANT: configure_for_func_testing.sh relies on DevStack to perform
extensive modification to the underlying host. Execution of the
script requires sudo privileges and it is recommended that the
following commands be invoked only on a clean and disposable VM.
A VM that has had DevStack previously installed on it is also fine. ::

    git clone https://git.openstack.org/openstack-dev/devstack ../devstack
    ./tools/configure_for_func_testing.sh ../devstack -i
    tox -e dsvm-functional

The '-i' option is optional and instructs the script to use DevStack
to install and configure all of OVN's package dependencies. It is
not necessary to provide this option if DevStack has already been used
to deploy OVN to the target host.

API & Scenario Tests
~~~~~~~~~~~~~~~~~~~~

To run the api or scenario tests, deploy Tempest, neutron-tempest-plugin
and OVN with DevStack and then run the following command,
from the tempest directory: ::

    $ export DEVSTACK_GATE_TEMPEST_REGEX="networking_ovn"
    $ tox -e all-plugin $DEVSTACK_GATE_TEMPEST_REGEX

If you want to limit the amount of tests, or run an individual test,
you can do, for instance: ::

    $ tox -e all-plugin neutron_tempest_plugin.api.admin.test_routers_ha
    $ tox -e all-plugin neutron_tempest_plugin.api.test_qos.QosTestJSON.test_create_policy

If you want to use special config for OVN, like use advanced images (Ubuntu
or CentOS) testing advanced features, you may need to add config
in tempest/etc/tempest.conf:

.. code-block:: ini

   [neutron_plugin_options]
   image_is_advanced = True

The Neutron tempest plugin configs are under ``neutron_plugin_options`` scope
of ``tempest.conf``.

Running Individual Tests
~~~~~~~~~~~~~~~~~~~~~~~~

For running individual test modules, cases or tests, you just need to pass
the dot-separated path you want as an argument to it.

For example, the following would run only a single test or test case::

      $ tox -e py27 networking_ovn.tests.unit.ovsdb.test_commands
      $ tox -e py27 networking_ovn.tests.unit.ovsdb.test_commands.TestAddLRouterCommand
      $ tox -e py27 networking_ovn.tests.unit.ovsdb.test_commands.TestAddLRouterCommand.test_lrouter_exists

If you want to pass other arguments to stestr, you can do the following::

      $ tox -e py27 -- networking_ovn.tests.unit.ovsdb.test_commands --serial


Coverage
--------

OVN has a fast growing code base and there are plenty of areas that
need better coverage.

To get a grasp of the areas where tests are needed, you can check
current unit tests coverage by running::

    $ tox -e cover

Note: The cover command can only show unit test coverage


Debugging
---------

By default, calls to pdb.set_trace() will be ignored when tests
are run. For pdb statements to work, invoke tox as follows::

    $ tox -e venv -- python -m testtools.run [test module path]

Tox-created virtual environments (venv's) can also be activated
after a tox run and reused for debugging::

    $ tox -e venv
    $ . .tox/venv/bin/activate
    $ python -m testtools.run [test module path]

Tox packages and installs the OVN source tree in a given venv
on every invocation, but if modifications need to be made between
invocation (e.g. adding more pdb statements), it is recommended
that the source tree be installed in the venv in editable mode::

    # run this only after activating the venv
    $ pip install --editable .

Editable mode ensures that changes made to the source tree are
automatically reflected in the venv, and that such changes are not
overwritten during the next tox run.

Post-mortem Debugging
~~~~~~~~~~~~~~~~~~~~~

TBD: how to do this with tox.

References
~~~~~~~~~~

.. _file-based-sqlite: http://lists.openstack.org/pipermail/openstack-dev/2016-July/099861.html

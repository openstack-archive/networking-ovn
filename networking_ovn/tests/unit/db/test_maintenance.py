# Copyright 2017 Red Hat, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import mock

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.common import config
import neutron.extensions
from neutron.services.revisions import revision_plugin
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit.extensions import test_securitygroup
from neutron_lib import constants as n_const
from neutron_lib.db import api as db_api

from networking_ovn.common import constants
from networking_ovn.db import maintenance as db_maint
from networking_ovn.db import revision as db_rev


EXTENSIONS_PATH = ':'.join(neutron.extensions.__path__)
PLUGIN_CLASS = (
    'networking_ovn.tests.unit.db.test_maintenance.TestMaintenancePlugin')


class TestMaintenancePlugin(test_securitygroup.SecurityGroupTestPlugin,
                            test_l3.TestL3NatBasePlugin):

    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = ['external-net', 'security-group']


class TestMaintenance(test_securitygroup.SecurityGroupsTestCase,
                      test_l3.L3NatTestCaseMixin):

    def setUp(self):
        service_plugins = {
            'router':
            'neutron.tests.unit.extensions.test_l3.TestL3NatServicePlugin'}
        super(TestMaintenance, self).setUp(plugin=PLUGIN_CLASS,
                                           service_plugins=service_plugins)
        l3_plugin = test_l3.TestL3NatServicePlugin()
        sec_plugin = test_securitygroup.SecurityGroupTestPlugin()
        ext_mgr = extensions.PluginAwareExtensionManager(
            EXTENSIONS_PATH, {'router': l3_plugin, 'sec': sec_plugin}
        )
        ext_mgr.extend_resources('2.0', attributes.RESOURCE_ATTRIBUTE_MAP)
        app = config.load_paste_app('extensions_test_app')
        self.ext_api = extensions.ExtensionMiddleware(app, ext_mgr=ext_mgr)
        self.session = db_api.get_writer_session()
        revision_plugin.RevisionPlugin()
        self.net = self._make_network(self.fmt, 'net1', True)['network']

        # Mock the default value for INCONSISTENCIES_OLDER_THAN so
        # tests won't need to wait for the timeout in order to validate
        # the database inconsistencies
        self.older_than_mock = mock.patch(
            'networking_ovn.db.maintenance.INCONSISTENCIES_OLDER_THAN', -1)
        self.older_than_mock.start()
        self.addCleanup(self.older_than_mock.stop)

    def test_get_inconsistent_resources(self):
        # Set the intial revision to -1 to force it to be incosistent
        db_rev.create_initial_revision(
            self.net['id'], constants.TYPE_NETWORKS, self.session,
            revision_number=-1)
        res = db_maint.get_inconsistent_resources()
        self.assertEqual(1, len(res))
        self.assertEqual(self.net['id'], res[0].resource_uuid)

    def test_get_inconsistent_resources_older_than(self):
        # Stop the mock so the INCONSISTENCIES_OLDER_THAN will have
        # it's default value
        self.older_than_mock.stop()
        db_rev.create_initial_revision(
            self.net['id'], constants.TYPE_NETWORKS, self.session,
            revision_number=-1)
        res = db_maint.get_inconsistent_resources()

        # Assert that nothing is returned because the entry is not old
        # enough to be picked as an inconsistency
        self.assertEqual(0, len(res))

        # Start the mock again and make sure it nows shows up as an
        # inconsistency
        self.older_than_mock.start()
        res = db_maint.get_inconsistent_resources()
        self.assertEqual(1, len(res))
        self.assertEqual(self.net['id'], res[0].resource_uuid)

    def test_get_inconsistent_resources_consistent(self):
        # Set the initial revision to 0 which is the initial revision_number
        # for recently created resources
        db_rev.create_initial_revision(
            self.net['id'], constants.TYPE_NETWORKS, self.session,
            revision_number=0)
        res = db_maint.get_inconsistent_resources()
        # Assert nothing is inconsistent
        self.assertEqual([], res)

    def test_get_deleted_resources(self):
        db_rev.create_initial_revision(
            self.net['id'], constants.TYPE_NETWORKS, self.session,
            revision_number=0)
        self._delete('networks', self.net['id'])
        res = db_maint.get_deleted_resources()

        self.assertEqual(1, len(res))
        self.assertEqual(self.net['id'], res[0].resource_uuid)
        self.assertIsNone(res[0].standard_attr_id)

    def _prepare_resources_for_ordering_test(self, delete=False):
        subnet = self._make_subnet(self.fmt, {'network': self.net}, '10.0.0.1',
                                   '10.0.0.0/24')['subnet']
        self._set_net_external(self.net['id'])
        info = {'network_id': self.net['id']}
        router = self._make_router(self.fmt, None,
                                   external_gateway_info=info)['router']
        fip = self._make_floatingip(self.fmt, self.net['id'])['floatingip']
        port = self._make_port(self.fmt, self.net['id'])['port']
        sg = self._make_security_group(self.fmt, 'sg1', '')['security_group']
        rule = self._build_security_group_rule(
            sg['id'], 'ingress', n_const.PROTO_NUM_TCP)
        sg_rule = self._make_security_group_rule(
            self.fmt, rule)['security_group_rule']

        db_rev.create_initial_revision(
            router['id'], constants.TYPE_ROUTERS, self.session)
        db_rev.create_initial_revision(
            subnet['id'], constants.TYPE_SUBNETS, self.session)
        db_rev.create_initial_revision(
            fip['id'], constants.TYPE_FLOATINGIPS, self.session)
        db_rev.create_initial_revision(
            port['id'], constants.TYPE_PORTS, self.session)
        db_rev.create_initial_revision(
            port['id'], constants.TYPE_ROUTER_PORTS, self.session)
        db_rev.create_initial_revision(
            sg['id'], constants.TYPE_SECURITY_GROUPS, self.session)
        db_rev.create_initial_revision(
            sg_rule['id'], constants.TYPE_SECURITY_GROUP_RULES, self.session)
        db_rev.create_initial_revision(
            self.net['id'], constants.TYPE_NETWORKS, self.session)

        if delete:
            self._delete('security-group-rules', sg_rule['id'])
            self._delete('floatingips', fip['id'])
            self._delete('ports', port['id'])
            self._delete('security-groups', sg['id'])
            self._delete('routers', router['id'])
            self._delete('subnets', subnet['id'])
            self._delete('networks', self.net['id'])

    def test_get_inconsistent_resources_order(self):
        self._prepare_resources_for_ordering_test()
        res = db_maint.get_inconsistent_resources()
        actual_order = tuple(r.resource_type for r in res)
        self.assertEqual(constants._TYPES_PRIORITY_ORDER, actual_order)

    def test_get_deleted_resources_order(self):
        self._prepare_resources_for_ordering_test(delete=True)
        res = db_maint.get_deleted_resources()
        actual_order = tuple(r.resource_type for r in res)
        self.assertEqual(tuple(reversed(constants._TYPES_PRIORITY_ORDER)),
                         actual_order)

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

from networking_ovn.common import constants as ovn_const
from networking_ovn.tests.functional import base


class TestRevisionNumbers(base.TestOVNFunctionalBase):

    def _create_network(self, name):
        data = {'network': {'name': name, 'tenant_id': self._tenant_id}}
        req = self.new_create_request('networks', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['network']

    def _update_network_name(self, net_id, new_name):
        data = {'network': {'name': new_name}}
        req = self.new_update_request('networks', data, net_id, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['network']

    def _find_network_row_by_name(self, name):
        for row in self.nb_api._tables['Logical_Switch'].rows.values():
            if (row.external_ids.get(
                    ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY) == name):
                return row

    def test_create_network(self):
        name = 'net1'
        neutron_net = self._create_network(name)
        ovn_net = self._find_network_row_by_name(name)

        ovn_revision = ovn_net.external_ids[ovn_const.OVN_REV_NUM_EXT_ID_KEY]
        self.assertEqual(str(2), ovn_revision)
        # Assert it also matches with the newest returned by neutron API
        self.assertEqual(str(neutron_net['revision_number']), ovn_revision)

    def test_update_network(self):
        new_name = 'netnew1'
        neutron_net = self._create_network('net1')
        updated_net = self._update_network_name(neutron_net['id'], new_name)
        ovn_net = self._find_network_row_by_name(new_name)

        ovn_revision = ovn_net.external_ids[ovn_const.OVN_REV_NUM_EXT_ID_KEY]
        self.assertEqual(str(3), ovn_revision)
        # Assert it also matches with the newest returned by neutron API
        self.assertEqual(str(updated_net['revision_number']), ovn_revision)

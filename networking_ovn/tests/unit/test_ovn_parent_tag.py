# Copyright (c) 2015 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from networking_ovn.common import constants as ovn_const
from networking_ovn.tests.unit.ml2 import test_mech_driver

OVN_PROFILE = ovn_const.OVN_PORT_BINDING_PROFILE


class TestOVNParentTagPortBinding(test_mech_driver.OVNMechanismDriverTestCase):

    # NOTE(rtheis): The neutron ML2 plugin does not provide drivers with
    # an interface to validate port bindings. As a result, a 500 error
    # (i.e. MechanismDriverError) is expected when the port binding
    # information is invalid.

    def test_create_port_with_invalid_parent(self):
        binding = {OVN_PROFILE: {"parent_name": 'invalid', 'tag': 1}}
        with self.network() as n:
            with self.subnet(n):
                self._create_port(
                    self.fmt, n['network']['id'],
                    expected_res_status=500,
                    arg_list=(OVN_PROFILE,),
                    **binding)

    def test_create_port_with_parent_and_tag(self):
        binding = {OVN_PROFILE: {"parent_name": '', 'tag': 1}}
        with self.network() as n:
            with self.subnet(n) as s:
                with self.port(s) as p:
                    binding[OVN_PROFILE]['parent_name'] = p['port']['id']
                    res = self._create_port(self.fmt, n['network']['id'],
                                            arg_list=(OVN_PROFILE,),
                                            **binding)
                    port = self.deserialize(self.fmt, res)
                    self.assertEqual(port['port'][OVN_PROFILE],
                                     binding[OVN_PROFILE])

    def test_create_port_with_invalid_tag(self):
        binding = {OVN_PROFILE: {"parent_name": '', 'tag': 'a'}}
        with self.network() as n:
            with self.subnet(n) as s:
                with self.port(s) as p:
                    binding[OVN_PROFILE]['parent_name'] = p['port']['id']
                    self._create_port(self.fmt, n['network']['id'],
                                      arg_list=(OVN_PROFILE,),
                                      expected_res_status=500,
                                      **binding)

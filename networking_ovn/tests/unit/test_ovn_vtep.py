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


class TestOVNVtepPortBinding(test_mech_driver.OVNMechanismDriverTestCase):

    # NOTE(rtheis): The neutron ML2 plugin does not provide drivers with
    # an interface to validate port bindings. As a result, a 500 error
    # (i.e. MechanismDriverError) is expected when the port binding
    # information is invalid.

    def test_create_port_with_vtep_options(self):
        binding = {OVN_PROFILE: {"vtep_physical_switch": 'psw1',
                   "vtep_logical_switch": 'lsw1'}}
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port(self.fmt, n['network']['id'],
                                        arg_list=(OVN_PROFILE,),
                                        **binding)
                port = self.deserialize(self.fmt, res)
                self.assertEqual(binding[OVN_PROFILE],
                                 port['port'][OVN_PROFILE])

    def test_create_port_with_only_vtep_physical_switch(self):
        binding = {OVN_PROFILE: {"vtep_physical_switch": 'psw'}}
        with self.network() as n:
            with self.subnet(n):
                self._create_port(self.fmt, n['network']['id'],
                                  arg_list=(OVN_PROFILE,),
                                  expected_res_status=500,
                                  **binding)

    def test_create_port_with_only_vtep_logical_switch(self):
        binding = {OVN_PROFILE: {"vtep_logical_switch": 'lsw1'}}
        with self.network() as n:
            with self.subnet(n):
                self._create_port(self.fmt, n['network']['id'],
                                  arg_list=(OVN_PROFILE,),
                                  expected_res_status=500,
                                  **binding)

    def test_create_port_with_invalid_vtep_logical_switch(self):
        binding = {OVN_PROFILE: {"vtep_logical_switch": 1234,
                                 "vtep_physical_switch": "psw1"}}
        with self.network() as n:
            with self.subnet(n):
                self._create_port(self.fmt, n['network']['id'],
                                  arg_list=(OVN_PROFILE,),
                                  expected_res_status=500,
                                  **binding)

    def test_create_port_with_vtep_options_and_parent_name_tag(self):
        binding = {OVN_PROFILE: {"vtep_logical_switch": "lsw1",
                                 "vtep_physical_switch": "psw1",
                                 "parent_name": "pname", "tag": 22}}
        with self.network() as n:
            with self.subnet(n):
                self._create_port(self.fmt, n['network']['id'],
                                  arg_list=(OVN_PROFILE,),
                                  expected_res_status=500,
                                  **binding)

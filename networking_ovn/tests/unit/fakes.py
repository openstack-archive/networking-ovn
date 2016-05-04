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
#

import mock


class FakeOvsdbOvnIdl(object):

    def __init__(self, **kwargs):
        def _fake(*args, **kwargs):
            return mock.MagicMock()
        self.transaction = _fake
        self.create_lswitch = mock.Mock()
        self.set_lswitch_ext_id = mock.Mock()
        self.delete_lswitch = mock.Mock()
        self.create_lport = mock.Mock()
        self.set_lport = mock.Mock()
        self.delete_lport = mock.Mock()
        self.get_all_logical_switches_ids = mock.Mock()
        self.get_logical_switch_ids = mock.Mock()
        self.get_all_logical_ports_ids = mock.Mock()
        self.create_lrouter = mock.Mock()
        self.update_lrouter = mock.Mock()
        self.delete_lrouter = mock.Mock()
        self.add_lrouter_port = mock.Mock()
        self.delete_lrouter_port = mock.Mock()
        self.set_lrouter_port_in_lport = mock.Mock()
        self.add_acl = mock.Mock()
        self.delete_acl = mock.Mock()
        self.update_acls = mock.Mock()
        self.idl = mock.Mock()

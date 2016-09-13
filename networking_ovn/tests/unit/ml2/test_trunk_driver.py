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

from networking_ovn.common.constants import OVN_ML2_MECH_DRIVER_NAME
from networking_ovn.ml2 import trunk_driver
from networking_ovn.tests.unit import fakes

from neutron.objects import trunk as trunk_objects
from neutron.tests import base

from oslo_config import cfg


class TestTrunkHandler(base.BaseTestCase):
    def setUp(self):
        super(TestTrunkHandler, self).setUp()
        self.context = mock.Mock()
        self.plugin_driver = mock.Mock()
        self.plugin_driver._nb_ovn = fakes.FakeOvsdbNbOvnIdl()
        self.handler = trunk_driver.OVNTrunkHandler(self.plugin_driver)
        self.trunk_1 = mock.Mock()
        self.trunk_1.port_id = "parent_port_1"

        self.trunk_2 = mock.Mock()
        self.trunk_2.port_id = "parent_port_2"

        self.sub_port_1 = mock.Mock()
        self.sub_port_1.segmentation_id = 40
        self.sub_port_1.trunk_id = "trunk-1"
        self.sub_port_1.port_id = "sub_port_1"

        self.sub_port_2 = mock.Mock()
        self.sub_port_2.segmentation_id = 41
        self.sub_port_2.trunk_id = "trunk-1"
        self.sub_port_2.port_id = "sub_port_2"

        self.sub_port_3 = mock.Mock()
        self.sub_port_3.segmentation_id = 42
        self.sub_port_3.trunk_id = "trunk-2"
        self.sub_port_3.port_id = "sub_port_3"

        self.sub_port_4 = mock.Mock()
        self.sub_port_4.segmentation_id = 43
        self.sub_port_4.trunk_id = "trunk-2"
        self.sub_port_4.port_id = "sub_port_4"

        self.get_trunk_object = mock.patch.object(
            trunk_objects.Trunk, "get_object").start()
        self.get_trunk_object.side_effect = lambda ctxt, id: \
            self.trunk_1 if id == 'trunk-1' else self.trunk_2

    def test_create_trunk(self):
        self.trunk_1.sub_ports = []

        self.handler.trunk_created(self.trunk_1)
        self.plugin_driver._nb_ovn.set_lswitch_port.assert_has_calls([])

        self.trunk_1.sub_ports = [self.sub_port_1, self.sub_port_2]
        self.handler.trunk_created(self.trunk_1)

        calls = [mock.call.set_lswitch_port("sub_port_1",
                                            parent_name="parent_port_1",
                                            tag=40),
                 mock.call.set_lswitch_port("sub_port_2",
                                            parent_name="parent_port_1",
                                            tag=41)]
        self.plugin_driver._nb_ovn.set_lswitch_port.assert_has_calls(
            calls, any_order=True)

    def test_delete_trunk(self):
        self.trunk_1.sub_ports = []
        self.handler.trunk_deleted(self.trunk_1)
        self.plugin_driver._nb_ovn.set_lswitch_port.assert_has_calls([])

        self.trunk_1.sub_ports = [self.sub_port_1, self.sub_port_2]
        self.handler.trunk_deleted(self.trunk_1)

        calls = [mock.call.set_lswitch_port("sub_port_1",
                                            parent_name=[],
                                            tag=[]),
                 mock.call.set_lswitch_port("sub_port_2",
                                            parent_name=[],
                                            tag=[])]
        self.plugin_driver._nb_ovn.set_lswitch_port.assert_has_calls(
            calls, any_order=True)

    def test_subports_added(self):
        self.handler.subports_added(self.trunk_1,
                                    [self.sub_port_1, self.sub_port_2])
        self.handler.subports_added(self.trunk_2,
                                    [self.sub_port_3, self.sub_port_4])
        calls = [mock.call.set_lswitch_port("sub_port_1",
                                            parent_name="parent_port_1",
                                            tag=40),
                 mock.call.set_lswitch_port("sub_port_2",
                                            parent_name="parent_port_1",
                                            tag=41),
                 mock.call.set_lswitch_port("sub_port_3",
                                            parent_name="parent_port_2",
                                            tag=42),
                 mock.call.set_lswitch_port("sub_port_4",
                                            parent_name="parent_port_2",
                                            tag=43)]
        self.plugin_driver._nb_ovn.set_lswitch_port.assert_has_calls(
            calls, any_order=True)

    def test_subports_deleted(self):
        self.handler.subports_deleted(self.trunk_1,
                                      [self.sub_port_1, self.sub_port_2])
        self.handler.subports_deleted(self.trunk_2,
                                      [self.sub_port_3, self.sub_port_4])
        calls = [mock.call.set_lswitch_port("sub_port_1",
                                            parent_name=[],
                                            tag=[]),
                 mock.call.set_lswitch_port("sub_port_2",
                                            parent_name=[],
                                            tag=[]),
                 mock.call.set_lswitch_port("sub_port_3",
                                            parent_name=[],
                                            tag=[]),
                 mock.call.set_lswitch_port("sub_port_4",
                                            parent_name=[],
                                            tag=[])]
        self.plugin_driver._nb_ovn.set_lswitch_port.assert_has_calls(
            calls, any_order=True)


class TestTrunkDriver(base.BaseTestCase):
    def setUp(self):
        super(TestTrunkDriver, self).setUp()

    def test_is_loaded(self):
        driver = trunk_driver.OVNTrunkDriver.create(mock.Mock())
        cfg.CONF.set_override('mechanism_drivers',
                              ["logger", OVN_ML2_MECH_DRIVER_NAME],
                              group='ml2')
        self.assertTrue(driver.is_loaded)

        cfg.CONF.set_override('mechanism_drivers',
                              ['ovs', 'logger'],
                              group='ml2')
        self.assertFalse(driver.is_loaded)

        cfg.CONF.set_override('core_plugin', 'some_plugin')
        self.assertFalse(driver.is_loaded)

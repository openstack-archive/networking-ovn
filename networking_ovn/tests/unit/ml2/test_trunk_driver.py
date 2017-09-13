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
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry

from networking_ovn.common.constants import OVN_ML2_MECH_DRIVER_NAME
from networking_ovn.ml2 import trunk_driver
from networking_ovn.tests.unit import fakes

from neutron.services.trunk import constants as trunk_consts
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

        self.get_trunk_object = mock.patch(
            "neutron.objects.trunk.Trunk.get_object").start()
        self.get_trunk_object.side_effect = lambda ctxt, id: \
            self.trunk_1 if id == 'trunk-1' else self.trunk_2

    def test_create_trunk(self):
        self.trunk_1.sub_ports = []

        with mock.patch.object(self.handler, '_set_binding_profile') as sbp:
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

        binding_prof_calls = [
            mock.call.set_binding_profile("sub_port_1",
                                          self.trunk_1.port_id,
                                          40),
            mock.call.set_binding_profile("sub_port_2",
                                          self.trunk_1.port_id,
                                          41)]
        sbp.assert_has_calls(binding_prof_calls, any_order=True)

    def test_delete_trunk(self):
        self.trunk_1.sub_ports = []

        with mock.patch.object(self.handler, '_set_binding_profile') as sbp:
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

        binding_prof_calls = [
            mock.call.set_binding_profile("sub_port_1", None),
            mock.call.set_binding_profile("sub_port_2", None)]
        sbp.assert_has_calls(binding_prof_calls, any_order=True)

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

    def _get_binding_profile_info(self, parent_name=None, tag=None):
        binding_profile = {}
        if parent_name and tag:
            binding_profile = {'parent_name': 'parent_port', 'tag': 40}
        return {'port': {'binding_profile': binding_profile}}

    def test__set_binding_profile(self):
        """Check that subport binding_profile is updated to the plugin."""
        self.handler._set_binding_profile('sub_port_1', 'parent_port', tag=40)
        self.handler._set_binding_profile('sub_port_1', None)

        calls = [mock.call.update_port(mock.ANY,
                                       self._get_binding_profile_info(
                                           'parent_port', 40)),
                 mock.call.update_port(mock.ANY,
                                       self._get_binding_profile_info(
                                           None, None))]
        self.plugin_driver._plugin.update_port.has_calls(calls, any_order=True)

    def _fake_trunk_event_payload(self):
        payload = mock.Mock()
        payload.current_trunk = mock.Mock()
        payload.current_trunk.port_id = 'current_trunk_port_id'
        payload.original_trunk = mock.Mock()
        payload.original_trunk.port_id = 'original_trunk_port_id'
        current_subport = mock.Mock()
        current_subport.segmentation_id = 40
        current_subport.trunk_id = 'current_trunk_port_id'
        current_subport.port_id = 'current_subport_port_id'
        original_subport = mock.Mock()
        original_subport.segmentation_id = 41
        original_subport.trunk_id = 'original_trunk_port_id'
        original_subport.port_id = 'original_subport_port_id'
        payload.current_trunk.sub_ports = [current_subport]
        payload.original_trunk.sub_ports = [original_subport]
        return payload

    def test_trunk_event_create(self):
        fake_payload = self._fake_trunk_event_payload()
        self.handler.trunk_event(
            mock.ANY, events.AFTER_CREATE, mock.ANY, fake_payload)
        self.plugin_driver._nb_ovn.set_lswitch_port.assert_called_once_with(
            fake_payload.current_trunk.sub_ports[0].port_id,
            parent_name=fake_payload.current_trunk.port_id,
            tag=fake_payload.current_trunk.sub_ports[0].segmentation_id)

    def test_trunk_event_delete(self):
        fake_payload = self._fake_trunk_event_payload()
        self.handler.trunk_event(
            mock.ANY, events.AFTER_DELETE, mock.ANY, fake_payload)
        self.plugin_driver._nb_ovn.set_lswitch_port.assert_called_once_with(
            fake_payload.original_trunk.sub_ports[0].port_id,
            parent_name=[],
            tag=[])

    def test_trunk_event_invalid(self):
        fake_payload = self._fake_trunk_event_payload()
        self.handler.trunk_event(
            mock.ANY, events.BEFORE_DELETE, mock.ANY, fake_payload)
        self.plugin_driver._nb_ovn.set_lswitch_port.assert_not_called()

    def _fake_subport_event_payload(self):
        payload = mock.Mock()
        payload.original_trunk = mock.Mock()
        payload.original_trunk.port_id = 'original_trunk_port_id'
        original_subport = mock.Mock()
        original_subport.segmentation_id = 41
        original_subport.trunk_id = 'original_trunk_port_id'
        original_subport.port_id = 'original_subport_port_id'
        payload.subports = [original_subport]
        return payload

    def test_subport_event_create(self):
        fake_payload = self._fake_subport_event_payload()
        self.handler.subport_event(
            mock.ANY, events.AFTER_CREATE, mock.ANY, fake_payload)
        self.plugin_driver._nb_ovn.set_lswitch_port.assert_called_once_with(
            fake_payload.subports[0].port_id,
            parent_name=fake_payload.original_trunk.port_id,
            tag=fake_payload.subports[0].segmentation_id)

    def test_subport_event_delete(self):
        fake_payload = self._fake_subport_event_payload()
        self.handler.subport_event(
            mock.ANY, events.AFTER_DELETE, mock.ANY, fake_payload)
        self.plugin_driver._nb_ovn.set_lswitch_port.assert_called_once_with(
            fake_payload.subports[0].port_id,
            parent_name=[],
            tag=[])

    def test_subport_event_invalid(self):
        fake_payload = self._fake_trunk_event_payload()
        self.handler.subport_event(
            mock.ANY, events.BEFORE_DELETE, mock.ANY, fake_payload)
        self.plugin_driver._nb_ovn.set_lswitch_port.assert_not_called()


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

    def test_register(self):
        driver = trunk_driver.OVNTrunkDriver.create(mock.Mock())
        with mock.patch.object(registry, 'subscribe') as mock_subscribe:
            driver.register(mock.ANY, mock.ANY, mock.Mock())
            calls = [mock.call.mock_subscribe(mock.ANY,
                                              trunk_consts.TRUNK,
                                              events.AFTER_CREATE),
                     mock.call.mock_subscribe(mock.ANY,
                                              trunk_consts.SUBPORTS,
                                              events.AFTER_CREATE),
                     mock.call.mock_subscribe(mock.ANY,
                                              trunk_consts.TRUNK,
                                              events.AFTER_DELETE),
                     mock.call.mock_subscribe(mock.ANY,
                                              trunk_consts.SUBPORTS,
                                              events.AFTER_DELETE)]
            mock_subscribe.assert_has_calls(calls, any_order=True)

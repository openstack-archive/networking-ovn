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

from oslo_config import cfg

from networking_ovn.common import config
from networking_ovn.common.constants import OVN_ML2_MECH_DRIVER_NAME

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.services.trunk import constants as trunk_consts
from neutron.services.trunk.drivers import base as trunk_base


SUPPORTED_SEGMENTATION_TYPES = (
    trunk_consts.VLAN,
)


class OVNTrunkHandler(object):
    def __init__(self, plugin_driver):
        self.plugin_driver = plugin_driver

    def _set_sub_ports(self, parent_port, subports):
        _nb_ovn = self.plugin_driver._nb_ovn
        with _nb_ovn.transaction(check_error=True) as txn:
            for port in subports:
                txn.add(_nb_ovn.set_lswitch_port(port.port_id,
                                                 parent_name=parent_port,
                                                 tag=port.segmentation_id))

    def _unset_sub_ports(self, subports):
        _nb_ovn = self.plugin_driver._nb_ovn
        with _nb_ovn.transaction(check_error=True) as txn:
            for port in subports:
                txn.add(_nb_ovn.set_lswitch_port(port.port_id,
                                                 parent_name=[],
                                                 tag=[]))

    def trunk_created(self, trunk):
        self._set_sub_ports(trunk.port_id, trunk.sub_ports)
        trunk.update(status=trunk_consts.ACTIVE_STATUS)

    def trunk_deleted(self, trunk):
        self._unset_sub_ports(trunk.sub_ports)

    def subports_added(self, trunk, subports):
        self._set_sub_ports(trunk.port_id, subports)
        trunk.update(status=trunk_consts.ACTIVE_STATUS)

    def subports_deleted(self, trunk, subports):
        self._unset_sub_ports(subports)
        trunk.update(status=trunk_consts.ACTIVE_STATUS)

    def trunk_event(self, resource, event, trunk_plugin, payload):
        if event == events.AFTER_CREATE:
            self.trunk_created(payload.current_trunk)
        elif event == events.AFTER_DELETE:
            self.trunk_deleted(payload.original_trunk)

    def subport_event(self, resource, event, trunk_plugin, payload):
        if event == events.AFTER_CREATE:
            self.subports_added(payload.original_trunk,
                                payload.subports)
        elif event == events.AFTER_DELETE:
            self.subports_deleted(payload.original_trunk,
                                  payload.subports)


class OVNTrunkDriver(trunk_base.DriverBase):
    @property
    def is_loaded(self):
        try:
            return OVN_ML2_MECH_DRIVER_NAME in cfg.CONF.ml2.mechanism_drivers
        except cfg.NoSuchOptError:
            return False

    def register(self, resource, event, trigger, **kwargs):
        super(OVNTrunkDriver, self).register(
            resource, event, trigger, **kwargs)
        self._handler = OVNTrunkHandler(self.plugin_driver)
        for event in (events.AFTER_CREATE, events.AFTER_DELETE):
            registry.subscribe(self._handler.trunk_event,
                               trunk_consts.TRUNK,
                               event)
            registry.subscribe(self._handler.subport_event,
                               trunk_consts.SUBPORTS,
                               event)

    @classmethod
    def create(cls, plugin_driver):
        cls.plugin_driver = plugin_driver
        return cls(OVN_ML2_MECH_DRIVER_NAME,
                   (config.get_ovn_vif_type(),),
                   SUPPORTED_SEGMENTATION_TYPES,
                   None,
                   can_trunk_bound_port=True)

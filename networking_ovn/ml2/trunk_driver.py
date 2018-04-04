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

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import context as n_context
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_db import exception as os_db_exc
from oslo_log import log

from networking_ovn.common.constants import OVN_ML2_MECH_DRIVER_NAME

from neutron.services.trunk import constants as trunk_consts
from neutron.services.trunk.drivers import base as trunk_base
from neutron_lib.api.definitions import portbindings


SUPPORTED_INTERFACES = (
    portbindings.VIF_TYPE_OVS,
    portbindings.VIF_TYPE_VHOST_USER,
)

SUPPORTED_SEGMENTATION_TYPES = (
    trunk_consts.VLAN,
)

LOG = log.getLogger(__name__)


class OVNTrunkHandler(object):
    def __init__(self, plugin_driver):
        self.plugin_driver = plugin_driver

    def _set_binding_profile(self, port_id, parent_port, tag=None):
        context = n_context.get_admin_context()
        binding_profile = {}
        if parent_port and tag:
            binding_profile = {'parent_name': parent_port, 'tag': tag}
        port = {'port': {'binding:profile': binding_profile}}
        if not tag:
            port['port']['binding:host_id'] = None
        try:
            self.plugin_driver._plugin.update_port(context, port_id, port)
        except (os_db_exc.DBReferenceError, n_exc.PortNotFound):
            LOG.debug("Port not found trying to set binding_profile: %s",
                      port_id)

    def _set_sub_ports(self, parent_port, subports):
        for port in subports:
            self._set_binding_profile(port.port_id, parent_port,
                                      tag=port.segmentation_id)

    def _unset_sub_ports(self, subports):
        for port in subports:
            self._set_binding_profile(port.port_id, None)

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

    @registry.receives(trunk_consts.TRUNK_PLUGIN, [events.AFTER_INIT])
    def register(self, resource, event, trigger, payload=None):
        super(OVNTrunkDriver, self).register(
            resource, event, trigger, payload=payload)
        self._handler = OVNTrunkHandler(self.plugin_driver)
        for trunk_event in (events.AFTER_CREATE, events.AFTER_DELETE):
            registry.subscribe(self._handler.trunk_event,
                               trunk_consts.TRUNK,
                               trunk_event)
            registry.subscribe(self._handler.subport_event,
                               trunk_consts.SUBPORTS,
                               trunk_event)

    @classmethod
    def create(cls, plugin_driver):
        cls.plugin_driver = plugin_driver
        return cls(OVN_ML2_MECH_DRIVER_NAME,
                   SUPPORTED_INTERFACES,
                   SUPPORTED_SEGMENTATION_TYPES,
                   None,
                   can_trunk_bound_port=True)

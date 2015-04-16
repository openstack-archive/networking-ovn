# Copyright 2015 Hewlett-Packard Development Company, L.P.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
#

from neutron.common import constants as q_const
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import l3_dvr_db
from neutron.db import l3_gwmode_db
from neutron.plugins.common import constants


class OVNL3RouterPlugin(db_base_plugin_v2.common_db_mixin.CommonDbMixin,
                        extraroute_db.ExtraRoute_db_mixin,
                        l3_dvr_db.L3_NAT_with_dvr_db_mixin,
                        l3_gwmode_db.L3_NAT_db_mixin):
    """Implementation of the OVN L3 Router Service Plugin.

    This class implements a L3 service plugin that provides
    router and floatingip resources and manages associated
    request/response.
    """
    supported_extension_aliases = ["dvr", "router", "ext-gw-mode",
                                   "extraroute"]

    def __init__(self):
        pass

    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("L3 Router Service Plugin for basic L3 forwarding"
                " using OVN")

    def filter_update_router_attributes(self, router):
        pass

    def create_router(self, context, router):
        pass

    def update_router(self, context, id, router):
        pass

    def delete_router(self, context, id):
        pass

    def create_floatingip(self, context, floatingip,
                          initial_status=q_const.FLOATINGIP_STATUS_ACTIVE):
        pass

    def update_floatingip(self, context, id, floatingip):
        pass

    def delete_floatingip(self, context, id):
        pass

    def add_router_interface(self, context, router_id, interface_info):
        pass

    def remove_router_interface(self, context, router_id, interface_info):
        pass

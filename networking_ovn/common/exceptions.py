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

from networking_ovn._i18n import _
from neutron_lib import exceptions


class L3AdminNetError(exceptions.NeutronException):
    message = _('L3 admin network validation failed. %(error_message)s.')


class L3AdminNetSubnetError(exceptions.NeutronException):
    message = _('L3 admin subnet validation failed. %(error_message)s.')


class L3AdminNetPortsError(exceptions.NeutronException):
    message = _('L3 admin network ports validation failed. %(error_message)s.')


class L3RouterPluginStaticRouteError(exceptions.NeutronException):
    message = _('Unable to find router connected to nexthop %(nexthop)s to '
                'add static route in router %(router)s.')

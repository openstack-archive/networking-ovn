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

# NOTE(russellb) This remains in its own file (vs constants.py) because we want
# to be able to easily import it and export the info without any dependencies
# on external imports.

# NOTE(russellb) If you update this list, please also update
# doc/source/features.rst and the current release note.
SUPPORTED_API_EXTENSIONS = [
    'address-scope',
    'agent',
    'availability_zone',
    'binding',
    'dhcp_agent_scheduler',
    'external-net',
    'extra_dhcp_opt',
    'extraroute',
    'l3-ha',
    'l3_agent_scheduler',
    'net-mtu',
    'network_availability_zone',
    'provider',
    'quotas',
    'router',
    'security-group',
    'subnet_allocation',
    'port-security',
    'allowed-address-pairs',
]

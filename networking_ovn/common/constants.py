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

from neutron.extensions import portbindings
import six

OVN_NETWORK_NAME_EXT_ID_KEY = 'neutron:network_name'
OVN_PORT_NAME_EXT_ID_KEY = 'neutron:port_name'
OVN_ROUTER_NAME_EXT_ID_KEY = 'neutron:router_name'
OVN_PHYSNET_EXT_ID_KEY = 'neutron:provnet-physical-network'
OVN_NETTYPE_EXT_ID_KEY = 'neutron:provnet-network-type'
OVN_SEGID_EXT_ID_KEY = 'neutron:provnet-segmentation-id'
OVN_PORT_BINDING_PROFILE = portbindings.PROFILE
OVN_PORT_BINDING_PROFILE_PARAMS = [{'parent_name': six.string_types,
                                    'tag': six.integer_types},
                                   {'vtep_physical_switch': six.string_types,
                                    'vtep_logical_switch': six.string_types}]

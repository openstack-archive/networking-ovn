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

from networking_ovn._i18n import _
from neutron.extensions import portbindings


ovn_opts = [
    cfg.StrOpt('ovsdb_connection', deprecated_for_removal=True,
               default='tcp:127.0.0.1:6640',
               help=_('The connection string for the native OVSDB backend.'
                      'This option is going to be deprecated and be replaced'
                      'by option ovn_nb_connection.')),
    cfg.StrOpt('ovn_nb_connection',
               deprecated_name='ovsdb_connection',
               default='tcp:127.0.0.1:6641',
               help=_('The connection string for the OVN_Northbound OVSDB')),
    cfg.StrOpt('ovn_sb_connection',
               default='tcp:127.0.0.1:6642',
               help=_('The connection string for the OVN_Southbound OVSDB')),
    cfg.IntOpt('ovsdb_connection_timeout',
               default=60,
               help=_('Timeout in seconds for the OVSDB '
                      'connection transaction')),
    cfg.StrOpt('neutron_sync_mode',
               default='log',
               choices=('off', 'log', 'repair'),
               help=_('The synchronization mode of OVN_Northbound OVSDB '
                      'with Neutron DB.\n'
                      'off - synchronization is off \n'
                      'log - during neutron-server startup, '
                      'check to see if OVN is in sync with '
                      'the Neutron database. '
                      ' Log warnings for any inconsistencies found so'
                      ' that an admin can investigate \n'
                      'repair - during neutron-server startup, automatically'
                      ' create resources found in Neutron but not in OVN.'
                      ' Also remove resources from OVN'
                      ' that are no longer in Neutron.')),
    cfg.BoolOpt('ovn_l3_mode',
                default=True,
                help=_('Whether to use OVN native L3 support. Do not change '
                       'the value for existing deployments that contain '
                       'routers.')),
    cfg.StrOpt("ovn_l3_scheduler",
               default='leastloaded',
               choices=('leastloaded', 'chance'),
               help=_('The OVN L3 Scheduler type used to schedule router '
                      'gateway ports on hypervisors/chassis. \n'
                      'leastloaded - chassis with fewest gateway ports '
                      'selected \n'
                      'chance - chassis randomly selected')),
    cfg.StrOpt("vif_type",
               default=portbindings.VIF_TYPE_OVS,
               help=_("Type of VIF to be used for ports valid values are "
                      "(%(ovs)s, %(dpdk)s) default %(ovs)s") % {
                          "ovs": portbindings.VIF_TYPE_OVS,
                          "dpdk": portbindings.VIF_TYPE_VHOST_USER},
               choices=[portbindings.VIF_TYPE_OVS,
                        portbindings.VIF_TYPE_VHOST_USER]),
    cfg.StrOpt("vhost_sock_dir",
               default="/var/run/openvswitch",
               help=_("The directory in which vhost virtio socket "
                      "is created by all the vswitch daemons")),
    cfg.BoolOpt('ovn_native_dhcp',
                default=True,
                help=_('Whether to use OVN native dhcp support')),
    cfg.IntOpt('dhcp_default_lease_time',
               default=(12 * 60 * 60),
               help=_('Default least time (in seconds ) to use when '
                      'ovn_native_dhcp is enabled.')),
]

cfg.CONF.register_opts(ovn_opts, group='ovn')


def list_opts():
    return [
        ('ovn', ovn_opts),
    ]


def get_ovn_nb_connection():
    return cfg.CONF.ovn.ovn_nb_connection


def get_ovn_sb_connection():
    return cfg.CONF.ovn.ovn_sb_connection


def get_ovn_ovsdb_timeout():
    return cfg.CONF.ovn.ovsdb_connection_timeout


def get_ovn_neutron_sync_mode():
    return cfg.CONF.ovn.neutron_sync_mode


def is_ovn_l3():
    return cfg.CONF.ovn.ovn_l3_mode


def get_ovn_l3_scheduler():
    return cfg.CONF.ovn.ovn_l3_scheduler


def get_ovn_vif_type():
    return cfg.CONF.ovn.vif_type


def get_ovn_vhost_sock_dir():
    return cfg.CONF.ovn.vhost_sock_dir


def is_ovn_dhcp():
    return cfg.CONF.ovn.ovn_native_dhcp


def get_ovn_dhcp_default_lease_time():
    return cfg.CONF.ovn.dhcp_default_lease_time

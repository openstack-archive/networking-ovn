# Copyright 2016 Red Hat, Inc.
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

from networking_ovn.common import constants as ovn_const
from networking_ovn.tests.functional import base
from neutron.extensions import external_net
from neutron.extensions import l3


class TestRouter(base.TestOVNFunctionalBase):
    def setUp(self):
        super(TestRouter, self).setUp()
        self.add_fake_chassis('ovs-host1')
        self.add_fake_chassis('ovs-host2')

    def _create_router(self, name='router', admin_state_up=True):
        return self.l3_plugin.create_router(
            self.context,
            {'router':
             {'name': name,
              'admin_state_up': admin_state_up,
              'tenant_id': self._tenant_id}})

    def test_gateway_chassis_on_router_gateway_port(self):
        router = self._create_router()
        kwargs = {'arg_list': (external_net.EXTERNAL,),
                  external_net.EXTERNAL: True}
        with self.subnet(), \
                self.network(**kwargs) as ext_net, \
                self.subnet(network=ext_net, cidr='20.0.0.0/24'):
            gw_info = {'network_id': ext_net['network']['id']}
            self.l3_plugin.update_router(
                self.context, router['id'],
                {'router': {l3.EXTERNAL_GW_INFO: gw_info}})
            expected = [row.name for row in
                        self.monitor_sb_db_idl.tables['Chassis'].rows.values()]
            for row in self.monitor_nb_db_idl.tables[
                    'Logical_Router_Port'].rows.values():
                if self.monitor_nb_db_idl.tables.get('Gateway_Chassis'):
                    chassis = [gwc.chassis_name for gwc in row.gateway_chassis]
                    self.assertItemsEqual(expected, chassis)
                else:
                    rc = row.options.get(ovn_const.OVN_GATEWAY_CHASSIS_KEY)
                    self.assertIn(rc, expected)

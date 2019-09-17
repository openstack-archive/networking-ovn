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

import uuid

from oslo_utils import uuidutils
from ovsdbapp import event as ovsdb_event
from ovsdbapp.tests.functional import base
from ovsdbapp.tests.functional.schema.ovn_southbound import test_impl_idl as \
    test_sb
from ovsdbapp.tests import utils

from networking_ovn.ovsdb import impl_idl_ovn as impl


class WaitForPortBindingEvent(test_sb.WaitForPortBindingEvent):
    def run(self, event, row, old):
        self.row = row
        super(WaitForPortBindingEvent, self).run(event, row, old)


class TestSbApi(base.FunctionalTestCase):
    schemas = ['OVN_Southbound', 'OVN_Northbound']

    def setUp(self):
        super(TestSbApi, self).setUp()
        self.data = {
            'chassis': [
                {'external_ids': {'ovn-bridge-mappings':
                                  'public:br-ex,private:br-0'}},
                {'external_ids': {'ovn-bridge-mappings':
                                  'public:br-ex,public2:br-ex'}},
                {'external_ids': {'ovn-bridge-mappings':
                                  'public:br-ex'}},
            ]
        }
        self.api = impl.OvsdbSbOvnIdl(self.connection['OVN_Southbound'])
        self.nbapi = impl.OvsdbNbOvnIdl(self.connection['OVN_Northbound'])
        self.load_test_data()
        self.handler = ovsdb_event.RowEventHandler()
        self.api.idl.notify = self.handler.notify

    def load_test_data(self):
        with self.api.transaction(check_error=True) as txn:
            for chassis in self.data['chassis']:
                chassis['name'] = utils.get_rand_device_name('chassis')
                chassis['hostname'] = '%s.localdomain.com' % chassis['name']
                txn.add(self.api.chassis_add(
                    chassis['name'], ['geneve'], chassis['hostname'],
                    hostname=chassis['hostname'],
                    external_ids=chassis['external_ids']))

    def test_get_chassis_hostname_and_physnets(self):
        mapping = self.api.get_chassis_hostname_and_physnets()
        self.assertTrue(len(self.data['chassis']) <= len(mapping))
        self.assertTrue(set(mapping.keys()) >=
                        {c['hostname'] for c in self.data['chassis']})

    def test_get_all_chassis(self):
        chassis_list = set(self.api.get_all_chassis())
        our_chassis = {c['name'] for c in self.data['chassis']}
        self.assertTrue(our_chassis <= chassis_list)

    def test_get_chassis_data_for_ml2_bind_port(self):
        host = self.data['chassis'][0]['hostname']
        dp, iface, phys = self.api.get_chassis_data_for_ml2_bind_port(host)
        self.assertEqual(dp, '')
        self.assertEqual(iface, '')
        self.assertItemsEqual(phys, ['private', 'public'])

    def test_chassis_exists(self):
        self.assertTrue(self.api.chassis_exists(
            self.data['chassis'][0]['hostname']))
        self.assertFalse(self.api.chassis_exists("nochassishere"))

    def test_get_chassis_and_physnets(self):
        mapping = self.api.get_chassis_and_physnets()
        self.assertTrue(len(self.data['chassis']) <= len(mapping))
        self.assertTrue(set(mapping.keys()) >=
                        {c['name'] for c in self.data['chassis']})

    def _add_switch_port(self, chassis_name, type='localport'):
        sname, pname = (utils.get_rand_device_name(prefix=p)
                        for p in ('switch', 'port'))
        chassis = self.api.lookup('Chassis', chassis_name)
        row_event = WaitForPortBindingEvent(pname)
        self.handler.watch_event(row_event)
        with self.nbapi.transaction(check_error=True) as txn:
            switch = txn.add(self.nbapi.ls_add(sname))
            port = txn.add(self.nbapi.lsp_add(sname, pname, type=type))
        row_event.wait()
        return chassis, switch.result, port.result, row_event.row

    def test_get_metadata_port_network(self):
        chassis, switch, port, binding = self._add_switch_port(
            self.data['chassis'][0]['name'])
        result = self.api.get_metadata_port_network(str(binding.datapath.uuid))
        self.assertEqual(binding, result)
        self.assertEqual(binding.datapath.external_ids['logical-switch'],
                         str(switch.uuid))

    def test_get_metadata_port_network_missing(self):
        val = str(uuid.uuid4())
        self.assertIsNone(self.api.get_metadata_port_network(val))

    def test_set_get_chassis_metadata_networks(self):
        name = self.data['chassis'][0]['name']
        nets = [str(uuid.uuid4()) for _ in range(3)]
        self.api.set_chassis_metadata_networks(name, nets).execute(
            check_error=True)
        self.assertEqual(nets, self.api.get_chassis_metadata_networks(name))

    def test_get_network_port_bindings_by_ip(self):
        chassis, switch, port, binding = self._add_switch_port(
            self.data['chassis'][0]['name'])
        mac = 'de:ad:be:ef:4d:ad'
        ipaddr = '192.0.2.1'
        self.nbapi.lsp_set_addresses(
            port.name, ['%s %s' % (mac, ipaddr)]).execute(check_error=True)
        self.api.lsp_bind(port.name, chassis.name).execute(check_error=True)
        result = self.api.get_network_port_bindings_by_ip(
            str(binding.datapath.uuid), ipaddr)
        self.assertIn(binding, result)

    def test_get_ports_on_chassis(self):
        chassis, switch, port, binding = self._add_switch_port(
            self.data['chassis'][0]['name'])
        self.api.lsp_bind(port.name, chassis.name).execute(check_error=True)
        self.assertEqual([binding],
                         self.api.get_ports_on_chassis(chassis.name))

    def test_get_logical_port_chassis_and_datapath(self):
        chassis, switch, port, binding = self._add_switch_port(
            self.data['chassis'][0]['name'])
        self.api.lsp_bind(port.name, chassis.name).execute(check_error=True)
        self.assertEqual(
            (chassis.name, str(binding.datapath.uuid)),
            self.api.get_logical_port_chassis_and_datapath(port.name))


class OvnNorthboundTest(base.FunctionalTestCase):
    schemas = ['OVN_Northbound']

    def setUp(self):
        super(OvnNorthboundTest, self).setUp()
        self.api = impl.OvsdbNbOvnIdl(self.connection)


class TestPortGroup(OvnNorthboundTest):

    def setUp(self):
        super(TestPortGroup, self).setUp()
        with self.api.transaction(check_error=True) as txn:
            sname = utils.get_rand_device_name('switch')
            switch = txn.add(self.api.ls_add(sname))
        self.switch = switch.result
        self.pg_name = 'testpg-%s' % uuidutils.generate_uuid()

    def test_port_group(self):
        # Assert the Port Group was added
        self.api.pg_add(self.pg_name).execute(check_error=True)
        row = self.api.db_find(
            'Port_Group',
            ('name', '=', self.pg_name)).execute(check_error=True)
        self.assertIsNotNone(row)
        self.assertEqual(self.pg_name, row[0]['name'])
        self.assertEqual([], row[0]['ports'])
        self.assertEqual([], row[0]['acls'])

        # Assert the Port Group was deleted
        self.api.pg_del(self.pg_name).execute(check_error=True)
        row = self.api.db_find(
            'Port_Group',
            ('name', '=', self.pg_name)).execute(check_error=True)
        self.assertEqual([], row)

    def test_port_group_ports(self):
        lsp_add_cmd = self.api.lsp_add(self.switch.uuid, 'testport')
        with self.api.transaction(check_error=True) as txn:
            txn.add(lsp_add_cmd)
            txn.add(self.api.pg_add(self.pg_name))

        port_uuid = lsp_add_cmd.result.uuid

        # Lets add the port using the UUID instead of a `Command` to
        # exercise the API
        self.api.pg_add_ports(self.pg_name, port_uuid).execute(
            check_error=True)
        row = self.api.db_find(
            'Port_Group',
            ('name', '=', self.pg_name)).execute(check_error=True)
        self.assertIsNotNone(row)
        self.assertEqual(self.pg_name, row[0]['name'])
        # Assert the port was added from the Port Group
        self.assertEqual([port_uuid], row[0]['ports'])

        # Delete the Port from the Port Group
        with self.api.transaction(check_error=True) as txn:
            txn.add(self.api.pg_del_ports(self.pg_name, port_uuid))

        row = self.api.db_find(
            'Port_Group',
            ('name', '=', self.pg_name)).execute(check_error=True)
        self.assertIsNotNone(row)
        self.assertEqual(self.pg_name, row[0]['name'])
        # Assert the port was removed from the Port Group
        self.assertEqual([], row[0]['ports'])

    def test_pg_del_ports_if_exists(self):
        self.api.pg_add(self.pg_name).execute(check_error=True)
        non_existent_res = uuidutils.generate_uuid()

        # Assert that if if_exists is False (default) it will raise an error
        self.assertRaises(RuntimeError, self.api.pg_del_ports(self.pg_name,
                          non_existent_res).execute, True)

        # Assert that if if_exists is True it won't raise an error
        self.api.pg_del_ports(self.pg_name, non_existent_res,
                              if_exists=True).execute(check_error=True)


class TestAclOps(OvnNorthboundTest):
    def setUp(self):
        super(TestAclOps, self).setUp()
        with self.api.transaction(check_error=True) as txn:
            sname = utils.get_rand_device_name('switch')
            pgname = utils.get_rand_device_name('switch')
            switch = txn.add(self.api.ls_add(sname))
            pg = txn.add(self.api.pg_add(pgname))
        self.switch = switch.result
        self.port_group = pg.result

    def _acl_add(self, entity, *args, **kwargs):
        self.assertIn(entity, ['lswitch', 'port_group'])
        if entity == 'lswitch':
            cmd = self.api.acl_add(self.switch.uuid, *args, **kwargs)
            resource = self.switch
        else:
            cmd = self.api.pg_acl_add(self.port_group.uuid, *args, **kwargs)
            resource = self.port_group

        aclrow = cmd.execute(check_error=True)
        self.assertIn(aclrow._row, resource.acls)
        self.assertEqual(cmd.direction, aclrow.direction)
        self.assertEqual(cmd.priority, aclrow.priority)
        self.assertEqual(cmd.match, aclrow.match)
        self.assertEqual(cmd.action, aclrow.action)
        return aclrow

    def test_acl_add(self):
        self._acl_add('lswitch', 'from-lport', 0,
                      'output == "fake_port" && ip', 'drop')

    def test_acl_add_exists(self):
        args = ('lswitch', 'from-lport', 0, 'output == "fake_port" && ip',
                'drop')
        self._acl_add(*args)
        self.assertRaises(RuntimeError, self._acl_add, *args)

    def test_acl_add_may_exist(self):
        args = ('from-lport', 0, 'output == "fake_port" && ip', 'drop')
        row = self._acl_add('lswitch', *args)
        row2 = self._acl_add('lswitch', *args, may_exist=True)
        self.assertEqual(row, row2)

    def test_acl_add_extids(self):
        external_ids = {'mykey': 'myvalue', 'yourkey': 'yourvalue'}
        acl = self._acl_add('lswitch',
                            'from-lport', 0, 'output == "fake_port" && ip',
                            'drop', **external_ids)
        self.assertEqual(external_ids, acl.external_ids)

    def test_acl_del_all(self):
        r1 = self._acl_add('lswitch', 'from-lport', 0, 'output == "fake_port"',
                           'drop')
        self.api.acl_del(self.switch.uuid).execute(check_error=True)
        self.assertNotIn(r1.uuid, self.api.tables['ACL'].rows)
        self.assertEqual([], self.switch.acls)

    def test_acl_del_direction(self):
        r1 = self._acl_add('lswitch', 'from-lport', 0,
                           'output == "fake_port"', 'drop')
        r2 = self._acl_add('lswitch', 'to-lport', 0,
                           'output == "fake_port"', 'allow')
        self.api.acl_del(self.switch.uuid, 'from-lport').execute(
            check_error=True)
        self.assertNotIn(r1, self.switch.acls)
        self.assertIn(r2, self.switch.acls)

    def test_acl_del_direction_priority_match(self):
        r1 = self._acl_add('lswitch', 'from-lport', 0,
                           'output == "fake_port"', 'drop')
        r2 = self._acl_add('lswitch', 'from-lport', 1,
                           'output == "fake_port"', 'allow')
        cmd = self.api.acl_del(self.switch.uuid,
                               'from-lport', 0, 'output == "fake_port"')
        cmd.execute(check_error=True)
        self.assertNotIn(r1, self.switch.acls)
        self.assertIn(r2, self.switch.acls)

    def test_acl_del_priority_without_direction(self):
        self.assertRaises(TypeError, self.api.acl_del, self.switch.uuid,
                          priority=0)

    def test_acl_list(self):
        r1 = self._acl_add('lswitch', 'from-lport', 0,
                           'output == "fake_port"', 'drop')
        r2 = self._acl_add('lswitch', 'from-lport', 1,
                           'output == "fake_port2"', 'allow')
        acls = self.api.acl_list(self.switch.uuid).execute(check_error=True)
        self.assertIn(r1, acls)
        self.assertIn(r2, acls)

    def test_pg_acl_add(self):
        self._acl_add('port_group', 'from-lport', 0,
                      'output == "fake_port" && ip', 'drop')

    def test_pg_acl_del_all(self):
        r1 = self._acl_add('port_group', 'from-lport', 0,
                           'output == "fake_port"', 'drop')
        self.api.pg_acl_del(self.port_group.uuid).execute(check_error=True)
        self.assertNotIn(r1.uuid, self.api.tables['ACL'].rows)
        self.assertEqual([], self.port_group.acls)

    def test_pg_acl_list(self):
        r1 = self._acl_add('port_group', 'from-lport', 0,
                           'output == "fake_port"', 'drop')
        r2 = self._acl_add('port_group', 'from-lport', 1,
                           'output == "fake_port2"', 'allow')
        acls = self.api.pg_acl_list(self.port_group.uuid).execute(
            check_error=True)
        self.assertIn(r1, acls)
        self.assertIn(r2, acls)

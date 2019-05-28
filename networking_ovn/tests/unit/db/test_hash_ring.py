# Copyright 2019 Red Hat, Inc.
# All Rights Reserved.
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

import datetime

import mock
from neutron_lib.db import api as db_api
from oslo_utils import timeutils
from sqlalchemy.orm import exc

from networking_ovn.db import hash_ring as db_hash_ring
from networking_ovn.db import models
from networking_ovn.tests.unit.db import base as db_base


class TestHashRing(db_base.DBTestCase):

    def _get_node_row(self, node_uuid):
        try:
            session = db_api.get_reader_session()
            with session.begin():
                return session.query(models.OVNHashRing).filter_by(
                    node_uuid=node_uuid).one()
        except exc.NoResultFound:
            pass

    def _add_nodes_and_assert_exists(self, count=1):
        nodes = []
        for i in range(count):
            node_uuid = db_hash_ring.add_node()
            self.assertIsNotNone(self._get_node_row(node_uuid))
            nodes.append(node_uuid)
        return nodes

    def test_add_node(self):
        self._add_nodes_and_assert_exists()

    def test_remove_nodes_from_host(self):
        nodes = self._add_nodes_and_assert_exists(count=3)

        # Add another node from a different host
        with mock.patch.object(db_hash_ring, 'CONF') as mock_conf:
            mock_conf.host = 'another-host-52359446-c366'
            another_host_node = self._add_nodes_and_assert_exists()[0]

        db_hash_ring.remove_nodes_from_host()
        # Assert that all nodes from that host have been removed
        for n in nodes:
            self.assertIsNone(self._get_node_row(n))

        # Assert that the node from another host wasn't removed
        self.assertIsNotNone(self._get_node_row(another_host_node))

    def test_touch_nodes_from_host(self):
        nodes = self._add_nodes_and_assert_exists(count=3)

        # Add another node from a different host
        with mock.patch.object(db_hash_ring, 'CONF') as mock_conf:
            mock_conf.host = 'another-host-52359446-c366'
            another_host_node = self._add_nodes_and_assert_exists()[0]

        # Assert that updated_at isn't updated yet
        for node in nodes:
            node_db = self._get_node_row(node)
            self.assertEqual(node_db.created_at, node_db.updated_at)

        # Assert the same for the node from another host
        node_db = self._get_node_row(another_host_node)
        self.assertEqual(node_db.created_at, node_db.updated_at)

        # Touch the nodes from our host
        db_hash_ring.touch_nodes_from_host()

        # Assert that updated_at is now updated
        for node in nodes:
            node_db = self._get_node_row(node)
            self.assertGreater(node_db.updated_at, node_db.created_at)

        # Assert that the node from another host hasn't been touched
        # (updated_at is not updated)
        node_db = self._get_node_row(another_host_node)
        self.assertEqual(node_db.created_at, node_db.updated_at)

    def test_active_nodes(self):
        self._add_nodes_and_assert_exists(count=3)

        # Add another node from a different host
        with mock.patch.object(db_hash_ring, 'CONF') as mock_conf:
            mock_conf.host = 'another-host-52359446-c366'
            another_host_node = self._add_nodes_and_assert_exists()[0]

        # Assert all nodes are active (within 60 seconds)
        self.assertEqual(4, len(db_hash_ring.get_active_nodes(interval=60)))

        # Substract 60 seconds from utcnow() and touch the nodes from
        # our host
        fake_utcnow = timeutils.utcnow() - datetime.timedelta(seconds=60)
        with mock.patch.object(timeutils, 'utcnow') as mock_utcnow:
            mock_utcnow.return_value = fake_utcnow
            db_hash_ring.touch_nodes_from_host()

        # Now assert that all nodes from our host are seeing as offline.
        # Only the node from another host should be active
        active_nodes = db_hash_ring.get_active_nodes(interval=60)
        self.assertEqual(1, len(active_nodes))
        self.assertEqual(another_host_node, active_nodes[0].node_uuid)

    def test_active_nodes_from_host(self):
        self._add_nodes_and_assert_exists(count=3)

        # Add another node from a different host
        another_host_id = 'another-host-52359446-c366'
        with mock.patch.object(db_hash_ring, 'CONF') as mock_conf:
            mock_conf.host = another_host_id
            self._add_nodes_and_assert_exists()

        # Assert only the 3 nodes from this host is returned
        active_nodes = db_hash_ring.get_active_nodes(interval=60,
                                                     from_host=True)
        self.assertEqual(3, len(active_nodes))
        self.assertNotIn(another_host_id, active_nodes)

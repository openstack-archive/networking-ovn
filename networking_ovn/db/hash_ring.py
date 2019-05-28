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

from neutron_lib.db import api as db_api
from oslo_config import cfg
from oslo_utils import timeutils
from oslo_utils import uuidutils

from networking_ovn.db import models

CONF = cfg.CONF


def add_node(node_uuid=None):
    if node_uuid is None:
        node_uuid = uuidutils.generate_uuid()

    session = db_api.get_writer_session()
    with session.begin():
        row = models.OVNHashRing(node_uuid=node_uuid, hostname=CONF.host)
        session.add(row)
    return node_uuid


def remove_nodes_from_host():
    session = db_api.get_writer_session()
    with session.begin():
        session.query(models.OVNHashRing).filter_by(
            hostname=CONF.host).delete()


def touch_nodes_from_host():
    session = db_api.get_writer_session()
    with session.begin():
        session.query(models.OVNHashRing).filter_by(
            hostname=CONF.host).update({'updated_at': timeutils.utcnow()})


def get_active_nodes(interval, from_host=False):
    session = db_api.get_reader_session()
    limit = timeutils.utcnow() - datetime.timedelta(seconds=interval)
    with session.begin():
        query = session.query(models.OVNHashRing).filter(
            models.OVNHashRing.updated_at >= limit)
        if from_host:
            query = query.filter_by(hostname=CONF.host)
        return query.all()

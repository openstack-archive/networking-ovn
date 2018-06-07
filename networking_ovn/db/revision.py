# Copyright 2017 Red Hat, Inc.
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

from neutron.db import standard_attr
from neutron_lib.db import api as db_api
from oslo_db import api as oslo_db_api
from oslo_log import log
from sqlalchemy.orm import exc

from networking_ovn.common import constants as ovn_const
from networking_ovn.common import exceptions as ovn_exc
from networking_ovn.common import utils
from networking_ovn.db import models

LOG = log.getLogger(__name__)

STD_ATTR_MAP = standard_attr.get_standard_attr_resource_model_map()

# 1:2 mapping for OVN, neutron router ports are simple ports, but
# for OVN we handle LSP & LRP objects
if STD_ATTR_MAP:
    STD_ATTR_MAP[ovn_const.TYPE_ROUTER_PORTS] = \
        STD_ATTR_MAP[ovn_const.TYPE_PORTS]

_wrap_db_retry = oslo_db_api.wrap_db_retry(
    max_retries=ovn_const.DB_MAX_RETRIES,
    retry_interval=ovn_const.DB_INITIAL_RETRY_INTERVAL,
    max_retry_interval=ovn_const.DB_MAX_RETRY_INTERVAL,
    inc_retry_interval=True, retry_on_deadlock=True)


def _get_standard_attr_id(session, resource_uuid, resource_type):
    try:
        row = session.query(STD_ATTR_MAP[resource_type]).filter_by(
            id=resource_uuid).one()
        return row.standard_attr_id
    except exc.NoResultFound:
        raise ovn_exc.StandardAttributeIDNotFound(
            resource_uuid=resource_uuid)


@_wrap_db_retry
def create_initial_revision(resource_uuid, resource_type, session,
                            revision_number=ovn_const.INITIAL_REV_NUM):
    LOG.debug('create_initial_revision uuid=%s, type=%s, rev=%s',
              resource_uuid, resource_type, revision_number)
    with session.begin(subtransactions=True):
        std_attr_id = _get_standard_attr_id(
            session, resource_uuid, resource_type)
        row = models.OVNRevisionNumbers(
            resource_uuid=resource_uuid, resource_type=resource_type,
            standard_attr_id=std_attr_id, revision_number=revision_number)
        session.add(row)


@_wrap_db_retry
def delete_revision(resource_id, resource_type):
    LOG.debug('delete_revision(%s)', resource_id)
    session = db_api.get_writer_session()
    with session.begin():
        row = session.query(models.OVNRevisionNumbers).filter_by(
            resource_uuid=resource_id,
            resource_type=resource_type).one_or_none()
        if row:
            session.delete(row)


def _ensure_revision_row_exist(session, resource, resource_type):
    """Ensure the revision row exists.

    Ensure the revision row exist before we try to bump its revision
    number. This method is part of the migration plan to deal with
    resources that have been created prior to the database sync work
    getting merged.
    """
    # TODO(lucasagomes): As the docstring says, this method was created to
    # deal with objects that already existed before the sync work. I believe
    # that we can remove this method after few development cycles. Or,
    # if we decide to make a migration script as well.
    with session.begin(subtransactions=True):
        try:
            session.query(models.OVNRevisionNumbers).filter_by(
                resource_uuid=resource['id'],
                resource_type=resource_type).one()
        except exc.NoResultFound:
            LOG.warning(
                'No revision row found for %(res_uuid)s (type: '
                '%(res_type)s) when bumping the revision number. '
                'Creating one.', {'res_uuid': resource['id'],
                                  'res_type': resource_type})
            create_initial_revision(resource['id'], resource_type, session)


@_wrap_db_retry
def bump_revision(resource, resource_type):
    session = db_api.get_writer_session()
    revision_number = utils.get_revision_number(resource, resource_type)
    with session.begin():
        _ensure_revision_row_exist(session, resource, resource_type)
        std_attr_id = _get_standard_attr_id(
            session, resource['id'], resource_type)
        row = session.merge(models.OVNRevisionNumbers(
            standard_attr_id=std_attr_id, resource_uuid=resource['id'],
            resource_type=resource_type))
        if revision_number < row.revision_number:
            LOG.debug(
                'Skip bumping the revision number for %(res_uuid)s (type: '
                '%(res_type)s) to %(rev_num)d. A higher version is already '
                'registered in the database (%(new_rev)d)',
                {'res_type': resource_type, 'res_uuid': resource['id'],
                 'rev_num': revision_number, 'new_rev': row.revision_number})
            return
        row.revision_number = revision_number
        session.merge(row)
    LOG.info('Successfully bumped revision number for resource '
             '%(res_uuid)s (type: %(res_type)s) to %(rev_num)d',
             {'res_uuid': resource['id'], 'res_type': resource_type,
              'rev_num': revision_number})

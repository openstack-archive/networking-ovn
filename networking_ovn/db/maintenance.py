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

from networking_ovn.db import models


def get_inconsistent_resources():
    """Get a list of inconsistent resources.

    :returns: A list of objects which the revision number from the
              ovn_revision_number and standardattributes tables differs.
    """
    session = db_api.get_reader_session()
    with session.begin():
        return (session.query(models.OVNRevisionNumbers).
                join(
                    standard_attr.StandardAttribute,
                    models.OVNRevisionNumbers.standard_attr_id ==
                    standard_attr.StandardAttribute.id).
                filter(
                    models.OVNRevisionNumbers.revision_number !=
                    standard_attr.StandardAttribute.revision_number).all())


def get_deleted_resources():
    """Get a list of resources that failed to be deleted in OVN.

    Get a list of resources that have been deleted from neutron but not
    in OVN. Once a resource is deleted in Neutron the ``standard_attr_id``
    foreign key in the ovn_revision_numbers table will be set to NULL.

    Upon successfully deleting the resource in OVN the entry in the
    ovn_revision_number should also be deleted but if something fails
    the entry will be kept and returned in this list so the maintenance
    thread can later fix it.
    """
    session = db_api.get_reader_session()
    with session.begin():
        return session.query(models.OVNRevisionNumbers).filter_by(
            standard_attr_id=None).all()

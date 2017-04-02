# Copyright 2016 Mirantis, Inc.  All rights reserved.
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

from networking_ovn.neutron_lib.db import model_base
from oslo_log import log as logging
import sqlalchemy as sa

#from neutron._i18n import _LE
from networking_ovn._i18n import _LE
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.db import api as db_api
from neutron.db import models_v2
#from neutron.db import standard_attr
from networking_ovn.neutron_lib.db import standard_attr

LOG = logging.getLogger(__name__)
PROVISIONING_COMPLETE = 'provisioning_complete'
# identifiers for the various entities that participate in provisioning
DHCP_ENTITY = 'DHCP'
L2_AGENT_ENTITY = 'L2'
_RESOURCE_TO_MODEL_MAP = {resources.PORT: models_v2.Port}


class ProvisioningBlock(model_base.BASEV2):
    # the standard attr id of the thing we want to block
    standard_attr_id = (
        sa.Column(sa.BigInteger().with_variant(sa.Integer(), 'sqlite'),
                  sa.ForeignKey(standard_attr.StandardAttribute.id,
                                ondelete="CASCADE"),
                  primary_key=True))
    # the entity that wants to block the status change (e.g. L2 Agent)
    entity = sa.Column(sa.String(255), nullable=False, primary_key=True)


def add_model_for_resource(resource, model):
    """Adds a mapping between a callback resource and a DB model."""
    _RESOURCE_TO_MODEL_MAP[resource] = model


#@db_api.retry_if_session_inactive()
def add_provisioning_component(context, object_id, object_type, entity):
    """Adds a provisioning block by an entity to a given object.

    Adds a provisioning block to the DB for object_id with an identifier
    of the entity that is doing the provisioning. While an object has these
    provisioning blocks present, this module will not emit any callback events
    indicating that provisioning has completed. Any logic that depends on
    multiple disjoint components may use these blocks and subscribe to the
    PROVISIONING_COMPLETE event to know when all components have completed.

    :param context: neutron api request context
    :param object_id: ID of object that has been provisioned
    :param object_type: callback resource type of the object
    :param entity: The entity that has provisioned the object
    """
    log_dict = {'entity': entity, 'oid': object_id, 'otype': object_type}
    # we get an object's ID, so we need to convert that into a standard attr id
    standard_attr_id = _get_standard_attr_id(context, object_id, object_type)
    if not standard_attr_id:
        return
    record = context.session.query(ProvisioningBlock).filter_by(
        standard_attr_id=standard_attr_id, entity=entity).first()
    if record:
        # an entry could be leftover from a previous transition that hasn't
        # yet been provisioned. (e.g. multiple updates in a short period)
        LOG.debug("Ignored duplicate provisioning block setup for %(otype)s "
                  "%(oid)s by entity %(entity)s.", log_dict)
        return
    with context.session.begin(subtransactions=True):
        record = ProvisioningBlock(standard_attr_id=standard_attr_id,
                                   entity=entity)
        context.session.add(record)
    LOG.debug("Transition to ACTIVE for %(otype)s object %(oid)s "
              "will not be triggered until provisioned by entity %(entity)s.",
              log_dict)


#@db_api.retry_if_session_inactive()
def remove_provisioning_component(context, object_id, object_type, entity,
                                  standard_attr_id=None):
    """Removes a provisioning block for an object with triggering a callback.

    Removes a provisioning block without triggering a callback. A user of this
    module should call this when a block is no longer correct. If the block has
    been satisfied, the 'provisioning_complete' method should be called.

    :param context: neutron api request context
    :param object_id: ID of object that has been provisioned
    :param object_type: callback resource type of the object
    :param entity: The entity that has provisioned the object
    :param standard_attr_id: Optional ID to pass to the function to avoid the
                             extra DB lookup to translate the object_id into
                             the standard_attr_id.
    :return: boolean indicating whether or not a record was deleted
    """
    with context.session.begin(subtransactions=True):
        standard_attr_id = standard_attr_id or _get_standard_attr_id(
            context, object_id, object_type)
        if not standard_attr_id:
            return False
        record = context.session.query(ProvisioningBlock).filter_by(
            standard_attr_id=standard_attr_id, entity=entity).first()
        if record:
            context.session.delete(record)
            return True
        return False


#@db_api.retry_if_session_inactive()
def provisioning_complete(context, object_id, object_type, entity):
    """Mark that the provisioning for object_id has been completed by entity.

    Marks that an entity has finished provisioning an object. If there are
    no remaining provisioning components, a callback will be triggered
    indicating that provisioning has been completed for the object. Subscribers
    to this callback must be idempotent because it may be called multiple
    times in high availability deployments.

    :param context: neutron api request context
    :param object_id: ID of object that has been provisioned
    :param object_type: callback resource type of the object
    :param entity: The entity that has provisioned the object
    """
    log_dict = {'oid': object_id, 'entity': entity, 'otype': object_type}
    # this can't be called in a transaction to avoid REPEATABLE READ
    # tricking us into thinking there are remaining provisioning components
    if context.session.is_active:
        raise RuntimeError(_LE("Must not be called in a transaction"))
    standard_attr_id = _get_standard_attr_id(context, object_id,
                                             object_type)
    if not standard_attr_id:
        return
    if remove_provisioning_component(context, object_id, object_type, entity,
                                     standard_attr_id):
        LOG.debug("Provisioning for %(otype)s %(oid)s completed by entity "
                  "%(entity)s.", log_dict)
    # now with that committed, check if any records are left. if None, emit
    # an event that provisioning is complete.
    records = context.session.query(ProvisioningBlock).filter_by(
        standard_attr_id=standard_attr_id).count()
    if not records:
        LOG.debug("Provisioning complete for %(otype)s %(oid)s", log_dict)
        registry.notify(object_type, PROVISIONING_COMPLETE,
                        'neutron.db.provisioning_blocks',
                        context=context, object_id=object_id)


#@db_api.retry_if_session_inactive()
def is_object_blocked(context, object_id, object_type):
    """Return boolean indicating if object has a provisioning block.

    :param context: neutron api request context
    :param object_id: ID of object that has been provisioned
    :param object_type: callback resource type of the object
    """
    standard_attr_id = _get_standard_attr_id(context, object_id,
                                             object_type)
    if not standard_attr_id:
        # object doesn't exist so it has no blocks
        return False
    return bool(context.session.query(ProvisioningBlock).filter_by(
                standard_attr_id=standard_attr_id).count())


def _get_standard_attr_id(context, object_id, object_type):
    model = _RESOURCE_TO_MODEL_MAP.get(object_type)
    if not model:
        raise RuntimeError(_LE("Could not find model for %s. If you are "
                               "adding provisioning blocks for a new resource "
                               "you must call add_model_for_resource during "
                               "initialization for your type.") % object_type)
    obj = (context.session.query(model).enable_eagerloads(False).
           filter_by(id=object_id).first())
    if not obj:
        # concurrent delete
        LOG.debug("Could not find standard attr ID for object %s.", object_id)
        return
    return obj.standard_attr_id

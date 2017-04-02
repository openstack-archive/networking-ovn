# Copyright (c) 2016 Hewlett Packard Enterprise Development Company, L.P.
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

import abc
import six

#from neutron_lib.api import converters
from networking_ovn.neutron_lib.api import converters
#from neutron_lib import constants
from networking_ovn.neutron_lib import constants

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.api.v2 import base
#from neutron.extensions import providernet
from networking_ovn.neutron_lib.extensions import providernet
from neutron import manager

SEGMENT = 'segment'
SEGMENTS = '%ss' % SEGMENT
SEGMENT_ID = 'segment_id'

NETWORK_TYPE = 'network_type'
PHYSICAL_NETWORK = 'physical_network'
SEGMENTATION_ID = 'segmentation_id'
NAME_LEN = attributes.NAME_MAX_LEN
DESC_LEN = attributes.DESCRIPTION_MAX_LEN

# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    SEGMENTS: {
        'id': {'allow_post': False,
               'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True,
                      'allow_put': False,
                      'validate': {'type:string':
                                   attributes.TENANT_ID_MAX_LEN},
                      'is_visible': False},
        'network_id': {'allow_post': True,
                       'allow_put': False,
                       'validate': {'type:uuid': None},
                       'is_visible': True},
        PHYSICAL_NETWORK: {'allow_post': True,
                           'allow_put': False,
                           'default': constants.ATTR_NOT_SPECIFIED,
                           'validate': {'type:string':
                                        providernet.PHYSICAL_NETWORK_MAX_LEN},
                           'is_visible': True},
        NETWORK_TYPE: {'allow_post': True,
                       'allow_put': False,
                       'validate': {'type:string':
                                    providernet.NETWORK_TYPE_MAX_LEN},
                       'is_visible': True},
        SEGMENTATION_ID: {'allow_post': True,
                          'allow_put': False,
                          'default': constants.ATTR_NOT_SPECIFIED,
                          'convert_to': converters.convert_to_int,
                          'is_visible': True},
        'name': {'allow_post': True,
                 'allow_put': True,
                 'default': constants.ATTR_NOT_SPECIFIED,
                 'validate': {'type:string_or_none': NAME_LEN},
                 'is_visible': True},
        'description': {'allow_post': True,
                        'allow_put': True,
                        'default': constants.ATTR_NOT_SPECIFIED,
                        'validate': {'type:string_or_none': DESC_LEN},
                        'is_visible': True},
    },
    attributes.SUBNETS: {
        SEGMENT_ID: {'allow_post': True,
                     'allow_put': False,
                     'default': None,
                     'validate': {'type:uuid_or_none': None},
                     'is_visible': True, },
    },
}


class Segment(extensions.ExtensionDescriptor):
    """Extension class supporting Segments."""

    @classmethod
    def get_name(cls):
        return "Segment"

    @classmethod
    def get_alias(cls):
        return "segment"

    @classmethod
    def get_description(cls):
        return "Segments extension."

    @classmethod
    def get_updated(cls):
        return "2016-02-24T17:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Extended Resource for service type management."""
        attributes.PLURALS[SEGMENTS] = SEGMENT
        resource_attributes = RESOURCE_ATTRIBUTE_MAP[SEGMENTS]
        controller = base.create_resource(
            SEGMENTS,
            SEGMENT,
            manager.NeutronManager.get_service_plugins()[SEGMENTS],
            resource_attributes)
        return [extensions.ResourceExtension(SEGMENTS,
                                             controller,
                                             attr_map=resource_attributes)]

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class SegmentPluginBase(object):

    @abc.abstractmethod
    def create_segment(self, context, segment):
        """Create a segment.

        Create a segment, which represents an L2 segment of a network.

        :param context: neutron api request context
        :param segment: dictionary describing the segment, with keys
                        as listed in the  :obj:`RESOURCE_ATTRIBUTE_MAP` object
                        in :file:`neutron/extensions/segment.py`.  All keys
                        will be populated.

        """

    @abc.abstractmethod
    def update_segment(self, context, uuid, segment):
        """Update values of a segment.

        :param context: neutron api request context
        :param uuid: UUID representing the segment to update.
        :param segment: dictionary with keys indicating fields to update.
                        valid keys are those that have a value of True for
                        'allow_put' as listed in the
                        :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                        :file:`neutron/extensions/segment.py`.
        """

    @abc.abstractmethod
    def get_segment(self, context, uuid, fields=None):
        """Retrieve a segment.

        :param context: neutron api request context
        :param uuid: UUID representing the segment to fetch.
        :param fields: a list of strings that are valid keys in a
                       segment dictionary as listed in the
                       :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                       :file:`neutron/extensions/segment.py`. Only these fields
                       will be returned.
        """

    @abc.abstractmethod
    def get_segments(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        """Retrieve a list of segments.

        The contents of the list depends on the identity of the user making the
        request (as indicated by the context) as well as any filters.

        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for
                        a segment as listed in the
                        :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                        :file:`neutron/extensions/segment.py`.  Values in this
                        dictionary are an iterable containing values that will
                        be used for an exact match comparison for that value.
                        Each result returned by this function will have matched
                        one of the values for each key in filters.
        :param fields: a list of strings that are valid keys in a
                       segment dictionary as listed in the
                       :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                       :file:`neutron/extensions/segment.py`. Only these fields
                       will be returned.
        """

    @abc.abstractmethod
    def delete_segment(self, context, uuid):
        """Delete a segment.

        :param context: neutron api request context
        :param uuid: UUID representing the segment to delete.
        """

    @abc.abstractmethod
    def get_segments_count(self, context, filters=None):
        """Return the number of segments.

        The result depends on the identity
        of the user making the request (as indicated by the context) as well
        as any filters.

        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for
                        a segment as listed in the
                        :obj:`RESOURCE_ATTRIBUTE_MAP` object
                        in :file:`neutron/extensions/segment.py`. Values in
                        this dictionary are an iterable containing values that
                        will be used for an exact match comparison for that
                        value.  Each result returned by this function will have
                        matched one of the values for each key in filters.
        """

    def get_plugin_description(self):
        return "Network Segments"

    @classmethod
    def get_plugin_type(cls):
        return SEGMENTS

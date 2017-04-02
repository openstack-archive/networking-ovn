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

from oslo_versionedobjects import fields as obj_fields

STANDARD_ATTRIBUTES = {
    'revision_number': obj_fields.IntegerField(),
    'description': obj_fields.StringField(nullable=True),
    'created_at': obj_fields.DateTimeField(nullable=True, tzinfo_aware=False),
    'updated_at': obj_fields.DateTimeField(nullable=True, tzinfo_aware=False),
}


def add_standard_attributes(cls):
    # Don't use parent's fields in case child class doesn't create
    # its own instance of list
    cls.fields = cls.fields.copy()
    cls.fields.update(STANDARD_ATTRIBUTES)

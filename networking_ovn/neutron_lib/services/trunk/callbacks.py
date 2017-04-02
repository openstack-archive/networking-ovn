# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


class TrunkPayload(object):
    """Payload for trunk-related callback registry notifications."""

    def __init__(self, context, trunk_id, current_trunk=None,
                 original_trunk=None, subports=None):
        self.context = context
        self.trunk_id = trunk_id
        self.current_trunk = current_trunk
        self.original_trunk = original_trunk
        self.subports = subports if subports else []

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.__dict__ == other.__dict__)

    def __ne__(self, other):
        return not self.__eq__(other)

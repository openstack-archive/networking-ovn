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
#
# INTERNAL INTERFACE: PLEASE NOTE THE LEADING _ ON THIS FILE. THIS IS
# NOT A LIBRARY INTERFACE. IF YOU WISH TO USE OSLO_I18N, please refer
# to http://docs.openstack.org/developer/oslo.i18n/usage.html

import oslo_i18n

_translators = oslo_i18n.TranslatorFactory(domain='neutron_lib')

# The primary translation function using the well-known name "_"
_ = _translators.primary

# Translators for log levels.
#
# The abbreviated names are meant to reflect the usual use of a short
# name like '_'. The "L" is for "log" and the other letter comes from
# the level.
_LI = _translators.log_info
_LW = _translators.log_warning
_LE = _translators.log_error
_LC = _translators.log_critical

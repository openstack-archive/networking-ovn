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

import six

from networking_ovn.neutron_lib import exceptions as n_exc
from sqlalchemy.orm import properties

#from neutron_lib._i18n import _
from networking_ovn.neutron_lib._i18n import _
from oslo_db import exception as db_exc
from oslo_utils import excutils
from sqlalchemy.orm import exc


def get_and_validate_sort_keys(sorts, model):
    """Extract sort keys from sorts and ensure they are valid for the model.

    :param sorts: A list of (key, direction) tuples.
    :param model: A sqlalchemy ORM model class.
    :returns: A list of the extracted sort keys.
    :raises BadRequest: If a sort key attribute references another resource
    and cannot be used in the sort.
    """

    sort_keys = [s[0] for s in sorts]
    for sort_key in sort_keys:
        try:
            sort_key_attr = getattr(model, sort_key)
        except AttributeError:
            # Extension attributes don't support sorting. Because it
            # existed in attr_info, it will be caught here.
            msg = _("'%s' is an invalid attribute for sort key") % sort_key
            raise n_exc.BadRequest(resource=model.__tablename__, msg=msg)
        if isinstance(sort_key_attr.property,
                      properties.RelationshipProperty):
            msg = _("Attribute '%(attr)s' references another resource and "
                    "cannot be used to sort '%(resource)s' resources"
                    ) % {'attr': sort_key, 'resource': model.__tablename__}
            raise n_exc.BadRequest(resource=model.__tablename__, msg=msg)

    return sort_keys


def get_sort_dirs(sorts, page_reverse=False):
    """Extract sort directions from sorts, possibly reversed.

    :param sorts: A list of (key, direction) tuples.
    :param page_reverse: True if sort direction is reversed.
    :returns: The list of extracted sort directions optionally reversed.
    """
    if page_reverse:
        return ['desc' if s[1] else 'asc' for s in sorts]
    return ['asc' if s[1] else 'desc' for s in sorts]


def _is_nested_instance(exception, etypes):
    """Check if exception or its inner excepts are an instance of etypes."""
    return (isinstance(exception, etypes) or
            isinstance(exception, n_exc.MultipleExceptions) and
            any(_is_nested_instance(i, etypes)
                for i in exception.inner_exceptions))


def is_retriable(exception):
    """Determine if the said exception is retriable.

    :param exception: The exception to check.
    :returns: True if 'exception' is retriable, otherwise False.
    """
    if _is_nested_instance(exception,
                           (db_exc.DBDeadlock, exc.StaleDataError,
                            db_exc.DBConnectionError,
                            db_exc.DBDuplicateEntry, db_exc.RetryRequest)):
        return True
    # Look for savepoints mangled by deadlocks. See bug/1590298 for details.
    return (_is_nested_instance(exception, db_exc.DBError) and
            '1305' in str(exception))


def reraise_as_retryrequest(function):
    """Wrap the said function with a RetryRequest upon error.

    :param function: The function to wrap/decorate.
    :returns: The 'function' wrapped in a try block that will reraise any
    Exception's as a RetryRequest.
    :raises RetryRequest: If the wrapped function raises retriable exception.
    """
    @six.wraps(function)
    def _wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception as e:
            with excutils.save_and_reraise_exception() as ctx:
                if is_retriable(e):
                    ctx.reraise = False
                    raise db_exc.RetryRequest(e)
    return _wrapped

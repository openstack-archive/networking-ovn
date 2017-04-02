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

from networking_ovn.neutron_lib._i18n import _
from networking_ovn.neutron_lib import exceptions as n_exc


def convert_to_boolean(data):
    """Convert a data value into a python bool.

    :param data: The data value to convert to a python bool. This function
    supports string types, bools, and ints for conversion of representation
    to python bool.
    :returns: The bool value of 'data' if it can be coerced.
    :raises InvalidInput: If the value can't be coerced to a python bool.
    """
    if isinstance(data, six.string_types):
        val = data.lower()
        if val == "true" or val == "1":
            return True
        if val == "false" or val == "0":
            return False
    elif isinstance(data, bool):
        return data
    elif isinstance(data, int):
        if data == 0:
            return False
        elif data == 1:
            return True
    msg = _("'%s' cannot be converted to boolean") % data
    raise n_exc.InvalidInput(error_message=msg)


def convert_to_boolean_if_not_none(data):
    """Uses convert_to_boolean() on the data if the data is not None.

    :param data: The data value to convert.
    :returns: The 'data' returned from convert_to_boolean() if 'data' is not
    None. None is returned if data is None.
    """
    if data is not None:
        return convert_to_boolean(data)


def convert_to_int(data):
    """Convert a data value to a python int.

    :param data: The data value to convert to a python int via python's
    built-in int() constructor.
    :returns: The int value of the data.
    :raises InvalidInput: If the value can't be converted to an int.
    """
    try:
        return int(data)
    except (ValueError, TypeError):
        msg = _("'%s' is not an integer") % data
        raise n_exc.InvalidInput(error_message=msg)


def convert_to_int_if_not_none(data):
    """Uses convert_to_int() on the data if the data is not None.

    :param data: The data value to convert.
    :returns: The 'data' returned from convert_to_int() if 'data' is not None.
    None is returned if data is None.
    """
    if data is not None:
        return convert_to_int(data)
    return data


def convert_to_positive_float_or_none(val):
    """Converts a value to a python float if the value is positive.

    :param val: The value to convert to a positive python float.
    :returns: The value as a python float. If the val is None, None is
    returned.
    :raises ValueError, InvalidInput: A ValueError is raised if the 'val'
    is a float, but is negative. InvalidInput is raised if 'val' can't be
    converted to a python float.
    """
    # NOTE(salv-orlando): This conversion function is currently used by
    # a vendor specific extension only at the moment  It is used for
    # port's RXTX factor in neutron.plugins.vmware.extensions.qos.
    # It is deemed however generic enough to be in this module as it
    # might be used in future for other API attributes.
    if val is None:
        return
    try:
        val = float(val)
        if val < 0:
            raise ValueError()
    except (ValueError, TypeError):
        msg = _("'%s' must be a non negative decimal.") % val
        raise n_exc.InvalidInput(error_message=msg)
    return val


def convert_kvp_str_to_list(data):
    """Convert a value of the form 'key=value' to ['key', 'value'].

    :param data: The string to parse for a key value pair.
    :returns: A list where element 0 is the key and element 1 is the value.
    :raises InvalidInput: If 'data' is not a key value string.
    """
    kvp = [x.strip() for x in data.split('=', 1)]
    if len(kvp) == 2 and kvp[0]:
        return kvp
    msg = _("'%s' is not of the form <key>=[value]") % data
    raise n_exc.InvalidInput(error_message=msg)


def convert_kvp_list_to_dict(kvp_list):
    """Convert a list of 'key=value' strings to a dict.

    :param kvp_list: A list of key value pair strings. For more info on the
    format see; convert_kvp_str_to_list().
    :returns: A dict who's key value pairs are populated by parsing 'kvp_list'.
    :raises InvalidInput: If any of the key value strings are malformed.
    """
    if kvp_list == ['True']:
        # No values were provided (i.e. '--flag-name')
        return {}
    kvp_map = {}
    for kvp_str in kvp_list:
        key, value = convert_kvp_str_to_list(kvp_str)
        kvp_map.setdefault(key, set())
        kvp_map[key].add(value)
    return dict((x, list(y)) for x, y in six.iteritems(kvp_map))


def convert_none_to_empty_list(value):
    """Convert value to an empty list if it's None.

    :param value: The value to convert.
    :returns: An empty list of 'value' is None, otherwise 'value'.
    """
    return [] if value is None else value


def convert_none_to_empty_dict(value):
    """Convert the value to an empty dict if it's None.

    :param value: The value to convert.
    :returns: An empty dict if 'value' is None, otherwise 'value'.
    """
    return {} if value is None else value


def convert_to_list(data):
    """Convert a value into a list.

    :param data: The value to convert.
    :return: A new list wrapped around 'data' whereupon the list is empty
    if 'data' is None.
    """
    if data is None:
        return []
    elif hasattr(data, '__iter__') and not isinstance(data, six.string_types):
        return list(data)
    else:
        return [data]

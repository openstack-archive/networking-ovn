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

import collections
import re

import functools
import inspect
import netaddr
from oslo_log import log as logging
from oslo_utils import uuidutils
import six

from neutron_lib._i18n import _
from neutron_lib.api import converters
from neutron_lib import constants
from neutron_lib import exceptions as n_exc

LOG = logging.getLogger(__name__)

# Used by range check to indicate no limit for a bound.
UNLIMITED = None

# Note: In order to ensure that the MAC address is unicast the first byte
# must be even.
MAC_PATTERN = "^%s[aceACE02468](:%s{2}){5}$" % (constants.HEX_ELEM,
                                                constants.HEX_ELEM)


def _verify_dict_keys(expected_keys, target_dict, strict=True):
    """Allows to verify keys in a dictionary.

    :param expected_keys: A list of keys expected to be present.
    :param target_dict: The dictionary which should be verified.
    :param strict: Specifies whether additional keys are allowed to be present.
    :return: True, if keys in the dictionary correspond to the specification.
    """
    if not isinstance(target_dict, dict):
        msg = (_("Invalid input. '%(target_dict)s' must be a dictionary "
                 "with keys: %(expected_keys)s") %
               {'target_dict': target_dict, 'expected_keys': expected_keys})
        LOG.debug(msg)
        return msg

    expected_keys = set(expected_keys)
    provided_keys = set(target_dict.keys())

    predicate = expected_keys.__eq__ if strict else expected_keys.issubset

    if not predicate(provided_keys):
        msg = (_("Validation of dictionary's keys failed. "
                 "Expected keys: %(expected_keys)s "
                 "Provided keys: %(provided_keys)s") %
               {'expected_keys': expected_keys,
                'provided_keys': provided_keys})
        LOG.debug(msg)
        return msg


def is_attr_set(attribute):
    return not (attribute is None or
                attribute is constants.ATTR_NOT_SPECIFIED)


def _validate_list_of_items(item_validator, data, *args, **kwargs):
    if not isinstance(data, list):
        msg = _("'%s' is not a list") % data
        return msg

    if len(set(data)) != len(data):
        msg = _("Duplicate items in the list: '%s'") % ', '.join(data)
        return msg

    for item in data:
        msg = item_validator(item, *args, **kwargs)
        if msg:
            return msg


def validate_values(data, valid_values=None):
    if data not in valid_values:
        msg = (_("'%(data)s' is not in %(valid_values)s") %
               {'data': data, 'valid_values': valid_values})
        LOG.debug(msg)
        return msg


def validate_not_empty_string_or_none(data, max_len=None):
    if data is not None:
        return validate_not_empty_string(data, max_len=max_len)


def validate_not_empty_string(data, max_len=None):
    msg = validate_string(data, max_len=max_len)
    if msg:
        return msg
    if not data.strip():
        msg = _("'%s' Blank strings are not permitted") % data
        LOG.debug(msg)
        return msg


def validate_string_or_none(data, max_len=None):
    if data is not None:
        return validate_string(data, max_len=max_len)


def validate_string(data, max_len=None):
    if not isinstance(data, six.string_types):
        msg = _("'%s' is not a valid string") % data
        LOG.debug(msg)
        return msg

    if max_len is not None and len(data) > max_len:
        msg = (_("'%(data)s' exceeds maximum length of %(max_len)s") %
               {'data': data, 'max_len': max_len})
        LOG.debug(msg)
        return msg


validate_list_of_unique_strings = functools.partial(_validate_list_of_items,
                                                    validate_string)


def validate_boolean(data, valid_values=None):
    try:
        converters.convert_to_boolean(data)
    except n_exc.InvalidInput:
        msg = _("'%s' is not a valid boolean value") % data
        LOG.debug(msg)
        return msg


def validate_integer(data, valid_values=None):
    """This function validates if the data is an integer.

    It checks both number or string provided to validate it's an
    integer and returns a message with the error if it's not

    :param data: The string or number to validate as integer
    :param valid_values: values to limit the 'data' to
    :return: Message if not an integer.
    """

    if valid_values is not None:
        msg = validate_values(data=data, valid_values=valid_values)
        if msg:
            return msg

    msg = _("'%s' is not an integer") % data
    try:
        fl_n = float(data)
        int_n = int(data)
    except (ValueError, TypeError, OverflowError):
        LOG.debug(msg)
        return msg

    # Fail test if non equal or boolean
    if fl_n != int_n:
        LOG.debug(msg)
        return msg
    elif isinstance(data, bool):
        msg = _("'%s' is not an integer:boolean") % data
        LOG.debug(msg)
        return msg


def validate_range(data, valid_values=None):
    """Check that integer value is within a range provided.

    Test is inclusive. Allows either limit to be ignored, to allow
    checking ranges where only the lower or upper limit matter.
    It is expected that the limits provided are valid integers or
    the value None.
    """

    min_value = valid_values[0]
    max_value = valid_values[1]
    try:
        data = int(data)
    except (ValueError, TypeError):
        msg = _("'%s' is not an integer") % data
        LOG.debug(msg)
        return msg
    if min_value is not UNLIMITED and data < min_value:
        msg = _("'%(data)s' is too small - must be at least "
                "'%(limit)d'") % {'data': data, 'limit': min_value}
        LOG.debug(msg)
        return msg
    if max_value is not UNLIMITED and data > max_value:
        msg = _("'%(data)s' is too large - must be no larger than "
                "'%(limit)d'") % {'data': data, 'limit': max_value}
        LOG.debug(msg)
        return msg


def validate_no_whitespace(data):
    """Validates that input has no whitespace."""
    if re.search(r'\s', data):
        msg = _("'%s' contains whitespace") % data
        LOG.debug(msg)
        raise n_exc.InvalidInput(error_message=msg)
    return data


def validate_mac_address(data, valid_values=None):
    try:
        valid_mac = netaddr.valid_mac(validate_no_whitespace(data))
    except Exception:
        valid_mac = False

    if valid_mac:
        valid_mac = (not netaddr.EUI(data) in
                     map(netaddr.EUI, constants.INVALID_MAC_ADDRESSES))
    # TODO(arosen): The code in this file should be refactored
    # so it catches the correct exceptions. validate_no_whitespace
    # raises AttributeError if data is None.
    if not valid_mac:
        msg = _("'%s' is not a valid MAC address") % data
        LOG.debug(msg)
        return msg


def validate_mac_address_or_none(data, valid_values=None):
    if data is not None:
        return validate_mac_address(data, valid_values)


def validate_ip_address(data, valid_values=None):
    msg = None
    try:
        # netaddr.core.ZEROFILL is only applicable to IPv4.
        # it will remove leading zeros from IPv4 address octets.
        ip = netaddr.IPAddress(validate_no_whitespace(data),
                               flags=netaddr.core.ZEROFILL)
        # The followings are quick checks for IPv6 (has ':') and
        # IPv4.  (has 3 periods like 'xx.xx.xx.xx')
        # NOTE(yamamoto): netaddr uses libraries provided by the underlying
        # platform to convert addresses.  For example, inet_aton(3).
        # Some platforms, including NetBSD and OS X, have inet_aton
        # implementation which accepts more varying forms of addresses than
        # we want to accept here.  The following check is to reject such
        # addresses.  For Example:
        #   >>> netaddr.IPAddress('1' * 59)
        #   IPAddress('199.28.113.199')
        #   >>> netaddr.IPAddress(str(int('1' * 59) & 0xffffffff))
        #   IPAddress('199.28.113.199')
        #   >>>
        if ':' not in data and data.count('.') != 3:
            msg = _("'%s' is not a valid IP address") % data
        # A leading '0' in IPv4 address may be interpreted as an octal number,
        # e.g. 011 octal is 9 decimal. Since there is no standard saying
        # whether IP address with leading '0's should be interpreted as octal
        # or decimal, hence we reject leading '0's to avoid ambiguity.
        elif ip.version == 4 and str(ip) != data:
            msg = _("'%(data)s' is not an accepted IP address, "
                    "'%(ip)s' is recommended") % {"data": data, "ip": ip}
    except Exception:
        msg = _("'%s' is not a valid IP address") % data
    if msg:
        LOG.debug(msg)
    return msg


def validate_ip_pools(data, valid_values=None):
    """Validate that start and end IP addresses are present.

    In addition to this the IP addresses will also be validated
    """
    if not isinstance(data, list):
        msg = _("Invalid data format for IP pool: '%s'") % data
        LOG.debug(msg)
        return msg

    expected_keys = ['start', 'end']
    for ip_pool in data:
        msg = _verify_dict_keys(expected_keys, ip_pool)
        if msg:
            return msg
        for k in expected_keys:
            msg = validate_ip_address(ip_pool[k])
            if msg:
                return msg


def validate_fixed_ips(data, valid_values=None):
    if not isinstance(data, list):
        msg = _("Invalid data format for fixed IP: '%s'") % data
        LOG.debug(msg)
        return msg

    ips = []
    for fixed_ip in data:
        if not isinstance(fixed_ip, dict):
            msg = _("Invalid data format for fixed IP: '%s'") % fixed_ip
            LOG.debug(msg)
            return msg
        if 'ip_address' in fixed_ip:
            # Ensure that duplicate entries are not set - just checking IP
            # suffices. Duplicate subnet_id's are legitimate.
            fixed_ip_address = fixed_ip['ip_address']
            if fixed_ip_address in ips:
                msg = _("Duplicate IP address '%s'") % fixed_ip_address
                LOG.debug(msg)
            else:
                msg = validate_ip_address(fixed_ip_address)
            if msg:
                return msg
            ips.append(fixed_ip_address)
        if 'subnet_id' in fixed_ip:
            msg = validate_uuid(fixed_ip['subnet_id'])
            if msg:
                return msg


def validate_nameservers(data, valid_values=None):
    if not hasattr(data, '__iter__'):
        msg = _("Invalid data format for nameserver: '%s'") % data
        LOG.debug(msg)
        return msg

    hosts = []
    for host in data:
        # This must be an IP address only
        msg = validate_ip_address(host)
        if msg:
            msg = _("'%(host)s' is not a valid nameserver. %(msg)s") % {
                'host': host, 'msg': msg}
            LOG.debug(msg)
            return msg
        if host in hosts:
            msg = _("Duplicate nameserver '%s'") % host
            LOG.debug(msg)
            return msg
        hosts.append(host)


def validate_hostroutes(data, valid_values=None):
    if not isinstance(data, list):
        msg = _("Invalid data format for hostroute: '%s'") % data
        LOG.debug(msg)
        return msg

    expected_keys = ['destination', 'nexthop']
    hostroutes = []
    for hostroute in data:
        msg = _verify_dict_keys(expected_keys, hostroute)
        if msg:
            return msg
        msg = validate_subnet(hostroute['destination'])
        if msg:
            return msg
        msg = validate_ip_address(hostroute['nexthop'])
        if msg:
            return msg
        if hostroute in hostroutes:
            msg = _("Duplicate hostroute '%s'") % hostroute
            LOG.debug(msg)
            return msg
        hostroutes.append(hostroute)


def validate_ip_address_or_none(data, valid_values=None):
    if data is not None:
        return validate_ip_address(data, valid_values)


def validate_subnet(data, valid_values=None):
    msg = None
    try:
        net = netaddr.IPNetwork(validate_no_whitespace(data))
        if '/' not in data or (net.version == 4 and str(net) != data):
            msg = _("'%(data)s' isn't a recognized IP subnet cidr,"
                    " '%(cidr)s' is recommended") % {"data": data,
                                                     "cidr": net.cidr}
        else:
            return
    except Exception:
        msg = _("'%s' is not a valid IP subnet") % data
    if msg:
        LOG.debug(msg)
    return msg


def validate_subnet_or_none(data, valid_values=None):
    if data is not None:
        return validate_subnet(data, valid_values)


validate_subnet_list = functools.partial(_validate_list_of_items,
                                         validate_subnet)


def validate_regex(data, valid_values=None):
    try:
        if re.match(valid_values, data):
            return
    except TypeError:
        pass

    msg = _("'%s' is not a valid input") % data
    LOG.debug(msg)
    return msg


def validate_regex_or_none(data, valid_values=None):
    if data is not None:
        return validate_regex(data, valid_values)


def validate_subnetpool_id(data, valid_values=None):
    if data != constants.IPV6_PD_POOL_ID:
        return validate_uuid_or_none(data, valid_values)


def validate_subnetpool_id_or_none(data, valid_values=None):
    if data is not None:
        return validate_subnetpool_id(data, valid_values)


def validate_uuid(data, valid_values=None):
    if not uuidutils.is_uuid_like(data):
        msg = _("'%s' is not a valid UUID") % data
        LOG.debug(msg)
        return msg


def validate_uuid_or_none(data, valid_values=None):
    if data is not None:
        return validate_uuid(data)


validate_uuid_list = functools.partial(_validate_list_of_items,
                                       validate_uuid)


def _validate_dict_item(key, key_validator, data):
    # Find conversion function, if any, and apply it
    conv_func = key_validator.get('convert_to')
    if conv_func:
        data[key] = conv_func(data.get(key))
    # Find validator function
    # TODO(salv-orlando): Structure of dict attributes should be improved
    # to avoid iterating over items
    val_func = val_params = None
    for (k, v) in six.iteritems(key_validator):
        if k.startswith('type:'):
            # ask forgiveness, not permission
            try:
                val_func = validators[k]
            except KeyError:
                msg = _("Validator '%s' does not exist.") % k
                LOG.debug(msg)
                return msg
            val_params = v
            break
    # Process validation
    if val_func:
        return val_func(data.get(key), val_params)


def validate_dict(data, key_specs=None):
    if not isinstance(data, dict):
        msg = _("'%s' is not a dictionary") % data
        LOG.debug(msg)
        return msg
    # Do not perform any further validation, if no constraints are supplied
    if not key_specs:
        return

    # Check whether all required keys are present
    required_keys = [key for key, spec in six.iteritems(key_specs)
                     if spec.get('required')]

    if required_keys:
        msg = _verify_dict_keys(required_keys, data, False)
        if msg:
            return msg

    # Check whether unexpected keys are supplied in data
    unexpected_keys = [key for key in data if key not in key_specs]
    if unexpected_keys:
        msg = _("Unexpected keys supplied: %s") % ', '.join(unexpected_keys)
        LOG.debug(msg)
        return msg

    # Perform validation and conversion of all values
    # according to the specifications.
    for key, key_validator in [(k, v) for k, v in six.iteritems(key_specs)
                               if k in data]:
        msg = _validate_dict_item(key, key_validator, data)
        if msg:
            return msg


def validate_dict_or_none(data, key_specs=None):
    if data is not None:
        return validate_dict(data, key_specs)


def validate_dict_or_empty(data, key_specs=None):
    if data != {}:
        return validate_dict(data, key_specs)


def validate_dict_or_nodata(data, key_specs=None):
    if data:
        return validate_dict(data, key_specs)


def validate_non_negative(data, valid_values=None):
    try:
        data = int(data)
    except (ValueError, TypeError):
        msg = _("'%s' is not an integer") % data
        LOG.debug(msg)
        return msg

    if data < 0:
        msg = _("'%s' should be non-negative") % data
        LOG.debug(msg)
        return msg


def validate_subports(data, valid_values=None):
    if not isinstance(data, list):
        msg = _("Invalid data format for subports: '%s' is not a list") % data
        LOG.debug(msg)
        return msg

    subport_ids = set()
    segmentations = collections.defaultdict(set)
    for subport in data:
        if not isinstance(subport, dict):
            msg = _("Invalid data format for subport: "
                    "'%s' is not a dict") % subport
            LOG.debug(msg)
            return msg

        # Expect a non duplicated and valid port_id for the subport
        if 'port_id' not in subport:
            msg = _("A valid port UUID must be specified")
            LOG.debug(msg)
            return msg
        elif validate_uuid(subport["port_id"]):
            msg = _("Invalid UUID for subport: '%s'") % subport["port_id"]
            return msg
        elif subport["port_id"] in subport_ids:
            msg = _("Non unique UUID for subport: '%s'") % subport["port_id"]
            return msg
        subport_ids.add(subport["port_id"])

        # Validate that both segmentation id and segmentation type are
        # specified, and that the client does not duplicate segmentation
        # ids
        segmentation_id = subport.get("segmentation_id")
        segmentation_type = subport.get("segmentation_type")
        if (not segmentation_id or not segmentation_type) and len(subport) > 1:
            msg = _("Invalid subport details '%s': missing segmentation "
                    "information. Must specify both segmentation_id and "
                    "segmentation_type") % subport
            LOG.debug(msg)
            return msg
        if segmentation_id in segmentations.get(segmentation_type, []):
            msg = _("Segmentation ID '%(seg_id)s' for '%(subport)s' is not "
                    "unique") % {"seg_id": segmentation_id,
                                 "subport": subport["port_id"]}
            LOG.debug(msg)
            return msg
        if segmentation_id:
            segmentations[segmentation_type].add(segmentation_id)


# Dictionary that maintains a list of validation functions
validators = {'type:dict': validate_dict,
              'type:dict_or_none': validate_dict_or_none,
              'type:dict_or_empty': validate_dict_or_empty,
              'type:dict_or_nodata': validate_dict_or_nodata,
              'type:fixed_ips': validate_fixed_ips,
              'type:hostroutes': validate_hostroutes,
              'type:ip_address': validate_ip_address,
              'type:ip_address_or_none': validate_ip_address_or_none,
              'type:ip_pools': validate_ip_pools,
              'type:mac_address': validate_mac_address,
              'type:mac_address_or_none': validate_mac_address_or_none,
              'type:nameservers': validate_nameservers,
              'type:non_negative': validate_non_negative,
              'type:range': validate_range,
              'type:regex': validate_regex,
              'type:regex_or_none': validate_regex_or_none,
              'type:string': validate_string,
              'type:string_or_none': validate_string_or_none,
              'type:not_empty_string': validate_not_empty_string,
              'type:not_empty_string_or_none':
              validate_not_empty_string_or_none,
              'type:subnet': validate_subnet,
              'type:subnet_list': validate_subnet_list,
              'type:subnet_or_none': validate_subnet_or_none,
              'type:subnetpool_id': validate_subnetpool_id,
              'type:subnetpool_id_or_none': validate_subnetpool_id_or_none,
              'type:subports': validate_subports,
              'type:uuid': validate_uuid,
              'type:uuid_or_none': validate_uuid_or_none,
              'type:uuid_list': validate_uuid_list,
              'type:values': validate_values,
              'type:boolean': validate_boolean,
              'type:integer': validate_integer,
              'type:list_of_unique_strings': validate_list_of_unique_strings}


def _to_validation_type(validation_type):
    return (validation_type
            if validation_type.startswith('type:')
            else 'type:' + validation_type)


def get_validator(validation_type, default=None):
    """Get a registered validator by type.

    :param validation_type: The type to retrieve the validator for.
    :param default: A default value to return if the validator is
    not registered.
    :return: The validator if registered, otherwise the default value.
    """
    return validators.get(_to_validation_type(validation_type), default)


def add_validator(validation_type, validator):
    """Dynamically add a validator.

    This can be used by clients to add their own, private validators, rather
    than directly modifying the data structure. The clients can NOT modify
    existing validators.
    """
    key = _to_validation_type(validation_type)
    if key in validators:
        # NOTE(boden): imp.load_source() forces module reinitialization that
        # can lead to validator redefinition from the same call site
        if inspect.getsource(validator) != inspect.getsource(validators[key]):
            msg = _("Validator type %s is already defined") % validation_type
            raise KeyError(msg)
        return
    validators[key] = validator

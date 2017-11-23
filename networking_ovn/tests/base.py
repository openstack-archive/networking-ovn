# -*- coding: utf-8 -*-

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os

from oslo_utils import fileutils
from oslotest import base

from networking_ovn.common import config


def setup_test_logging(config_opts, log_dir, log_file_path_template):
    # Have each test log into its own log file
    config_opts.set_override('debug', True)
    fileutils.ensure_tree(log_dir, mode=0o755)
    log_file = sanitize_log_path(
        os.path.join(log_dir, log_file_path_template))
    config_opts.set_override('log_file', log_file)
    config.setup_logging()


def sanitize_log_path(path):
    # Sanitize the string so that its log path is shell friendly
    replace_map = {' ': '-', '(': '_', ')': '_'}
    for s, r in replace_map.items():
        path = path.replace(s, r)
    return path


class TestCase(base.BaseTestCase):

    """Test case base class for all unit tests."""

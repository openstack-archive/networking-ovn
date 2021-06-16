# Copyright 2016 Red Hat, Inc.
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

from neutron.common import config
from neutron_lib import worker


class MaintenanceWorker(worker.BaseWorker):
    need_import_workaround = True

    def start(self):
        super(MaintenanceWorker, self).start()
        # NOTE(twilson) The super class will trigger the post_fork_initialize
        # in the driver, which starts the connection/IDL notify loop which
        # keeps the process from exiting

    def stop(self):
        """Stop service."""
        super(MaintenanceWorker, self).stop()

    def wait(self):
        """Wait for service to complete."""
        super(MaintenanceWorker, self).wait()

    @staticmethod
    def reset():
        config.reset_service()

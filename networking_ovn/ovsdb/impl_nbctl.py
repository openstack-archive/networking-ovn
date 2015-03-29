# Copyright (c) 2015 Openstack Foundation
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

from oslo_config import cfg

from networking_ovn.ovsdb import ovn_api
import neutron.agent.linux.utils as linux_utils
from neutron.i18n import _


class Transaction(ovn_api.Transaction):
    def __init__(self):
        self.commands = []

    def add(self, command):
        self.commands.append(command)
        return command

    @staticmethod
    def _nbctl_opts():
        if cfg.CONF.ovn.database:
            return '-d %s' % cfg.CONF.ovn.database
        return ''

    def commit(self):
        for cmd in self.commands:
            cmd_str = 'ovn-nbctl %s %s' % (Transaction._nbctl_opts(),
                                           cmd.command)
            self.run_nbctl(cmd_str)

    def run_nbctl(self, cmd):
        cmd_str = cmd.split()
        linux_utils.execute(cmd_str, run_as_root=True)


class Command(ovn_api.Command):
    def __init__(self, command):
        self.command = command
        self.result = None

    def execute(self):
        with Transaction() as txn:
            txn.add(self)
        return self.result


class OvsdbNbctl(ovn_api.API):
    def transaction(self, check_error=False, log_errors=True, **kwargs):
        return Transaction()

    def create_lswitch(self, lswitch_name, may_exist=True):
        return Command('lswitch-add %s' % lswitch_name)

    def delete_lswitch(self, lswitch_name=None, ext_id=None, if_exists=True):
        # TODO(gsagie) support ext_id deletion
        if (lswitch_name is not None):
            return Command('lswitch-del %s' % lswitch_name)
        else:
            raise RuntimeError(_("Currently only support delete "
                               "by lswitch-name"))

    def set_lswitch_ext_id(self, lswitch_id, ext_id):
        # TODO(gsagie) support ext_id list
        return Command('lswitch-set-external-id %s %s %s'
                       % (lswitch_id, ext_id[0], ext_id[1]))

    def create_lport(self, lport_name, lswitch_name, may_exist=True):
        return Command('lport-add %s %s' % (lport_name, lswitch_name))

    def delete_lport(self, lport_name=None, ext_id=None, if_exist=True):
        # TODO(gsagie) support ext_id deletion
        if (lport_name is not None):
            return Command('lport-del %s' % lport_name)
        else:
            raise RuntimeError(_("Currently only support "
                               "delete by lport-name"))

    def set_lport_mac(self, lport_name, mac):
        return Command('lport-set-macs %s %s' % (lport_name, mac))

    def set_lport_ext_id(self, lport_name, ext_id):
        # TODO(gsagie) support ext_id list
        return Command('lport-set-external-id %s %s %s'
                       % (lport_name, ext_id[0], ext_id[1]))

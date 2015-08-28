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

from neutron.agent.ovsdb.native.commands import BaseCommand
from neutron.agent.ovsdb.native import idlutils
from neutron.i18n import _


class AddLSwitchCommand(BaseCommand):
    def __init__(self, api, name, may_exist, **columns):
        super(AddLSwitchCommand, self).__init__(api)
        self.name = name
        self.columns = columns
        self.may_exist = may_exist

    def run_idl(self, txn):
        if self.may_exist:
            lswitch = idlutils.row_by_value(self.api.idl, 'Logical_Switch',
                                            'name', self.name, None)
            if lswitch:
                return
        row = txn.insert(self.api._tables['Logical_Switch'])
        row.name = self.name
        for col, val in self.columns.items():
            setattr(row, col, val)


class DelLSwitchCommand(BaseCommand):
    def __init__(self, api, name, if_exists):
        super(DelLSwitchCommand, self).__init__(api)
        self.name = name
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            lswitch = idlutils.row_by_value(self.api.idl, 'Logical_Switch',
                                            'name', self.name)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Switch %s does not exist") % self.name
            raise RuntimeError(msg)

        self.api._tables['Logical_Switch'].rows[lswitch.uuid].delete()


class LSwitchSetExternalIdCommand(BaseCommand):
    def __init__(self, api, name, field, value, if_exists):
        super(LSwitchSetExternalIdCommand, self).__init__(api)
        self.name = name
        self.field = field
        self.value = value
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            lswitch = idlutils.row_by_value(self.api.idl, 'Logical_Switch',
                                            'name', self.name)

        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Switch %s does not exist") % self.name
            raise RuntimeError(msg)

        external_ids = getattr(lswitch, 'external_ids', {})
        external_ids[self.field] = self.value
        lswitch.external_ids = external_ids


class AddLogicalPortCommand(BaseCommand):
    def __init__(self, api, lport, lswitch, may_exist, **columns):
        super(AddLogicalPortCommand, self).__init__(api)
        self.lport = lport
        self.lswitch = lswitch
        self.may_exist = may_exist
        self.columns = columns

    def run_idl(self, txn):
        try:
            lswitch = idlutils.row_by_value(self.api.idl, 'Logical_Switch',
                                            'name', self.lswitch)
            ports = getattr(lswitch, 'ports', [])
        except idlutils.RowNotFound:
            msg = _("Logical Switch %s does not exist") % self.lswitch
            raise RuntimeError(msg)
        if self.may_exist:
            port = idlutils.row_by_value(self.api.idl,
                                         'Logical_Port', 'name',
                                         self.lport, None)
            if port:
                return

        port = txn.insert(self.api._tables['Logical_Port'])
        port.name = self.lport
        for col, val in self.columns.items():
            setattr(port, col, val)
        # add the newly created port to exiting lswitch
        ports.append(port.uuid)
        setattr(lswitch, 'ports', ports)
        lswitch.verify('ports')


class SetLogicalPortCommand(BaseCommand):
    def __init__(self, api, lport, if_exists, **columns):
        super(SetLogicalPortCommand, self).__init__(api)
        self.lport = lport
        self.columns = columns
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            port = idlutils.row_by_value(self.api.idl, 'Logical_Port',
                                         'name', self.lport)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Port %s does not exist") % self.lport
            raise RuntimeError(msg)

        for col, val in self.columns.items():
            setattr(port, col, val)


class DelLogicalPortCommand(BaseCommand):
    def __init__(self, api, lport, lswitch, if_exists):
        super(DelLogicalPortCommand, self).__init__(api)
        self.lport = lport
        self.lswitch = lswitch
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            lport = idlutils.row_by_value(self.api.idl, 'Logical_Port',
                                          'name', self.lport)
            lswitch = idlutils.row_by_value(self.api.idl, 'Logical_Switch',
                                            'name', self.lswitch)
            ports = getattr(lswitch, 'ports', [])
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Port %s does not exist") % self.lport
            raise RuntimeError(msg)

        ports.remove(lport)
        lswitch.verify('ports')
        setattr(lswitch, 'ports', ports)
        self.api._tables['Logical_Port'].rows[lport.uuid].delete()


class AddLRouterCommand(BaseCommand):
    def __init__(self, api, name, may_exist, **columns):
        super(AddLRouterCommand, self).__init__(api)
        self.name = name
        self.columns = columns
        self.may_exist = may_exist

    def run_idl(self, txn):
        if self.may_exist:
            lrouter = idlutils.row_by_value(self.api.idl, 'Logical_Router',
                                            'name', self.name, None)
            if lrouter:
                return

        row = txn.insert(self.api._tables['Logical_Router'])
        row.name = self.name
        for col, val in self.columns.items():
            setattr(row, col, val)


class UpdateLRouterCommand(BaseCommand):
    def __init__(self, api, name, if_exists, **columns):
        super(UpdateLRouterCommand, self).__init__(api)
        self.name = name
        self.columns = columns
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            lrouter = idlutils.row_by_value(self.api.idl, 'Logical_Router',
                                            'name', self.name, None)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Router %s does not exist") % self.name
            raise RuntimeError(msg)

        if lrouter:
            for col, val in self.columns.items():
                setattr(lrouter, col, val)
            return


class DelLRouterCommand(BaseCommand):
    def __init__(self, api, name, if_exists):
        super(DelLRouterCommand, self).__init__(api)
        self.name = name
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            lrouter = idlutils.row_by_value(self.api.idl, 'Logical_Router',
                                            'name', self.name)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Router %s does not exist") % self.name
            raise RuntimeError(msg)

        self.api._tables['Logical_Router'].rows[lrouter.uuid].delete()


class AddLRouterPortCommand(BaseCommand):
    def __init__(self, api, name, lrouter, lswitch, may_exist, **columns):
        super(AddLRouterPortCommand, self).__init__(api)
        self.name = name
        self.lrouter = lrouter
        self.lswitch = lswitch
        self.columns = columns
        self.may_exist = may_exist

    def run_idl(self, txn):

        lrouter = idlutils.row_by_value(self.api.idl, 'Logical_Router',
                                        'name', self.lrouter)
        lswitch = idlutils.row_by_value(self.api.idl, 'Logical_Switch',
                                        'name', self.lswitch)
        lrouter_ports = getattr(lrouter, 'ports', [])

        if self.may_exist:
            if getattr(lswitch, 'router_port', None) in lrouter_ports:
                return

        lrouter_port = txn.insert(self.api._tables['Logical_Router_Port'])
        lrouter_port.name = self.name
        for col, val in self.columns.items():
            setattr(lrouter_port, col, val)

        lrouter_ports.append(lrouter_port)
        setattr(lrouter, 'ports', lrouter_ports)
        lswitch.router_port = lrouter_port


class DelLRouterPortCommand(BaseCommand):
    def __init__(self, api, name, lrouter, lswitch, if_exists):
        super(DelLRouterPortCommand, self).__init__(api)
        self.name = name
        self.lrouter = lrouter
        self.lswitch = lswitch
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:

            lrouter = idlutils.row_by_value(self.api.idl, 'Logical_Router',
                                            'name', self.lrouter)
            lswitch = idlutils.row_by_value(self.api.idl, 'Logical_Switch',
                                            'name', self.lswitch)
            lrouter_ports = getattr(lrouter, 'ports', [])

            lrouter_port = idlutils.row_by_value(self.api.idl,
                                                 'Logical_Router_Port',
                                                 'name', self.name)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Router Port %s does not exist") % self.name
            raise RuntimeError(msg)

        lrouter_ports.remove(lrouter_port)
        setattr(lrouter, 'ports', lrouter_ports)
        setattr(lswitch, 'router_port', [])


class AddACLCommand(BaseCommand):
    def __init__(self, api, lswitch, lport, **columns):
        super(AddACLCommand, self).__init__(api)
        self.lswitch = lswitch
        self.lport = lport
        self.columns = columns

    def run_idl(self, txn):
        try:
            lswitch = idlutils.row_by_value(self.api.idl, 'Logical_Switch',
                                            'name', self.lswitch)
        except idlutils.RowNotFound:
            msg = _("Logical Switch %s does not exist") % self.lswitch
            raise RuntimeError(msg)

        row = txn.insert(self.api._tables['ACL'])
        for col, val in self.columns.items():
            setattr(row, col, val)
        row.external_ids = {'neutron:lport': self.lport}
        acls = getattr(lswitch, 'acls', [])
        acls.append(row.uuid)
        setattr(lswitch, 'acls', acls)
        lswitch.verify('acls')


class DelACLCommand(BaseCommand):
    def __init__(self, api, lswitch, lport, if_exists):
        super(DelACLCommand, self).__init__(api)
        self.lswitch = lswitch
        self.lport = lport
        self.if_exists = if_exists

    def run_idl(self, txn):
        try:
            lswitch = idlutils.row_by_value(self.api.idl, 'Logical_Switch',
                                            'name', self.lswitch)
        except idlutils.RowNotFound:
            if self.if_exists:
                return
            msg = _("Logical Switch %s does not exist") % self.lswitch
            raise RuntimeError(msg)

        acls_to_del = []
        acls = getattr(lswitch, 'acls', [])
        for acl in acls:
            ext_ids = getattr(acl, 'external_ids', {})
            if ext_ids.get('neutron:lport') == self.lport:
                acls_to_del.append(acl)
        for acl in acls_to_del:
            acls.remove(acl)
            acl.delete()
        setattr(lswitch, 'acls', acls)
        lswitch.verify('acls')

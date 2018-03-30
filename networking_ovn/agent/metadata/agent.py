# Copyright 2017 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
import re

from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.common import utils
from neutron_lib import constants as n_const
from oslo_concurrency import lockutils
from oslo_log import log
from ovsdbapp.backend.ovs_idl import event as row_event
from ovsdbapp.backend.ovs_idl import vlog
import six

from networking_ovn.agent.metadata import driver as metadata_driver
from networking_ovn.agent.metadata import ovsdb
from networking_ovn.agent.metadata import server as metadata_server
from networking_ovn.common import config
from networking_ovn.common import constants as ovn_const


LOG = log.getLogger(__name__)
_SYNC_STATE_LOCK = lockutils.ReaderWriterLock()


NS_PREFIX = 'ovnmeta-'
METADATA_DEFAULT_PREFIX = 16
METADATA_DEFAULT_IP = '169.254.169.254'
METADATA_DEFAULT_CIDR = '%s/%d' % (METADATA_DEFAULT_IP,
                                   METADATA_DEFAULT_PREFIX)
METADATA_PORT = 80
MAC_PATTERN = re.compile(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', re.I)

MetadataPortInfo = collections.namedtuple('MetadataPortInfo', ['mac',
                                                               'ip_addresses'])


def _sync_lock(f):
    """Decorator to block all operations for a global sync call."""
    @six.wraps(f)
    def wrapped(*args, **kwargs):
        with _SYNC_STATE_LOCK.write_lock():
            return f(*args, **kwargs)
    return wrapped


def _wait_if_syncing(f):
    """Decorator to wait if any sync operations are in progress."""
    @six.wraps(f)
    def wrapped(*args, **kwargs):
        with _SYNC_STATE_LOCK.read_lock():
            return f(*args, **kwargs)
    return wrapped


class PortBindingChassisEvent(row_event.RowEvent):
    def __init__(self, metadata_agent):
        self.agent = metadata_agent
        table = 'Port_Binding'
        events = (self.ROW_UPDATE)
        super(PortBindingChassisEvent, self).__init__(
            events, table, None)
        self.event_name = 'PortBindingChassisEvent'

    @_wait_if_syncing
    def run(self, event, row, old):
        # Check if the port has been bound/unbound to our chassis and update
        # the metadata namespace accordingly.
        # Type must be empty to make sure it's a VIF.
        if row.type != "":
            return
        new_chassis = getattr(row, 'chassis', [])
        old_chassis = getattr(old, 'chassis', [])
        if new_chassis and new_chassis[0].name == self.agent.chassis:
            LOG.info("Port %s in datapath %s bound to our chassis",
                     row.logical_port, str(row.datapath.uuid))
            self.agent.update_datapath(str(row.datapath.uuid))
        elif old_chassis and old_chassis[0].name == self.agent.chassis:
            LOG.info("Port %s in datapath %s unbound from our chassis",
                     row.logical_port, str(row.datapath.uuid))
            self.agent.update_datapath(str(row.datapath.uuid))


class ChassisCreateEvent(row_event.RowEvent):
    """Row create event - Chassis name == our_chassis.

    On connection, we get a dump of all chassis so if we catch a creation
    of our own chassis it has to be a reconnection. In this case, we need
    to do a full sync to make sure that we capture all changes while the
    connection to OVSDB was down.
    """

    def __init__(self, metadata_agent):
        self.agent = metadata_agent
        self.first_time = True
        table = 'Chassis'
        events = (self.ROW_CREATE)
        super(ChassisCreateEvent, self).__init__(
            events, table, (('name', '=', self.agent.chassis),))
        self.event_name = 'ChassisCreateEvent'

    def run(self, event, row, old):
        if self.first_time:
            self.first_time = False
        else:
            LOG.info("Connection to OVSDB established, doing a full sync")
            self.agent.sync()


class MetadataAgent(object):

    def __init__(self, conf):
        self.conf = conf
        vlog.use_python_logger(max_level=config.get_ovn_ovsdb_log_level())
        self._process_monitor = external_process.ProcessMonitor(
            config=self.conf,
            resource_type='metadata')

    def start(self):

        # Launch the server that will act as a proxy between the VM's and Nova.
        proxy = metadata_server.UnixDomainMetadataProxy(self.conf)
        proxy.run()

        # Open the connection to OVS database
        self.ovs_idl = ovsdb.MetadataAgentOvsIdl().start()
        self.chassis = self._get_own_chassis_name()

        # Open the connection to OVN SB database.
        self.sb_idl = ovsdb.MetadataAgentOvnSbIdl(
            [PortBindingChassisEvent(self), ChassisCreateEvent(self)]).start()

        # Do the initial sync.
        self.sync()

        proxy.wait()

    def _get_own_chassis_name(self):
        """Return the external_ids:system-id value of the Open_vSwitch table.

        As long as ovn-controller is running on this node, the key is
        guaranteed to exist and will include the chassis name.
        """
        ext_ids = self.ovs_idl.db_get(
            'Open_vSwitch', '.', 'external_ids').execute()
        return ext_ids['system-id']

    @_sync_lock
    def sync(self):
        """Agent sync.

        This function will make sure that all networks with ports in our
        chassis are serving metadata. Also, it will tear down those namespaces
        which were serving metadata but are no longer needed.
        """
        metadata_namespaces = self.ensure_all_networks_provisioned()
        system_namespaces = ip_lib.list_network_namespaces()
        unused_namespaces = [ns for ns in system_namespaces if
                             ns.startswith(NS_PREFIX) and
                             ns not in metadata_namespaces]
        for ns in unused_namespaces:
            self.teardown_datapath(self._get_datapath_name(ns))

    @staticmethod
    def _get_veth_name(datapath):
        return ['{}{}{}'.format(n_const.TAP_DEVICE_PREFIX,
                                datapath[:10], i) for i in [0, 1]]

    @staticmethod
    def _get_datapath_name(namespace):
        return namespace[len(NS_PREFIX):]

    @staticmethod
    def _get_namespace_name(datapath):
        return NS_PREFIX + datapath

    def teardown_datapath(self, datapath):
        """Unprovision this datapath to stop serving metadata.

        This function will shutdown metadata proxy if it's running and delete
        the VETH pair, the OVS port and the namespace.
        """
        self.update_chassis_metadata_networks(datapath, remove=True)
        namespace = self._get_namespace_name(datapath)
        ip = ip_lib.IPWrapper(namespace)
        # If the namespace doesn't exist, return
        if not ip.netns.exists(namespace):
            return

        LOG.info("Cleaning up %s namespace which is not needed anymore",
                 namespace)

        metadata_driver.MetadataDriver.destroy_monitored_metadata_proxy(
            self._process_monitor, datapath, self.conf, namespace)

        veth_name = self._get_veth_name(datapath)
        self.ovs_idl.del_port(
            veth_name[0], bridge=self.conf.ovs_integration_bridge).execute()
        if ip_lib.device_exists(veth_name[0]):
            ip_lib.IPWrapper().del_veth(veth_name[0])

        ip.garbage_collect_namespace()

    def update_datapath(self, datapath):
        """Update the metadata service for this datapath.

        This function will:
        * Provision the namespace if it wasn't already in place.
        * Update the namespace if it was already serving metadata (for example,
          after binding/unbinding the first/last port of a subnet in our
          chassis).
        * Tear down the namespace if there are no more ports in our chassis
          for this datapath.
        """
        ports = self.sb_idl.get_ports_on_chassis(self.chassis)
        datapath_ports = [p for p in ports if p.type == '' and
                          str(p.datapath.uuid) == datapath]
        if datapath_ports:
            self.provision_datapath(datapath)
        else:
            self.teardown_datapath(datapath)

    def provision_datapath(self, datapath):
        """Provision the datapath so that it can serve metadata.

        This function will create the namespace and VETH pair if needed
        and assign the IP addresses to the interface corresponding to the
        metadata port of the network. It will also remove existing IP
        addresses that are no longer needed.

        :return: The metadata namespace name of this datapath
        """
        LOG.debug("Provisioning datapath %s", datapath)
        port = self.sb_idl.get_metadata_port_network(datapath)
        # If there's no metadata port or it doesn't have a MAC or IP
        # addresses, then tear the namespace down if needed. This might happen
        # when there are no subnets yet created so metadata port doesn't have
        # an IP address.
        if not (port and port.mac and
                port.external_ids.get(ovn_const.OVN_CIDRS_EXT_ID_KEY, None)):
            LOG.debug("There is no metadata port for datapath %s or it has no "
                      "MAC or IP addresses configured, tearing the namespace "
                      "down if needed", datapath)
            self.teardown_datapath(datapath)
            return

        # First entry of the mac field must be the MAC address.
        match = MAC_PATTERN.match(port.mac[0].split(' ')[0])
        # If it is not, we can't provision the namespace. Tear it down if
        # needed and log the error.
        if not match:
            LOG.error("Metadata port for datapath %s doesn't have a MAC "
                      "address, tearing the namespace down if needed",
                      datapath)
            self.teardown_datapath(datapath)
            return

        mac = match.group()
        ip_addresses = set(
            port.external_ids[ovn_const.OVN_CIDRS_EXT_ID_KEY].split(' '))
        ip_addresses.add(METADATA_DEFAULT_CIDR)
        metadata_port = MetadataPortInfo(mac, ip_addresses)

        # Create the VETH pair if it's not created. Also the add_veth function
        # will create the namespace for us.
        namespace = self._get_namespace_name(datapath)
        veth_name = self._get_veth_name(datapath)

        ip1 = ip_lib.IPDevice(veth_name[0])
        if ip_lib.device_exists(veth_name[1], namespace):
            ip2 = ip_lib.IPDevice(veth_name[1], namespace)
        else:
            LOG.debug("Creating VETH %s in %s namespace", veth_name[1],
                      namespace)
            # Might happen that the end in the root namespace exists even
            # though the other end doesn't. Make sure we delete it first if
            # that's the case.
            if ip1.exists():
                ip1.link.delete()
            ip1, ip2 = ip_lib.IPWrapper().add_veth(
                veth_name[0], veth_name[1], namespace)

        # Make sure both ends of the VETH are up
        ip1.link.set_up()
        ip2.link.set_up()

        # Configure the MAC address.
        ip2.link.set_address(metadata_port.mac)
        dev_info = ip2.addr.list()

        # Configure the IP addresses on the VETH pair and remove those
        # that we no longer need.
        current_cidrs = {dev['cidr'] for dev in dev_info}
        for ipaddr in current_cidrs - metadata_port.ip_addresses:
            ip2.addr.delete(ipaddr)
        for ipaddr in metadata_port.ip_addresses - current_cidrs:
            # NOTE(dalvarez): metadata only works on IPv4. We're doing this
            # extra check here because it could be that the metadata port has
            # an IPv6 address if there's an IPv6 subnet with SLAAC in its
            # network. Neutron IPAM will autoallocate an IPv6 address for every
            # port in the network.
            if utils.get_ip_version(ipaddr) == 4:
                ip2.addr.add(ipaddr)

        # Configure the OVS port and add external_ids:iface-id so that it
        # can be tracked by OVN.
        self.ovs_idl.add_port(self.conf.ovs_integration_bridge,
                              veth_name[0]).execute()
        self.ovs_idl.db_set(
            'Interface', veth_name[0],
            ('external_ids', {'iface-id': port.logical_port})).execute()

        # Spawn metadata proxy if it's not already running.
        metadata_driver.MetadataDriver.spawn_monitored_metadata_proxy(
            self._process_monitor, namespace, METADATA_PORT,
            self.conf, network_id=datapath)

        self.update_chassis_metadata_networks(datapath)
        return namespace

    def ensure_all_networks_provisioned(self):
        """Ensure that all datapaths are provisioned.

        This function will make sure that all datapaths with ports bound to
        our chassis have its namespace, VETH pair and OVS port created and
        metadata proxy is up and running.

        :return: A list with the namespaces that are currently serving
        metadata
        """
        # Retrieve all ports in our Chassis with type == ''
        ports = self.sb_idl.get_ports_on_chassis(self.chassis)
        datapaths = {str(p.datapath.uuid) for p in ports if p.type == ''}
        namespaces = []
        # Make sure that all those datapaths are serving metadata
        for datapath in datapaths:
            netns = self.provision_datapath(datapath)
            if netns:
                namespaces.append(netns)

        return namespaces

    def update_chassis_metadata_networks(self, datapath, remove=False):
        """Update metadata networks hosted in this chassis.

        Add or remove a datapath from the list of current datapaths that
        we're currently serving metadata.
        """
        current_dps = self.sb_idl.get_chassis_metadata_networks(self.chassis)
        updated = False
        if remove:
            if datapath in current_dps:
                current_dps.remove(datapath)
                updated = True
        else:
            if datapath not in current_dps:
                current_dps.append(datapath)
                updated = True

        if updated:
            with self.sb_idl.create_transaction(check_error=True) as txn:
                txn.add(self.sb_idl.set_chassis_metadata_networks(
                    self.chassis, current_dps))

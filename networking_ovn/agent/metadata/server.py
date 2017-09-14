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

import hashlib
import hmac

import httplib2
from neutron.agent.linux import utils as agent_utils
from neutron.conf.agent.metadata import config
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import encodeutils
import six
import six.moves.urllib.parse as urlparse
import webob

from networking_ovn._i18n import _
from networking_ovn.agent.metadata import ovsdb
from networking_ovn.common import constants as ovn_const


LOG = logging.getLogger(__name__)

MODE_MAP = {
    config.USER_MODE: 0o644,
    config.GROUP_MODE: 0o664,
    config.ALL_MODE: 0o666,
}


class MetadataProxyHandler(object):

    def __init__(self, conf):
        self.conf = conf
        self.subscribe()

    def subscribe(self):
        registry.subscribe(self.post_fork_initialize,
                           resources.PROCESS,
                           events.AFTER_INIT)

    def post_fork_initialize(self, resource, event, trigger, **kwargs):
        # We need to open a connection to OVN SouthBound database for
        # each worker so that we can process the metadata requests.
        self.sb_idl = ovsdb.MetadataAgentOvnSbIdl().start()

    @webob.dec.wsgify(RequestClass=webob.Request)
    def __call__(self, req):
        try:
            LOG.debug("Request: %s", req)

            instance_id, project_id = self._get_instance_and_project_id(req)
            if instance_id:
                return self._proxy_request(instance_id, project_id, req)
            else:
                return webob.exc.HTTPNotFound()

        except Exception:
            LOG.exception("Unexpected error.")
            msg = _('An unknown error has occurred. '
                    'Please try your request again.')
            explanation = six.text_type(msg)
            return webob.exc.HTTPInternalServerError(explanation=explanation)

    def _get_instance_and_project_id(self, req):
        remote_address = req.headers.get('X-Forwarded-For')
        network_id = req.headers.get('X-OVN-Network-ID')

        ports = self.sb_idl.get_network_port_bindings_by_ip(network_id,
                                                            remote_address)
        if len(ports) == 1:
            external_ids = ports[0].external_ids
            return (external_ids[ovn_const.OVN_DEVID_EXT_ID_KEY],
                    external_ids[ovn_const.OVN_PROJID_EXT_ID_KEY])
        return None, None

    def _proxy_request(self, instance_id, tenant_id, req):
        headers = {
            'X-Forwarded-For': req.headers.get('X-Forwarded-For'),
            'X-Instance-ID': str(instance_id),
            'X-Tenant-ID': str(tenant_id),
            'X-Instance-ID-Signature': self._sign_instance_id(instance_id)
        }

        nova_host_port = '%s:%s' % (self.conf.nova_metadata_host,
                                    self.conf.nova_metadata_port)
        LOG.debug('Request to Nova at %s', nova_host_port)
        LOG.debug(headers)
        url = urlparse.urlunsplit((
            self.conf.nova_metadata_protocol,
            nova_host_port,
            req.path_info,
            req.query_string,
            ''))

        h = httplib2.Http(
            ca_certs=self.conf.auth_ca_cert,
            disable_ssl_certificate_validation=self.conf.nova_metadata_insecure
        )
        if self.conf.nova_client_cert and self.conf.nova_client_priv_key:
            h.add_certificate(self.conf.nova_client_priv_key,
                              self.conf.nova_client_cert,
                              nova_host_port)
        resp, content = h.request(url, method=req.method, headers=headers,
                                  body=req.body)

        if resp.status == 200:
            req.response.content_type = resp['content-type']
            req.response.body = content
            LOG.debug(str(resp))
            return req.response
        elif resp.status == 403:
            LOG.warning(
                'The remote metadata server responded with Forbidden. This '
                'response usually occurs when shared secrets do not match.'
            )
            return webob.exc.HTTPForbidden()
        elif resp.status == 400:
            return webob.exc.HTTPBadRequest()
        elif resp.status == 404:
            return webob.exc.HTTPNotFound()
        elif resp.status == 409:
            return webob.exc.HTTPConflict()
        elif resp.status == 500:
            msg = _(
                'Remote metadata server experienced an internal server error.'
            )
            LOG.debug(msg)
            explanation = six.text_type(msg)
            return webob.exc.HTTPInternalServerError(explanation=explanation)
        else:
            raise Exception(_('Unexpected response code: %s') % resp.status)

    def _sign_instance_id(self, instance_id):
        secret = self.conf.metadata_proxy_shared_secret
        secret = encodeutils.to_utf8(secret)
        instance_id = encodeutils.to_utf8(instance_id)
        return hmac.new(secret, instance_id, hashlib.sha256).hexdigest()


class UnixDomainMetadataProxy(object):

    def __init__(self, conf):
        self.conf = conf
        agent_utils.ensure_directory_exists_without_file(
            cfg.CONF.metadata_proxy_socket)

    def _get_socket_mode(self):
        mode = self.conf.metadata_proxy_socket_mode
        if mode == config.DEDUCE_MODE:
            user = self.conf.metadata_proxy_user
            if (not user or user == '0' or user == 'root'
                    or agent_utils.is_effective_user(user)):
                # user is agent effective user or root => USER_MODE
                mode = config.USER_MODE
            else:
                group = self.conf.metadata_proxy_group
                if not group or agent_utils.is_effective_group(group):
                    # group is agent effective group => GROUP_MODE
                    mode = config.GROUP_MODE
                else:
                    # otherwise => ALL_MODE
                    mode = config.ALL_MODE
        return MODE_MAP[mode]

    def run(self):
        self.server = agent_utils.UnixDomainWSGIServer(
            'networking-ovn-metadata-agent')
        self.server.start(MetadataProxyHandler(self.conf),
                          self.conf.metadata_proxy_socket,
                          workers=self.conf.metadata_workers,
                          backlog=self.conf.metadata_backlog,
                          mode=self._get_socket_mode())

    def wait(self):
        self.server.wait()

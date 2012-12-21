# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Spanish National Research Council
#
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

import uuid

from keystone.common import logging
from keystone.common import wsgi
from keystone import exception
from keystone import identity
from keystone.openstack.common import cfg
from keystone.openstack.common import jsonutils

LOG = logging.getLogger(__name__)

CONF = cfg.CONF
opts = [
    cfg.StrOpt("ldap_policy", default="/etc/keystone/ldapauthz.json"),
    cfg.BoolOpt("autocreate_users", default=False),
]
CONF.register_opts(opts, group="ldapauthz")

class LDAPAuthZMiddleware(wsgi.Middleware):
    def __init__(self, *args, **kwargs):
        self.identity_api = identity.Manager()
        try:
            self.ldap_json = jsonutils.loads(
                open(CONF.ldapauthz.ldap_policy).read())
        except ValueError:
            raise exception.UnexpectedError("Bad formatted LDAP json data "
                                            "from %s" % CONF.ldapauthz.ldap_policy)
        except:
            raise exception.UnexpectedError("Could no load LDAP json data "
                                            "from %s" % CONF.ldapauthz.ldap_policy)
        super(LDAPAuthZMiddleware, self).__init__(*args, **kwargs)

    def is_applicable(self, request):
        return request.environ.get('REMOTE_USER', None) != None

    #XXX(enolfc) this is quite similar to the VOMS case, refactor!
    def _check_user(self, user_dn, tenant_name):
        try:
            user_ref =  self.identity_api.get_user_by_name(
                self.identity_api, user_dn)
        except exception.UserNotFound:
            if CONF.ldapauthz.autocreate_users:
                user_id = uuid.uuid4().hex
                LOG.info(_("Autocreating REMOTE_USER %s with id %s") %
                        (user_dn, user_id))
                user = {
                    "id": user_id,
                    "name": user_dn,
                    "enabled": True,
                }
                urii = self.identity_api.create_user(self.identity_api,
                                              user_id,
                                              user)
            else:
                LOG.debug(_("REMOTE_USER %s not found") % user_dn)
                raise exception.Unauthorized(message="User not found")
        try:
            user_ref =  self.identity_api.get_user_by_name(
                self.identity_api, user_dn)
            tenant_ref = self.identity_api.get_tenant_by_name(
                self.identity_api, tenant_name)
            if CONF.ldapauthz.autocreate_users:
                tenants = self.identity_api.get_tenants_for_user(
                    self.identity_api, user_ref["id"])
                if tenant_ref["id"] not in tenants:
                    LOG.info(_("Automatically adding user %s to tenant %s") %
                            (user_dn, tenant_ref["name"]))
                    self.identity_api.add_user_to_tenant(
                        self.identity_api,
                        tenant_ref["id"],
                        user_ref["id"])
        except exception.TenantNotFound:
            LOG.debug(_("Tenant %s not found") % tenant_name)
            raise exception.Unauthorized(message="Tenant not found")
        except exception.UserNotFound:
            LOG.debug(_("Tenant %s not found") % tenant_name)
            raise exception.Unauthorized(message="User not found")

    def _map_user(self, user_dn):
        # XXX(enolfc): missing the mapping here, only '*' considered
        mapping = self.ldap_json.get('*', {})
        tenant_name = mapping.get("tenant", None)
        if not tenant_name:
            raise exception.Unauthorized(message="Your LDAP user is not accepted")
        return tenant_name
          
    def process_request(self, request):
        if request.environ.get('REMOTE_USER', None) is None:
            # Assume that it is authenticated upstream
            return self.application

        user_dn = request.environ.get('REMOTE_USER')
        self._check_user(user_dn, self._map_user(user_dn))

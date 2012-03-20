# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

from keystone import config
from keystone.common import logging
from keystone.common.ldap.wrapper import LdapWrapper
from keystone.identity.backends.sql import Identity as SQLIdentity

def _filter_user(user_ref):
    if user_ref:
        user_ref.pop('password', None)
    return user_ref

class UserLdap(LdapWrapper):
    options_name = "user"

CONF = config.CONF

class Identity(SQLIdentity):
    def authenticate(self, user_id=None, tenant_id=None, password=None):
        """Authenticate based on a user, tenant and password.

        Expects the user object to have a password field and the tenant to be
        in the list of tenants on the user.

        """
        ldap_user = UserLdap()
        user_ref = ldap_user.authenticate(user_id, password)
        logging.debug("LDAP Authentication: %s" % user_ref is not None)
        if not user_ref:
            # let the sql identity decide
            return super(Identity, self).authenticate(user_id,
                                                      tenant_id,
                                                      password)
        tenant_ref = None
        metadata_ref = None

        tenants = self.get_tenants_for_user(user_id)
        logging.debug("LDAP user tenants: %s" % tenants)
        if tenant_id and tenant_id not in tenants:
            raise AssertionError('Invalid tenant')

        tenant_ref = self.get_tenant(tenant_id)
        if tenant_ref:
            metadata_ref = self.get_metadata(user_id, tenant_id)
        else:
            metadata_ref = {}
        return (_filter_user(user_ref), tenant_ref, metadata_ref)

    def get_tenant_users(self, tenant_id):
        sql_refs = super(Identity, self).get_tenant_users(tenant_id)
        ldap_refs = []
        tenant_ref = self.get_tenant(tenant_id)
        if tenant_ref and tenant_ref['name'] == CONF.ldap.default_tenant:
            ldap_refs = UserLdap().get_all()
        return sql_refs + ldap_refs

    def get_user(self, user_id):
        ldap_user = UserLdap()
        if not ldap_user.valid_dn(user_id):
            return super(Identity, self).get_user(user_id)
        return _filter_user(ldap_user.get_by_dn(user_id))

    def get_user_by_name(self, user_name):
        ldap_user = UserLdap()
        user_ref = ldap_user.get_by_name(user_name)
        if not user_ref:
            user_ref = self._get_user_by_name(user_name)
        return _filter_user(user_ref)

    def get_metadata(self, user_id, tenant_id):
        ldap_user = UserLdap()
        if not ldap_user.valid_dn(user_id):
            return super(Identity, self).get_metadata(user_id, tenant_id)
        else:
            ldap_roles = CONF.ldap.default_roles
            # XXX: quite inefficient, it gets all roles and then checks
            return {'roles': [x.id for x in self.list_roles()
                                          if x.name in ldap_roles]}

    def list_users(self):
        sql_refs = super(Identity, self).list_users()
        ldap_refs = UserLdap().get_all_users()
        return sql_refs + ldap_refs

    def get_tenants_for_user(self, user_id):
        ldap_user = UserLdap()
        if not ldap_user.valid_dn(user_id):
            return super(Identity, self).get_tenants_for_user(user_id)
        else:
            tenant = self.get_tenant_by_name(CONF.ldap.default_tenant)
            if tenant:
                return [tenant['id']]

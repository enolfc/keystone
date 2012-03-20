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

from keystone import identity
from keystone import config
from keystone.common.ldap.wrapper import LdapWrapper
from keystone.contrib.ec2.backends.sql import Ec2 as SQLEc2

# to get the tenant_id
conf = config.CONF


class EC2Ldap(LdapWrapper):
    options_name = "ec2"

    def _filter_cred(self, ref):
        if not ref:
            return ref
        ref['user_id'] = ref.pop('id')
        if conf.ldap.default_tenant:
            # get tenants from Identity API
            id_api = identity.Manager()
            tenant = id_api.get_tenant_by_name(
                    context=None,      # XXX context is not really used...
                    tenant_name=conf.ldap.default_tenant)
            if tenant:
                ref['tenant_id'] = tenant['id']
        return ref

    def get_by_name(self, cred_id):
        return self._filter_cred(super(EC2Ldap, self).get_by_name(cred_id))

    def get_by_dn(self, dn):
        return self._filter_cred(super(EC2Ldap, self).get_by_dn(dn))


class Ec2(SQLEc2):
    def get_credential(self, credential_id):
        cred_ref = EC2Ldap().get_by_name(credential_id)
        if not cred_ref:
            cred_ref = super(Ec2, self).get_credential(credential_id)
        return cred_ref

    def list_credentials(self, user_id):
        ec2ldap = EC2Ldap()
        if not ec2ldap.valid_dn(user_id):
            return super(Ec2, self).list_credentials(user_id)
        cred_ref = ec2ldap.get_by_dn(user_id)
        if not cred_ref:
            return []
        return [cred_ref]

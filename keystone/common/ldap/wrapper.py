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

import ldap
import ldap.dn
import ldap.filter

from keystone import config
from keystone.common import logging

conf = config.CONF


def ldap2py(val):
    LDAP_VALUES = {
        'TRUE': True,
        'FALSE': False,
    }
    try:
        return LDAP_VALUES[val]
    except KeyError:
        pass
    try:
        return int(val)
    except ValueError:
        pass
    return val


class LdapWrapper(object):
    DEFAULT_TREE_DN = "ou=Users,dc=example,dc=com"
    DEFAULT_ID_ATTR = "uid"
    DEFAULT_OBJECTCLASS = "top"
    attribute_mapping = {}

    def __init__(self):
        self.url = conf.ldap.url
        self.user = conf.ldap.user
        self.password = conf.ldap.password

        if self.options_name is not None:
            dn = '%s_tree_dn' % self.options_name
            self.tree_dn = (getattr(conf.ldap, dn) or self.DEFAULT_TREE_DN)

            idatt = '%s_id_attribute' % self.options_name
            self.id_attr = getattr(conf.ldap, idatt) or self.DEFAULT_ID_ATTR

            objclass = '%s_objectclass' % self.options_name
            self.object_class = (getattr(conf.ldap, objclass)
                                 or self.DEFAULT_OBJECTCLASS)
            for attr_map in [x for x in conf.ldap.keys()
                               if '%s_attrmap_' % self.options_name in x]:
                m = getattr(conf.ldap, attr_map) or None
                if m:
                    self.attribute_mapping[attr_map.split('_')[-1]] = m

    def valid_dn(self, dn):
        try:
            return ldap.dn.str2dn(dn)
        except ldap.DECODING_ERROR:
            return None

    def _get_connection(self, user=None, password=None):
        if not user:
            user = self.user
        if not password:
            password = self.password
        conn = None
        try:
            conn = ldap.initialize(self.url)
            conn.simple_bind_s(user, password)
        except (ldap.INVALID_CREDENTIALS, ldap.INVALID_DN_SYNTAX):
            logging.debug("Unable to connect to %s with %s" % (self.url, user))
        except ldap.SERVER_DOWN:
            logging.debug("Unable to connect to %s, server is down" % self.url)
        finally:
            return conn

    def _ldap_res_to_dict(self, res):
        obj = {'id': res[0]}
        for k in self.attribute_mapping:
            try:
                v = res[1][self.attribute_mapping.get(k, k)]
            except:
                pass
            else:
                try:
                    obj[k] = v[0]
                except IndexError:
                    obj[k] = None
        return obj

    def _ldap_search(self, conn, dn, scope, query=None):
        try:
            if query:
                res = conn.search_s(dn, scope, query)
            else:
                res = conn.search_s(dn, scope)
            return map(self._ldap_res_to_dict,
                       [(dn, dict([(typ, map(ldap2py, values))
                                for typ, values in attrs.iteritems()]))
                        for dn, attrs in res])
        except (ldap.NO_SUCH_OBJECT, ldap.INVALID_DN_SYNTAX):
            return []

    def _get_objects(self, filter=None):
        query = '(objectClass=%s)' % (self.object_class,)
        if filter is not None:
            query = '(&%s%s)' % (filter, query)
        conn = self._get_connection()
        if not conn:
            return []
        return self._ldap_search(conn, self.tree_dn,
                                 ldap.SCOPE_SUBTREE, query)

    def get_by_dn(self, dn):
        conn = self._get_connection()
        if not conn:
            return None
        try:
            l = self._ldap_search(conn, dn, ldap.SCOPE_BASE)
            if l:
                return l[0]
        except ldap.INVALID_DN_SYNTAX:
            return None

    def get_all(self):
        return self._get_objects()

    def get_by_name(self, obj_name):
        l = self._get_objects('(%s=%s)' % \
                             (self.id_attr,
                              ldap.filter.escape_filter_chars(obj_name),))
        if l:
            return l[0]
        return None

    def authenticate(self, user, password):
        conn = self._get_connection(user, password)
        if not conn:
            return []
        return self._ldap_search(conn, user, ldap.SCOPE_BASE)[0]

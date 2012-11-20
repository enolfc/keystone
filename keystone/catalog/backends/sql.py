# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 OpenStack LLC
# Copyright 2012 Canonical Ltd.
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

from keystone import catalog
from keystone.catalog import core
from keystone.common import sql
from keystone.common.sql import migration
from keystone import config
from keystone import exception


CONF = config.CONF


class Service(sql.ModelBase, sql.DictBase):
    __tablename__ = 'service'
    attributes = ['id', 'type']
    id = sql.Column(sql.String(64), primary_key=True)
    type = sql.Column(sql.String(255))
    extra = sql.Column(sql.JsonBlob())


class Endpoint(sql.ModelBase, sql.DictBase):
    __tablename__ = 'endpoint'
    attributes = ['id', 'region', 'service_id']
    id = sql.Column(sql.String(64), primary_key=True)
    region = sql.Column('region', sql.String(255))
    service_id = sql.Column(sql.String(64),
                            sql.ForeignKey('service.id'),
                            nullable=False)
    extra = sql.Column(sql.JsonBlob())


class Catalog(sql.Base, catalog.Driver):
    def db_sync(self):
        migration.db_sync()

    # Services
    def list_services(self):
        session = self.get_session()
        services = session.query(Service)
        return [s['id'] for s in list(services)]

    def get_service(self, service_id):
        session = self.get_session()
        service_ref = session.query(Service).filter_by(id=service_id).first()
        if not service_ref:
            raise exception.ServiceNotFound(service_id=service_id)
        return service_ref.to_dict()

    def delete_service(self, service_id):
        session = self.get_session()
        with session.begin():
            session.query(Endpoint).filter_by(service_id=service_id).delete()
            if not session.query(Service).filter_by(id=service_id).delete():
                raise exception.ServiceNotFound(service_id=service_id)
            session.flush()

    def create_service(self, service_id, service_ref):
        session = self.get_session()
        with session.begin():
            service = Service.from_dict(service_ref)
            session.add(service)
            session.flush()
        return service.to_dict()

    # Endpoints
    def create_endpoint(self, endpoint_id, endpoint_ref):
        session = self.get_session()
        self.get_service(endpoint_ref['service_id'])
        new_endpoint = Endpoint.from_dict(endpoint_ref)
        with session.begin():
            session.add(new_endpoint)
            session.flush()
        return new_endpoint.to_dict()

    def delete_endpoint(self, endpoint_id):
        session = self.get_session()
        with session.begin():
            if not session.query(Endpoint).filter_by(id=endpoint_id).delete():
                raise exception.EndpointNotFound(endpoint_id=endpoint_id)
            session.flush()

    def get_endpoint(self, endpoint_id):
        session = self.get_session()
        endpoint_ref = session.query(Endpoint)
        endpoint_ref = endpoint_ref.filter_by(id=endpoint_id).first()
        if not endpoint_ref:
            raise exception.EndpointNotFound(endpoint_id=endpoint_id)
        return endpoint_ref.to_dict()

    def list_endpoints(self):
        session = self.get_session()
        endpoints = session.query(Endpoint)
        return [e['id'] for e in list(endpoints)]

    def get_catalog(self, user_id, tenant_id, metadata=None):
        d = dict(CONF.iteritems())
        d.update({'tenant_id': tenant_id,
                  'user_id': user_id})
        catalog = {}

        endpoints = [self.get_endpoint(e)
                     for e in self.list_endpoints()]
        for ep in endpoints:
            service = self.get_service(ep['service_id'])
            srv_type = service['type']
            srv_name = service['name']
            region = ep['region']

            if region not in catalog:
                catalog[region] = {}

            catalog[region][srv_type] = {}

            srv_type = catalog[region][srv_type]
            srv_type['id'] = ep['id']
            srv_type['name'] = srv_name
            srv_type['publicURL'] = core.format_url(ep.get('publicurl', ''), d)
            srv_type['internalURL'] = core.format_url(ep.get('internalurl'), d)
            srv_type['adminURL'] = core.format_url(ep.get('adminurl'), d)

        return catalog

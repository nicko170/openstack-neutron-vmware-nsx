# Copyright 2017 VMware, Inc.
# All Rights Reserved
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

import copy

from neutron_lib import exceptions as n_exc
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import db as nsx_db
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_common
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgeListenerManagerFromDict(base_mgr.Nsxv3LoadbalancerBaseManager):
    def _get_virtual_server_kwargs(self, context, listener, vs_name, tags,
                                   app_profile_id, certificate=None):
        # If loadbalancer vip_port already has floating ip, use floating
        # IP as the virtual server VIP address. Else, use the loadbalancer
        # vip_address directly on virtual server.
        filters = {'port_id': [listener['loadbalancer']['vip_port_id']]}
        floating_ips = self.core_plugin.get_floatingips(context,
                                                        filters=filters)
        if floating_ips:
            lb_vip_address = floating_ips[0]['floating_ip_address']
        else:
            lb_vip_address = listener['loadbalancer']['vip_address']
        kwargs = {'enabled': listener['admin_state_up'],
                  'ip_address': lb_vip_address,
                  'port': listener['protocol_port'],
                  'application_profile_id': app_profile_id,
                  'description': listener.get('description')}
        if vs_name:
            kwargs['display_name'] = vs_name
        if tags:
            kwargs['tags'] = tags
        if listener['connection_limit'] != -1:
            kwargs['max_concurrent_connections'] = \
                listener['connection_limit']
        if 'default_pool_id' in listener:
            if listener['default_pool_id']:
                pool_binding = nsx_db.get_nsx_lbaas_pool_binding(
                    context.session, listener['loadbalancer']['id'],
                    listener['default_pool_id'])
                if pool_binding:
                    kwargs['pool_id'] = pool_binding.get('lb_pool_id')
            else:
                # Remove the default pool
                kwargs['pool_id'] = None
                kwargs['persistence_profile_id'] = ''

        ssl_profile_binding = self._get_ssl_profile_binding(
            tags, certificate=certificate)
        if (listener['protocol'] == lb_const.LB_PROTOCOL_TERMINATED_HTTPS and
            ssl_profile_binding):
            kwargs.update(ssl_profile_binding)
        elif listener['protocol'] == lb_const.LB_PROTOCOL_UDP:
            kwargs['ip_protocol'] = lb_const.LB_PROTOCOL_UDP
        return kwargs

    def _get_ssl_profile_binding(self, tags, certificate=None):
        tm_client = self.core_plugin.nsxlib.trust_management
        if certificate:
            # First check if NSX already has certificate with same pem.
            # If so, use that certificate for ssl binding. Otherwise,
            # create a new certificate on NSX.
            cert_ids = tm_client.find_cert_with_pem(
                certificate.get('certificate'))
            if cert_ids:
                nsx_cert_id = cert_ids[0]
            else:
                nsx_cert_id = tm_client.create_cert(
                    certificate.get('certificate'),
                    private_key=certificate.get('private_key'),
                    passphrase=certificate.get('passphrase'),
                    tags=tags)
            return {
                'client_ssl_profile_binding': {
                    'ssl_profile_id': self.core_plugin.client_ssl_profile,
                    'default_certificate_id': nsx_cert_id
                }
            }

    def _get_listener_tags(self, context, listener):
        tags = lb_utils.get_tags(self.core_plugin, listener['id'],
                                 lb_const.LB_LISTENER_TYPE,
                                 listener['tenant_id'],
                                 context.project_name)
        if listener['loadbalancer'].get('name'):
            tags.append({
                'scope': lb_const.LB_LB_NAME,
                'tag': listener['loadbalancer']['name'][:utils.MAX_TAG_LEN]})
        tags.append({
            'scope': lb_const.LB_LB_TYPE,
            'tag': listener['loadbalancer_id']})
        return tags

    def _validate_default_pool(self, context, listener, vs_id, completor,
                               old_listener=None):
        if listener.get('default_pool_id'):
            pool_binding = nsx_db.get_nsx_lbaas_pool_binding(
                context.session, listener['loadbalancer']['id'],
                listener['default_pool_id'])
            if (pool_binding and pool_binding['lb_vs_id'] and
                (vs_id is None or pool_binding['lb_vs_id'] != vs_id)):
                completor(success=False)
                msg = (_('Default pool %s is already used by another '
                         'listener') % listener['default_pool_id'])
                raise n_exc.BadRequest(resource='lbaas-pool', msg=msg)

            lb_common.validate_session_persistence(
                listener.get('default_pool'), listener, completor)

    def _update_default_pool_and_binding(self, context, listener, vs_data,
                                         completor, old_listener=None):
        vs_client = self.core_plugin.nsxlib.load_balancer.virtual_server
        if listener.get('default_pool_id'):
            vs_id = vs_data['id']
            lb_id = (listener.get('loadbalancer_id') or
                     listener.get('loadbalancer', {}).get('id'))
            pool_id = listener['default_pool_id']
            pool = listener['default_pool']
            old_pool = None
            if old_listener:
                old_pool = old_listener.get('default_pool')
            try:
                switch_type = lb_common.session_persistence_type_changed(
                    pool, old_pool)
                (persistence_profile_id,
                 post_process_func) = lb_utils.setup_session_persistence(
                    self.core_plugin.nsxlib,
                    pool,
                    lb_utils.get_pool_tags(context, self.core_plugin, pool),
                    switch_type, listener, vs_data)
            except nsxlib_exc.ManagerError:
                with excutils.save_and_reraise_exception():
                    completor(success=False)
                    LOG.error("Failed to configure session persistence "
                              "profile for listener %s", listener['id'])
            try:
                # Update persistence profile and pool on virtual server
                vs_client.update(
                    vs_id,
                    persistence_profile_id=persistence_profile_id)
                LOG.debug("Updated NSX virtual server %(vs_id)s with "
                          "persistence profile %(prof)s",
                          {'vs_id': vs_id,
                           'prof': persistence_profile_id})
                if post_process_func:
                    post_process_func()
            except nsxlib_exc.ManagerError:
                with excutils.save_and_reraise_exception():
                    completor(success=False)
                    LOG.error("Failed to attach persistence profile %s to "
                              "virtual server %s",
                              persistence_profile_id, vs_id)
            # Update the DB binding of the default pool
            nsx_db.update_nsx_lbaas_pool_binding(
                context.session, lb_id, pool_id, vs_id)

    def _remove_default_pool_binding(self, context, listener):
        if not listener.get('default_pool_id'):
            return

        # Remove the current default pool from the DB bindings
        lb_id = (listener.get('loadbalancer_id') or
                 listener.get('loadbalancer', {}).get('id'))
        pool_id = listener['default_pool_id']
        pool_binding = nsx_db.get_nsx_lbaas_pool_binding(
            context.session, lb_id, pool_id)
        if pool_binding:
            nsx_db.update_nsx_lbaas_pool_binding(
                context.session, lb_id, pool_id, None)

    def create(self, context, listener, completor,
               certificate=None):
        lb_id = listener['loadbalancer_id']
        nsxlib_lb = self.core_plugin.nsxlib.load_balancer
        app_client = nsxlib_lb.application_profile
        vs_client = nsxlib_lb.virtual_server
        service_client = nsxlib_lb.service
        vs_name = utils.get_name_and_uuid(listener['name'] or 'listener',
                                          listener['id'])
        tags = self._get_listener_tags(context, listener)

        if (listener['protocol'] == lb_const.LB_PROTOCOL_HTTP or
                listener['protocol'] == lb_const.LB_PROTOCOL_TERMINATED_HTTPS):
            profile_type = lb_const.LB_HTTP_PROFILE
        elif (listener['protocol'] == lb_const.LB_PROTOCOL_TCP or
              listener['protocol'] == lb_const.LB_PROTOCOL_HTTPS):
            profile_type = lb_const.LB_TCP_PROFILE
        elif listener['protocol'] == lb_const.LB_PROTOCOL_UDP:
            profile_type = lb_const.LB_UDP_PROFILE
        else:
            completor(success=False)
            msg = (_('Cannot create listener %(listener)s with '
                     'protocol %(protocol)s') %
                   {'listener': listener['id'],
                    'protocol': listener['protocol']})
            raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)
        # Validate default pool
        self._validate_default_pool(context, listener, None, completor)
        try:
            app_profile = app_client.create(
                display_name=vs_name, resource_type=profile_type, tags=tags)
            app_profile_id = app_profile['id']
            kwargs = self._get_virtual_server_kwargs(
                context, listener, vs_name, tags, app_profile_id, certificate)
            virtual_server = vs_client.create(**kwargs)
        except nsxlib_exc.ManagerError:
            completor(success=False)
            msg = _('Failed to create virtual server at NSX backend')
            raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)

        # If there is already lb:lb_service binding, add the virtual
        # server to the lb service
        binding = nsx_db.get_nsx_lbaas_loadbalancer_binding(
            context.session, lb_id)
        if not binding:
            completor(success=False)
            msg = _('Failed to get loadbalancer %s binding') % lb_id
            raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)

        lb_service_id = binding['lb_service_id']
        try:
            service_client.add_virtual_server(lb_service_id,
                                              virtual_server['id'])
        except nsxlib_exc.ManagerError:
            completor(success=False)
            msg = _('Failed to add virtual server to lb service '
                    'at NSX backend')
            # delete the backend virtual server
            vs_client.delete(virtual_server['id'])
            raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)

        nsx_db.add_nsx_lbaas_listener_binding(
            context.session, lb_id, listener['id'], app_profile_id,
            virtual_server['id'])
        self._update_default_pool_and_binding(
            context, listener, virtual_server, completor)
        completor(success=True)

    def update(self, context, old_listener, new_listener, completor,
               certificate=None):
        nsxlib_lb = self.core_plugin.nsxlib.load_balancer
        vs_client = nsxlib_lb.virtual_server
        app_client = nsxlib_lb.application_profile
        vs_name = None
        tags = None
        if new_listener['name'] != old_listener['name']:
            vs_name = utils.get_name_and_uuid(
                new_listener['name'] or 'listener',
                new_listener['id'])
            tags = self._get_listener_tags(context, new_listener)

        binding = nsx_db.get_nsx_lbaas_listener_binding(
            context.session, old_listener['loadbalancer_id'],
            old_listener['id'])
        if not binding:
            msg = (_('Cannot find listener %(listener)s binding on NSX '
                     'backend'), {'listener': old_listener['id']})
            raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)

        # Validate default pool
        self._validate_default_pool(
            context, new_listener, binding['lb_vs_id'], completor,
            old_listener=old_listener)

        try:
            vs_id = binding['lb_vs_id']
            app_profile_id = binding['app_profile_id']
            updated_kwargs = self._get_virtual_server_kwargs(
                context, new_listener, vs_name, tags, app_profile_id,
                certificate)
            vs_data = vs_client.update(vs_id, **updated_kwargs)
            if vs_name:
                app_client.update(app_profile_id, display_name=vs_name,
                                  tags=tags)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to update listener %(listener)s with '
                          'error %(error)s',
                          {'listener': old_listener['id'], 'error': e})
        # Update default pool and session persistence (do this even if the
        # default pool did not change, as there might have been an error the
        # last time)
        self._remove_default_pool_binding(context, old_listener)
        self._update_default_pool_and_binding(context, new_listener,
                                              vs_data, completor,
                                              old_listener)

        completor(success=True)

    def delete(self, context, listener, completor):
        lb_id = listener['loadbalancer_id']
        nsxlib_lb = self.core_plugin.nsxlib.load_balancer
        service_client = nsxlib_lb.service
        vs_client = nsxlib_lb.virtual_server
        app_client = nsxlib_lb.application_profile

        binding = nsx_db.get_nsx_lbaas_listener_binding(
            context.session, lb_id, listener['id'])
        if binding:
            vs_id = binding['lb_vs_id']
            app_profile_id = binding['app_profile_id']
            lb_binding = nsx_db.get_nsx_lbaas_loadbalancer_binding(
                context.session, lb_id)
            if not lb_binding:
                completor(success=False)
                msg = (_('Failed to delete virtual server: %(listener)s: '
                         'loadbalancer %(lb)s mapping was not found') %
                       {'listener': listener['id'], 'lb': lb_id})
                raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)
            try:
                lbs_id = lb_binding.get('lb_service_id')
                lb_service = service_client.get(lbs_id)
                vs_list = lb_service.get('virtual_server_ids')
                if vs_list and vs_id in vs_list:
                    service_client.remove_virtual_server(lbs_id, vs_id)
            except (nsxlib_exc.ResourceNotFound, nsx_exc.NsxResourceNotFound):
                LOG.error('Loadbalancing service %s not found at backend' %
                          lbs_id)
            except nsxlib_exc.ManagerError:
                completor(success=False)
                msg = (_('Failed to remove virtual server: %(listener)s '
                         'from lb service %(lbs)s') %
                       {'listener': listener['id'], 'lbs': lbs_id})
                raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)
            try:
                persist_profile_id = None
                if listener.get('default_pool_id'):
                    vs_data = vs_client.update(vs_id, pool_id='')
                    persist_profile_id = vs_data.get('persistence_profile_id')
                    # Update pool binding to disassociate virtual server
                    self._remove_default_pool_binding(context, listener)
                vs_client.delete(vs_id)
                # Also delete the old session persistence profile
                if persist_profile_id:
                    lb_utils.delete_persistence_profile(
                        self.core_plugin.nsxlib, persist_profile_id)
            except (nsxlib_exc.ResourceNotFound, nsx_exc.NsxResourceNotFound):
                LOG.error("virtual server not found on nsx: %(vs)s" %
                          {'vs': vs_id})
            except nsxlib_exc.ManagerError:
                completor(success=False)
                msg = (_('Failed to delete virtual server: %(listener)s') %
                       {'listener': listener['id']})
                raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)
            try:
                app_client.delete(app_profile_id)
            except (nsxlib_exc.ResourceNotFound, nsx_exc.NsxResourceNotFound):
                LOG.error("application profile not found on nsx: %s",
                          app_profile_id)
            except nsxlib_exc.ManagerError as e:
                # This probably means that the application profile is being
                # used by a listener outside of openstack
                LOG.error("Failed to delete application profile %s from the "
                          "NSX: %s", app_profile_id, e)

            # Delete imported NSX cert if there is any
            cert_tags = [{'scope': lb_const.LB_LISTENER_TYPE,
                          'tag': listener['id']}]
            results = self.core_plugin.nsxlib.search_by_tags(
                tags=cert_tags)
            # Only delete object related to certificate used by listener
            for res_obj in results['results']:
                res_type = res_obj.get('resource_type')
                if res_type in lb_const.LB_CERT_RESOURCE_TYPE:
                    tm_client = self.core_plugin.nsxlib.trust_management
                    try:
                        tm_client.delete_cert(res_obj['id'])
                    except nsxlib_exc.ManagerError:
                        LOG.error("Exception thrown when trying to delete "
                                  "certificate: %(cert)s",
                                  {'cert': res_obj['id']})

            nsx_db.delete_nsx_lbaas_listener_binding(
                context.session, lb_id, listener['id'])

        completor(success=True)

    def delete_cascade(self, context, listener, completor):
        self.delete(context, listener, completor)


def stats_getter(context, core_plugin, ignore_list=None):
    """Update Octavia statistics for each listener (virtual server)"""
    stat_list = []
    lb_service_client = core_plugin.nsxlib.load_balancer.service
    # Go over all the loadbalancers & services
    lb_bindings = nsx_db.get_nsx_lbaas_loadbalancer_bindings(
        context.session)
    for lb_binding in lb_bindings:
        if ignore_list and lb_binding['loadbalancer_id'] in ignore_list:
            continue

        lb_service_id = lb_binding.get('lb_service_id')
        try:
            # get the NSX statistics for this LB service
            # Since this is called periodically, silencing it at the logs
            rsp = lb_service_client.get_stats(lb_service_id, silent=True)
            if rsp and 'virtual_servers' in rsp:
                # Go over each virtual server in the response
                for vs in rsp['virtual_servers']:
                    # look up the virtual server in the DB
                    vs_bind = nsx_db.get_nsx_lbaas_listener_binding_by_vs_id(
                        context.session, vs['virtual_server_id'])
                    if vs_bind and 'statistics' in vs:
                        vs_stats = vs['statistics']
                        stats = copy.copy(lb_const.LB_EMPTY_STATS)
                        stats['id'] = vs_bind.listener_id
                        stats['request_errors'] = 0  # currently unsupported
                        for stat, stat_value in lb_const.LB_STATS_MAP.items():
                            lb_stat = stat_value
                            stats[stat] += vs_stats[lb_stat]
                        stat_list.append(stats)

        except nsxlib_exc.ManagerError:
            pass

    return stat_list

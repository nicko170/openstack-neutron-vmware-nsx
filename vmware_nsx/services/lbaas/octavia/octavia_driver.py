# Copyright 2018 VMware, Inc.
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
import ipaddress
import socket
import time

from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging as messaging
from oslo_messaging.rpc import dispatcher
import tenacity

from octavia.api.drivers import utils as oct_utils
from octavia.db import api as db_apis
from octavia.db import repositories
from octavia_lib.api.drivers import driver_lib
from octavia_lib.api.drivers import exceptions
from octavia_lib.api.drivers import provider_base as driver_base
from octavia_lib.common import constants as o_const

from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.octavia import constants as d_const

LOG = logging.getLogger(__name__)
cfg.CONF.import_group('oslo_messaging', 'octavia.common.config')

TRANSPORT = None
RPC_SERVER = None


def _log_before_retry(retry_state):
    if retry_state.attempt_number > 1:
        LOG.warning("Retrying the call to _update_loadbalancer_status due to "
                    "timeout")


def get_transport():
    global TRANSPORT
    if not TRANSPORT:
        TRANSPORT = messaging.get_rpc_transport(cfg.CONF)
    return TRANSPORT


def get_rpc_server(target, endpoints, access_policy):
    global RPC_SERVER
    if not RPC_SERVER:
        RPC_SERVER = messaging.get_rpc_server(
            TRANSPORT, target, endpoints, executor='threading',
            access_policy=access_policy)
    return RPC_SERVER


# List of keys per object type that will not be sent to the listener
unsupported_keys = {'Loadbalancer': ['vip_qos_policy_id'],
                    'Listener': ['sni_container_refs',
                                 'insert_headers',
                                 'timeout_client_data',
                                 'timeout_member_connect',
                                 'timeout_member_data',
                                 'timeout_tcp_inspect'],
                    'HealthMonitor': ['max_retries_down'],
                    'Member': ['monitor_address', 'monitor_port']}


class NSXOctaviaDriver(driver_base.ProviderDriver):
    @log_helpers.log_method_call
    def __init__(self):
        super(NSXOctaviaDriver, self).__init__()
        self._init_rpc_messaging()
        self.repositories = repositories.Repositories()

    @log_helpers.log_method_call
    def _init_rpc_messaging(self):
        topic = d_const.OCTAVIA_TO_DRIVER_TOPIC
        transport = get_transport()
        target = messaging.Target(topic=topic, exchange="common",
                                  namespace='control', fanout=False,
                                  version='1.0')
        self.client = messaging.RPCClient(transport, target)

    def get_obj_project_id(self, obj_type, obj_dict):
        if obj_dict.get('project_id'):
            return obj_dict['project_id']
        if obj_dict.get('tenant_id'):
            return obj_dict['tenant_id']

        # look for the project id of the attached objects
        project_id = None
        if obj_dict.get('loadbalancer_id'):
            db_lb = self.repositories.load_balancer.get(
                db_apis.get_session(), id=obj_dict['loadbalancer_id'])
            if db_lb:
                project_id = db_lb.project_id
        if not project_id and obj_dict.get('pool_id'):
            db_pool = self.repositories.pool.get(
                db_apis.get_session(), id=obj_dict['pool_id'])
            if db_pool:
                project_id = db_pool.load_balancer.project_id
        if not project_id and obj_dict.get('listener_id'):
            db_list = self.repositories.listener.get(
                db_apis.get_session(), id=obj_dict['listener_id'])
            if db_list:
                project_id = db_list.load_balancer.project_id
        if not project_id and obj_dict.get('l7policy_id'):
            db_policy = self.repositories.l7policy.get(
                db_apis.get_session(), id=obj_dict['l7policy_id'])
            if db_policy:
                if db_policy.listener:
                    db_lb = db_policy.listener.load_balancer
                elif db_policy.redirect_pool:
                    db_lb = db_policy.redirect_pool.load_balancer
                if db_lb:
                    project_id = db_lb.project_id

        if not project_id:
            LOG.warning("Could not find the tenant id for %(type)s "
                        "%(obj)s", {'type': obj_type, 'obj': obj_dict})
        return project_id

    def _get_load_balancer_dict(self, loadbalancer_id):
        if not loadbalancer_id:
            return
        db_lb = self.repositories.load_balancer.get(
            db_apis.get_session(), id=loadbalancer_id)
        if not db_lb:
            return
        lb_dict = {'name': db_lb.name, 'id': loadbalancer_id}
        if db_lb.vip:
            lb_dict['vip_port_id'] = db_lb.vip.port_id
            lb_dict['vip_address'] = db_lb.vip.ip_address
            lb_dict['vip_port_id'] = db_lb.vip.port_id
            lb_dict['vip_network_id'] = db_lb.vip.network_id
            lb_dict['vip_subnet_id'] = db_lb.vip.subnet_id
        # Add the listeners to the dictionary
        listeners = []
        for listener in db_lb.listeners:
            db_listener = self.repositories.listener.get(
                db_apis.get_session(), id=listener.id)
            listener_obj = oct_utils.db_listener_to_provider_listener(
                db_listener)
            listener_dict = listener_obj.to_dict(
                recurse=False, render_unsets=True)
            # Add allowed cidrs too
            listener_dict['allowed_cidrs'] = listener_obj.allowed_cidrs
            listeners.append(listener_dict)
        lb_dict['listeners'] = listeners
        return lb_dict

    def _get_listener_in_pool_dict(self, pool_dict, is_update):
        if 'listener' not in pool_dict:
            if pool_dict.get('listener_id'):
                db_listener = self.repositories.listener.get(
                    db_apis.get_session(), id=pool_dict['listener_id'])
                listener_obj = oct_utils.db_listener_to_provider_listener(
                    db_listener)
                listener_dict = listener_obj.to_dict(
                    recurse=False, render_unsets=True)
                listener_dict['id'] = listener_dict['listener_id']
                listener_dict['l7_policies'] = listener_dict['l7policies']
                # Add the loadbalancer to the listener dict
                if pool_dict.get('loadbalancer_id'):
                    # Generate a loadbalancer object
                    listener_dict['loadbalancer'] = (
                        self._get_load_balancer_dict(
                            pool_dict['loadbalancer_id']))
                pool_dict['listener'] = listener_dict
                if 'listeners' not in pool_dict:
                    # multiple listeners is not really supported yet
                    pool_dict['listeners'] = [listener_dict]
            # Do not add listener in update situation, as we want to use
            # the original listener of this pool
            elif not is_update:
                pool_dict['listener'] = None
                if 'listeners' not in pool_dict:
                    pool_dict['listeners'] = []

    def _get_pool_dict(self, pool_id, is_update, parent_project_id=None):
        if not pool_id:
            return {}
        db_pool = self.repositories.pool.get(db_apis.get_session(), id=pool_id)
        if not db_pool:
            return {}
        pool_obj = oct_utils.db_pool_to_provider_pool(db_pool)
        pool_dict = pool_obj.to_dict(recurse=True, render_unsets=True)
        pool_dict['id'] = pool_id
        # Get the load balancer object
        if pool_dict.get('loadbalancer_id'):
            # Generate a loadbalancer object
            pool_dict['loadbalancer'] = self._get_load_balancer_dict(
                pool_dict['loadbalancer_id'])
        if 'listener' not in pool_dict:
            self._get_listener_in_pool_dict(pool_dict, is_update)
        # make sure this pool has a project id
        if not pool_dict.get('project_id'):
            project_id = self.get_obj_project_id('Pool', pool_dict)
            if project_id is None:
                project_id = parent_project_id
            pool_dict['tenant_id'] = pool_dict['project_id'] = project_id
        for member in pool_dict.get('members', []):
            member['id'] = member['member_id']

        return pool_dict

    def _get_hm_dict(self, hm_id, is_update):
        if not hm_id:
            return {}
        db_hm = self.repositories.health_monitor.get(
            db_apis.get_session(), id=hm_id)
        if not db_hm:
            return {}
        hm_obj = oct_utils.db_HM_to_provider_HM(db_hm)
        hm_dict = hm_obj.to_dict(recurse=True, render_unsets=True)
        hm_dict['id'] = hm_id
        # Get the pol object
        if hm_dict.get('pool_id'):
            hm_dict['pool'] = self._get_pool_dict(
                hm_dict['pool_id'], is_update)
        return hm_dict

    def update_policy_dict(self, policy_dict, policy_obj, is_update=False):
        if policy_dict.get('listener_id'):
            db_list = self.repositories.listener.get(
                db_apis.get_session(), id=policy_dict['listener_id'])
            list_obj = oct_utils.db_listener_to_provider_listener(db_list)
            list_dict = list_obj.to_dict(recurse=True, render_unsets=True)
            list_dict['id'] = policy_dict['listener_id']
            policy_dict['listener'] = list_dict
        if policy_obj.rules:
            policy_dict['rules'] = []
            for rule in policy_obj.rules:
                if isinstance(rule, dict):
                    rule_dict = rule
                else:
                    rule_dict = rule.to_dict(recurse=False, render_unsets=True)
                rule_dict['id'] = rule_dict['l7rule_id']
                policy_dict['rules'].append(rule_dict)
        elif not is_update:
            policy_dict['rules'] = []

    def _remove_unsupported_keys(self, obj_type, obj_dict):
        for key in unsupported_keys.get(obj_type, []):
            if key in obj_dict:
                if obj_dict.get(key):
                    LOG.warning("Ignoring %(key)s:%(val)s in %(type)s as the "
                                "NSX plugin does not currently support it",
                                {'key': key, 'val': obj_dict[key],
                                 'type': obj_type})
                del obj_dict[key]

    def obj_to_dict(self, obj, is_update=False, project_id=None):
        obj_type = obj.__class__.__name__
        # create a dictionary out of the object
        render_unsets = bool(not is_update)
        obj_dict = obj.to_dict(recurse=True, render_unsets=render_unsets)

        # Update the dictionary to match what the nsx driver expects
        if not project_id:
            project_id = self.get_obj_project_id(obj_type, obj_dict)
        obj_dict['tenant_id'] = obj_dict['project_id'] = project_id

        if 'id' not in obj_dict:
            obj_dict['id'] = obj_dict.get('%s_id' % obj_type.lower())

        if not obj_dict.get('name') and not is_update:
            obj_dict['name'] = ""

        self._remove_unsupported_keys(obj_type, obj_dict)

        if obj_type == 'LoadBalancer':
            # clean listeners and pools for update case:
            if 'listeners' in obj_dict:
                if is_update and not obj_dict['listeners']:
                    del obj_dict['listeners']
                else:
                    if obj_dict['listeners'] is None:
                        obj_dict['listeners'] = []
                    for listener in obj_dict['listeners']:
                        listener['id'] = listener['listener_id']
                        for policy in listener.get('l7policies', []):
                            policy['id'] = policy['l7policy_id']
                            for rule in policy.get('rules', []):
                                rule['id'] = rule['l7rule_id']
            if 'pools' in obj_dict:
                if is_update and not obj_dict['pools']:
                    del obj_dict['pools']
                else:
                    if obj_dict['pools'] is None:
                        obj_dict['pools'] = []
                    for pool in obj_dict['pools']:
                        pool['id'] = pool['pool_id']
                        for member in pool.get('members', []):
                            member['id'] = member['member_id']
                        if pool.get('healthmonitor'):
                            pool['healthmonitor'] = self._get_hm_dict(
                                pool['healthmonitor']['healthmonitor_id'],
                                is_update)
                        pool['tenant_id'] = project_id

        elif obj_type == 'Listener':
            if 'l7policies' in obj_dict:
                obj_dict['l7_policies'] = obj_dict['l7policies']
            if obj_dict.get('loadbalancer_id'):
                # Generate a loadbalancer object
                obj_dict['loadbalancer'] = self._get_load_balancer_dict(
                    obj_dict['loadbalancer_id'])
            if obj_dict.get('default_pool_id'):
                # Generate the default pool object
                obj_dict['default_pool'] = self._get_pool_dict(
                    obj_dict['default_pool_id'], is_update, project_id)

        elif obj_type == 'Pool':
            if 'listener' not in obj_dict:
                self._get_listener_in_pool_dict(obj_dict, is_update)
            if obj_dict.get('loadbalancer_id'):
                # Generate a loadbalancer object
                obj_dict['loadbalancer'] = self._get_load_balancer_dict(
                    obj_dict['loadbalancer_id'])
            if obj_dict.get('healthmonitor'):
                obj_dict['healthmonitor']['id'] = obj_dict[
                    'healthmonitor']['healthmonitor_id']
            for member in obj_dict.get('members', []):
                member['id'] = member['member_id']

        elif obj_type == 'Member':
            # Get the pool object
            if obj_dict.get('pool_id'):
                obj_dict['pool'] = self._get_pool_dict(
                    obj_dict['pool_id'], is_update)
                obj_dict['loadbalancer'] = None
                if 'loadbalancer' in obj_dict['pool']:
                    obj_dict['loadbalancer'] = obj_dict['pool']['loadbalancer']
                    if not obj_dict.get('subnet_id'):
                        # Use the parent vip_subnet_id instead
                        obj_dict['subnet_id'] = obj_dict['loadbalancer'][
                            'vip_subnet_id']
            elif not is_update:
                # Do not set pool & LB if in update situation, as we want to
                # use the original data of this member
                obj_dict['pool'] = None
                obj_dict['loadbalancer'] = None

        elif obj_type == 'HealthMonitor':
            # Get the pool object
            if obj_dict.get('pool_id'):
                obj_dict['pool'] = self._get_pool_dict(
                    obj_dict['pool_id'], is_update)

        elif obj_type == 'L7Policy':
            self.update_policy_dict(obj_dict, obj, is_update=is_update)

        elif obj_type == 'L7Rule':
            # Get the L7 policy object
            if obj_dict.get('l7policy_id'):
                db_policy = self.repositories.l7policy.get(
                    db_apis.get_session(), id=obj_dict['l7policy_id'])
                policy_obj = oct_utils.db_l7policy_to_provider_l7policy(
                    db_policy)
                policy_dict = policy_obj.to_dict(
                    recurse=True, render_unsets=True)
                policy_dict['id'] = obj_dict['l7policy_id']
                self.update_policy_dict(
                    policy_dict, policy_obj, is_update=is_update)

                # During create operations, the created rule will not be
                # retrieved from Octavia DB, as it is updated later on
                if policy_dict.get('rules') is None:
                    policy_dict['rules'] = []
                if (obj_dict['l7rule_id'] not in
                        [r['l7rule_id'] for r in
                         policy_dict.get('rules', [])]):
                    # Deepcopy obj_dict to avoid circular reference while
                    # serializing to JSON
                    policy_dict['rules'].append(copy.deepcopy(obj_dict))
                obj_dict['policy'] = policy_dict

        LOG.debug("Translated %(type)s to dictionary: %(obj)s",
                  {'type': obj_type, 'obj': obj_dict})
        return obj_dict

    # Load Balancer
    @log_helpers.log_method_call
    def create_vip_port(self, loadbalancer_id, project_id, vip_dictionary):
        raise exceptions.NotImplementedError()

    @log_helpers.log_method_call
    def loadbalancer_create(self, loadbalancer):
        kw = {'loadbalancer': self.obj_to_dict(loadbalancer)}
        self.client.cast({}, 'loadbalancer_create', **kw)

    @log_helpers.log_method_call
    def loadbalancer_delete(self, loadbalancer, cascade=False):
        kw = {'loadbalancer': self.obj_to_dict(loadbalancer),
              'cascade': cascade}
        self.client.cast({}, 'loadbalancer_delete', **kw)

    @log_helpers.log_method_call
    def loadbalancer_failover(self, loadbalancer_id):
        LOG.error('Loadbalancer failover is handled by platform')
        raise exceptions.NotImplementedError()

    @log_helpers.log_method_call
    def loadbalancer_update(self, old_loadbalancer, new_loadbalancer):
        old_dict = self.obj_to_dict(old_loadbalancer)
        new_dict = copy.deepcopy(old_dict)
        new_dict.update(self.obj_to_dict(
            new_loadbalancer, is_update=True,
            project_id=old_dict.get('project_id')))
        kw = {'old_loadbalancer': old_dict,
              'new_loadbalancer': new_dict}
        self.client.cast({}, 'loadbalancer_update', **kw)

    def _create_lb_certificate(self, listener_dict):
        # Extract Octavia certificate data into a dict which is readable by
        # the listener_mgr
        if listener_dict.get('default_tls_container_ref'):
            cert_data = listener_dict.get('default_tls_container_data', {})
            return {'ref': listener_dict.get('default_tls_container_ref'),
                    'certificate': cert_data.get('certificate'),
                    'private_key': cert_data.get('private_key'),
                    'passphrase': cert_data.get('passphrase')}

    # Listener
    @log_helpers.log_method_call
    def listener_create(self, listener):
        dict_list = self.obj_to_dict(listener)
        cert = self._create_lb_certificate(dict_list)
        kw = {'listener': dict_list, 'cert': cert}
        self.client.cast({}, 'listener_create', **kw)

    @log_helpers.log_method_call
    def listener_delete(self, listener):
        kw = {'listener': self.obj_to_dict(listener)}
        self.client.cast({}, 'listener_delete', **kw)

    @log_helpers.log_method_call
    def listener_update(self, old_listener, new_listener):
        old_dict = self.obj_to_dict(old_listener)
        new_dict = copy.deepcopy(old_dict)
        new_dict.update(self.obj_to_dict(
            new_listener, is_update=True,
            project_id=old_dict.get('project_id')))
        cert = self._create_lb_certificate(new_dict)
        kw = {'old_listener': old_dict,
              'new_listener': new_dict,
              'cert': cert}
        self.client.cast({}, 'listener_update', **kw)

    # Pool
    @log_helpers.log_method_call
    def pool_create(self, pool):
        kw = {'pool': self.obj_to_dict(pool)}
        self.client.cast({}, 'pool_create', **kw)

    @log_helpers.log_method_call
    def pool_delete(self, pool):
        kw = {'pool': self.obj_to_dict(pool)}
        self.client.cast({}, 'pool_delete', **kw)

    @log_helpers.log_method_call
    def pool_update(self, old_pool, new_pool):
        old_dict = self.obj_to_dict(old_pool)
        new_dict = copy.deepcopy(old_dict)
        new_pool_dict = self.obj_to_dict(
            new_pool, is_update=True, project_id=old_dict.get('project_id'))
        new_dict.update(new_pool_dict)
        kw = {'old_pool': old_dict,
              'new_pool': new_dict}
        self.client.cast({}, 'pool_update', **kw)

    # Member
    @log_helpers.log_method_call
    def member_create(self, member):
        kw = {'member': self.obj_to_dict(member)}
        self.client.cast({}, 'member_create', **kw)

    @log_helpers.log_method_call
    def member_delete(self, member):
        kw = {'member': self.obj_to_dict(member)}
        self.client.cast({}, 'member_delete', **kw)

    @log_helpers.log_method_call
    def member_update(self, old_member, new_member):
        old_dict = self.obj_to_dict(old_member)
        new_dict = copy.deepcopy(old_dict)
        new_dict.update(self.obj_to_dict(
            new_member, is_update=True, project_id=old_dict.get('project_id')))
        kw = {'old_member': old_dict,
              'new_member': new_dict}
        self.client.cast({}, 'member_update', **kw)

    @log_helpers.log_method_call
    def member_batch_update(self, members):
        raise NotImplementedError()

    # Health Monitor
    @log_helpers.log_method_call
    def health_monitor_create(self, healthmonitor):
        if healthmonitor.type == lb_const.LB_HEALTH_MONITOR_UDP_CONNECT:
            raise exceptions.UnsupportedOptionError(
                user_fault_string="UDP-CONNECT monitor is not supported")

        kw = {'healthmonitor': self.obj_to_dict(healthmonitor)}
        self.client.cast({}, 'healthmonitor_create', **kw)

    @log_helpers.log_method_call
    def health_monitor_delete(self, healthmonitor):
        kw = {'healthmonitor': self.obj_to_dict(healthmonitor)}
        self.client.cast({}, 'healthmonitor_delete', **kw)

    @log_helpers.log_method_call
    def health_monitor_update(self, old_healthmonitor, new_healthmonitor):
        old_dict = self.obj_to_dict(old_healthmonitor)
        new_dict = copy.deepcopy(old_dict)
        new_dict.update(self.obj_to_dict(
            new_healthmonitor, is_update=True,
            project_id=old_dict.get('project_id')))
        kw = {'old_healthmonitor': old_dict,
              'new_healthmonitor': new_dict}
        self.client.cast({}, 'healthmonitor_update', **kw)

    # L7 Policy
    @log_helpers.log_method_call
    def l7policy_create(self, l7policy):
        kw = {'l7policy': self.obj_to_dict(l7policy)}
        self.client.cast({}, 'l7policy_create', **kw)

    @log_helpers.log_method_call
    def l7policy_delete(self, l7policy):
        kw = {'l7policy': self.obj_to_dict(l7policy)}
        self.client.cast({}, 'l7policy_delete', **kw)

    @log_helpers.log_method_call
    def l7policy_update(self, old_l7policy, new_l7policy):
        old_dict = self.obj_to_dict(old_l7policy)
        new_dict = copy.deepcopy(old_dict)
        new_dict.update(self.obj_to_dict(
            new_l7policy, is_update=True,
            project_id=old_dict.get('project_id')))
        kw = {'old_l7policy': old_dict,
              'new_l7policy': new_dict}
        self.client.cast({}, 'l7policy_update', **kw)

    # L7 Rule
    @log_helpers.log_method_call
    def l7rule_create(self, l7rule):
        kw = {'l7rule': self.obj_to_dict(l7rule)}
        self.client.cast({}, 'l7rule_create', **kw)

    @log_helpers.log_method_call
    def l7rule_delete(self, l7rule):
        kw = {'l7rule': self.obj_to_dict(l7rule)}
        self.client.cast({}, 'l7rule_delete', **kw)

    @log_helpers.log_method_call
    def l7rule_update(self, old_l7rule, new_l7rule):
        old_dict = self.obj_to_dict(old_l7rule)
        new_dict = copy.deepcopy(old_dict)
        new_dict.update(self.obj_to_dict(
            new_l7rule, is_update=True, project_id=old_dict.get('project_id')))
        kw = {'old_l7rule': old_dict,
              'new_l7rule': new_dict}
        self.client.cast({}, 'l7rule_update', **kw)

    # Flavor
    @log_helpers.log_method_call
    def get_supported_flavor_metadata(self):
        try:
            md = self.client.call({}, 'get_supported_flavor_metadata')
        except Exception:
            raise exceptions.DriverError()

        if md is None:
            raise exceptions.NotImplementedError()
        return md

    @log_helpers.log_method_call
    def validate_flavor(self, flavor_metadata):
        kw = {'flavor_metadata': flavor_metadata}
        try:
            result = self.client.call({}, 'validate_flavor', **kw)
        except Exception:
            raise exceptions.DriverError()

        if result and result.get('valid', False):
            return None
        if result:
            raise exceptions.UnsupportedOptionError()
        raise exceptions.NotImplementedError()

    # AZ
    @log_helpers.log_method_call
    def get_supported_availability_zone_metadata(self):
        try:
            md = self.client.call(
                {}, 'get_supported_availability_zone_metadata')
        except Exception:
            raise exceptions.DriverError()

        if md is None:
            raise exceptions.NotImplementedError()
        return md

    @log_helpers.log_method_call
    def validate_availability_zone(self, availability_zone_metadata):
        kw = {'availability_zone_metadata': availability_zone_metadata}
        try:
            result = self.client.call({}, 'validate_availability_zone', **kw)
        except Exception:
            raise exceptions.DriverError()

        if result and result.get('valid', False):
            return None
        if result:
            raise exceptions.UnsupportedOptionError()
        raise exceptions.NotImplementedError()


class NSXOctaviaDriverEndpoint(driver_lib.DriverLibrary):
    target = messaging.Target(namespace="control", version='1.0')

    def __init__(self, status_socket=driver_lib.DEFAULT_STATUS_SOCKET,
                 stats_socket=driver_lib.DEFAULT_STATS_SOCKET, **kwargs):
        super(NSXOctaviaDriverEndpoint, self).__init__(
            status_socket, stats_socket, **kwargs)
        self.repositories = repositories.Repositories()

    def _removed_not_in_db(self, status, status_type, db_type):
        if not status.get(status_type):
            return

        fixed_data = []
        for obj in status[status_type]:
            db_rep = getattr(self.repositories, db_type)
            db_obj = db_rep.get(self.db_session, id=obj['id'])
            if db_obj:
                fixed_data.append(obj)
            else:
                LOG.warning("Skipping update of %s %s - not in DB",
                            db_type, obj['id'])
        status[status_type] = fixed_data

    @log_helpers.log_method_call
    def update_loadbalancer_status(self, ctxt, status):
        # refresh the driver lib session
        self.db_session = db_apis.get_session()
        if status.get('members', []):
            # Make sure all the members have ids
            fixed_members = []
            for member in status['members']:
                if member.get('id'):
                    fixed_members.append(member)
                elif member.get('member_ip') and member.get('pool_id'):
                    # Find the member id by the normalized member-ip in the
                    # octavia DB
                    norm_ip = str(ipaddress.ip_address(member['member_ip']))
                    db_members, _ = self.repositories.member.get_all(
                        self.db_session,
                        pool_id=member['pool_id'])
                    for db_member in db_members:
                        norm_db = str(ipaddress.ip_address(
                            db_member.ip_address))
                        if norm_db == norm_ip:
                            member['id'] = db_member.id
                            fixed_members.append(member)
                            break
                    if not member.get('id'):
                        LOG.warning("update_loadbalancer_status: could not "
                                    "find the ID of member %s of pool %s",
                                    member['member_ip'], member['pool_id'])
            status['members'] = fixed_members

        # Remove resources that are missing from the octavia DB. This could be
        # a result of old/other deployments or neutron-lbaas loadbalancers not
        # yet migrated to octavia
        self._removed_not_in_db(status, 'loadbalancers', 'load_balancer')
        self._removed_not_in_db(status, 'listeners', 'listener')
        self._removed_not_in_db(status, 'pools', 'pool')

        try:
            return self._update_loadbalancer_status(status)
        except exceptions.UpdateStatusError as e:
            LOG.error("Failed to update Octavia loadbalancer status. "
                      "Status %s, Error %s", status, e.fault_string)

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(30), reraise=True,
        wait=tenacity.wait_exponential(multiplier=1, min=1, max=5),
        before=_log_before_retry,
        retry=tenacity.retry_if_exception_type(
            exceptions.UpdateStatusError))
    def _update_loadbalancer_status(self, status):
        return super(NSXOctaviaDriverEndpoint,
              self).update_loadbalancer_status(status)

    @log_helpers.log_method_call
    def update_listener_statistics(self, ctxt, statistics):
        # refresh the driver lib session
        self.db_session = db_apis.get_session()
        # Remove listeners that are missing from the octavia DB. This could be
        # a result of old/other deployments or neutron-lbaas loadbalancers not
        # yet migrated to octavia
        self._removed_not_in_db(statistics, 'listeners', 'listener')
        if not statistics.get('listeners'):
            return
        try:
            return super(NSXOctaviaDriverEndpoint,
                         self).update_listener_statistics(statistics)
        except exceptions.UpdateStatisticsError as e:
            LOG.error("Failed to update Octavia listener statistics. "
                      "Stats %s, Error %s", statistics, e.fault_string)

    @log_helpers.log_method_call
    def get_active_loadbalancers(self, ctxt):
        # refresh the driver lib session
        self.db_session = db_apis.get_session()
        lbs, _ = self.repositories.load_balancer.get_all(
            self.db_session, provisioning_status=o_const.ACTIVE)
        return [lb.id for lb in lbs]


@log_helpers.log_method_call
def vmware_nsx_provider_agent(exit_event):
    # Initialize RPC listener
    topic = d_const.DRIVER_TO_OCTAVIA_TOPIC
    server = socket.gethostname()
    target = messaging.Target(topic=topic, server=server,
                              exchange="common", fanout=False)
    endpoints = [NSXOctaviaDriverEndpoint()]
    access_policy = dispatcher.DefaultRPCAccessPolicy
    get_transport()
    octavia_server = get_rpc_server(target, endpoints, access_policy)
    octavia_server.start()

    LOG.info('VMware NSX Octavia provider agent has started.')
    while not exit_event.is_set():
        time.sleep(1)
    LOG.info('VMware NSX Octavia provider agent is exiting.')

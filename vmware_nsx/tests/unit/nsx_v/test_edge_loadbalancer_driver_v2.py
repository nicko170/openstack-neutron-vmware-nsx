# Copyright 2015 VMware, Inc.
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

from unittest import mock

from oslo_config import cfg

from neutron.services.flavors import flavors_plugin
from neutron.tests import base
from neutron_lib import context
from neutron_lib import exceptions as n_exc

from vmware_nsx.db import nsxv_db
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas.nsx_v.implementation import healthmon_mgr
from vmware_nsx.services.lbaas.nsx_v.implementation import l7policy_mgr
from vmware_nsx.services.lbaas.nsx_v.implementation import l7rule_mgr
from vmware_nsx.services.lbaas.nsx_v.implementation import listener_mgr
from vmware_nsx.services.lbaas.nsx_v.implementation import loadbalancer_mgr
from vmware_nsx.services.lbaas.nsx_v.implementation import member_mgr
from vmware_nsx.services.lbaas.nsx_v.implementation import pool_mgr
from vmware_nsx.services.lbaas.nsx_v import lbaas_common as lb_common
from vmware_nsx.services.lbaas.octavia import octavia_listener
from vmware_nsx.tests.unit.services.lbaas import lb_data_models as lb_models
from vmware_nsx.tests.unit.services.lbaas import lb_translators

# TODO(asarfaty): Use octavia api for those tests
LB_VIP = '10.0.0.10'
LB_SUBNET = 'some-subnet'
LB_EDGE_ID = 'edge-x'
LB_ID = 'xxx-xxx'
LB_TENANT_ID = 'yyy-yyy'
LB_VIP_FWR_ID = 'fwr-1'
LB_BINDING = {'loadbalancer_id': LB_ID,
              'edge_id': LB_EDGE_ID,
              'edge_fw_rule_id': LB_VIP_FWR_ID,
              'vip_address': LB_VIP}
LISTENER_ID = 'xxx-111'
EDGE_APP_PROFILE_ID = 'appp-x'
EDGE_APP_PROF_DEF = {'sslPassthrough': False, 'insertXForwardedFor': False,
                     'serverSslEnabled': False, 'name': LISTENER_ID,
                     'template': 'http',
                     'persistence': {
                          'cookieMode': 'insert',
                          'cookieName': 'default_cookie_name',
                          'method': 'cookie'}}
EDGE_VIP_ID = 'vip-aaa'
EDGE_VIP_DEF = {'protocol': 'http', 'name': 'vip_' + LISTENER_ID,
                'connectionLimit': 0, 'defaultPoolId': None,
                'ipAddress': LB_VIP, 'port': 80, 'accelerationEnabled': False,
                'applicationProfileId': EDGE_APP_PROFILE_ID, 'description': '',
                'enabled': True}
LISTENER_BINDING = {'loadbalancer_id': LB_ID,
                    'listener_id': LISTENER_ID,
                    'app_profile_id': EDGE_APP_PROFILE_ID,
                    'vse_id': EDGE_VIP_ID}
POOL_ID = 'ppp-qqq'
EDGE_POOL_ID = 'pool-xx'
EDGE_POOL_DEF = {'transparent': False, 'name': 'pool_' + POOL_ID,
                 'algorithm': 'round-robin', 'description': ''}
POOL_BINDING = {'loadbalancer_id': LB_ID,
                'pool_id': POOL_ID,
                'edge_pool_id': EDGE_POOL_ID}
MEMBER_ID = 'mmm-mmm'
MEMBER_ADDRESS = '10.0.0.200'
EDGE_MEMBER_DEF = {'monitorPort': 80, 'name': 'member-' + MEMBER_ID,
                   'weight': 1, 'ipAddress': MEMBER_ADDRESS, 'port': 80,
                   'condition': 'disabled'}
POOL_FW_SECT = '10001'
HM_ID = 'hhh-mmm'
EDGE_HM_ID = 'hm-xx'
EDGE_HM_DEF = {'maxRetries': 1, 'interval': 3, 'type': 'icmp', 'name': HM_ID,
               'timeout': 3}

HM_BINDING = {'loadbalancer_id': LB_ID,
              'pool_id': POOL_ID,
              'hm_id': HM_ID,
              'edge_id': LB_EDGE_ID,
              'edge_mon_id': EDGE_HM_ID}

L7POL_ID = 'l7pol-l7pol'
EDGE_RULE_ID = 'app-rule-xx'
L7POL_BINDING = {'policy_id': L7POL_ID,
                 'edge_id': LB_EDGE_ID,
                 'edge_app_rule_id': EDGE_RULE_ID}
EDGE_L7POL_DEF = {'script': 'http-request deny if TRUE',
                  'name': 'pol_' + L7POL_ID}

L7RULE_ID1 = 'l7rule-111'
L7RULE_ID2 = 'l7rule-222'


class BaseTestEdgeLbaasV2(base.BaseTestCase):
    def _tested_entity(self):
        return None

    def completor(self, success=True):
        self.last_completor_succees = success
        self.last_completor_called = True

    def setUp(self):
        super(BaseTestEdgeLbaasV2, self).setUp()

        self.last_completor_succees = False
        self.last_completor_called = False
        self.context = context.get_admin_context()
        self.nsx_v = mock.Mock()
        octavia_objects = {
            'loadbalancer': loadbalancer_mgr.EdgeLoadBalancerManagerFromDict(
                self.nsx_v),
            'listener': listener_mgr.EdgeListenerManagerFromDict(self.nsx_v),
            'pool': pool_mgr.EdgePoolManagerFromDict(self.nsx_v),
            'member': member_mgr.EdgeMemberManagerFromDict(self.nsx_v),
            'healthmonitor': healthmon_mgr.EdgeHealthMonitorManagerFromDict(
                self.nsx_v),
            'l7policy': l7policy_mgr.EdgeL7PolicyManagerFromDict(self.nsx_v),
            'l7rule': l7rule_mgr.EdgeL7RuleManagerFromDict(self.nsx_v)}

        self.edge_driver = octavia_listener.NSXOctaviaListenerEndpoint(
            **octavia_objects)

        self.lbv2_driver = mock.Mock()
        self.core_plugin = mock.Mock()
        self.flavor_plugin = flavors_plugin.FlavorsPlugin()
        base_mgr.LoadbalancerBaseManager._lbv2_driver = self.lbv2_driver
        base_mgr.LoadbalancerBaseManager._core_plugin = self.core_plugin
        base_mgr.LoadbalancerBaseManager._flavor_plugin = self.flavor_plugin
        self._patch_lb_plugin(self.lbv2_driver, self._tested_entity)

        self.lb = lb_models.LoadBalancer(LB_ID, LB_TENANT_ID, 'lb-name', '',
                                         LB_SUBNET, 'port-id', LB_VIP)
        self.listener = lb_models.Listener(LISTENER_ID, LB_TENANT_ID,
                                           'l-name', '', None, LB_ID,
                                           'HTTP', protocol_port=80,
                                           loadbalancer=self.lb,
                                           admin_state_up=True)
        self.sess_persist = lb_models.SessionPersistence(type='HTTP_COOKIE')
        self.pool = lb_models.Pool(POOL_ID, LB_TENANT_ID, 'pool-name', '',
                                   None, 'HTTP', 'ROUND_ROBIN',
                                   loadbalancer_id=LB_ID,
                                   listener=self.listener,
                                   listeners=[self.listener],
                                   loadbalancer=self.lb,
                                   session_persistence=self.sess_persist)
        self.listener.default_pool = self.pool
        self.member = lb_models.Member(MEMBER_ID, LB_TENANT_ID, POOL_ID,
                                       MEMBER_ADDRESS, 80, 1, pool=self.pool)
        self.hm = lb_models.HealthMonitor(HM_ID, LB_TENANT_ID, 'PING', 3, 3,
                                          1, pool=self.pool)
        self.l7policy = lb_models.L7Policy(L7POL_ID, LB_TENANT_ID,
                                           name='policy-test',
                                           description='policy-desc',
                                           listener_id=LISTENER_ID,
                                           action='REJECT',
                                           listener=self.listener,
                                           position=1)
        self.l7rule1 = lb_models.L7Rule(L7RULE_ID1, LB_TENANT_ID,
                                        l7policy_id=L7POL_ID,
                                        compare_type='EQUAL_TO',
                                        invert=False,
                                        type='HEADER',
                                        key='key1',
                                        value='val1',
                                        policy=self.l7policy)
        self.l7rule2 = lb_models.L7Rule(L7RULE_ID2, LB_TENANT_ID,
                                        l7policy_id=L7POL_ID,
                                        compare_type='STARTS_WITH',
                                        invert=True,
                                        type='PATH',
                                        value='/images',
                                        policy=self.l7policy)

        # Translate LBaaS objects to dictionaries
        self.lb_dict = lb_translators.lb_loadbalancer_obj_to_dict(
            self.lb)
        self.listener_dict = lb_translators.lb_listener_obj_to_dict(
            self.listener)
        self.pool_dict = lb_translators.lb_pool_obj_to_dict(
            self.pool)
        self.member_dict = lb_translators.lb_member_obj_to_dict(
            self.member)
        self.hm_dict = lb_translators.lb_hm_obj_to_dict(
            self.hm)
        self.l7policy_dict = lb_translators.lb_l7policy_obj_to_dict(
            self.l7policy)
        self.l7rule1_dict = lb_translators.lb_l7rule_obj_to_dict(
            self.l7rule1)
        self.l7rule2_dict = lb_translators.lb_l7rule_obj_to_dict(
            self.l7rule2)

    def tearDown(self):
        self._unpatch_lb_plugin(self.lbv2_driver, self._tested_entity)
        super(BaseTestEdgeLbaasV2, self).tearDown()

    def _patch_lb_plugin(self, lb_plugin, manager):
        self.real_manager = getattr(lb_plugin, manager)
        lb_manager = mock.patch.object(lb_plugin, manager).start()
        mock.patch.object(lb_manager, 'create').start()
        mock.patch.object(lb_manager, 'update').start()
        mock.patch.object(lb_manager, 'delete').start()
        mock.patch.object(lb_manager, 'successful_completion').start()

    def _unpatch_lb_plugin(self, lb_plugin, manager):
        setattr(lb_plugin, manager, self.real_manager)


class TestEdgeLbaasV2LoadbalancerOnRtr(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2LoadbalancerOnRtr, self).setUp()
        cfg.CONF.set_override('use_routers_as_lbaas_platform',
                              self._deploy_on_router, group="nsxv")

    @property
    def _tested_entity(self):
        return 'load_balancer'

    @property
    def _edge_getter(self):
        return 'get_lbaas_edge_id_for_subnet'

    @property
    def _deploy_on_router(self):
        return True

    def test_create(self):
        with mock.patch.object(lb_common, self._edge_getter
                               ) as mock_get_edge, \
            mock.patch.object(lb_common, 'add_vip_as_secondary_ip'
                              ) as mock_vip_sec_ip, \
            mock.patch.object(lb_common, 'add_vip_fw_rule'
                              ) as mock_add_vip_fwr, \
            mock.patch.object(lb_common, 'set_lb_firewall_default_rule'
                              ) as mock_set_fw_rule, \
            mock.patch.object(lb_common, 'enable_edge_acceleration'
                              ) as mock_enable_edge_acceleration, \
            mock.patch.object(nsxv_db,
                              'get_nsxv_lbaas_loadbalancer_binding_by_edge'
                              ) as mock_get_lb_binding_by_edge, \
            mock.patch.object(nsxv_db, 'add_nsxv_lbaas_loadbalancer_binding'
                              ) as mock_db_binding:
            mock_get_edge.return_value = LB_EDGE_ID
            mock_add_vip_fwr.return_value = LB_VIP_FWR_ID
            mock_get_lb_binding_by_edge.return_value = []
            self.edge_driver.loadbalancer.create(
                self.context, self.lb_dict, self.completor)

            if self._deploy_on_router:
                mock_vip_sec_ip.assert_called_with(self.edge_driver.pool.vcns,
                                                   LB_EDGE_ID,
                                                   LB_VIP)
                mock_get_edge.assert_called_with(mock.ANY, mock.ANY,
                                                 LB_SUBNET, LB_TENANT_ID)
            else:
                mock_set_fw_rule.assert_called_with(
                    self.edge_driver.pool.vcns, LB_EDGE_ID, 'accept')
                mock_get_edge.assert_called_with(mock.ANY, mock.ANY, LB_ID,
                                                 LB_VIP, mock.ANY,
                                                 LB_TENANT_ID, mock.ANY)

            mock_add_vip_fwr.assert_called_with(self.edge_driver.pool.vcns,
                                                LB_EDGE_ID,
                                                LB_ID,
                                                LB_VIP)
            mock_db_binding.assert_called_with(self.context.session,
                                               LB_ID,
                                               LB_EDGE_ID,
                                               LB_VIP_FWR_ID,
                                               LB_VIP)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)
            mock_enable_edge_acceleration.assert_called_with(
                self.edge_driver.pool.vcns, LB_EDGE_ID)

    def test_update(self):
        new_lb = lb_models.LoadBalancer(LB_ID, 'yyy-yyy', 'lb-name', 'heh-huh',
                                        LB_SUBNET, 'port-id', LB_VIP)
        new_lb_dict = lb_translators.lb_loadbalancer_obj_to_dict(new_lb)
        self.edge_driver.loadbalancer.update(
            self.context, self.lb_dict, new_lb_dict, self.completor)
        self.assertTrue(self.last_completor_called)
        self.assertTrue(self.last_completor_succees)

    def test_delete_old(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_binding, \
            mock.patch.object(lb_common, 'del_vip_fw_rule') as mock_del_fwr, \
            mock.patch.object(lb_common, 'del_vip_as_secondary_ip'
                              ) as mock_vip_sec_ip, \
            mock.patch.object(lb_common, 'set_lb_firewall_default_rule'
                              ) as mock_set_fw_rule, \
            mock.patch.object(nsxv_db, 'del_nsxv_lbaas_loadbalancer_binding',
                              ) as mock_del_binding, \
            mock.patch.object(self.core_plugin, 'get_ports'
                              ) as mock_get_ports, \
            mock.patch.object(self.core_plugin, 'get_router',
                              return_value={'router_type': 'exclusive'}), \
            mock.patch.object(nsxv_db, 'get_nsxv_router_binding_by_edge'
                              ) as mock_get_r_binding:
            mock_get_binding.return_value = LB_BINDING
            mock_get_ports.return_value = []
            mock_get_r_binding.return_value = {'router_id': 'xxxx'}
            self.edge_driver.loadbalancer.delete(
                self.context, self.lb_dict, self.completor)

            mock_del_fwr.assert_called_with(self.edge_driver.pool.vcns,
                                            LB_EDGE_ID,
                                            LB_VIP_FWR_ID)
            mock_vip_sec_ip.assert_called_with(self.edge_driver.pool.vcns,
                                               LB_EDGE_ID,
                                               LB_VIP)
            mock_del_binding.assert_called_with(self.context.session,
                                                LB_ID)
            mock_set_fw_rule.assert_called_with(
                self.edge_driver.pool.vcns, LB_EDGE_ID, 'deny')
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete_new(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_binding, \
            mock.patch.object(lb_common, 'set_lb_firewall_default_rule'
                              ) as mock_set_fw_rule, \
            mock.patch.object(nsxv_db, 'del_nsxv_lbaas_loadbalancer_binding',
                              ) as mock_del_binding, \
            mock.patch.object(self.core_plugin, 'get_ports'
                              ) as mock_get_ports, \
            mock.patch.object(self.core_plugin.edge_manager, 'delete_lrouter'
                              ) as mock_delete_lrouter, \
            mock.patch.object(nsxv_db, 'get_nsxv_router_binding_by_edge'
                              ) as mock_get_r_binding:
            mock_get_binding.return_value = LB_BINDING
            mock_get_ports.return_value = []
            router_id = 'lbaas-xxxx'
            mock_get_r_binding.return_value = {'router_id': router_id}
            self.edge_driver.loadbalancer.delete(
                self.context, self.lb_dict, self.completor)

            mock_del_binding.assert_called_with(self.context.session,
                                                LB_ID)
            mock_set_fw_rule.assert_called_with(
                self.edge_driver.pool.vcns, LB_EDGE_ID, 'deny')
            mock_delete_lrouter.assert_called_with(
                mock.ANY, 'lbaas-' + LB_ID, dist=False)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)


class TestEdgeLbaasV2LoadbalancerOnEdge(TestEdgeLbaasV2LoadbalancerOnRtr):
    @property
    def _edge_getter(self):
        return 'get_lbaas_edge_id'

    @property
    def _deploy_on_router(self):
        return False

    def setUp(self):
        super(TestEdgeLbaasV2LoadbalancerOnEdge, self).setUp()

    def test_create_with_flavor(self):
        flavor_name = 'large'
        with mock.patch.object(lb_common, 'get_lbaas_edge_id'
                               ) as mock_get_edge, \
            mock.patch.object(lb_common, 'add_vip_fw_rule'
                              ) as mock_add_vip_fwr, \
            mock.patch.object(lb_common, 'set_lb_firewall_default_rule'
                              ) as mock_set_fw_rule, \
            mock.patch.object(lb_common, 'enable_edge_acceleration'
                              ) as mock_enable_edge_acceleration, \
            mock.patch.object(nsxv_db,
                              'get_nsxv_lbaas_loadbalancer_binding_by_edge'
                              ) as mock_get_lb_binding_by_edge, \
            mock.patch.object(nsxv_db, 'add_nsxv_lbaas_loadbalancer_binding'
                              ) as mock_db_binding,\
            mock.patch('neutron.services.flavors.flavors_plugin.FlavorsPlugin.'
                      'get_flavor', return_value={'name': flavor_name}):
            mock_get_edge.return_value = LB_EDGE_ID
            mock_add_vip_fwr.return_value = LB_VIP_FWR_ID
            mock_get_lb_binding_by_edge.return_value = []
            self.lb.flavor_id = 'dummy'
            lb_dict = lb_translators.lb_loadbalancer_obj_to_dict(self.lb)
            self.edge_driver.loadbalancer.create(
                self.context, lb_dict, self.completor)

            mock_add_vip_fwr.assert_called_with(self.edge_driver.pool.vcns,
                                                LB_EDGE_ID,
                                                LB_ID,
                                                LB_VIP)
            mock_db_binding.assert_called_with(self.context.session,
                                               LB_ID,
                                               LB_EDGE_ID,
                                               LB_VIP_FWR_ID,
                                               LB_VIP)
            mock_set_fw_rule.assert_called_with(
                self.edge_driver.pool.vcns, LB_EDGE_ID, 'accept')
            mock_get_edge.assert_called_with(
                mock.ANY, mock.ANY, LB_ID, LB_VIP,
                mock.ANY, LB_TENANT_ID, flavor_name)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)
            mock_enable_edge_acceleration.assert_called_with(
                self.edge_driver.pool.vcns, LB_EDGE_ID)
            self.lb.flavor_id = None

    def test_create_with_illegal_flavor(self):
        flavor_name = 'no_size'
        with mock.patch.object(lb_common, 'get_lbaas_edge_id'
                               ) as mock_get_edge, \
            mock.patch.object(lb_common, 'add_vip_fw_rule'
                              ) as mock_add_vip_fwr, \
            mock.patch.object(nsxv_db,
                              'get_nsxv_lbaas_loadbalancer_binding_by_edge'
                              ) as mock_get_lb_binding_by_edge, \
            mock.patch('neutron.services.flavors.flavors_plugin.FlavorsPlugin.'
                      'get_flavor', return_value={'name': flavor_name}):
            mock_get_edge.return_value = LB_EDGE_ID
            mock_add_vip_fwr.return_value = LB_VIP_FWR_ID
            mock_get_lb_binding_by_edge.return_value = []
            self.lb.flavor_id = 'dummy'
            lb_dict = lb_translators.lb_loadbalancer_obj_to_dict(self.lb)
            self.assertRaises(
                n_exc.InvalidInput,
                self.edge_driver.loadbalancer.create,
                self.context, lb_dict, self.completor)
            self.lb.flavor_id = None


class TestEdgeLbaasV2Listener(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2Listener, self).setUp()

    @property
    def _tested_entity(self):
        return 'listener'

    def test_create(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_lb_binding, \
            mock.patch.object(self.edge_driver.pool.vcns, 'create_app_profile'
                              ) as mock_create_app_prof, \
            mock.patch.object(self.edge_driver.pool.vcns, 'create_vip'
                              ) as mock_create_vip, \
            mock.patch.object(nsxv_db, 'add_nsxv_lbaas_listener_binding'
                              ) as mock_add_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding',
                              return_value=None):
            mock_get_lb_binding.return_value = LB_BINDING
            mock_create_app_prof.return_value = (
                {'location': 'x/' + EDGE_APP_PROFILE_ID}, None)
            mock_create_vip.return_value = (
                {'location': 'x/' + EDGE_VIP_ID}, None)

            self.edge_driver.listener.create(
                self.context, self.listener_dict, self.completor)

            mock_create_app_prof.assert_called_with(LB_EDGE_ID,
                                                    EDGE_APP_PROF_DEF)
            mock_create_vip.assert_called_with(LB_EDGE_ID,
                                               EDGE_VIP_DEF)
            mock_add_binding.assert_called_with(
                self.context.session, LB_ID, LISTENER_ID, EDGE_APP_PROFILE_ID,
                EDGE_VIP_ID)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_update(self):
        new_listener = lb_models.Listener(LISTENER_ID, LB_TENANT_ID,
                                          'l-name', '', None, LB_ID,
                                          'HTTP', protocol_port=8000,
                                          loadbalancer=self.lb,
                                          admin_state_up=True)
        new_listener.default_pool = self.pool
        new_listener_dict = lb_translators.lb_listener_obj_to_dict(
            new_listener)

        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_listener_binding'
                               ) as mock_get_listener_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                              ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding',
                              return_value=None), \
            mock.patch.object(self.edge_driver.pool.vcns, 'update_app_profile'
                              ) as mock_upd_app_prof, \
            mock.patch.object(self.edge_driver.pool.vcns, 'update_vip'
                              ) as mock_upd_vip:
            mock_get_listener_binding.return_value = LISTENER_BINDING
            mock_get_lb_binding.return_value = LB_BINDING

            self.edge_driver.listener.update(
                self.context, self.listener_dict, new_listener_dict,
                self.completor)

            mock_upd_app_prof.assert_called_with(LB_EDGE_ID,
                                                 EDGE_APP_PROFILE_ID,
                                                 EDGE_APP_PROF_DEF)

            edge_vip_def = EDGE_VIP_DEF.copy()
            edge_vip_def['port'] = 8000
            mock_upd_vip.assert_called_with(LB_EDGE_ID, EDGE_VIP_ID,
                                            edge_vip_def)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_listener_binding'
                               ) as mock_get_listener_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                              ) as mock_get_lb_binding, \
            mock.patch.object(self.edge_driver.pool.vcns, 'delete_vip'
                              ) as mock_del_vip, \
            mock.patch.object(self.edge_driver.pool.vcns, 'delete_app_profile'
                              ) as mock_del_app_prof, \
            mock.patch.object(nsxv_db, 'del_nsxv_lbaas_listener_binding'
                              ) as mock_del_binding:
            mock_get_listener_binding.return_value = LISTENER_BINDING
            mock_get_lb_binding.return_value = LB_BINDING

            self.edge_driver.listener.delete(
                self.context, self.listener_dict, self.completor)

            mock_del_vip.assert_called_with(LB_EDGE_ID, EDGE_VIP_ID)
            mock_del_app_prof.assert_called_with(LB_EDGE_ID,
                                                 EDGE_APP_PROFILE_ID)
            mock_del_binding.assert_called_with(self.context.session,
                                                LB_ID, LISTENER_ID)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)


class TestEdgeLbaasV2Pool(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2Pool, self).setUp()

    @property
    def _tested_entity(self):
        return 'pool'

    def test_create(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_listener_binding'
                               ) as mock_get_listener_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                              ) as mock_get_lb_binding, \
            mock.patch.object(self.edge_driver.pool.vcns, 'create_pool'
                              ) as mock_create_pool, \
            mock.patch.object(nsxv_db, 'add_nsxv_lbaas_pool_binding'
                              ) as mock_add_binding, \
            mock.patch.object(self.edge_driver.pool.vcns, 'update_vip'
                              ) as mock_upd_vip,\
            mock.patch.object(self.edge_driver.pool.vcns, 'update_app_profile'
                              ) as mock_upd_app_prof:
            mock_get_listener_binding.return_value = LISTENER_BINDING
            mock_get_lb_binding.return_value = LB_BINDING
            mock_create_pool.return_value = (
                {'location': 'x/' + EDGE_POOL_ID}, None)

            self.edge_driver.pool.create(
                self.context, self.pool_dict, self.completor)

            mock_create_pool.assert_called_with(LB_EDGE_ID,
                                                EDGE_POOL_DEF.copy())
            mock_add_binding.assert_called_with(self.context.session,
                                                LB_ID, POOL_ID, EDGE_POOL_ID)
            edge_vip_def = EDGE_VIP_DEF.copy()
            edge_vip_def['defaultPoolId'] = EDGE_POOL_ID
            mock_upd_vip.assert_called_with(LB_EDGE_ID, EDGE_VIP_ID,
                                            edge_vip_def)
            mock_upd_app_prof.assert_called_with(LB_EDGE_ID,
                                                 EDGE_APP_PROFILE_ID,
                                                 EDGE_APP_PROF_DEF)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_update(self):
        new_pool = lb_models.Pool(POOL_ID, LB_TENANT_ID, 'pool-name', '',
                                  None, 'HTTP', 'LEAST_CONNECTIONS',
                                  listener=self.listener)
        new_pool_dict = lb_translators.lb_pool_obj_to_dict(new_pool)
        list_bind = {'app_profile_id': EDGE_APP_PROFILE_ID}
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding'
                              ) as mock_get_pool_binding,\
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_listener_binding',
                              return_value=list_bind),\
            mock.patch.object(self.edge_driver.pool.vcns, 'update_pool'
                              ) as mock_upd_pool,\
            mock.patch.object(self.edge_driver.pool.vcns, 'get_pool'
                              ) as mock_get_pool,\
            mock.patch.object(self.edge_driver.pool.vcns, 'update_app_profile'
                              ) as mock_upd_app_prof:
            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_pool_binding.return_value = POOL_BINDING
            fake_edge = EDGE_POOL_DEF.copy()
            fake_edge['monitorId'] = 'monitor-7'
            fake_edge['member'] = ['member1', 'member2']
            mock_get_pool.return_value = (None, fake_edge)
            self.edge_driver.pool.update(
                self.context, self.pool_dict, new_pool_dict, self.completor)

            edge_pool_def = EDGE_POOL_DEF.copy()
            edge_pool_def['algorithm'] = 'leastconn'
            edge_pool_def['monitorId'] = 'monitor-7'
            edge_pool_def['member'] = ['member1', 'member2']
            mock_upd_pool.assert_called_with(
                LB_EDGE_ID, EDGE_POOL_ID, edge_pool_def)
            mock_upd_app_prof.assert_called_with(LB_EDGE_ID,
                                                 EDGE_APP_PROFILE_ID,
                                                 EDGE_APP_PROF_DEF)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding'
                              ) as mock_get_pool_binding,\
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_listener_binding'
                              ) as mock_get_listener_binding, \
            mock.patch.object(self.edge_driver.pool.vcns, 'update_vip'
                              ) as mock_upd_vip, \
            mock.patch.object(self.edge_driver.pool.vcns, 'delete_pool'
                              ) as mock_del_pool, \
            mock.patch.object(nsxv_db, 'del_nsxv_lbaas_pool_binding'
                              ) as mock_del_binding,\
            mock.patch.object(lb_common, 'is_lb_on_router_edge'
                              ) as mock_lb_router, \
            mock.patch.object(self.edge_driver.pool.vcns, 'update_app_profile'
                              ):
            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_pool_binding.return_value = POOL_BINDING
            mock_get_listener_binding.return_value = LISTENER_BINDING
            mock_lb_router.return_value = False

            self.edge_driver.pool.delete(
                self.context, self.pool_dict, self.completor)

            mock_upd_vip.assert_called_with(LB_EDGE_ID, EDGE_VIP_ID,
                                            EDGE_VIP_DEF)
            mock_del_pool.assert_called_with(LB_EDGE_ID, EDGE_POOL_ID)
            mock_del_binding.assert_called_with(
                self.context.session, LB_ID, POOL_ID)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)


def _nsx_member(ip_address):
    return {'ipAddress': ip_address,
            'weight': 1,
            'port': 80,
            'monitorPort': 80,
            'name': 'member-test',
            'condition': 'enabled'}


def _lbaas_member(ip_address):
    return {'address': ip_address,
            'weight': 1,
            'protocol_port': 80,
            'id': 'test',
            'admin_state_up': True}


class TestEdgeLbaasV2Member(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2Member, self).setUp()

    @property
    def _tested_entity(self):
        return 'member'

    def test_create(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding'
                              ) as mock_get_pool_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_router_binding_by_edge'
                              ), \
            mock.patch.object(self.edge_driver.pool.vcns, 'get_pool'
                              ) as mock_get_pool, \
            mock.patch.object(self.edge_driver.pool.vcns, 'update_pool'
                              ) as mock_update_pool:
            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_pool_binding.return_value = POOL_BINDING
            mock_get_pool.return_value = (None, EDGE_POOL_DEF.copy())

            self.edge_driver.member.create(
                self.context, self.member_dict, self.completor)

            edge_pool_def = EDGE_POOL_DEF.copy()
            edge_pool_def['member'] = [EDGE_MEMBER_DEF]
            mock_update_pool.assert_called_with(
                LB_EDGE_ID, EDGE_POOL_ID, edge_pool_def)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_update(self):
        new_member = lb_models.Member(MEMBER_ID, LB_TENANT_ID, POOL_ID,
                                      MEMBER_ADDRESS, 8000, 1, True,
                                      pool=self.pool)
        new_member_dict = lb_translators.lb_member_obj_to_dict(new_member)
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding'
                              ) as mock_get_pool_binding, \
            mock.patch.object(self.edge_driver.pool.vcns, 'get_pool'
                              ) as mock_get_pool, \
            mock.patch.object(self.edge_driver.pool.vcns, 'update_pool'
                              ) as mock_update_pool:
            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_pool_binding.return_value = POOL_BINDING
            edge_pool_def = EDGE_POOL_DEF.copy()
            edge_pool_def['member'] = [EDGE_MEMBER_DEF]
            mock_get_pool.return_value = (None, edge_pool_def)
            new_member_dict['pool']['members'] = [{'address': MEMBER_ADDRESS}]
            self.edge_driver.member.update(
                self.context, self.member_dict,
                new_member_dict, self.completor)

            edge_member_def = EDGE_MEMBER_DEF.copy()
            edge_member_def['port'] = 8000
            edge_member_def['monitorPort'] = 8000
            edge_member_def['condition'] = 'enabled'
            edge_pool_def['member'] = [edge_member_def]
            mock_update_pool.assert_called_with(
                LB_EDGE_ID, EDGE_POOL_ID, edge_pool_def)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding'
                              ) as mock_get_pool_binding, \
            mock.patch.object(self.edge_driver.pool.vcns, 'get_pool'
                              ) as mock_get_pool, \
            mock.patch.object(self.core_plugin, 'get_ports'
                              ) as mock_get_ports, \
            mock.patch.object(lb_common, 'is_lb_on_router_edge'
                              ) as mock_lb_router, \
            mock.patch.object(lb_common, 'delete_lb_interface'
                              ) as mock_del_lb_iface, \
            mock.patch.object(self.edge_driver.pool.vcns, 'update_pool'
                              ) as mock_update_pool:
            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_pool_binding.return_value = POOL_BINDING
            mock_lb_router.return_value = False
            edge_pool_def = EDGE_POOL_DEF.copy()
            edge_pool_def['member'] = [EDGE_MEMBER_DEF]
            mock_get_pool.return_value = (None, edge_pool_def)
            mock_get_ports.return_value = []
            self.edge_driver.member.delete(
                self.context, self.member_dict, self.completor)

            edge_pool_def['member'] = []
            mock_update_pool.assert_called_with(
                LB_EDGE_ID, EDGE_POOL_ID, edge_pool_def)
            mock_del_lb_iface.assert_called_with(
                self.context, self.core_plugin, LB_ID, None)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def _do_member_validation_test(self, in_ips, in_edge_ips, out_edge_ips):
        pool = self.pool_dict.copy()
        edge_pool = EDGE_POOL_DEF.copy()

        pool['members'] = [_lbaas_member(m) for m in in_ips]

        edge_pool['member'] = [_nsx_member(m) for m in in_edge_ips]

        member_mgr._validate_pool_members(pool, edge_pool)
        self.assertEqual(edge_pool['member'], [_nsx_member(m)
                                               for m in out_edge_ips])

    def test_validate_pool_members_valid_lists(self):
        self._do_member_validation_test(['10.0.0.10', '10.0.0.11'],
                                        ['10.0.0.10', '10.0.0.11'],
                                        ['10.0.0.10', '10.0.0.11'])

    def test_validate_pool_members_nsx_extra(self):
        self._do_member_validation_test(['10.0.0.10'],
                                        ['10.0.0.10', '10.0.0.11'],
                                        ['10.0.0.10'])

    def test_validate_pool_members_lbaas_extra(self):
        self._do_member_validation_test(['10.0.0.10', '10.0.0.11'],
                                        ['10.0.0.10'],
                                        ['10.0.0.10', '10.0.0.11'])


class TestEdgeLbaasV2HealthMonitor(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2HealthMonitor, self).setUp()

    @property
    def _tested_entity(self):
        return 'health_monitor'

    def test_create(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding'
                              ) as mock_get_pool_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_monitor_binding'
                              ) as mock_get_mon_binding, \
            mock.patch.object(self.edge_driver.pool.vcns,
                              'create_health_monitor') as mock_create_hm, \
            mock.patch.object(nsxv_db, 'add_nsxv_lbaas_monitor_binding'
                              ) as mock_add_hm_binding, \
            mock.patch.object(self.edge_driver.pool.vcns, 'get_pool'
                              ) as mock_get_pool, \
            mock.patch.object(self.edge_driver.pool.vcns, 'update_pool'
                              ) as mock_update_pool:
            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_pool_binding.return_value = POOL_BINDING
            mock_get_mon_binding.return_value = None
            mock_create_hm.return_value = (
                {'location': 'x/' + EDGE_HM_ID}, None)
            mock_get_pool.return_value = (None, EDGE_POOL_DEF.copy())

            self.edge_driver.healthmonitor.create(
                self.context, self.hm_dict, self.completor)

            mock_create_hm.assert_called_with(LB_EDGE_ID, EDGE_HM_DEF)
            mock_add_hm_binding.assert_called_with(
                self.context.session, LB_ID, POOL_ID, HM_ID, LB_EDGE_ID,
                EDGE_HM_ID)
            edge_pool_def = EDGE_POOL_DEF.copy()
            edge_pool_def['monitorId'] = [EDGE_HM_ID]
            mock_update_pool.assert_called_with(
                LB_EDGE_ID, EDGE_POOL_ID, edge_pool_def)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_update(self):
        new_hm = lb_models.HealthMonitor(HM_ID, LB_TENANT_ID, 'PING', 3, 3,
                                         3, pool=self.pool)
        new_hm_dict = lb_translators.lb_hm_obj_to_dict(new_hm)
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding'
                              ) as mock_get_pool_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_monitor_binding'
                              ) as mock_get_mon_binding, \
            mock.patch.object(self.edge_driver.pool.vcns,
                              'update_health_monitor') as mock_upd_hm:
            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_pool_binding.return_value = POOL_BINDING
            mock_get_mon_binding.return_value = HM_BINDING

            self.edge_driver.healthmonitor.update(
                self.context, self.hm_dict, new_hm_dict, self.completor)

            edge_hm_def = EDGE_HM_DEF.copy()
            edge_hm_def['maxRetries'] = 3
            mock_upd_hm.assert_called_with(LB_EDGE_ID, EDGE_HM_ID, edge_hm_def)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding'
                              ) as mock_get_pool_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_monitor_binding'
                              ) as mock_get_mon_binding, \
            mock.patch.object(self.edge_driver.pool.vcns,
                              'delete_health_monitor') as mock_del_hm, \
            mock.patch.object(self.edge_driver.pool.vcns, 'get_pool'
                              ) as mock_get_pool, \
            mock.patch.object(self.edge_driver.pool.vcns, 'update_pool'
                              ) as mock_update_pool, \
            mock.patch.object(nsxv_db, 'del_nsxv_lbaas_monitor_binding'
                              ) as mock_del_binding:

            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_pool_binding.return_value = POOL_BINDING
            mock_get_mon_binding.return_value = HM_BINDING
            edge_pool_def = EDGE_POOL_DEF.copy()
            edge_pool_def['monitorId'] = [EDGE_HM_ID]
            mock_get_pool.return_value = (None, edge_pool_def)

            self.edge_driver.healthmonitor.delete(
                self.context, self.hm_dict, self.completor)

            mock_del_hm.assert_called_with(LB_EDGE_ID, EDGE_HM_ID)
            edge_pool_def['monitorId'] = []
            mock_update_pool.assert_called_with(
                LB_EDGE_ID, EDGE_POOL_ID, edge_pool_def)
            mock_del_binding.assert_called_with(self.context.session, LB_ID,
                                                POOL_ID, HM_ID, LB_EDGE_ID)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)


class TestEdgeLbaasV2L7Policy(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2L7Policy, self).setUp()

    @property
    def _tested_entity(self):
        return 'l7policy'

    def test_create(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_l7policy_binding'
                               ) as mock_get_l7policy_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                              ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_listener_binding'
                              ) as mock_get_listener_binding, \
            mock.patch.object(nsxv_db, 'add_nsxv_lbaas_l7policy_binding'
                              ) as mock_add_l7policy_binding,\
            mock.patch.object(self.edge_driver.pool.vcns, 'create_app_rule'
                              ) as mock_create_rule, \
            mock.patch.object(self.edge_driver.pool.vcns, 'get_vip'
                              ) as mock_get_vip, \
            mock.patch.object(self.edge_driver.pool.vcns, 'update_vip'
                              ) as mock_upd_vip:
            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_l7policy_binding.return_value = L7POL_BINDING
            mock_get_listener_binding.return_value = LISTENER_BINDING
            mock_create_rule.return_value = (
                {'location': 'x/' + EDGE_RULE_ID}, None)
            mock_get_vip.return_value = (None, EDGE_VIP_DEF.copy())

            self.edge_driver.l7policy.create(
                self.context, self.l7policy_dict, self.completor)

            mock_create_rule.assert_called_with(LB_EDGE_ID,
                                                EDGE_L7POL_DEF.copy())
            mock_add_l7policy_binding.assert_called_with(
                self.context.session, L7POL_ID, LB_EDGE_ID, EDGE_RULE_ID)

            edge_vip_def = EDGE_VIP_DEF.copy()
            edge_vip_def['applicationRuleId'] = [EDGE_RULE_ID]
            mock_upd_vip.assert_called_with(LB_EDGE_ID, EDGE_VIP_ID,
                                            edge_vip_def)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_update(self):
        url = 'http://www.test.com'
        new_pol = lb_models.L7Policy(L7POL_ID, LB_TENANT_ID,
                                     name='policy-test',
                                     description='policy-desc',
                                     listener_id=LISTENER_ID,
                                     action='REDIRECT_TO_URL',
                                     redirect_url=url,
                                     listener=self.listener,
                                     position=2)
        new_pol_dict = lb_translators.lb_l7policy_obj_to_dict(new_pol)
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_l7policy_binding'
                               ) as mock_get_l7policy_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                              ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_listener_binding'
                              ) as mock_get_listener_binding, \
            mock.patch.object(self.edge_driver.pool.vcns, 'get_vip'
                              ) as mock_get_vip, \
            mock.patch.object(self.edge_driver.pool.vcns, 'update_vip'
                              ) as mock_upd_vip, \
            mock.patch.object(self.edge_driver.pool.vcns, 'update_app_rule'
                              ) as mock_update_rule:
            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_l7policy_binding.return_value = L7POL_BINDING
            mock_get_listener_binding.return_value = LISTENER_BINDING
            edge_vip_def = EDGE_VIP_DEF.copy()
            edge_vip_def['applicationRuleId'] = [EDGE_RULE_ID]
            mock_get_vip.return_value = (None, edge_vip_def)

            self.edge_driver.l7policy.update(
                self.context, self.l7policy_dict,
                new_pol_dict, self.completor)

            edge_rule_def = EDGE_L7POL_DEF.copy()
            edge_rule_def['script'] = "redirect location %s if TRUE" % url
            mock_update_rule.assert_called_with(
                LB_EDGE_ID, EDGE_RULE_ID, edge_rule_def)
            mock_upd_vip.assert_called()
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_l7policy_binding'
                               ) as mock_get_l7policy_binding, \
            mock.patch.object(nsxv_db, 'del_nsxv_lbaas_l7policy_binding'
                              ) as mock_del_l7policy_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                              ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding'
                              ) as mock_get_pool_binding,\
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_listener_binding'
                              ) as mock_get_listener_binding, \
            mock.patch.object(self.edge_driver.pool.vcns, 'delete_app_rule'
                              ) as mock_del_app_rule, \
            mock.patch.object(self.edge_driver.pool.vcns, 'get_vip'
                              ) as mock_get_vip, \
            mock.patch.object(self.edge_driver.pool.vcns, 'update_vip'
                              ) as mock_upd_vip:
            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_pool_binding.return_value = POOL_BINDING
            mock_get_listener_binding.return_value = LISTENER_BINDING
            mock_get_l7policy_binding.return_value = L7POL_BINDING
            edge_vip_def = EDGE_VIP_DEF.copy()
            edge_vip_def['applicationRuleId'] = [EDGE_RULE_ID]
            mock_get_vip.return_value = (None, edge_vip_def)

            self.edge_driver.l7policy.delete(
                self.context, self.l7policy_dict, self.completor)

            edge_vip_def2 = EDGE_VIP_DEF.copy()
            edge_vip_def2['applicationRuleId'] = []
            mock_upd_vip.assert_called_with(LB_EDGE_ID, EDGE_VIP_ID,
                                            edge_vip_def2)
            mock_del_app_rule.assert_called_with(LB_EDGE_ID, EDGE_RULE_ID)
            mock_del_l7policy_binding.assert_called_with(
                self.context.session, L7POL_ID)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)


class TestEdgeLbaasV2L7Rule(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2L7Rule, self).setUp()

    @property
    def _tested_entity(self):
        return 'l7rule'

    def test_create(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_l7policy_binding'
                               ) as mock_get_l7policy_binding, \
            mock.patch.object(self.edge_driver.pool.vcns, 'update_app_rule'
                              ) as mock_update_rule:
            mock_get_l7policy_binding.return_value = L7POL_BINDING

            # Create the first rule
            self.l7rule1.policy.rules = [self.l7rule1]
            rule1_dict = lb_translators.lb_l7rule_obj_to_dict(self.l7rule1)
            self.edge_driver.l7rule.create(
                self.context, rule1_dict, self.completor)

            edge_rule_def = EDGE_L7POL_DEF.copy()
            edge_rule_def['script'] = (
                "acl %(rule_id)s hdr(key1) -i val1\n"
                "http-request deny if %(rule_id)s" %
                {'rule_id': L7RULE_ID1})
            mock_update_rule.assert_called_with(
                LB_EDGE_ID, EDGE_RULE_ID, edge_rule_def)

            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

            # Create the 2nd rule
            self.l7rule2.policy.rules = [self.l7rule1, self.l7rule2]
            rule2_dict = lb_translators.lb_l7rule_obj_to_dict(self.l7rule2)
            self.edge_driver.l7rule.create(
                self.context, rule2_dict, self.completor)

            edge_rule_def = EDGE_L7POL_DEF.copy()
            edge_rule_def['script'] = (
                "acl %(rule_id1)s hdr(key1) -i val1\n"
                "acl %(rule_id2)s path_beg -i /images\n"
                "http-request deny if %(rule_id1)s !%(rule_id2)s" %
                {'rule_id1': L7RULE_ID1,
                 'rule_id2': L7RULE_ID2})
            mock_update_rule.assert_called_with(
                LB_EDGE_ID, EDGE_RULE_ID, edge_rule_def)
            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_update(self):
        new_rule = lb_models.L7Rule(L7RULE_ID1, LB_TENANT_ID,
                                    l7policy_id=L7POL_ID,
                                    compare_type='EQUAL_TO',
                                    invert=False,
                                    type='HEADER',
                                    key='key2',
                                    value='val1',
                                    policy=self.l7policy)
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_l7policy_binding'
                               ) as mock_get_l7policy_binding, \
            mock.patch.object(self.edge_driver.pool.vcns, 'update_app_rule'
                              ) as mock_update_rule:
            mock_get_l7policy_binding.return_value = L7POL_BINDING

            new_rule.policy.rules = [new_rule]
            new_rule_dict = lb_translators.lb_l7rule_obj_to_dict(new_rule)
            self.edge_driver.l7rule.update(
                self.context, self.l7rule1_dict, new_rule_dict,
                self.completor)

            edge_rule_def = EDGE_L7POL_DEF.copy()
            edge_rule_def['script'] = (
                "acl %(rule_id)s hdr(key2) -i val1\n"
                "http-request deny if %(rule_id)s" %
                {'rule_id': L7RULE_ID1})
            mock_update_rule.assert_called_with(
                LB_EDGE_ID, EDGE_RULE_ID, edge_rule_def)

            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

    def test_delete(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_l7policy_binding'
                               ) as mock_get_l7policy_binding, \
            mock.patch.object(self.edge_driver.pool.vcns, 'update_app_rule'
                              ) as mock_update_rule:
            mock_get_l7policy_binding.return_value = L7POL_BINDING

            self.l7rule1.policy.rules = []
            rule_dict = lb_translators.lb_l7rule_obj_to_dict(self.l7rule1)
            self.edge_driver.l7rule.delete(
                self.context, rule_dict, self.completor)

            edge_rule_def = EDGE_L7POL_DEF.copy()
            edge_rule_def['script'] = (
                "http-request deny if TRUE")
            mock_update_rule.assert_called_with(
                LB_EDGE_ID, EDGE_RULE_ID, edge_rule_def)

            self.assertTrue(self.last_completor_called)
            self.assertTrue(self.last_completor_succees)

# Copyright (c) 2018 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import mock

from oslo_config import cfg
from oslo_utils import uuidutils
from webob import exc

from neutron.extensions import address_scope
from neutron.extensions import l3
from neutron.extensions import securitygroup as secgrp
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.extensions import test_address_scope
from neutron.tests.unit.extensions import test_extraroute as test_ext_route
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin
from neutron.tests.unit.extensions import test_securitygroup
from neutron.tests.unit import testlib_api

from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import extra_dhcp_opt as edo_ext
from neutron_lib.api.definitions import extraroute as xroute_apidef
from neutron_lib.api.definitions import l3_ext_gw_mode as l3_egm_apidef
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.api.definitions import vlantransparent as vlan_apidef
from neutron_lib.callbacks import events
from neutron_lib.callbacks import exceptions as nc_exc
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.objects import registry as obj_reg
from neutron_lib.plugins import directory

from vmware_nsx.common import utils
from vmware_nsx.extensions import providersecuritygroup as provider_sg
from vmware_nsx.plugins.common import plugin as com_plugin
from vmware_nsx.plugins.nsx_p import plugin as nsx_plugin
from vmware_nsx.services.lbaas.nsx_p.implementation import loadbalancer_mgr
from vmware_nsx.services.lbaas.octavia import octavia_listener

from vmware_nsx.tests import unit as vmware
from vmware_nsx.tests.unit.common_plugin import common_v3
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3.policy import constants as pol_const
from vmware_nsxlib.v3 import utils as nsxlib_utils


PLUGIN_NAME = 'vmware_nsx.plugin.NsxPolicyPlugin'
NSX_OVERLAY_TZ_NAME = 'OVERLAY_TZ'
NSX_VLAN_TZ_NAME = 'VLAN_TZ'
DEFAULT_TIER0_ROUTER_UUID = "efad0078-9204-4b46-a2d8-d4dd31ed448f"
NSX_DHCP_PROFILE_ID = 'DHCP_PROFILE'
NSX_MD_PROXY_ID = 'MD_PROXY'
LOGICAL_SWITCH_ID = '00000000-1111-2222-3333-444444444444'


def _return_id_key(*args, **kwargs):
    return {'id': uuidutils.generate_uuid()}


def _return_id_key_list(*args, **kwargs):
    return [{'id': uuidutils.generate_uuid()}]


def _return_same(key, *args, **kwargs):
    return key


class NsxPPluginTestCaseMixin(
    test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self, plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None, **kwargs):

        self._mock_nsx_policy_backend_calls()
        self.setup_conf_overrides()
        super(NsxPPluginTestCaseMixin, self).setUp(plugin=plugin,
                                                   ext_mgr=ext_mgr)
        self.ctx = context.get_admin_context()

    def _mock_nsx_policy_backend_calls(self):
        resource_list_result = {'results': [{'id': 'test',
                                             'display_name': 'test'}]}
        mock.patch(
            "vmware_nsxlib.v3.policy.NsxPolicyLib.get_version",
            return_value=nsx_constants.NSX_VERSION_3_1_0).start()
        mock.patch(
            "vmware_nsxlib.v3.client.RESTClient.get").start()
        mock.patch(
            "vmware_nsxlib.v3.client.RESTClient.list",
            return_value=resource_list_result).start()
        mock.patch(
            "vmware_nsxlib.v3.client.RESTClient.patch").start()
        mock.patch(
            "vmware_nsxlib.v3.client.RESTClient.update").start()
        mock.patch(
            "vmware_nsxlib.v3.client.RESTClient.delete").start()
        mock.patch("vmware_nsxlib.v3.policy.core_resources."
                   "NsxPolicyCommunicationMapApi._get_last_seq_num",
                   return_value=-1).start()
        mock.patch("vmware_nsxlib.v3.policy.core_resources."
                   "NsxPolicyResourceBase._wait_until_realized",
                   return_value={'state': pol_const.STATE_REALIZED}
                   ).start()
        mock.patch("vmware_nsxlib.v3.policy.core_resources."
                   "NsxPolicyTier1Api.update_transport_zone").start()
        mock.patch("vmware_nsxlib.v3.policy.core_resources."
                   "NsxPolicySegmentApi.get_realized_logical_switch_id",
                   return_value=LOGICAL_SWITCH_ID
                   ).start()
        mock.patch("vmware_nsxlib.v3.policy.core_resources."
                   "NsxPolicySegmentApi.wait_until_state_successful"
                   ).start()
        mock.patch("vmware_nsxlib.v3.policy.core_resources."
                   "NsxPolicySegmentApi.get_realized_id",
                   return_value=LOGICAL_SWITCH_ID
                   ).start()
        mock.patch("vmware_nsxlib.v3.policy.core_resources."
                   "NsxPolicySegmentApi.set_admin_state").start()
        mock.patch("vmware_nsxlib.v3.policy.core_resources."
                   "NsxPolicySegmentPortApi.set_admin_state").start()
        mock.patch("vmware_nsxlib.v3.policy.core_resources.NsxPolicyTier0Api."
                   "get_edge_cluster_path", return_value="x/1").start()
        mock.patch("vmware_nsxlib.v3.policy.core_resources."
                   "NsxPolicyEdgeClusterApi.get_edge_node_nsx_ids",
                   return_value=["node1"]).start()
        mock.patch("vmware_nsxlib.v3.NsxLib.get_tag_limits",
                   return_value=nsxlib_utils.TagLimits(20, 40, 15)).start()
        # Add some nsxlib mocks for the passthrough apis
        mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                   return_value=nsx_constants.NSX_VERSION_3_0_0).start()
        mock.patch("vmware_nsxlib.v3.core_resources.NsxLibLogicalRouter."
                   "update").start()
        mock.patch("vmware_nsxlib.v3.core_resources.NsxLibTransportNode."
                   "get_transport_zones",
                   return_value=[NSX_OVERLAY_TZ_NAME,
                                 NSX_VLAN_TZ_NAME, mock.ANY]).start()
        mock.patch("vmware_nsxlib.v3.core_resources.NsxLibEdgeCluster."
                   "get_transport_nodes", return_value=["dummy"]).start()
        mock.patch("vmware_nsxlib.v3.NsxLib."
                   "get_id_by_resource_and_tag").start()

    def setup_conf_overrides(self):
        cfg.CONF.set_override('default_overlay_tz', NSX_OVERLAY_TZ_NAME,
                              'nsx_p')
        cfg.CONF.set_override('default_vlan_tz', NSX_VLAN_TZ_NAME, 'nsx_p')
        cfg.CONF.set_override('dhcp_profile', NSX_DHCP_PROFILE_ID, 'nsx_p')
        cfg.CONF.set_override('metadata_proxy', NSX_MD_PROXY_ID, 'nsx_p')
        cfg.CONF.set_override('dhcp_agent_notification', False)

    def _create_network(self, fmt, name, admin_state_up,
                        arg_list=None, providernet_args=None,
                        set_context=False, tenant_id=None,
                        **kwargs):
        tenant_id = tenant_id or self._tenant_id
        data = {'network': {'name': name,
                            'admin_state_up': admin_state_up,
                            'tenant_id': tenant_id}}
        # Fix to allow the router:external attribute and any other
        # attributes containing a colon to be passed with
        # a double underscore instead
        kwargs = dict((k.replace('__', ':'), v) for k, v in kwargs.items())
        if extnet_apidef.EXTERNAL in kwargs:
            arg_list = (extnet_apidef.EXTERNAL, ) + (arg_list or ())

        if providernet_args:
            kwargs.update(providernet_args)
        for arg in (('admin_state_up', 'tenant_id', 'shared',
                     'availability_zone_hints') + (arg_list or ())):
            # Arg must be present
            if arg in kwargs:
                data['network'][arg] = kwargs[arg]
        network_req = self.new_create_request('networks', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            network_req.environ['neutron.context'] = context.Context(
                '', tenant_id)
        return network_req.get_response(self.api)

    def _create_l3_ext_network(self, physical_network='abc'):
        name = 'l3_ext_net'
        net_type = utils.NetworkTypes.L3_EXT
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: physical_network}
        return self.network(name=name,
                            router__external=True,
                            providernet_args=providernet_args,
                            arg_list=(pnet.NETWORK_TYPE,
                                      pnet.PHYSICAL_NETWORK))

    def _initialize_azs(self):
        self.plugin.init_availability_zones()
        self.plugin._init_default_config()


class NsxPTestNetworks(test_db_base_plugin_v2.TestNetworksV2,
                       NsxPPluginTestCaseMixin):

    def setUp(self, plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        # add vlan transparent to the configuration
        cfg.CONF.set_override('vlan_transparent', True)
        super(NsxPTestNetworks, self).setUp(plugin=plugin,
                                            ext_mgr=ext_mgr)

    def tearDown(self):
        super(NsxPTestNetworks, self).tearDown()

    def test_create_provider_flat_network(self):
        providernet_args = {pnet.NETWORK_TYPE: 'flat'}
        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'NsxPolicySegmentApi.create_or_overwrite',
                        side_effect=_return_id_key) as nsx_create, \
            mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                       'NsxPolicySegmentApi.delete') as nsx_delete, \
            mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                       'NsxPolicyTransportZoneApi.get_transport_type',
                       return_value=nsx_constants.TRANSPORT_TYPE_VLAN), \
            self.network(name='flat_net',
                         providernet_args=providernet_args,
                         arg_list=(pnet.NETWORK_TYPE, )) as net:
            self.assertEqual('flat', net['network'].get(pnet.NETWORK_TYPE))
            # make sure the network is created at the backend
            nsx_create.assert_called_once()

            # Delete the network and make sure it is deleted from the backend
            req = self.new_delete_request('networks', net['network']['id'])
            res = req.get_response(self.api)
            self.assertEqual(exc.HTTPNoContent.code, res.status_int)
            nsx_delete.assert_called_once()

    def test_create_provider_flat_network_with_physical_net(self):
        physical_network = DEFAULT_TIER0_ROUTER_UUID
        providernet_args = {pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: physical_network}
        with mock.patch(
            'vmware_nsxlib.v3.policy.core_resources.NsxPolicyTransportZoneApi.'
            'get_transport_type',
            return_value=nsx_constants.TRANSPORT_TYPE_VLAN), \
            self.network(name='flat_net',
                         providernet_args=providernet_args,
                         arg_list=(pnet.NETWORK_TYPE,
                                   pnet.PHYSICAL_NETWORK)) as net:
            self.assertEqual('flat', net['network'].get(pnet.NETWORK_TYPE))

    def test_create_provider_flat_network_with_vlan(self):
        providernet_args = {pnet.NETWORK_TYPE: 'flat',
                            pnet.SEGMENTATION_ID: 11}
        with mock.patch(
            'vmware_nsxlib.v3.policy.core_resources.NsxPolicyTransportZoneApi.'
            'get_transport_type',
            return_value=nsx_constants.TRANSPORT_TYPE_VLAN):
            result = self._create_network(fmt='json', name='bad_flat_net',
                                          admin_state_up=True,
                                          providernet_args=providernet_args,
                                          arg_list=(pnet.NETWORK_TYPE,
                                                    pnet.SEGMENTATION_ID))
            data = self.deserialize('json', result)
            # should fail
            self.assertEqual('InvalidInput', data['NeutronError']['type'])

    def test_create_provider_geneve_network(self):
        providernet_args = {pnet.NETWORK_TYPE: 'geneve'}
        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'NsxPolicySegmentApi.create_or_overwrite',
                        side_effect=_return_id_key) as nsx_create, \
            mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                       'NsxPolicySegmentApi.delete') as nsx_delete, \
            self.network(name='geneve_net',
                         providernet_args=providernet_args,
                         arg_list=(pnet.NETWORK_TYPE, )) as net:
            self.assertEqual('geneve', net['network'].get(pnet.NETWORK_TYPE))
            # make sure the network is created at the backend
            nsx_create.assert_called_once()

            # Delete the network and make sure it is deleted from the backend
            req = self.new_delete_request('networks', net['network']['id'])
            res = req.get_response(self.api)
            self.assertEqual(exc.HTTPNoContent.code, res.status_int)
            nsx_delete.assert_called_once()

    def test_create_provider_geneve_network_with_physical_net(self):
        physical_network = DEFAULT_TIER0_ROUTER_UUID
        providernet_args = {pnet.NETWORK_TYPE: 'geneve',
                            pnet.PHYSICAL_NETWORK: physical_network}
        with mock.patch(
            'vmware_nsxlib.v3.policy.core_resources.NsxPolicyTransportZoneApi.'
            'get_transport_type',
            return_value=nsx_constants.TRANSPORT_TYPE_OVERLAY),\
            self.network(name='geneve_net',
                         providernet_args=providernet_args,
                         arg_list=(pnet.NETWORK_TYPE, )) as net:
            self.assertEqual('geneve', net['network'].get(pnet.NETWORK_TYPE))

    def test_create_provider_geneve_network_with_vlan(self):
        providernet_args = {pnet.NETWORK_TYPE: 'geneve',
                            pnet.SEGMENTATION_ID: 11}
        with mock.patch(
            'vmware_nsxlib.v3.policy.core_resources.NsxPolicyTransportZoneApi.'
            'get_transport_type',
            return_value=nsx_constants.TRANSPORT_TYPE_OVERLAY):
            result = self._create_network(fmt='json', name='bad_geneve_net',
                                          admin_state_up=True,
                                          providernet_args=providernet_args,
                                          arg_list=(pnet.NETWORK_TYPE,
                                                    pnet.SEGMENTATION_ID))
            data = self.deserialize('json', result)
            # should fail
            self.assertEqual('InvalidInput', data['NeutronError']['type'])

    def test_create_provider_vlan_network(self):
        providernet_args = {pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 11}
        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'NsxPolicySegmentApi.create_or_overwrite',
                        side_effect=_return_id_key) as nsx_create, \
            mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                       'NsxPolicySegmentApi.delete') as nsx_delete, \
            mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                       'NsxPolicyTransportZoneApi.get_transport_type',
                       return_value=nsx_constants.TRANSPORT_TYPE_VLAN), \
            self.network(name='vlan_net',
                         providernet_args=providernet_args,
                         arg_list=(pnet.NETWORK_TYPE,
                                   pnet.SEGMENTATION_ID)) as net:
            self.assertEqual('vlan', net['network'].get(pnet.NETWORK_TYPE))
            # make sure the network is created at the backend
            nsx_create.assert_called_once()

            # Delete the network and make sure it is deleted from the backend
            req = self.new_delete_request('networks', net['network']['id'])
            res = req.get_response(self.api)
            self.assertEqual(exc.HTTPNoContent.code, res.status_int)
            nsx_delete.assert_called_once()

    def test_create_provider_nsx_network(self):
        physical_network = 'Fake logical switch'
        providernet_args = {pnet.NETWORK_TYPE: 'nsx-net',
                            pnet.PHYSICAL_NETWORK: physical_network}

        with mock.patch(
            'vmware_nsxlib.v3.policy.core_resources.NsxPolicySegmentApi.'
            'create_or_overwrite',
            side_effect=nsxlib_exc.ResourceNotFound) as nsx_create, \
            mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                       'NsxPolicySegmentApi.delete') as nsx_delete, \
            self.network(name='nsx_net',
                         providernet_args=providernet_args,
                         arg_list=(pnet.NETWORK_TYPE,
                                   pnet.PHYSICAL_NETWORK)) as net:
            self.assertEqual('nsx-net', net['network'].get(pnet.NETWORK_TYPE))
            self.assertEqual(physical_network,
                             net['network'].get(pnet.PHYSICAL_NETWORK))
            # make sure the network is NOT created at the backend
            nsx_create.assert_not_called()

            # Delete the network. It should NOT deleted from the backend
            req = self.new_delete_request('networks', net['network']['id'])
            res = req.get_response(self.api)
            self.assertEqual(exc.HTTPNoContent.code, res.status_int)
            nsx_delete.assert_not_called()

    def test_create_provider_bad_nsx_network(self):
        physical_network = 'Bad logical switch'
        providernet_args = {pnet.NETWORK_TYPE: 'nsx-net',
                            pnet.PHYSICAL_NETWORK: physical_network}
        with mock.patch(
            "vmware_nsxlib.v3.policy.core_resources.NsxPolicySegmentApi.get",
            side_effect=nsxlib_exc.ResourceNotFound):
            result = self._create_network(fmt='json', name='bad_nsx_net',
                                          admin_state_up=True,
                                          providernet_args=providernet_args,
                                          arg_list=(pnet.NETWORK_TYPE,
                                                    pnet.PHYSICAL_NETWORK))
            data = self.deserialize('json', result)
            # should fail
            self.assertEqual('InvalidInput', data['NeutronError']['type'])

    def _test_transparent_vlan_net(self, net_type, tz_type, should_succeed):
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            vlan_apidef.VLANTRANSPARENT: True}
        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'NsxPolicyTransportZoneApi.get_transport_type',
                        return_value=tz_type):
            result = self._create_network(fmt='json', name='vlan_net',
                                          admin_state_up=True,
                                          providernet_args=providernet_args,
                                          arg_list=(
                                              pnet.NETWORK_TYPE,
                                              vlan_apidef.VLANTRANSPARENT))
            data = self.deserialize('json', result)
            if should_succeed:
                self.assertEqual(net_type,
                                 data['network'].get(pnet.NETWORK_TYPE))
                self.assertTrue(
                    data['network'].get(vlan_apidef.VLANTRANSPARENT))
            else:
                self.assertEqual('InvalidInput', data['NeutronError']['type'])

    def test_create_non_provider_network_with_transparent(self):
        self._test_transparent_vlan_net(
            net_type="",
            tz_type=nsx_constants.TRANSPORT_TYPE_OVERLAY,
            should_succeed=False)

    def test_create_provider_overlay_network_with_transparent(self):
        self._test_transparent_vlan_net(
            net_type=utils.NsxV3NetworkTypes.GENEVE,
            tz_type=nsx_constants.TRANSPORT_TYPE_OVERLAY,
            should_succeed=True)

    def test_create_provider_flat_network_with_transparent(self):
        self._test_transparent_vlan_net(
            net_type=utils.NsxV3NetworkTypes.FLAT,
            tz_type=nsx_constants.TRANSPORT_TYPE_VLAN,
            should_succeed=True)

    def test_create_provider_vlan_network_with_transparent(self):
        self._test_transparent_vlan_net(
            net_type=utils.NsxV3NetworkTypes.VLAN,
            tz_type=nsx_constants.TRANSPORT_TYPE_VLAN,
            should_succeed=True)

    def test_network_update_external_failure(self):
        data = {'network': {'name': 'net1',
                            'router:external': 'True',
                            'tenant_id': 'tenant_one',
                            'provider:physical_network': 'stam'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        ext_net_id = network['network']['id']

        # should fail to update the network to non-external
        args = {'network': {'router:external': 'False'}}
        req = self.new_update_request('networks', args,
                                      ext_net_id, fmt='json')
        res = self.deserialize('json', req.get_response(self.api))
        self.assertEqual('InvalidInput',
                         res['NeutronError']['type'])

    @mock.patch.object(nsx_plugin.NsxPolicyPlugin,
                       'validate_availability_zones')
    def test_create_network_with_availability_zone(self, mock_validate_az):
        name = 'net-with-zone'
        zone = ['zone1']

        mock_validate_az.return_value = None
        with self.network(name=name, availability_zone_hints=zone) as net:
            az_hints = net['network']['availability_zone_hints']
            self.assertListEqual(az_hints, zone)

    def test_create_net_with_qos(self):
        policy_id = uuidutils.generate_uuid()
        data = {'network': {
                    'tenant_id': self._tenant_id,
                    'qos_policy_id': policy_id,
                    'name': 'qos_net',
                    'admin_state_up': True,
                    'shared': False}
                }
        dummy = mock.Mock()
        dummy.id = policy_id
        with mock.patch.object(self.plugin, '_validate_qos_policy_id'),\
            mock.patch.object(obj_reg.load_class('QosPolicy'),
                              'get_network_policy',
                              return_value=dummy):
            net = self.plugin.create_network(self.ctx, data)
            self.assertEqual(policy_id, net['qos_policy_id'])
            net = self.plugin.get_network(self.ctx, net['id'])
            self.assertEqual(policy_id, net['qos_policy_id'])

    def test_update_net_with_qos(self):
        data = {'network': {
                    'tenant_id': self._tenant_id,
                    'name': 'qos_net',
                    'admin_state_up': True,
                    'shared': False}
                }
        net = self.plugin.create_network(self.ctx, data)
        policy_id = uuidutils.generate_uuid()
        data['network']['qos_policy_id'] = policy_id
        dummy = mock.Mock()
        dummy.id = policy_id
        with mock.patch.object(self.plugin, '_validate_qos_policy_id'),\
            mock.patch.object(obj_reg.load_class('QosPolicy'),
                              'get_network_policy',
                              return_value=dummy):
            res = self.plugin.update_network(self.ctx, net['id'], data)
            self.assertEqual(policy_id, res['qos_policy_id'])
            res = self.plugin.get_network(self.ctx, net['id'])
            self.assertEqual(policy_id, res['qos_policy_id'])

    def test_create_ens_network_with_qos(self):
        cfg.CONF.set_override('ens_support', True, 'nsx_v3')
        mock_ens = mock.patch('vmware_nsxlib.v3.policy'
                              '.core_resources.NsxPolicyTransportZoneApi'
                              '.get_host_switch_mode', return_value='ENS')
        mock_tz = mock.patch('vmware_nsxlib.v3'
                             '.core_resources.NsxLibLogicalSwitch.get',
                             return_value={'transport_zone_id': 'xxx'})
        mock_tt = mock.patch('vmware_nsxlib.v3.policy'
                             '.core_resources.NsxPolicyTransportZoneApi'
                             '.get_transport_type', return_value='VLAN')
        policy_id = uuidutils.generate_uuid()
        data = {'network': {
                'name': 'qos_net',
                'tenant_id': 'some_tenant',
                'provider:network_type': 'flat',
                'provider:physical_network': 'xxx',
                'admin_state_up': True,
                'shared': False,
                'qos_policy_id': policy_id,
                'port_security_enabled': False}}
        with mock_ens, mock_tz, mock_tt, mock.patch.object(
                self.plugin, '_validate_qos_policy_id'):
            res = self.plugin.create_network(context.get_admin_context(), data)
            self.assertEqual(policy_id, res['qos_policy_id'])

    def test_update_ens_network_with_qos(self):
        cfg.CONF.set_override('ens_support', True, 'nsx_v3')
        mock_ens = mock.patch('vmware_nsxlib.v3.policy'
                              '.core_resources.NsxPolicyTransportZoneApi'
                              '.get_host_switch_mode', return_value='ENS')
        mock_tz = mock.patch('vmware_nsxlib.v3'
                             '.core_resources.NsxLibLogicalSwitch.get',
                             return_value={'transport_zone_id': 'xxx'})
        mock_tt = mock.patch('vmware_nsxlib.v3.policy'
                             '.core_resources.NsxPolicyTransportZoneApi'
                             '.get_transport_type', return_value='VLAN')
        data = {'network': {
                'name': 'qos_net',
                'tenant_id': 'some_tenant',
                'provider:network_type': 'flat',
                'provider:physical_network': 'xxx',
                'admin_state_up': True,
                'shared': False,
                'port_security_enabled': False}}
        with mock_ens, mock_tz, mock_tt,\
            mock.patch.object(self.plugin, '_validate_qos_policy_id'):
            network = self.plugin.create_network(context.get_admin_context(),
                                                 data)
            policy_id = uuidutils.generate_uuid()
            data = {'network': {
                    'id': network['id'],
                    'admin_state_up': True,
                    'shared': False,
                    'port_security_enabled': False,
                    'tenant_id': 'some_tenant',
                    'qos_policy_id': policy_id}}
            res = self.plugin.update_network(
                context.get_admin_context(),
                network['id'], data)
            self.assertEqual(policy_id, res['qos_policy_id'])

    def test_update_network_port_sec(self):
        data = {'network': {
                'name': 'psec_net',
                'tenant_id': 'some_tenant',
                'admin_state_up': True,
                'shared': False,
                'port_security_enabled': True}}
        network = self.plugin.create_network(context.get_admin_context(),
                                             data)
        self.assertEqual(True, network['port_security_enabled'])
        data = {'network': {
                'id': network['id'],
                'admin_state_up': True,
                'shared': False,
                'port_security_enabled': False,
                'tenant_id': 'some_tenant'}}
        res = self.plugin.update_network(context.get_admin_context(),
                                         network['id'], data)
        self.assertEqual(False, res['port_security_enabled'])

    def test_update_network_l3_ext_provider(self):
        with self._create_l3_ext_network() as network:
            net_data = network['network']
            data = {'network': {'id': net_data['id'],
                                'provider:network_type': 'l3_ext',
                                'provider:physical_network': 'other'}}
            res = self.plugin.update_network(context.get_admin_context(),
                                             net_data['id'], data)
            self.assertEqual('other', res['provider:physical_network'])

    def test_update_network_l3_ext_provider_segmentation_id_fails(self):
        with self._create_l3_ext_network() as network:
            net_data = network['network']
            data = {'network': {'id': net_data['id'],
                                'provider:network_type': 'l3_ext',
                                'provider:physical_network': 'other',
                                'provider:segmentation_id': 666}}
            self.assertRaises(n_exc.InvalidInput,
                              self.plugin.update_network,
                              context.get_admin_context(),
                              net_data['id'], data)

    def test_update_network_l3_ext_provider_no_original_prov_fails(self):
        with self.network(name='test_no_prov') as network:
            net_data = network['network']
            data = {'network': {'id': net_data['id'],
                                'provider:network_type': 'l3_ext',
                                'provider:physical_network': 'other',
                                'provider:segmentation_id': 666}}
            self.assertRaises(n_exc.InvalidInput,
                              self.plugin.update_network,
                              context.get_admin_context(),
                              net_data['id'], data)

    def test_update_network_no_prov_does_not_update_bindings(self):
        with mock.patch(
            'vmware_nsx.db.db.delete_network_bindings') as mock_del_bindings,\
             mock.patch(
            'vmware_nsx.db.db.add_network_binding') as mock_add_bindings,\
                self.network(name='test_no_prov') as network:
            net_data = network['network']
            data = {'network': {'id': net_data['id'],
                                'name': 'new_name'}}
            res = self.plugin.update_network(context.get_admin_context(),
                                             net_data['id'], data)
            self.assertEqual('new_name', res['name'])
            mock_del_bindings.assert_not_called()
            mock_add_bindings.assert_not_called()

    def test_update_network_l3_ext_provider_other_original_prov_fails(self):
        providernet_args = {pnet.NETWORK_TYPE: 'geneve'}
        with self.network(name='test_geneve_net',
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE, )) as network:
            net_data = network['network']
            data = {'network': {'id': net_data['id'],
                                'provider:network_type': 'l3_ext',
                                'provider:physical_network': 'other',
                                'provider:segmentation_id': 666}}
            self.assertRaises(n_exc.InvalidInput,
                              self.plugin.update_network,
                              context.get_admin_context(),
                              net_data['id'], data)


class NsxPTestPorts(common_v3.NsxV3TestPorts,
                    common_v3.NsxV3SubnetMixin,
                    NsxPPluginTestCaseMixin):
    def setUp(self, **kwargs):
        super(NsxPTestPorts, self).setUp(**kwargs)

    @common_v3.with_disable_dhcp
    def test_requested_ips_only(self):
        return super(NsxPTestPorts, self).test_requested_ips_only()

    @common_v3.with_disable_dhcp
    def test_list_ports_with_sort_emulated(self):
        return super(NsxPTestPorts,
                     self).test_list_ports_with_sort_emulated()

    @common_v3.with_disable_dhcp
    def test_list_ports_with_pagination_native(self):
        return super(NsxPTestPorts,
                     self).test_list_ports_with_pagination_native()

    @common_v3.with_disable_dhcp
    def test_list_ports_for_network_owner(self):
        return super(NsxPTestPorts, self).test_list_ports_for_network_owner()

    @common_v3.with_disable_dhcp
    def test_list_ports_public_network(self):
        return super(NsxPTestPorts, self).test_list_ports_public_network()

    @common_v3.with_disable_dhcp
    def test_list_ports(self):
        return super(NsxPTestPorts, self).test_list_ports()

    @common_v3.with_disable_dhcp
    def test_get_ports_count(self):
        return super(NsxPTestPorts, self).test_get_ports_count()

    @common_v3.with_disable_dhcp
    def test_list_ports_with_sort_native(self):
        return super(NsxPTestPorts, self).test_list_ports_with_sort_native()

    @common_v3.with_disable_dhcp
    def test_list_ports_with_pagination_emulated(self):
        return super(NsxPTestPorts,
                     self).test_list_ports_with_pagination_emulated()

    def test_update_port_delete_ip(self):
        # This test case overrides the default because the nsx plugin
        # implements port_security/security groups and it is not allowed
        # to remove an ip address from a port unless the security group
        # is first removed.
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                data = {'port': {'admin_state_up': False,
                                 'fixed_ips': [],
                                 secgrp.SECURITYGROUPS: []}}
                req = self.new_update_request('ports',
                                              data, port['port']['id'])
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual(res['port']['admin_state_up'],
                                 data['port']['admin_state_up'])
                self.assertEqual(res['port']['fixed_ips'],
                                 data['port']['fixed_ips'])

    def test_create_port_with_qos(self):
        with self.network() as network:
            policy_id = uuidutils.generate_uuid()
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'qos_policy_id': policy_id,
                        'name': 'qos_port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': 'fake_owner',
                        'fixed_ips': [],
                        'mac_address': '00:00:00:00:00:01'}
                    }
            with mock.patch.object(self.plugin, '_validate_qos_policy_id'):
                port = self.plugin.create_port(self.ctx, data)
                self.assertEqual(policy_id, port['qos_policy_id'])
                # Get port should also return the qos policy id
                with mock.patch('vmware_nsx.services.qos.common.utils.'
                                'get_port_policy_id',
                                return_value=policy_id):
                    port = self.plugin.get_port(self.ctx, port['id'])
                    self.assertEqual(policy_id, port['qos_policy_id'])

    def test_update_port_with_qos(self):
        with self.network() as network:
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'qos_port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': 'fake_owner',
                        'fixed_ips': [],
                        'mac_address': '00:00:00:00:00:01'}
                    }
            port = self.plugin.create_port(self.ctx, data)
            policy_id = uuidutils.generate_uuid()
            data['port']['qos_policy_id'] = policy_id
            with mock.patch.object(self.plugin, '_validate_qos_policy_id'):
                res = self.plugin.update_port(self.ctx, port['id'], data)
                self.assertEqual(policy_id, res['qos_policy_id'])
                # Get port should also return the qos policy id
                with mock.patch('vmware_nsx.services.qos.common.utils.'
                                'get_port_policy_id',
                                return_value=policy_id):
                    res = self.plugin.get_port(self.ctx, port['id'])
                    self.assertEqual(policy_id, res['qos_policy_id'])

                # now remove the qos from the port
                data['port']['qos_policy_id'] = None
                res = self.plugin.update_port(self.ctx, port['id'], data)
                self.assertIsNone(res['qos_policy_id'])

    def test_create_ext_port_with_qos_fail(self):
        with self._create_l3_ext_network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24',
                             enable_dhcp=False),\
                mock.patch.object(self.plugin, '_validate_qos_policy_id'):
                policy_id = uuidutils.generate_uuid()
                data = {'port': {'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'qos_policy_id': policy_id}}
                # Cannot add qos policy to a router port
                self.assertRaises(n_exc.InvalidInput,
                          self.plugin.create_port, self.ctx, data)

    def _test_create_illegal_port_with_qos_fail(self, device_owner):
        with self.network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24'),\
                mock.patch.object(self.plugin, '_validate_qos_policy_id'):
                policy_id = uuidutils.generate_uuid()
                data = {'port': {'network_id': network['network']['id'],
                                 'tenant_id': self._tenant_id,
                                 'device_owner': device_owner,
                                 'qos_policy_id': policy_id}}
                # Cannot add qos policy to this type of port
                self.assertRaises(n_exc.InvalidInput,
                          self.plugin.create_port, self.ctx, data)

    def test_create_port_ens_with_qos_fail(self):
        with self.network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24'):
                policy_id = uuidutils.generate_uuid()
                mock_ens = mock.patch(
                    'vmware_nsxlib.v3.policy.core_resources.'
                    'NsxPolicyTransportZoneApi.get_host_switch_mode',
                    return_value='ENS')
                mock_tz = mock.patch(
                    'vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch.get',
                    return_value={'transport_zone_id': 'xxx'})
                mock_tt = mock.patch(
                    'vmware_nsxlib.v3.policy.core_resources.'
                    'NsxPolicyTransportZoneApi.get_transport_type',
                    return_value='VLAN')
                data = {'port': {
                    'network_id': network['network']['id'],
                    'tenant_id': self._tenant_id,
                    'name': 'qos_port',
                    'admin_state_up': True,
                    'device_id': 'fake_device',
                    'device_owner': 'fake_owner',
                    'fixed_ips': [],
                    'port_security_enabled': False,
                    'mac_address': '00:00:00:00:00:01',
                    'qos_policy_id': policy_id}
                }
                # Cannot add qos policy to this type of port
                with mock_ens, mock_tz, mock_tt, \
                    mock.patch.object(self.plugin, '_validate_qos_policy_id'):
                    res = self.plugin.create_port(self.ctx, data)
                    self.assertEqual(policy_id, res['qos_policy_id'])

    def test_create_port_with_mac_learning_true(self):
        plugin = directory.get_plugin()
        ctx = context.get_admin_context()
        with self.network() as network:
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': 'fake_owner',
                        'fixed_ips': [],
                        'port_security_enabled': False,
                        'mac_address': '00:00:00:00:00:01',
                        'mac_learning_enabled': True}
                    }
            port = plugin.create_port(ctx, data)
            self.assertTrue(port['mac_learning_enabled'])

    def test_create_port_with_mac_learning_false(self):
        plugin = directory.get_plugin()
        ctx = context.get_admin_context()
        with self.network() as network:
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': 'fake_owner',
                        'fixed_ips': [],
                        'port_security_enabled': False,
                        'mac_address': '00:00:00:00:00:01',
                        'mac_learning_enabled': False}
                    }
            port = plugin.create_port(ctx, data)
            self.assertFalse(port['mac_learning_enabled'])

    def test_update_port_with_mac_learning_true(self):
        plugin = directory.get_plugin()
        ctx = context.get_admin_context()
        with self.network() as network:
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': 'fake_owner',
                        'fixed_ips': [],
                        'port_security_enabled': False,
                        'mac_address': '00:00:00:00:00:01'}
                    }
            port = plugin.create_port(ctx, data)
            data['port']['mac_learning_enabled'] = True
            update_res = plugin.update_port(ctx, port['id'], data)
            self.assertTrue(update_res['mac_learning_enabled'])

    def test_update_port_with_mac_learning_false(self):
        plugin = directory.get_plugin()
        ctx = context.get_admin_context()
        with self.network() as network:
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': 'fake_owner',
                        'fixed_ips': [],
                        'port_security_enabled': False,
                        'mac_address': '00:00:00:00:00:01'}
                    }
            port = plugin.create_port(ctx, data)
            data['port']['mac_learning_enabled'] = False
            update_res = plugin.update_port(ctx, port['id'], data)
            self.assertFalse(update_res['mac_learning_enabled'])

    def test_update_port_with_mac_learning_failes(self):
        plugin = directory.get_plugin()
        ctx = context.get_admin_context()
        with self.network() as network:
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': constants.DEVICE_OWNER_FLOATINGIP,
                        'fixed_ips': [],
                        'port_security_enabled': False,
                        'mac_address': '00:00:00:00:00:01'}
                    }
            port = plugin.create_port(ctx, data)
            data['port']['mac_learning_enabled'] = True
            self.assertRaises(
                n_exc.InvalidInput,
                plugin.update_port, ctx, port['id'], data)

    def _create_l3_ext_network(
        self, physical_network=DEFAULT_TIER0_ROUTER_UUID):
        name = 'l3_ext_net'
        net_type = utils.NetworkTypes.L3_EXT
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: physical_network}
        return self.network(name=name,
                            router__external=True,
                            providernet_args=providernet_args,
                            arg_list=(pnet.NETWORK_TYPE,
                                      pnet.PHYSICAL_NETWORK))

    def test_fail_create_port_with_ext_net(self):
        expected_error = 'InvalidInput'
        with self._create_l3_ext_network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24',
                             enable_dhcp=False):
                device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'X'
                res = self._create_port(self.fmt,
                                        network['network']['id'],
                                        exc.HTTPBadRequest.code,
                                        device_owner=device_owner)
                data = self.deserialize(self.fmt, res)
                self.assertEqual(expected_error, data['NeutronError']['type'])

    def test_fail_update_port_with_ext_net(self):
        with self._create_l3_ext_network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24',
                             enable_dhcp=False) as subnet:
                with self.port(subnet=subnet) as port:
                    device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'X'
                    data = {'port': {'device_owner': device_owner}}
                    req = self.new_update_request('ports',
                                                  data, port['port']['id'])
                    res = req.get_response(self.api)
                    self.assertEqual(exc.HTTPBadRequest.code,
                                     res.status_int)

    def _test_create_direct_network(self, vlan_id=0):
        net_type = vlan_id and 'vlan' or 'flat'
        name = 'direct_net'
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: 'tzuuid'}
        if vlan_id:
            providernet_args[pnet.SEGMENTATION_ID] = vlan_id

        mock_tt = mock.patch('vmware_nsxlib.v3.policy'
                             '.core_resources.NsxPolicyTransportZoneApi'
                             '.get_transport_type',
                             return_value=nsx_constants.TRANSPORT_TYPE_VLAN)
        mock_tt.start()
        return self.network(name=name,
                            providernet_args=providernet_args,
                            arg_list=(pnet.NETWORK_TYPE,
                                      pnet.PHYSICAL_NETWORK,
                                      pnet.SEGMENTATION_ID))

    def _test_create_port_vnic_direct(self, vlan_id):
        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'NsxPolicyTransportZoneApi.get_transport_type',
                        return_value=nsx_constants.TRANSPORT_TYPE_VLAN),\
            self._test_create_direct_network(vlan_id=vlan_id) as network:
            # Check that port security conflicts
            kwargs = {portbindings.VNIC_TYPE: portbindings.VNIC_DIRECT,
                      psec.PORTSECURITY: True}
            net_id = network['network']['id']
            res = self._create_port(self.fmt, net_id=net_id,
                                    arg_list=(portbindings.VNIC_TYPE,
                                              psec.PORTSECURITY),
                                    **kwargs)
            self.assertEqual(res.status_int, exc.HTTPBadRequest.code)

            # Check that security group conflicts
            kwargs = {portbindings.VNIC_TYPE: portbindings.VNIC_DIRECT,
                      'security_groups': [
                          '4cd70774-cc67-4a87-9b39-7d1db38eb087'],
                      psec.PORTSECURITY: False}
            net_id = network['network']['id']
            res = self._create_port(self.fmt, net_id=net_id,
                                    arg_list=(portbindings.VNIC_TYPE,
                                              psec.PORTSECURITY),
                                    **kwargs)
            self.assertEqual(res.status_int, exc.HTTPBadRequest.code)

            # All is kosher so we can create the port
            kwargs = {portbindings.VNIC_TYPE: portbindings.VNIC_DIRECT}
            net_id = network['network']['id']
            res = self._create_port(self.fmt, net_id=net_id,
                                    arg_list=(portbindings.VNIC_TYPE,),
                                    **kwargs)
            port = self.deserialize('json', res)
            self.assertEqual("direct", port['port'][portbindings.VNIC_TYPE])
            self.assertEqual("dvs", port['port'][portbindings.VIF_TYPE])
            self.assertEqual(
                vlan_id,
                port['port'][portbindings.VIF_DETAILS]['segmentation-id'])

            # try to get the same port
            req = self.new_show_request('ports', port['port']['id'], self.fmt)
            sport = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual("dvs", sport['port'][portbindings.VIF_TYPE])
            self.assertEqual("direct", sport['port'][portbindings.VNIC_TYPE])
            self.assertEqual(
                vlan_id,
                sport['port'][portbindings.VIF_DETAILS]['segmentation-id'])

    def test_create_port_vnic_direct_flat(self):
        self._test_create_port_vnic_direct(0)

    def test_create_port_vnic_direct_vlan(self):
        self._test_create_port_vnic_direct(10)

    def test_create_port_vnic_direct_invalid_network(self):
        with self.network(name='not vlan/flat') as net:
            kwargs = {portbindings.VNIC_TYPE: portbindings.VNIC_DIRECT,
                      psec.PORTSECURITY: False}
            net_id = net['network']['id']
            res = self._create_port(self.fmt, net_id=net_id,
                                    arg_list=(portbindings.VNIC_TYPE,
                                              psec.PORTSECURITY),
                                    **kwargs)
            self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

    def test_update_vnic_direct(self):
        with self._test_create_direct_network(vlan_id=7) as network:
            with self.subnet(network=network) as subnet:
                with self.port(subnet=subnet) as port:
                    # need to do two updates as the update for port security
                    # disabled requires that it can only change 2 items
                    data = {'port': {psec.PORTSECURITY: False,
                                     'security_groups': []}}
                    req = self.new_update_request('ports',
                                                  data, port['port']['id'])
                    res = self.deserialize('json', req.get_response(self.api))
                    self.assertEqual(portbindings.VNIC_NORMAL,
                                     res['port'][portbindings.VNIC_TYPE])

                    data = {'port': {portbindings.VNIC_TYPE:
                                     portbindings.VNIC_DIRECT}}

                    req = self.new_update_request('ports',
                                                  data, port['port']['id'])
                    res = self.deserialize('json', req.get_response(self.api))
                    self.assertEqual(portbindings.VNIC_DIRECT,
                                     res['port'][portbindings.VNIC_TYPE])

    def test_port_invalid_vnic_type(self):
        with self._test_create_direct_network(vlan_id=7) as network:
            kwargs = {portbindings.VNIC_TYPE: 'invalid',
                      psec.PORTSECURITY: False}
            net_id = network['network']['id']
            res = self._create_port(self.fmt, net_id=net_id,
                                    arg_list=(portbindings.VNIC_TYPE,
                                              psec.PORTSECURITY),
                                    **kwargs)
            self.assertEqual(res.status_int, exc.HTTPBadRequest.code)

    def test_create_ipv6_port(self):
        with self.network(name='net') as network:
            self._make_v6_subnet(network, constants.DHCPV6_STATEFUL)
            res = self._create_port(self.fmt, net_id=network['network']['id'])
            port = self.deserialize(self.fmt, res)
            self.assertIn('id', port['port'])

    def test_create_ipv6_port_with_extra_dhcp(self):
        with self.network(name='net') as network:
            self._make_v6_subnet(network, constants.DHCPV6_STATEFUL)
            opt_list = [{'opt_name': 'bootfile-name',
                         'opt_value': 'pxelinux.0'},
                        {'opt_name': 'tftp-server-address',
                         'opt_value': '123.123.123.123'}]
            params = {edo_ext.EXTRADHCPOPTS: opt_list,
                      'arg_list': (edo_ext.EXTRADHCPOPTS,)}
            self._create_port(self.fmt, network['network']['id'],
                              exc.HTTPBadRequest.code, **params)

    def test_update_ipv6_port_with_extra_dhcp(self):
        with self.network(name='net') as network:
            self._make_v6_subnet(network, constants.DHCPV6_STATEFUL)
            res = self._create_port(self.fmt, net_id=network['network']['id'])
            port = self.deserialize(self.fmt, res)
            self.assertIn('id', port['port'])

            opt_list = [{'opt_name': 'bootfile-name',
                         'opt_value': 'pxelinux.0'},
                        {'opt_name': 'tftp-server-address',
                         'opt_value': '123.123.123.123'}]
            data = {'port': {edo_ext.EXTRADHCPOPTS: opt_list}}
            req = self.new_update_request('ports', data, port['port']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertIn('NeutronError', res)

    def test_requested_subnet_id_v6_slaac(self):
        self.skipTest("NSX subnet GW validation")

    def test_requested_invalid_fixed_ip_address_v6_slaac(self):
        self.skipTest("NSX subnet GW validation")

    def test_delete_port_shared_network_with_dhcp_sub(self):
        with mock.patch.object(
            self.plugin.nsxpolicy.segment_dhcp_static_bindings,
            'delete') as mock_delete_binding:
            with self.network(shared=True) as network:
                with self.subnet(network):
                    port_res = self._create_port(
                        self.fmt, network['network']['id'],
                        exc.HTTPCreated.code,
                        tenant_id='another_tenant',
                        set_context=True)
                    port = self.deserialize(self.fmt, port_res)
                    self._delete('ports', port['port']['id'])
                    self._show('ports', port['port']['id'],
                            expected_code=exc.HTTPNotFound.code)
                mock_delete_binding.assert_called_once_with(
                    network['network']['id'], mock.ANY)

    # Tests overriden from base class as they're expected to pass instead
    # of failing with the policy plugin
    def test_create_port_additional_ip(self):
        """Test that creation of port with additional IP fails."""
        self.plugin.use_policy_dhcp = True
        with mock.patch.object(
            self.plugin.nsxpolicy.segment_dhcp_static_bindings,
            'list') as mock_list_bindings:
            with mock.patch.object(
                self.plugin.nsxpolicy.segment_dhcp_static_bindings,
                'create_or_overwrite_v4') as mock_create_bindings:
                with self.subnet() as subnet:
                    data = {'port':
                            {'network_id': subnet['subnet']['network_id'],
                             'tenant_id': subnet['subnet']['tenant_id'],
                             'device_owner': 'compute:meh',
                             'fixed_ips': [{'subnet_id':
                                            subnet['subnet']['id']},
                                           {'subnet_id':
                                            subnet['subnet']['id']}]}}
                    port_req = self.new_create_request('ports', data)
                    res = port_req.get_response(self.api)
                    self.assertEqual(201, res.status_int)
                    res = self.deserialize('json', res)
                    fixed_ips = res['port']['fixed_ips']
                    subnet_ids = set(item['subnet_id'] for item in fixed_ips)
                    self.assertEqual(1, len(subnet_ids))
                    self.assertIn(subnet['subnet']['id'], subnet_ids)
                    mock_list_bindings.assert_called_once()
                    mock_create_bindings.assert_called_once_with(
                        mock.ANY, mock.ANY,
                        binding_id=mock.ANY,
                        gateway_address=subnet['subnet']['gateway_ip'],
                        host_name=mock.ANY,
                        ip_address=fixed_ips[0]['ip_address'],
                        lease_time=mock.ANY,
                        mac_address=res['port']['mac_address'],
                        options=mock.ANY)

    def test_update_port_add_additional_ip(self):
        with self.subnet() as subnet:
            post_data = {
                'port': {
                    'network_id': subnet['subnet']['network_id'],
                    'tenant_id': subnet['subnet']['tenant_id'],
                    'device_owner': 'compute:meh',
                    'fixed_ips': [{'subnet_id':
                                    subnet['subnet']['id']}]}}
            post_req = self.new_create_request('ports', post_data)
            res = post_req.get_response(self.api)
            self.assertEqual(201, res.status_int)
            port = self.deserialize('json', res)
            orig_fixed_ip = (
                port['port']['fixed_ips'][0]['ip_address'])
            with mock.patch.object(
                self.plugin.nsxpolicy.segment_dhcp_static_bindings,
                'list') as mock_list_bindings:
                with mock.patch.object(
                    self.plugin.nsxpolicy.segment_dhcp_static_bindings,
                    'create_or_overwrite_v4') as mock_create_bindings:
                    mock_list_bindings.return_value = [
                        {'ip_address': orig_fixed_ip}
                    ]
                    put_data = {
                        'port': {
                            'device_owner': 'compute:meh',
                            'fixed_ips': [
                                {'subnet_id': subnet['subnet']['id'],
                                 'ip_address': orig_fixed_ip},
                                {'subnet_id': subnet['subnet']['id']}]}}
                    put_req = self.new_update_request(
                        'ports', put_data, port['port']['id'])
                    put_res = put_req.get_response(self.api)
                    self.assertEqual(200, put_res.status_int)
                    upd_port = self.deserialize('json', res)['port']
                    fixed_ips = upd_port['fixed_ips']
                    subnet_ids = set(item['subnet_id'] for item in fixed_ips)
                    self.assertEqual(1, len(subnet_ids))
                    self.assertIn(subnet['subnet']['id'], subnet_ids)
                    mock_list_bindings.assert_called_once()
                    mock_create_bindings.assert_not_called()

    def test_update_port_clear_ip(self):
        with self.subnet() as subnet:
            post_data = {
                'port': {
                    'network_id': subnet['subnet']['network_id'],
                    'tenant_id': subnet['subnet']['tenant_id'],
                    'device_owner': 'compute:meh',
                    'fixed_ips': [{'subnet_id': subnet['subnet']['id']},
                                  {'subnet_id': subnet['subnet']['id']}]}}
            post_req = self.new_create_request('ports', post_data)
            res = post_req.get_response(self.api)
            self.assertEqual(201, res.status_int)
            port = self.deserialize('json', res)
            with mock.patch.object(
                self.plugin.nsxpolicy.segment_dhcp_static_bindings,
                'list') as mock_list_bindings:
                with mock.patch.object(
                    self.plugin.nsxpolicy.segment_dhcp_static_bindings,
                    'create_or_overwrite_v4') as mock_create_bindings:
                    put_data = {'port':
                                {'fixed_ips': [],
                                 secgrp.SECURITYGROUPS: []}}
                    put_req = self.new_update_request(
                        'ports', put_data, port['port']['id'])
                    res = put_req.get_response(self.api)
                    self.assertEqual(200, res.status_int)
                    res = self.deserialize('json', res)
                    fixed_ips = res['port']['fixed_ips']
                    subnet_ids = set(item['subnet_id'] for item in fixed_ips)
                    self.assertEqual(0, len(subnet_ids))
                    mock_list_bindings.assert_not_called()
                    mock_create_bindings.assert_not_called()

    def test_update_port_ip_in_allowed_pair_cidr(self):
        with self.subnet() as subnet:
            post_data = {
                'port': {
                    'network_id': subnet['subnet']['network_id'],
                    'tenant_id': subnet['subnet']['tenant_id'],
                    'device_owner': 'compute:meh',
                    'fixed_ips': [{'subnet_id':
                                    subnet['subnet']['id']}]}}
            post_req = self.new_create_request('ports', post_data)
            res = post_req.get_response(self.api)
            self.assertEqual(201, res.status_int)
            port = self.deserialize('json', res)
            with mock.patch.object(
                self.plugin.nsxpolicy.segment_port,
                'create_or_overwrite') as mock_port:
                put_data = {
                    'port': {
                        'allowed_address_pairs': [
                            {'ip_address': subnet['subnet']['cidr']}
                        ]
                    }
                }
                put_req = self.new_update_request(
                    'ports', put_data, port['port']['id'])
                put_res = put_req.get_response(self.api)
                self.assertEqual(200, put_res.status_int)
                self.assertEqual(1, len(mock_port.mock_calls))
                _n, _a, kwargs = mock_port.mock_calls[0]
                actual_binding = kwargs['address_bindings'][0]
                self.assertEqual(
                    subnet['subnet']['cidr'],
                    actual_binding.ip_address)

    def test_update_port_ip_not_in_allowed_pair_cidr(self):
        with self.subnet() as subnet:
            post_data = {
                'port': {
                    'network_id': subnet['subnet']['network_id'],
                    'tenant_id': subnet['subnet']['tenant_id'],
                    'device_owner': 'compute:meh',
                    'fixed_ips': [{'subnet_id':
                                    subnet['subnet']['id']}]}}
            post_req = self.new_create_request('ports', post_data)
            res = post_req.get_response(self.api)
            self.assertEqual(201, res.status_int)
            port = self.deserialize('json', res)
            fixed_ip = (
                port['port']['fixed_ips'][0]['ip_address'])
            with mock.patch.object(
                self.plugin.nsxpolicy.segment_port,
                'create_or_overwrite') as mock_port:
                put_data = {
                    'port': {
                        'allowed_address_pairs': [
                            {'ip_address': '1.2.3.0/24'}
                        ]
                    }
                }
                put_req = self.new_update_request(
                    'ports', put_data, port['port']['id'])
                put_res = put_req.get_response(self.api)
                self.assertEqual(200, put_res.status_int)
                self.assertEqual(1, len(mock_port.mock_calls))
                _n, _a, kwargs = mock_port.mock_calls[0]
                actual_bindings = kwargs['address_bindings']
                addresses = set([b.ip_address for b in actual_bindings])
                self.assertEqual(
                    set([fixed_ip, '1.2.3.0/24']),
                    addresses)

    def test_update_port_allowed_pair_cidr(self):
        with self.subnet() as subnet:
            post_data = {
                'port': {
                    'network_id': subnet['subnet']['network_id'],
                    'tenant_id': subnet['subnet']['tenant_id'],
                    'allowed_address_pairs': [
                        {'ip_address': '10.4.0.32',
                         'mac_address': '00:00:5e:00:01:fa'},
                        {'ip_address': '10.40.1.125',
                         'mac_address': 'fa:16:3e:ef:b1:be'}],
                    'device_owner': 'compute:meh',
                    'fixed_ips': [{'subnet_id':
                                    subnet['subnet']['id']}]}}
            post_req = self.new_create_request('ports', post_data)
            res = post_req.get_response(self.api)
            self.assertEqual(201, res.status_int)
            port = self.deserialize('json', res)
            fixed_ip = (
                port['port']['fixed_ips'][0]['ip_address'])
            with mock.patch.object(
                self.plugin.nsxpolicy.segment_port,
                'create_or_overwrite') as mock_port:
                put_data = {
                    'port': {
                        'allowed_address_pairs': [
                            {'ip_address': '10.4.0.0/24'}
                        ]
                    }
                }
                put_req = self.new_update_request(
                    'ports', put_data, port['port']['id'])
                put_res = put_req.get_response(self.api)
                self.assertEqual(200, put_res.status_int)
                self.assertEqual(1, len(mock_port.mock_calls))
                _n, _a, kwargs = mock_port.mock_calls[0]
                actual_bindings = kwargs['address_bindings']
                addresses = set([b.ip_address for b in actual_bindings])
                self.assertEqual(
                    set([fixed_ip, '10.4.0.0/24']),
                    addresses)


class NsxPTestSubnets(common_v3.NsxV3TestSubnets,
                      NsxPPluginTestCaseMixin):
    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None):
        super(NsxPTestSubnets, self).setUp(plugin=plugin, ext_mgr=ext_mgr)

    def _create_subnet_bulk(self, fmt, number, net_id, name,
                            ip_version=4, **kwargs):
        base_data = {'subnet': {'network_id': net_id,
                                'ip_version': ip_version,
                                'enable_dhcp': False,
                                'tenant_id': self._tenant_id}}
        if 'ipv6_mode' in kwargs:
            base_data['subnet']['ipv6_ra_mode'] = kwargs['ipv6_mode']
            base_data['subnet']['ipv6_address_mode'] = kwargs['ipv6_mode']
        # auto-generate cidrs as they should not overlap
        base_cidr = "10.0.%s.0/24"
        if ip_version == constants.IP_VERSION_6:
            base_cidr = "fd%s::/64"

        # auto-generate cidrs as they should not overlap
        overrides = dict((k, v)
                         for (k, v) in zip(range(number),
                                           [{'cidr': base_cidr % num}
                                            for num in range(number)]))
        kwargs.update({'override': overrides})
        return self._create_bulk(fmt, number, 'subnet', base_data, **kwargs)

    @common_v3.with_disable_dhcp_once
    def test_create_subnet_ipv6_slaac_with_port_on_network(self):
        super(NsxPTestSubnets,
              self).test_create_subnet_ipv6_slaac_with_port_on_network()

    def test_create_subnet_ipv6_gw_values(self):
        self.skipTest("IPv6 gateway IP is assigned by the plugin")

    def test_create_subnet_ipv6_gw_is_nw_start_addr(self):
        self.skipTest("NSX subnet GW validation")

    def test_create_subnet_ipv6_gw_is_nw_start_addr_canonicalize(self):
        self.skipTest("NSX subnet GW validation")

    def test_create_subnet_ipv6_out_of_cidr_global(self):
        self.skipTest("NSX subnet GW validation")

    def test_create_subnet_ipv6_out_of_cidr_lla(self):
        self.skipTest("NSX subnet GW validation")

    def test_create_subnet_gw_outside_cidr_returns_201(self):
        self.skipTest("NSX subnet GW validation")

    def test_update_subnet_gw_outside_cidr_returns_200(self):
        self.skipTest("NSX subnet GW validation")

    def test_create_subnet_allocation_pools_with_prefixlen_31(self):
        self.skipTest("NSX subnet GW validation")

    def test_update_subnet_allocation_pools_with_prefixlen_31(self):
        self.skipTest("NSX subnet GW validation")

    def test_create_subnet_allocation_pools_with_prefixlen_32(self):
        self.skipTest("NSX subnet GW validation")

    def test_create_subnet_ipv6_gw_validation(self):
        # Illegal GW as first ip in range
        gateway_ip = 'fe80::0'
        cidr = 'fe80::/64'
        with testlib_api.ExpectedException(
                exc.HTTPClientError) as ctx_manager:
            self._test_create_subnet(
                gateway_ip=gateway_ip,
                cidr=cidr,
                ip_version=constants.IP_VERSION_6,
                enable_dhcp=True,
                ipv6_ra_mode=constants.DHCPV6_STATEFUL,
                ipv6_address_mode=constants.DHCPV6_STATEFUL)
            self.assertEqual(exc.HTTPClientError.code,
                             ctx_manager.exception.code)

        gateway_ip = '2080::0'
        cidr = 'fe80::/64'
        with testlib_api.ExpectedException(
                exc.HTTPClientError) as ctx_manager:
            self._test_create_subnet(
                gateway_ip=gateway_ip,
                cidr=cidr,
                ip_version=constants.IP_VERSION_6,
                enable_dhcp=True,
                ipv6_ra_mode=constants.DHCPV6_STATEFUL,
                ipv6_address_mode=constants.DHCPV6_STATEFUL)
            self.assertEqual(exc.HTTPClientError.code,
                             ctx_manager.exception.code)

    def test_create_ipv6_subnet_with_host_routes(self):
        # IPv6 host routes are not allowed
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                    'cidr': '100::/64',
                    'ip_version': 6,
                    'tenant_id': network['network']['tenant_id'],
                    'host_routes': [{'destination': '200::/64',
                                     'nexthop': '100::16'}]}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(exc.HTTPClientError.code, res.status_int)

    def test_update_ipv6_subnet_with_host_routes(self):
        # IPv6 host routes are not allowed
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                    'cidr': '100::/64',
                    'ip_version': 6,
                    'tenant_id': network['network']['tenant_id']}}
            subnet_req = self.new_create_request('subnets', data)
            subnet = self.deserialize(self.fmt,
                                      subnet_req.get_response(self.api))
            sub_id = subnet['subnet']['id']
            # update host routes should fail
            data = {'subnet': {'host_routes': [{'destination': '200::/64',
                                                'nexthop': '100::16'}]}}
            update_req = self.new_update_request('subnets', data, sub_id)
            res = update_req.get_response(self.api)
            self.assertEqual(exc.HTTPClientError.code, res.status_int)

    def _verify_dhcp_service(self, network_id, tenant_id, enabled):
        # Verify if DHCP service is enabled on a network.
        port_res = self._list_ports('json', 200, network_id,
                                    tenant_id=tenant_id,
                                    device_owner=constants.DEVICE_OWNER_DHCP)
        port_list = self.deserialize('json', port_res)
        self.assertEqual(len(port_list['ports']) == 1, enabled)

    def test_create_dhcpv6_subnet(self):
        with mock.patch("vmware_nsxlib.v3.policy.core_resources."
                        "NsxPolicySegmentApi.update") as seg_update,\
            mock.patch("vmware_nsxlib.v3.policy.core_resources."
                       "NsxPolicySegmentApi.get", return_value={}),\
            self.subnet(ip_version=constants.IP_VERSION_6, cidr='fe80::/64',
                        enable_dhcp=True) as subnet:
            self.assertEqual(True, subnet['subnet']['enable_dhcp'])
            # verify that the dhcp port was created
            self._verify_dhcp_service(subnet['subnet']['network_id'],
                                      subnet['subnet']['tenant_id'], True)
            # verify backend calls
            seg_update.assert_called_once_with(
                dhcp_server_config_id=NSX_DHCP_PROFILE_ID,
                multicast=False,
                segment_id=subnet['subnet']['network_id'],
                subnets=[mock.ANY])

    def test_subnet_enable_dhcpv6(self):
        with self.subnet(ip_version=constants.IP_VERSION_6, cidr='fe80::/64',
                         enable_dhcp=False) as subnet:
            data = {'subnet': {'enable_dhcp': True}}
            with mock.patch("vmware_nsxlib.v3.policy.core_resources."
                            "NsxPolicySegmentApi.update") as seg_update,\
                mock.patch("vmware_nsxlib.v3.policy.core_resources."
                           "NsxPolicySegmentApi.get", return_value={}):
                req = self.new_update_request('subnets', data,
                                              subnet['subnet']['id'])
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual(True, res['subnet']['enable_dhcp'])
                # verify that the dhcp port was created
                self._verify_dhcp_service(subnet['subnet']['network_id'],
                                          subnet['subnet']['tenant_id'], True)
                # verify backend calls
                seg_update.assert_called_with(
                    dhcp_server_config_id=NSX_DHCP_PROFILE_ID,
                    segment_id=subnet['subnet']['network_id'],
                    multicast=False,
                    subnets=[mock.ANY])

    def test_subnet_disable_dhcpv6(self):
        with self.subnet(ip_version=constants.IP_VERSION_6, cidr='fe80::/64',
                         enable_dhcp=True) as subnet:
            data = {'subnet': {'enable_dhcp': False}}
            with mock.patch("vmware_nsxlib.v3.policy.core_resources."
                            "NsxPolicySegmentApi.update") as seg_update:
                req = self.new_update_request('subnets', data,
                                              subnet['subnet']['id'])
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual(False, res['subnet']['enable_dhcp'])
                # verify that the dhcp port was deleted
                self._verify_dhcp_service(subnet['subnet']['network_id'],
                                          subnet['subnet']['tenant_id'], False)
                # verify backend calls
                seg_update.assert_called_once_with(
                    dhcp_server_config_id=None,
                    segment_id=subnet['subnet']['network_id'],
                    multicast=False,
                    subnets=[])

    def test_delete_ipv6_dhcp_subnet(self):
        with self.subnet(ip_version=constants.IP_VERSION_6, cidr='fe80::/64',
                         enable_dhcp=True) as subnet:
            with mock.patch("vmware_nsxlib.v3.policy.core_resources."
                            "NsxPolicySegmentApi.update") as seg_update:
                req = self.new_delete_request(
                    'subnets', subnet['subnet']['id'])
                res = req.get_response(self.api)
                self.assertEqual(exc.HTTPNoContent.code, res.status_int)
                # verify that the dhcp port was deleted
                self._verify_dhcp_service(subnet['subnet']['network_id'],
                                          subnet['subnet']['tenant_id'], False)
                # verify backend calls
                seg_update.assert_called_once_with(
                    dhcp_server_config_id=None,
                    segment_id=subnet['subnet']['network_id'],
                    multicast=False,
                    subnets=[])


class NsxPTestSecurityGroup(common_v3.FixExternalNetBaseTest,
                            NsxPPluginTestCaseMixin,
                            test_securitygroup.TestSecurityGroups,
                            test_securitygroup.SecurityGroupDBTestCase):

    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None):
        super(NsxPTestSecurityGroup, self).setUp(plugin=plugin,
                                                 ext_mgr=ext_mgr)
        self.project_id = test_db_base_plugin_v2.TEST_TENANT_ID
        # add provider group attributes
        secgrp.Securitygroup().update_attributes_map(
            provider_sg.EXTENDED_ATTRIBUTES_2_0)

    def test_create_security_group_rule_icmp_with_type_and_code(self):
        """No non-zero icmp codes are currently supported by the NSX"""
        self.skipTest('not supported')

    def test_create_security_group_rule_icmp_with_type(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            direction = "ingress"
            remote_ip_prefix = "10.0.0.0/24"
            protocol = "icmp"
            # port_range_min (ICMP type) is greater than port_range_max
            # (ICMP code) in order to confirm min <= max port check is
            # not called for ICMP.
            port_range_min = 14
            port_range_max = None
            keys = [('remote_ip_prefix', remote_ip_prefix),
                    ('security_group_id', security_group_id),
                    ('direction', direction),
                    ('protocol', protocol),
                    ('port_range_min', port_range_min),
                    ('port_range_max', port_range_max)]
            with self.security_group_rule(security_group_id, direction,
                                          protocol, port_range_min,
                                          port_range_max,
                                          remote_ip_prefix) as rule:
                for k, v, in keys:
                    self.assertEqual(rule['security_group_rule'][k], v)

    @common_v3.with_no_dhcp_subnet
    def test_list_ports_security_group(self):
        return super(NsxPTestSecurityGroup,
                     self).test_list_ports_security_group()

    @mock.patch.object(nsx_plugin.NsxPolicyPlugin, 'get_security_group')
    def test_create_security_group_rule_with_invalid_tcp_or_udp_protocol(
        self, get_mock):
        super(NsxPTestSecurityGroup, self).\
            test_create_security_group_rule_with_invalid_tcp_or_udp_protocol()

    @mock.patch.object(nsx_plugin.NsxPolicyPlugin, 'get_security_group')
    def test_create_security_group_source_group_ip_and_ip_prefix(
        self, get_mock):
        super(NsxPTestSecurityGroup, self).\
            test_create_security_group_source_group_ip_and_ip_prefix()

    def _create_default_sg(self):
        self.plugin._ensure_default_security_group(
            context.get_admin_context(), self.project_id)

    def test_sg_create_on_nsx(self):
        """Verify that a group and comm-map are created for a new SG"""
        # Make sure the default SG is created before testing
        self._create_default_sg()
        name = description = 'sg1'
        with mock.patch("vmware_nsxlib.v3.policy.core_resources."
                        "NsxPolicyGroupApi.create_or_overwrite_with_conditions"
                        ) as group_create,\
            mock.patch("vmware_nsxlib.v3.policy.core_resources."
                       "NsxPolicyCommunicationMapApi."
                       "create_or_overwrite_map_only") as comm_map_create,\
            self.security_group(name, description) as sg:
            sg_id = sg['security_group']['id']
            nsx_name = utils.get_name_and_uuid(name, sg_id)
            group_create.assert_called_once_with(
                nsx_name, pol_const.DEFAULT_DOMAIN, group_id=sg_id,
                description=description,
                conditions=[mock.ANY], tags=mock.ANY)
            comm_map_create.assert_called_once_with(
                nsx_name, pol_const.DEFAULT_DOMAIN, map_id=sg_id,
                description=description,
                tags=mock.ANY,
                category=pol_const.CATEGORY_ENVIRONMENT)

    def _create_provider_security_group(self):
        body = {'security_group': {'name': 'provider-deny',
                                   'tenant_id': self._tenant_id,
                                   'description': 'provider sg',
                                   'provider': True}}
        security_group_req = self.new_create_request('security-groups', body)
        return self.deserialize(self.fmt,
                                security_group_req.get_response(self.ext_api))

    def test_provider_sg_on_port(self):
        psg = self._create_provider_security_group()
        with mock.patch("vmware_nsxlib.v3.policy.core_resources."
                        "NsxPolicySegmentPortApi.create_or_overwrite"
                        ) as port_create:
            with self.port(tenant_id=self._tenant_id) as port:
                # make sure the port has the provider sg
                port_data = port['port']
                self.assertEqual(1, len(port_data['provider_security_groups']))
                self.assertEqual(psg['security_group']['id'],
                                 port_data['provider_security_groups'][0])

                # Make sure the correct security groups tags were set
                port_create.assert_called_once()
                actual_tags = port_create.call_args[1]['tags']
                sg_tags = 0
                psg_tag_found = False
                for tag in actual_tags:
                    if tag['scope'] == 'os-security-group':
                        sg_tags += 1
                        if tag['tag'] == psg['security_group']['id']:
                            psg_tag_found = True
                self.assertEqual(2, sg_tags)
                self.assertTrue(psg_tag_found)

    def test_remove_provider_sg_from_port(self):
        psg = self._create_provider_security_group()
        with self.port(tenant_id=self._tenant_id) as port:
            with mock.patch("vmware_nsxlib.v3.policy.core_resources."
                            "NsxPolicySegmentPortApi.create_or_overwrite"
                            ) as port_update:
                # specifically remove the provider sg from the port
                data = {'port': {'provider_security_groups': []}}
                req = self.new_update_request('ports',
                                              data, port['port']['id'])
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual(0,
                                 len(res['port']['provider_security_groups']))
                # Make sure the correct security groups tags were set
                port_update.assert_called_once()
                actual_tags = port_update.call_args[1]['tags']
                sg_tags = 0
                psg_tag_found = False
                for tag in actual_tags:
                    if tag['scope'] == 'os-security-group':
                        sg_tags += 1
                        if tag['tag'] == psg['security_group']['id']:
                            psg_tag_found = True
                self.assertEqual(1, sg_tags)
                self.assertFalse(psg_tag_found)

    def test_sg_rule_create_on_nsx(self):
        """Verify that a comm-map entry is created for a new SG rule """
        name = description = 'sg1'
        direction = "ingress"
        remote_ip_prefix = "10.0.0.0/24"
        protocol = "tcp"
        port_range_min = 80
        port_range_max = 80
        with self.security_group(name, description) as sg:
            sg_id = sg['security_group']['id']
            with mock.patch("vmware_nsxlib.v3.policy.core_resources."
                            "NsxPolicyCommunicationMapApi.patch_entries"
                            ) as update_policy,\
                self.security_group_rule(sg_id, direction,
                                         protocol, port_range_min,
                                         port_range_max,
                                         remote_ip_prefix):
                update_policy.assert_called_once()

    def test_create_security_group_rule_with_remote_group(self):
        with self.security_group() as sg1, self.security_group() as sg2:
            security_group_id = sg1['security_group']['id']
            direction = "ingress"
            remote_group_id = sg2['security_group']['id']
            protocol = "tcp"
            keys = [('remote_group_id', remote_group_id),
                    ('security_group_id', security_group_id),
                    ('direction', direction),
                    ('protocol', protocol)]
            with self.security_group_rule(
                security_group_id, direction=direction, protocol=protocol,
                remote_group_id=remote_group_id) as rule:
                for k, v, in keys:
                    self.assertEqual(rule['security_group_rule'][k], v)

    def test_delete_security_group_rule_with_remote_group(self):
        com_plugin.subscribe()
        with self.security_group() as sg1, self.security_group() as sg2:
            security_group_id = sg1['security_group']['id']
            direction = "ingress"
            remote_group_id = sg2['security_group']['id']
            protocol = "tcp"
            with self.security_group_rule(
                security_group_id, direction=direction, protocol=protocol,
                remote_group_id=remote_group_id) as rule,\
                mock.patch.object(
                    self.plugin, "delete_security_group_rule") as del_rule:
                # delete sg2
                self._delete('security-groups', remote_group_id,
                             exc.HTTPNoContent.code)
                # verify the rule was deleted
                del_rule.assert_called_once_with(
                    mock.ANY, rule["security_group_rule"]["id"])

    def test_create_security_group_rule_remote_address_group_id(self):
        self.skipTest('No support for SG address groups')

    def test_delete_address_group_in_use(self):
        self.skipTest('No support for SG address groups')

    def test_create_security_group_rule_multiple_remotes(self):
        self.skipTest('No support for SG address groups')

    def test_list_security_groups_with_shared_filter_false(self):
        self.skipTest('No support for SG shared field')


class NsxPTestL3ExtensionManager(object):

    def get_resources(self):
        # Simulate extension of L3 attribute map
        l3.L3().update_attributes_map(
            l3_egm_apidef.RESOURCE_ATTRIBUTE_MAP)
        l3.L3().update_attributes_map(
            xroute_apidef.RESOURCE_ATTRIBUTE_MAP)
        return (l3.L3.get_resources() +
                address_scope.Address_scope.get_resources())

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class NsxPTestL3NatTest(common_v3.FixExternalNetBaseTest,
                        common_v3.NsxV3SubnetMixin,
                        NsxPPluginTestCaseMixin,
                        test_l3_plugin.L3BaseForIntTests,
                        test_address_scope.AddressScopeTestCase):

    def setUp(self, *args, **kwargs):
        cfg.CONF.set_override('api_extensions_path', vmware.NSXEXT_PATH)
        cfg.CONF.set_default('max_routes', 3)
        kwargs['ext_mgr'] = (kwargs.get('ext_mgr') or
                             NsxPTestL3ExtensionManager())

        # Make sure the LB callback is not called on router deletion
        self.lb_mock1 = mock.patch(
            "vmware_nsx.services.lbaas.octavia.octavia_listener."
            "NSXOctaviaListenerEndpoint._check_lb_service_on_router")
        self.lb_mock1.start()
        self.lb_mock2 = mock.patch(
            "vmware_nsx.services.lbaas.octavia.octavia_listener."
            "NSXOctaviaListenerEndpoint._check_lb_service_on_router_interface")
        self.lb_mock2.start()

        super(NsxPTestL3NatTest, self).setUp(*args, **kwargs)
        self.original_subnet = self.subnet
        self.original_network = self.network

        self.plugin_instance = directory.get_plugin()
        self._plugin_name = "%s.%s" % (
            self.plugin_instance.__module__,
            self.plugin_instance.__class__.__name__)
        self._plugin_class = self.plugin_instance.__class__

    def external_network(self, name='net1',
                         admin_state_up=True,
                         fmt=None, **kwargs):
        if not name:
            name = 'l3_ext_net'
        physical_network = 'abc'
        net_type = utils.NetworkTypes.L3_EXT
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: physical_network}
        return self.original_network(name=name,
                                     admin_state_up=admin_state_up,
                                     fmt=fmt,
                                     router__external=True,
                                     providernet_args=providernet_args,
                                     arg_list=(pnet.NETWORK_TYPE,
                                         pnet.PHYSICAL_NETWORK))

    def test_floatingip_create_different_fixed_ip_same_port(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_router_add_interface_multiple_ipv4_subnet_port_returns_400(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_router_add_interface_multiple_ipv6_subnet_port(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_floatingip_update_different_fixed_ip_same_port(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_create_multiple_floatingips_same_fixed_ip_same_port(self):
        self.skipTest('Multiple fixed ips on a port are not supported')


class NsxPTestL3NatTestCase(NsxPTestL3NatTest,
                            test_l3_plugin.L3NatDBIntTestCase,
                            test_ext_route.ExtraRouteDBTestCaseBase):

    def setUp(self, *args, **kwargs):
        super(NsxPTestL3NatTestCase, self).setUp(*args, **kwargs)

        mock.patch.object(self.plugin.nsxpolicy, 'search_by_tags',
                          return_value={'results': []}).start()

    def test__notify_gateway_port_ip_changed(self):
        self.skipTest('not supported')

    def test__notify_gateway_port_ip_not_changed(self):
        self.skipTest('not supported')

    def test_floatingip_via_router_interface_returns_201(self):
        self.skipTest('not supported')

    def test_floatingip_via_router_interface_returns_404(self):
        self.skipTest('not supported')

    def test_network_update_external(self):
        # This plugin does not support updating the external flag of a network
        self.skipTest('not supported')

    def test_network_update_external_failure(self):
        # This plugin does not support updating the external flag of a network
        self.skipTest('not supported')

    def test_router_add_gateway_dup_subnet1_returns_400(self):
        self.skipTest('not supported')

    def test_router_add_interface_dup_subnet2_returns_400(self):
        self.skipTest('not supported')

    def test_router_add_interface_ipv6_port_existing_network_returns_400(self):
        self.skipTest('not supported')

    def test_routes_update_for_multiple_routers(self):
        self.skipTest('not supported')

    def test_floatingip_multi_external_one_internal(self):
        self.skipTest('not supported')

    def test_floatingip_same_external_and_internal(self):
        self.skipTest('not supported')

    def test_route_update_with_external_route(self):
        self.skipTest('not supported')

    def test_floatingip_update_subnet_gateway_disabled(self):
        self.skipTest('not supported')

    def test_floatingip_update_to_same_port_id_twice(self):
        self.skipTest('Plugin changes floating port status')

    def test_router_add_interface_by_port_other_tenant_address_out_of_pool(
        self):
        # multiple fixed ips per port are not supported
        self.skipTest('not supported')

    def test_router_add_interface_by_port_other_tenant_address_in_pool(self):
        # multiple fixed ips per port are not supported
        self.skipTest('not supported')

    def test_router_add_interface_by_port_admin_address_out_of_pool(self):
        # multiple fixed ips per port are not supported
        self.skipTest('not supported')

    def test_router_add_gateway_no_subnet(self):
        self.skipTest('No support for no subnet gateway set')

    def test_router_remove_ipv6_subnet_from_interface(self):
        self.skipTest('not supported')

    def test_router_add_interface_multiple_ipv6_subnets_same_net(self):
        self.skipTest('not supported')

    def test_router_add_interface_multiple_ipv4_subnets(self):
        self.skipTest('not supported')

    def test_router_update_gateway_upon_subnet_create_max_ips_ipv6(self):
        self.skipTest('not supported')

    def test_router_delete_dhcpv6_stateless_subnet_inuse_returns_409(self):
        self.skipTest('not supported')

    @common_v3.with_disable_dhcp
    @common_v3.with_external_network
    def test_router_update_gateway_upon_subnet_create_ipv6(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_update_gateway_upon_subnet_create_ipv6()

    def test_router_delete_ipv6_slaac_subnet_inuse_returns_409(self):
        self.skipTest('not supported')

    def test_router_add_gateway_multiple_subnets_ipv6(self):
        self.skipTest('not supported')

    def test_slaac_profile_single_subnet(self):
        with mock.patch("vmware_nsxlib.v3.policy.core_resources."
                        "NsxPolicyTier1Api.update") as t1_update:

            with self.router() as r, self.network() as n:
                with self.subnet(network=n, cidr='fd00::0/64',
                                 gateway_ip='fd00::1', ip_version=6,
                                 ipv6_address_mode='slaac',
                                 ipv6_ra_mode='slaac') as s:

                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s['subnet']['id'],
                                                  None)
                    # Validate T1 was updated with slaac profile
                    t1_update.assert_called_with(
                        r['router']['id'],
                        ipv6_ndra_profile_id='neutron-slaac-profile')

                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s['subnet']['id'],
                                                  None)
                    # Validate T1 was updated with default profile
                    t1_update.assert_called_with(
                        r['router']['id'],
                        ipv6_ndra_profile_id='neutron-no-slaac-profile')

    def test_slaac_profile_dual_stack(self):
        with mock.patch("vmware_nsxlib.v3.policy.core_resources."
                        "NsxPolicyTier1Api.update") as t1_update:

            with self.router() as r,\
                self.network() as n:
                with self.subnet(network=n, cidr='2.3.3.0/24') as s1,\
                    self.subnet(network=n, cidr='fd10::0/64',
                                gateway_ip='fd10::1', ip_version=6,
                                ipv6_address_mode='slaac',
                                ipv6_ra_mode='slaac') as s2:

                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s1['subnet']['id'],
                                                  None)
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)
                    # Validate T1 was updated with slaac profile
                    t1_update.assert_called_with(
                        r['router']['id'],
                        ipv6_ndra_profile_id='neutron-slaac-profile')

                    # Remove non-slaac subnets first
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s1['subnet']['id'],
                                                  None)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)

                    # Validate T1 was updated with default profile
                    t1_update.assert_called_with(
                        r['router']['id'],
                        ipv6_ndra_profile_id='neutron-no-slaac-profile')

                    self._delete('subnets', s1['subnet']['id'])
                    self._delete('subnets', s2['subnet']['id'])

    def test_slaac_profile_multi_net(self):
        with mock.patch("vmware_nsxlib.v3.policy.core_resources."
                        "NsxPolicyTier1Api.update") as t1_update:

            with self.router() as r,\
                self.network() as n1, self.network() as n2:
                with self.subnet(network=n1, cidr='fd00::0/64',
                                 gateway_ip='fd00::1', ip_version=6,
                                 enable_dhcp=False) as s1,\
                    self.subnet(network=n2, cidr='fd10::0/64',
                                gateway_ip='fd10::1', ip_version=6,
                                ipv6_address_mode='slaac',
                                ipv6_ra_mode='slaac') as s2,\
                    self.subnet(network=n2, cidr='2.3.3.0/24',
                                gateway_ip='2.3.3.1') as s3:

                    # Add three subnets to the router, with slaac-enabled one
                    # in the middle
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s1['subnet']['id'],
                                                  None)
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s3['subnet']['id'],
                                                  None)
                    # Validate T1 was updated with slaac profile
                    t1_update.assert_called_with(
                        r['router']['id'],
                        ipv6_ndra_profile_id='neutron-slaac-profile')

                    # Remove non-slaac subnets first
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s1['subnet']['id'],
                                                  None)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s3['subnet']['id'],
                                                  None)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)
                    # Validate T1 was updated with default profile
                    t1_update.assert_called_with(
                        r['router']['id'],
                        ipv6_ndra_profile_id='neutron-no-slaac-profile')

    def _test_router_add_dual_stack_subnets(self, s6_first=False):
        """Add dual stack subnets to router"""

        with mock.patch("vmware_nsxlib.v3.policy.core_resources."
                        "NsxPolicySegmentApi.update") as seg_update:

            with self.router() as r, self.network() as n:
                with self.subnet(
                    network=n, cidr='fd00::0/64', gateway_ip='fd00::1',
                        ip_version=6, enable_dhcp=False) as s6, self.subnet(
                        network=n, cidr='2.0.0.0/24',
                        gateway_ip='2.0.0.1') as s4:

                    subnets = []
                    if s6_first:
                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      s6['subnet']['id'],
                                                      None)
                        subnets.append(s6['subnet']['cidr'])

                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s4['subnet']['id'],
                                                  None)
                    subnets.append(s4['subnet']['cidr'])

                    if not s6_first:
                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      s6['subnet']['id'],
                                                      None)
                        subnets.append(s6['subnet']['cidr'])

                    # We expect two subnet objects on segment
                    seg_update.assert_called_with(
                        n['network']['id'],
                        multicast=mock.ANY,
                        subnets=[mock.ANY, mock.ANY],
                        tier1_id=r['router']['id'])

    def test_router_add_v4_v6_subnets(self):
        self._test_router_add_dual_stack_subnets()

    def test_router_add_v6_v4_subnets(self):
        self._test_router_add_dual_stack_subnets(s6_first=True)

    def test_router_remove_dual_stack_subnets(self):
        """Delete dual stack subnets from router interface"""

        with self.router() as r, self.network() as n:
            with self.subnet(network=n, cidr='fd00::0/64',
                             ip_version=6, enable_dhcp=False) as s6, \
                self.subnet(network=n, cidr='2.0.0.0/24') as s4:

                body6 = self._router_interface_action('add', r['router']['id'],
                                                     s6['subnet']['id'],
                                                     None)
                body4 = self._router_interface_action('add', r['router']['id'],
                                              s4['subnet']['id'], None)
                port = self._show('ports', body6['port_id'])
                self.assertEqual(1, len(port['port']['fixed_ips']))
                port = self._show('ports', body4['port_id'])
                self.assertEqual(1, len(port['port']['fixed_ips']))
                self._router_interface_action('remove', r['router']['id'],
                                              s6['subnet']['id'], None)
                self._router_interface_action('remove', r['router']['id'],
                                              s4['subnet']['id'], None)

    def test_router_add_interface_ipv6_single_subnet(self):
        with self.router() as r, self.network() as n:
            with self.subnet(network=n, cidr='fd00::1/64',
                             gateway_ip='fd00::1', ip_version=6,
                             enable_dhcp=False) as s:
                self._test_router_add_interface_subnet(r, s)

    def test_router_set_gateway_cidr_overlapped_with_subnets(self):
        self.skipTest('2 dhcp subnets not supported')

    @common_v3.with_disable_dhcp
    def test_route_clear_routes_with_None(self):
        super(NsxPTestL3NatTestCase,
              self).test_route_clear_routes_with_None()

    @common_v3.with_disable_dhcp
    def test_route_update_with_multi_routes(self):
        super(NsxPTestL3NatTestCase,
              self).test_route_update_with_multi_routes()

    @common_v3.with_disable_dhcp
    def test_route_update_with_one_route(self):
        super(NsxPTestL3NatTestCase,
              self).test_route_update_with_one_route()

    @common_v3.with_disable_dhcp
    def test_router_update_delete_routes(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_update_delete_routes()

    @common_v3.with_disable_dhcp
    def test_router_interface_in_use_by_route(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_interface_in_use_by_route()

    @common_v3.with_disable_dhcp
    def test_create_floatingip_with_assoc_to_ipv4_and_ipv6_port(self):
        super(NsxPTestL3NatTestCase,
              self).test_create_floatingip_with_assoc_to_ipv4_and_ipv6_port()

    @common_v3.with_external_subnet
    def test_router_update_gateway_with_external_ip_used_by_gw(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_update_gateway_with_external_ip_used_by_gw()

    @common_v3.with_external_subnet
    def test_router_update_gateway_with_invalid_external_ip(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_update_gateway_with_invalid_external_ip()

    @common_v3.with_external_subnet
    def test_router_update_gateway_with_invalid_external_subnet(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_update_gateway_with_invalid_external_subnet()

    @common_v3.with_external_network
    def test_router_update_gateway_with_different_external_subnet(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_update_gateway_with_different_external_subnet()

    @common_v3.with_external_subnet_once
    def test_router_update_gateway_with_existed_floatingip(self):
        with self.subnet(cidr='20.0.0.0/24') as subnet:
            self._set_net_external(subnet['subnet']['network_id'])
            with self.floatingip_with_assoc() as fip:
                self._add_external_gateway_to_router(
                    fip['floatingip']['router_id'],
                    subnet['subnet']['network_id'],
                    expected_code=exc.HTTPConflict.code)

    @common_v3.with_external_network
    def test_router_update_gateway_add_multiple_prefixes_ipv6(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_update_gateway_add_multiple_prefixes_ipv6()

    @common_v3.with_external_network
    def test_router_concurrent_delete_upon_subnet_create(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_concurrent_delete_upon_subnet_create()

    @common_v3.with_external_subnet
    def test_router_add_gateway_dup_subnet2_returns_400(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_add_gateway_dup_subnet2_returns_400()

    @common_v3.with_external_subnet
    def test_router_update_gateway(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_update_gateway()

    @common_v3.with_external_subnet
    def test_router_create_with_gwinfo(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_create_with_gwinfo()

    @common_v3.with_external_subnet
    def test_router_clear_gateway_callback_failure_returns_409(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_clear_gateway_callback_failure_returns_409()

    @common_v3.with_external_subnet
    def test_router_create_with_gwinfo_ext_ip(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_create_with_gwinfo_ext_ip()

    @common_v3.with_external_network
    def test_router_create_with_gwinfo_ext_ip_subnet(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_create_with_gwinfo_ext_ip_subnet()

    @common_v3.with_external_subnet_second_time
    def test_router_delete_with_floatingip_existed_returns_409(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_delete_with_floatingip_existed_returns_409()

    @common_v3.with_external_subnet
    def test_router_add_and_remove_gateway_tenant_ctx(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_add_and_remove_gateway_tenant_ctx()

    @common_v3.with_external_subnet
    def test_router_add_and_remove_gateway(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_add_and_remove_gateway()

    @common_v3.with_external_subnet
    def test_floatingip_list_with_sort(self):
        super(NsxPTestL3NatTestCase,
              self).test_floatingip_list_with_sort()

    @common_v3.with_external_subnet_once
    def test_floatingip_with_assoc_fails(self):
        super(NsxPTestL3NatTestCase,
              self).test_floatingip_with_assoc_fails()

    @common_v3.with_external_subnet_second_time
    def test_floatingip_update_same_fixed_ip_same_port(self):
        super(NsxPTestL3NatTestCase,
              self).test_floatingip_update_same_fixed_ip_same_port()

    @common_v3.with_external_subnet
    def test_floatingip_list_with_pagination_reverse(self):
        super(NsxPTestL3NatTestCase,
              self).test_floatingip_list_with_pagination_reverse()

    @common_v3.with_external_subnet_once
    def test_floatingip_association_on_unowned_router(self):
        super(NsxPTestL3NatTestCase,
              self).test_floatingip_association_on_unowned_router()

    @common_v3.with_external_network
    def test_delete_ext_net_with_disassociated_floating_ips(self):
        super(NsxPTestL3NatTestCase,
              self).test_delete_ext_net_with_disassociated_floating_ips()

    @common_v3.with_external_network
    def test_create_floatingip_with_subnet_and_invalid_fip_address(self):
        super(
            NsxPTestL3NatTestCase,
            self).test_create_floatingip_with_subnet_and_invalid_fip_address()

    @common_v3.with_external_subnet
    def test_create_floatingip_with_duplicated_specific_ip(self):
        super(NsxPTestL3NatTestCase,
              self).test_create_floatingip_with_duplicated_specific_ip()

    @common_v3.with_external_subnet
    def test_create_floatingip_with_subnet_id_non_admin(self):
        super(NsxPTestL3NatTestCase,
              self).test_create_floatingip_with_subnet_id_non_admin()

    @common_v3.with_external_subnet
    def test_floatingip_list_with_pagination(self):
        super(NsxPTestL3NatTestCase,
              self).test_floatingip_list_with_pagination()

    @common_v3.with_external_subnet
    def test_create_floatingips_native_quotas(self):
        super(NsxPTestL3NatTestCase,
              self).test_create_floatingips_native_quotas()

    @common_v3.with_external_network
    def test_create_floatingip_with_multisubnet_id(self):
        super(NsxPTestL3NatTestCase,
              self).test_create_floatingip_with_multisubnet_id()

    @common_v3.with_external_network
    def test_create_floatingip_with_subnet_id_and_fip_address(self):
        super(NsxPTestL3NatTestCase,
              self).test_create_floatingip_with_subnet_id_and_fip_address()

    @common_v3.with_external_subnet
    def test_create_floatingip_with_specific_ip(self):
        super(NsxPTestL3NatTestCase,
              self).test_create_floatingip_with_specific_ip()

    @common_v3.with_external_network
    def test_create_floatingip_ipv6_and_ipv4_network_creates_ipv4(self):
        super(NsxPTestL3NatTestCase,
              self).test_create_floatingip_ipv6_and_ipv4_network_creates_ipv4()

    @common_v3.with_external_subnet_once
    def test_create_floatingip_non_admin_context_agent_notification(self):
        super(
            NsxPTestL3NatTestCase,
            self).test_create_floatingip_non_admin_context_agent_notification()

    @common_v3.with_external_subnet
    def test_create_floatingip_no_ext_gateway_return_404(self):
        super(NsxPTestL3NatTestCase,
              self).test_create_floatingip_no_ext_gateway_return_404()

    @common_v3.with_external_subnet
    def test_create_floatingip_with_specific_ip_out_of_allocation(self):
        super(NsxPTestL3NatTestCase,
              self).test_create_floatingip_with_specific_ip_out_of_allocation()

    @common_v3.with_external_subnet_third_time
    def test_floatingip_update_different_router(self):
        super(NsxPTestL3NatTestCase,
              self).test_floatingip_update_different_router()

    def test_floatingip_update(self):
        super(NsxPTestL3NatTestCase, self).test_floatingip_update(
            expected_status=constants.FLOATINGIP_STATUS_DOWN)

    @common_v3.with_external_subnet_second_time
    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(self._plugin_name)

    def test_router_add_gateway_notifications(self):
        with self.router() as r,\
            self._create_l3_ext_network() as ext_net,\
            self.subnet(network=ext_net, enable_dhcp=False):
            with mock.patch.object(registry, 'publish') as publish:
                self._add_external_gateway_to_router(
                    r['router']['id'], ext_net['network']['id'])
                expected = [mock.call(
                                resources.ROUTER_GATEWAY,
                                events.AFTER_CREATE, mock.ANY,
                                payload=mock.ANY)]
                publish.assert_has_calls(expected)

    def test_router_add_gateway_no_subnet_forbidden(self):
        with self.router() as r:
            with self._create_l3_ext_network() as n:
                self._add_external_gateway_to_router(
                    r['router']['id'], n['network']['id'],
                    expected_code=exc.HTTPBadRequest.code)

    def test_route_update_illegal_ip_ver(self):
        routes = [{'destination': '21.0.0.0/24',
                   'nexthop': 'fd00::d6c'}]
        with self.router() as r:
            with self.subnet(cidr='fd00::0/64', ip_version=6,
                             enable_dhcp=False) as s:
                fixed_ip_data = [{'ip_address': 'fd00::2'}]
                with self.port(subnet=s, fixed_ips=fixed_ip_data) as p:
                    self._router_interface_action(
                        'add', r['router']['id'], None, p['port']['id'])
                    self._update('routers', r['router']['id'],
                                 {'router': {'routes': routes}},
                                 expected_code=400)

    def test_router_update_on_external_port(self):
        with self.router() as r:
            with self._create_l3_ext_network() as ext_net,\
                self.subnet(network=ext_net, cidr='10.0.1.0/24',
                            enable_dhcp=False) as s:
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                body = self._show('routers', r['router']['id'])
                net_id = body['router']['external_gateway_info']['network_id']
                self.assertEqual(net_id, s['subnet']['network_id'])
                port_res = self._list_ports(
                    'json',
                    200,
                    s['subnet']['network_id'],
                    tenant_id=r['router']['tenant_id'],
                    device_owner=constants.DEVICE_OWNER_ROUTER_GW)
                port_list = self.deserialize('json', port_res)
                self.assertEqual(len(port_list['ports']), 1)

                routes = [{'destination': '135.207.0.0/16',
                           'nexthop': '10.0.1.3'}]

                self.assertRaises(n_exc.InvalidInput,
                                  self.plugin_instance.update_router,
                                  context.get_admin_context(),
                                  r['router']['id'],
                                  {'router': {'routes':
                                              routes}})

                updates = {'admin_state_up': False}
                self.assertRaises(n_exc.InvalidInput,
                                  self.plugin_instance.update_router,
                                  context.get_admin_context(),
                                  r['router']['id'],
                                  {'router': updates})

                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                body = self._show('routers', r['router']['id'])
                gw_info = body['router']['external_gateway_info']
                self.assertIsNone(gw_info)

    @mock.patch.object(nsx_plugin.NsxPolicyPlugin,
                       'validate_availability_zones')
    def test_create_router_with_availability_zone(self, mock_validate_az):
        name = 'rtr-with-zone'
        zone = ['zone1']
        mock_validate_az.return_value = None
        with self.router(name=name, availability_zone_hints=zone) as rtr:
            az_hints = rtr['router']['availability_zone_hints']
            self.assertListEqual(zone, az_hints)

    def test_update_router_distinct_edge_cluster(self):
        # define an edge cluster in the config
        edge_cluster = uuidutils.generate_uuid()
        cfg.CONF.set_override('edge_cluster', edge_cluster, 'nsx_p')
        self._initialize_azs()
        path_prefix = ("/infra/sites/default/enforcement-points/default/"
                       "edge-clusters/")
        # create a router and external network
        with self.router() as r, \
            self._create_l3_ext_network() as ext_net, \
            self.subnet(network=ext_net, cidr='10.0.1.0/24',
                        enable_dhcp=False) as s, \
            mock.patch("vmware_nsxlib.v3.policy.core_resources."
                       "NsxPolicyTier1Api.get_edge_cluster_path",
                       return_value=False), \
            mock.patch("vmware_nsxlib.v3.policy.core_resources."
                       "NsxPolicyTier1Api.set_edge_cluster_path"
                       ) as add_srv_router,\
            mock.patch("vmware_nsxlib.v3.policy.core_resources."
                       "NsxPolicyTier1Api.get_realized_id"):
            self._add_external_gateway_to_router(
                r['router']['id'],
                s['subnet']['network_id'])
            add_srv_router.assert_called_once_with(
                mock.ANY, '%s%s' % (path_prefix, edge_cluster))

    def test_router_add_interface_cidr_overlapped_with_gateway(self):
        with self.router() as r,\
            self._create_l3_ext_network() as ext_net,\
            self.subnet(cidr='10.0.1.0/24') as s1,\
            self.subnet(network=ext_net, cidr='10.0.0.0/16',
                        enable_dhcp=False) as s2:
            self._add_external_gateway_to_router(
                r['router']['id'],
                s2['subnet']['network_id'])
            res = self._router_interface_action(
                'add', r['router']['id'],
                s1['subnet']['id'], None,
                expected_code=exc.HTTPBadRequest.code)
            self.assertIn('NeutronError', res)

    def test_router_add_gateway_overlapped_with_interface_cidr(self):
        with self.router() as r,\
            self._create_l3_ext_network() as ext_net,\
            self.subnet(cidr='10.0.1.0/24') as s1,\
            self.subnet(network=ext_net, cidr='10.0.0.0/16',
                        enable_dhcp=False) as s2:
            self._router_interface_action(
                'add', r['router']['id'],
                s1['subnet']['id'], None)
            res = self._add_external_gateway_to_router(
                r['router']['id'],
                s2['subnet']['network_id'],
                expected_code=exc.HTTPBadRequest.code)
            self.assertIn('NeutronError', res)

    def test_router_add_interface_by_port_cidr_overlapped_with_gateway(self):
        with self.router() as r,\
            self._create_l3_ext_network() as ext_net,\
            self.subnet(cidr='10.0.1.0/24') as s1,\
            self.subnet(network=ext_net, cidr='10.0.0.0/16',
                        enable_dhcp=False) as s2,\
            self.port(subnet=s1) as p:
            self._add_external_gateway_to_router(
                r['router']['id'],
                s2['subnet']['network_id'])

            res = self._router_interface_action(
                'add', r['router']['id'],
                None,
                p['port']['id'],
                expected_code=exc.HTTPBadRequest.code)
            self.assertIn('NeutronError', res)

    @common_v3.with_disable_dhcp
    def test_create_floatingip_with_assoc_to_ipv6_subnet(self):
        super(NsxPTestL3NatTestCase,
              self).test_create_floatingip_with_assoc_to_ipv6_subnet()

    @common_v3.with_disable_dhcp
    def test_router_add_interface_ipv6_subnet_without_gateway_ip(self):
        super(NsxPTestL3NatTestCase,
              self).test_router_add_interface_ipv6_subnet_without_gateway_ip()

    @common_v3.with_disable_dhcp
    def test_router_add_interface_multiple_ipv6_subnets_different_net(self):
        super(NsxPTestL3NatTestCase, self).\
            test_router_add_interface_multiple_ipv6_subnets_different_net()

    @common_v3.with_disable_dhcp
    def test_create_floatingip_ipv6_only_network_returns_400(self):
        super(NsxPTestL3NatTestCase,
              self).test_create_floatingip_ipv6_only_network_returns_400()

    def test_router_add_iface_ipv6_ext_ra_subnet_returns_400(self):
        self.skipTest('DHCPv6 not supported')

    def test_create_floatingip_invalid_fixed_ipv6_address_returns_400(self):
        self.skipTest('Failed because of illegal port id')

    def test_create_floatingip_with_router_interface_device_owner_fail(self):
        # This tests that an error is raised when trying to assign a router
        # interface port with floatingip.

        with self.subnet(cidr='30.0.0.0/24', gateway_ip=None) as private_sub:
            with self.port(
                    subnet=private_sub,
                    device_owner=constants.DEVICE_OWNER_ROUTER_INTF) as p:
                port_id = p['port']['id']
                with self.router() as r:
                    self._router_interface_action('add', r['router']['id'],
                                                  None, port_id)
            with self.external_network() as public_net, self.subnet(
                    network=public_net, cidr='12.0.0.0/24',
                    enable_dhcp=False) as public_sub:
                self._add_external_gateway_to_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                self._make_floatingip(
                    self.fmt, public_sub['subnet']['network_id'],
                    port_id=port_id,
                    http_status=exc.HTTPBadRequest.code)

    def test_assign_floatingip_to_router_interface_device_owner_fail(self):
        # This tests that an error is raised when trying to assign a router
        # interface port with floatingip.

        with self.subnet(cidr='30.0.0.0/24', gateway_ip=None) as private_sub:
            with self.port(
                    subnet=private_sub,
                    device_owner=constants.DEVICE_OWNER_ROUTER_INTF) as p:
                port_id = p['port']['id']
                with self.router() as r:
                    self._router_interface_action('add', r['router']['id'],
                                                  None, port_id)
            with self.external_network() as public_net, self.subnet(
                    network=public_net, cidr='12.0.0.0/24',
                    enable_dhcp=False) as public_sub:
                self._add_external_gateway_to_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                fip = self._make_floatingip(self.fmt, public_sub[
                    'subnet']['network_id'])
                self._update('floatingips', fip['floatingip'][
                    'id'], {'floatingip': {'port_id': port_id}},
                            expected_code=exc.HTTPBadRequest.code)

    def test_router_delete_with_lb_service(self):
        self.lb_mock1.stop()
        self.lb_mock2.stop()
        # Create the LB object - here the delete callback is registered
        loadbalancer = loadbalancer_mgr.EdgeLoadBalancerManagerFromDict()
        oct_listener = octavia_listener.NSXOctaviaListenerEndpoint(
            loadbalancer=loadbalancer)
        with self.router() as router:
            with mock.patch.object(
                self.plugin.nsxpolicy, 'search_by_tags',
                return_value={'results': [{'id': 'dummy'}]}):
                self.assertRaises(nc_exc.CallbackFailure,
                                  self.plugin_instance.delete_router,
                                  context.get_admin_context(),
                                  router['router']['id'])
        # Unregister callback
        oct_listener._unsubscribe_router_delete_callback()
        self.lb_mock1.start()
        self.lb_mock2.start()

    def test_router_delete_with_no_lb_service(self):
        self.lb_mock1.stop()
        self.lb_mock2.stop()
        # Create the LB object - here the delete callback is registered
        loadbalancer = loadbalancer_mgr.EdgeLoadBalancerManagerFromDict()
        oct_listener = octavia_listener.NSXOctaviaListenerEndpoint(
            loadbalancer=loadbalancer)
        with self.router() as router:
            with mock.patch.object(
                self.plugin.nsxpolicy, 'search_by_tags',
                return_value={'results': []}):
                self.plugin_instance.delete_router(
                    context.get_admin_context(),
                    router['router']['id'])
        # Unregister callback
        oct_listener._unsubscribe_router_delete_callback()
        self.lb_mock1.start()
        self.lb_mock2.start()

    def test_router_gw_info_rollback(self):
        """Fail the GW addition and verify rollback was performed"""
        with self.router() as r,\
            self.external_network() as public_net,\
            self.subnet(network=public_net, cidr='12.0.0.0/24',
                        enable_dhcp=False) as s1,\
            mock.patch("vmware_nsxlib.v3.policy.core_resources."
                       "NsxPolicyTier1Api.update_route_advertisement",
                       side_effect=nsxlib_exc.NsxLibException):
            # Make sure creation fails
            self._add_external_gateway_to_router(
                r['router']['id'],
                s1['subnet']['network_id'],
                expected_code=exc.HTTPInternalServerError.code)
            # Make sure there is no GW configured
            body = self._show('routers', r['router']['id'])
            self.assertIsNone(body['router']['external_gateway_info'])

    def test_router_create_with_gw_info_failed(self):
        """Fail the GW addition during router creation
        and verify rollback was performed
        """
        with self.router() as r,\
            self.external_network() as public_net,\
            self.subnet(network=public_net, cidr='12.0.0.0/24',
                        enable_dhcp=False) as s1,\
            mock.patch("vmware_nsxlib.v3.policy.core_resources."
                       "NsxPolicyTier1Api.update_route_advertisement",
                       side_effect=nsxlib_exc.NsxLibException):
            # Make sure creation fails
            self._add_external_gateway_to_router(
                r['router']['id'],
                s1['subnet']['network_id'],
                expected_code=exc.HTTPInternalServerError.code)
            # Make sure there is no GW configured
            body = self._show('routers', r['router']['id'])
            self.assertIsNone(body['router']['external_gateway_info'])

    def test_create_router_gateway_fails(self):
        with self.external_network() as public_net,\
            self.subnet(network=public_net, cidr='12.0.0.0/24',
                        enable_dhcp=False),\
            mock.patch.object(self.plugin.nsxpolicy.tier1,
                              "get_edge_cluster_path",
                              return_value=False),\
            mock.patch.object(self.plugin.nsxpolicy.tier1,
                              "set_edge_cluster_path",
                              side_effect=nsxlib_exc.NsxLibException):
            data = {'router': {
                'name': 'router1', 'admin_state_up': True,
                'tenant_id': self._tenant_id,
                'external_gateway_info': {
                    'network_id': public_net['network']['id']}}}

            self.assertRaises(nsxlib_exc.NsxLibException,
                              self.plugin.create_router, self.ctx, data)
            # Verify router doesn't persist on failure
            routers = self.plugin.get_routers(self.ctx)
            self.assertEqual(0, len(routers))

    def test_delete_router_gateway_fails(self):
        """Verify that router deletion continues even if gw update fails"""
        with self.router() as r,\
            self.external_network() as public_net,\
            self.subnet(network=public_net, cidr='12.0.0.0/24',
                        enable_dhcp=False) as s1:
            self._add_external_gateway_to_router(
                r['router']['id'],
                s1['subnet']['network_id'])
            with mock.patch("vmware_nsxlib.v3.policy.core_resources."
                            "NsxPolicyTier1Api.update_route_advertisement",
                            side_effect=nsxlib_exc.NsxLibException):
                self._delete('routers', r['router']['id'])
                routers = self.plugin.get_routers(self.ctx)
                self.assertEqual(0, len(routers))

    def _test_nat_rules_firewall_match(self, config_val, call_val):
        cfg.CONF.set_override('firewall_match_internal_addr', config_val,
                              'nsx_p')
        with self.subnet(cidr='20.0.0.0/24') as subnet:
            self._set_net_external(subnet['subnet']['network_id'])
            with mock.patch("vmware_nsxlib.v3.policy.core_resources."
                            "NsxPolicyTier1NatRuleApi."
                            "create_or_overwrite") as add_func,\
                self.floatingip_with_assoc():
                add_func.assert_called_with(
                    mock.ANY, mock.ANY, action='DNAT',
                    destination_network=mock.ANY,
                    firewall_match=call_val,
                    nat_rule_id=mock.ANY, sequence_number=mock.ANY,
                    translated_network=mock.ANY)

    def test_nat_rules_firewall_match_internal(self):
        self._test_nat_rules_firewall_match(
            True, pol_const.NAT_FIREWALL_MATCH_INTERNAL)

    def test_nat_rules_firewall_match_external(self):
        self._test_nat_rules_firewall_match(
            False, pol_const.NAT_FIREWALL_MATCH_EXTERNAL)

    def test_router_interface_with_dhcp_subnet(self):
        # Policy DHCP does not allow 1 dhcp subnet and another router
        # interface subnet on the same overlay network
        with self.router() as r,\
            self.network() as net,\
            self.subnet(cidr='20.0.0.0/24', network=net),\
            self.subnet(cidr='30.0.0.0/24', network=net,
                        enable_dhcp=False) as if_subnet:
            self._router_interface_action(
                'add', r['router']['id'],
                if_subnet['subnet']['id'], None,
                expected_code=exc.HTTPBadRequest.code)

    def test_router_interface_with_ipv6_no_gateway_subnet(self):
        # Policy DHCP does not allow 1 dhcp subnet without gw
        # and another router interface subnet on the same overlay network
        # even on different ip-version
        with self.router() as r,\
            self.network() as net,\
            self.subnet(cidr='20.0.0.0/24', network=net),\
            self.subnet(cidr='60::/64', ip_version=6, network=net,
                        enable_dhcp=False, gateway_ip=None) as if_subnet:
            self._router_interface_action(
                'add', r['router']['id'],
                if_subnet['subnet']['id'], None,
                expected_code=exc.HTTPBadRequest.code)

    def test_router_interface_with_ipv6_dhcp_subnet(self):
        # Policy DHCP allow s1 dhcp subnet and another router
        # interface subnet on the same overlay network with different ip-ver
        with self.router() as r,\
            self.network() as net,\
            self.subnet(cidr='20.0.0.0/24', network=net),\
            self.subnet(cidr='60::/64', ip_version=6, network=net,
                        enable_dhcp=False) as if_subnet:
            self._router_interface_action(
                'add', r['router']['id'],
                if_subnet['subnet']['id'], None)

    def test_router_interface_ndprofile_ipv4(self):
        with self.router() as r,\
            self.network() as net,\
            self.subnet(cidr='20.0.0.0/24', network=net) as if_subnet,\
            mock.patch("vmware_nsxlib.v3.policy.core_resources."
                       "NsxPolicyTier1Api.update") as t1_update:
            # Adding ipv4 interface
            self._router_interface_action(
                'add', r['router']['id'],
                if_subnet['subnet']['id'], None)
            t1_update.assert_not_called()

            # Removing ipv4 interface
            self._router_interface_action(
                'remove', r['router']['id'],
                if_subnet['subnet']['id'], None)
            t1_update.assert_not_called()

    def _test_router_interface_ndprofile(self, profile_with,
                                         enable_dhcp=True, mode='slaac'):
        with self.router() as r,\
            self.network() as net,\
            self.subnet(cidr='2001::/64', network=net,
                        ip_version=6, enable_dhcp=enable_dhcp,
                        ipv6_address_mode=mode,
                        ipv6_ra_mode=mode) as if_subnet,\
            mock.patch("vmware_nsxlib.v3.policy.core_resources."
                       "NsxPolicyTier1Api.update") as t1_update:
            # Adding subnet interface
            self._router_interface_action(
                'add', r['router']['id'],
                if_subnet['subnet']['id'], None)
            t1_update.assert_called_with(
                r['router']['id'],
                ipv6_ndra_profile_id=profile_with)
            t1_update.reset_mock()

            # Removing subnet interface
            self._router_interface_action(
                'remove', r['router']['id'],
                if_subnet['subnet']['id'], None)
            t1_update.assert_called_with(
                r['router']['id'],
                ipv6_ndra_profile_id=nsx_plugin.NO_SLAAC_NDRA_PROFILE_ID)

    def test_router_interface_ndprofile_no_dhcp(self):
        self._test_router_interface_ndprofile(
            nsx_plugin.NO_SLAAC_NDRA_PROFILE_ID,
            enable_dhcp=False, mode=None)

    def test_router_interface_ndprofile_slaac(self):
        self._test_router_interface_ndprofile(
            nsx_plugin.SLAAC_NDRA_PROFILE_ID,
            enable_dhcp=True, mode=constants.IPV6_SLAAC)

    def test_router_interface_ndprofile_stateful(self):
        self._test_router_interface_ndprofile(
            nsx_plugin.STATEFUL_DHCP_NDRA_PROFILE_ID,
            enable_dhcp=True, mode=constants.DHCPV6_STATEFUL)

    def test_router_interface_ndprofile_stateless(self):
        self._test_router_interface_ndprofile(
            nsx_plugin.STATELESS_DHCP_NDRA_PROFILE_ID,
            enable_dhcp=True, mode=constants.DHCPV6_STATELESS)

    def _test_router_interfaces_ndprofile(self, sub1_enable_dhcp, sub1_mode,
                                          sub2_enable_dhcp, sub2_mode,
                                          sub1_profile, mixed_profile=None,
                                          successful=True,
                                          sub1_ipversion=6, sub2_ipversion=6):
        cidr1 = '2001::/64' if sub1_ipversion == 6 else '201.0.0.0/24'
        cidr2 = '2002::/64' if sub2_ipversion == 6 else '202.0.0.0/24'
        with self.router() as r,\
            self.network() as net1, self.network() as net2,\
            self.subnet(cidr=cidr1, network=net1,
                        ip_version=sub1_ipversion,
                        enable_dhcp=sub1_enable_dhcp,
                        ipv6_address_mode=sub1_mode,
                        ipv6_ra_mode=sub1_mode) as sub1,\
            self.subnet(cidr=cidr2, network=net2,
                        ip_version=sub2_ipversion,
                        enable_dhcp=sub2_enable_dhcp,
                        ipv6_address_mode=sub2_mode,
                        ipv6_ra_mode=sub2_mode) as sub2,\
            mock.patch("vmware_nsxlib.v3.policy.core_resources."
                       "NsxPolicyTier1Api.update") as t1_update:

            # Adding first interface
            self._router_interface_action(
                'add', r['router']['id'],
                sub1['subnet']['id'], None)
            if sub1_ipversion == 6:
                t1_update.assert_called_with(
                    r['router']['id'],
                    ipv6_ndra_profile_id=sub1_profile)
                t1_update.reset_mock()
            else:
                t1_update.assert_not_called()

            # Adding the 2nd interface
            expected_code = (exc.HTTPBadRequest.code if not successful
                             else exc.HTTPOk.code)
            self._router_interface_action(
                'add', r['router']['id'],
                sub2['subnet']['id'], None,
                expected_code=expected_code)
            if not successful:
                return
            if sub2_ipversion == 6:
                t1_update.assert_called_with(
                    r['router']['id'],
                    ipv6_ndra_profile_id=mixed_profile)
                t1_update.reset_mock()
            else:
                t1_update.assert_not_called()

            # Removing the 2nd interface
            self._router_interface_action(
                'remove', r['router']['id'],
                sub2['subnet']['id'], None)
            if sub2_ipversion == 6:
                t1_update.assert_called_with(
                    r['router']['id'],
                    ipv6_ndra_profile_id=sub1_profile)
            else:
                t1_update.assert_not_called()

    def test_router_interfaces_ndprofile_slaac_slaac(self):
        self._test_router_interfaces_ndprofile(
            True, constants.IPV6_SLAAC,
            True, constants.IPV6_SLAAC,
            nsx_plugin.SLAAC_NDRA_PROFILE_ID,
            nsx_plugin.SLAAC_NDRA_PROFILE_ID)

    def test_router_interfaces_ndprofile_slaac_stateful(self):
        self._test_router_interfaces_ndprofile(
            True, constants.IPV6_SLAAC,
            True, constants.DHCPV6_STATEFUL,
            nsx_plugin.SLAAC_NDRA_PROFILE_ID,
            None, successful=False)

    def test_router_interfaces_ndprofile_slaac_stateless(self):
        self._test_router_interfaces_ndprofile(
            True, constants.IPV6_SLAAC,
            True, constants.DHCPV6_STATELESS,
            nsx_plugin.SLAAC_NDRA_PROFILE_ID,
            None, successful=False)

    def test_router_interfaces_ndprofile_disabled_stateful(self):
        self._test_router_interfaces_ndprofile(
            False, None,
            True, constants.DHCPV6_STATEFUL,
            nsx_plugin.NO_SLAAC_NDRA_PROFILE_ID,
            nsx_plugin.STATEFUL_DHCP_NDRA_PROFILE_ID)

    def test_router_interfaces_ndprofile_disabled_stateless(self):
        self._test_router_interfaces_ndprofile(
            False, None,
            True, constants.DHCPV6_STATELESS,
            nsx_plugin.NO_SLAAC_NDRA_PROFILE_ID,
            nsx_plugin.STATELESS_DHCP_NDRA_PROFILE_ID)

    def test_router_interfaces_ndprofile_stateful_stateless(self):
        self._test_router_interfaces_ndprofile(
            True, constants.DHCPV6_STATEFUL,
            True, constants.DHCPV6_STATELESS,
            nsx_plugin.STATEFUL_DHCP_NDRA_PROFILE_ID,
            None, successful=False)

    def test_router_interfaces_ndprofile_v4_stateless(self):
        self._test_router_interfaces_ndprofile(
            True, None,
            True, constants.DHCPV6_STATELESS,
            nsx_plugin.NO_SLAAC_NDRA_PROFILE_ID,
            nsx_plugin.STATELESS_DHCP_NDRA_PROFILE_ID,
            sub1_ipversion=4)

    def test_router_interfaces_ndprofile_stateless_v4(self):
        self._test_router_interfaces_ndprofile(
            True, constants.DHCPV6_STATELESS,
            True, None,
            nsx_plugin.STATELESS_DHCP_NDRA_PROFILE_ID,
            nsx_plugin.STATELESS_DHCP_NDRA_PROFILE_ID,
            sub2_ipversion=4)

    def _add_external_gateway_to_router(self, router_id, network_id,
                                        expected_code=exc.HTTPOk.code,
                                        neutron_context=None, ext_ips=None,
                                        **kwargs):
        # Copy the neutron api to add support for disabled SNAT
        ext_ips = ext_ips or []
        body = {'router':
                {'external_gateway_info': {'network_id': network_id}}}
        if ext_ips:
            body['router']['external_gateway_info'][
                'external_fixed_ips'] = ext_ips
        if 'policy_id' in kwargs:
            body['router']['external_gateway_info'][
                'qos_policy_id'] = kwargs.get('policy_id')
        if 'enable_snat' in kwargs:
            body['router']['external_gateway_info'][
                'enable_snat'] = kwargs.get('enable_snat')
        return self._update('routers', router_id, body,
                            expected_code=expected_code,
                            neutron_context=neutron_context)

    def test_router_vlan_interface_sr(self):
        providernet_args = {pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 11}

        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'NsxPolicyTransportZoneApi.get_transport_type',
                        return_value=nsx_constants.TRANSPORT_TYPE_VLAN), \
            self.network(name='vlan_net',
                         providernet_args=providernet_args,
                         arg_list=(pnet.NETWORK_TYPE,
                                   pnet.SEGMENTATION_ID)) as net,\
            self.router() as r,\
            self.subnet(cidr='2001::/64', network=net,
                        ip_version=6, enable_dhcp=False,
                        ipv6_address_mode=None,
                        ipv6_ra_mode=None) as if_subnet,\
            self._create_l3_ext_network() as ext_net,\
            self.subnet(network=ext_net, cidr='10.0.0.0/16',
                        enable_dhcp=False) as ext_sub,\
            mock.patch("vmware_nsxlib.v3.policy.core_resources."
                       "NsxPolicyTier1Api.get_edge_cluster_path",
                       return_value=None),\
            mock.patch("vmware_nsxlib.v3.policy.core_resources."
                       "NsxPolicyTier1Api.get_realized_id"),\
            mock.patch("vmware_nsxlib.v3.policy.core_resources."
                       "NsxPolicyTier1Api.set_edge_cluster_path"
                       ) as add_srv_router,\
            mock.patch("vmware_nsxlib.v3.policy.core_resources."
                       "NsxPolicyTier1Api.remove_edge_cluster"
                       ) as del_srv_router:

            # Add router GW
            self._add_external_gateway_to_router(
                r['router']['id'],
                ext_sub['subnet']['network_id'],
                enable_snat=False)

            # Adding subnet interface
            self._router_interface_action(
                'add', r['router']['id'],
                if_subnet['subnet']['id'], None)
            # verify service router was created
            add_srv_router.assert_called_once_with(r['router']['id'], mock.ANY)

            # Removing subnet interface
            self._router_interface_action(
                'remove', r['router']['id'],
                if_subnet['subnet']['id'], None)
            # verify service router was removed
            del_srv_router.assert_called_once_with(r['router']['id'])

    def _test_router_vlan_interface_ndprofile(self, profile_with,
                                              enable_dhcp=True, mode='slaac'):
        providernet_args = {pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 11}

        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'NsxPolicyTransportZoneApi.get_transport_type',
                        return_value=nsx_constants.TRANSPORT_TYPE_VLAN), \
            self.network(name='vlan_net',
                         providernet_args=providernet_args,
                         arg_list=(pnet.NETWORK_TYPE,
                                   pnet.SEGMENTATION_ID)) as net,\
            self.router() as r,\
            self.subnet(cidr='2001::/64', network=net,
                        ip_version=6, enable_dhcp=enable_dhcp,
                        ipv6_address_mode=mode,
                        ipv6_ra_mode=mode) as if_subnet,\
            self._create_l3_ext_network() as ext_net,\
            self.subnet(network=ext_net, cidr='10.0.0.0/16',
                        enable_dhcp=False) as ext_sub,\
            mock.patch("vmware_nsxlib.v3.policy.core_resources."
                       "NsxPolicyTier1Api.add_segment_interface") as t1_add,\
            mock.patch("vmware_nsxlib.v3.policy.core_resources."
                       "NsxPolicyTier1Api.remove_segment_interface") as t1_del:

            # Add router GW
            self._add_external_gateway_to_router(
                r['router']['id'],
                ext_sub['subnet']['network_id'])

            # Adding subnet interface
            self._router_interface_action(
                'add', r['router']['id'],
                if_subnet['subnet']['id'], None)
            t1_add.assert_called_once_with(
                r['router']['id'], mock.ANY, mock.ANY, [mock.ANY],
                profile_with)

            # Removing subnet interface
            self._router_interface_action(
                'remove', r['router']['id'],
                if_subnet['subnet']['id'], None)
            t1_del.assert_called_once_with(r['router']['id'], mock.ANY)

    def test_router_vlan_interface_ndprofile_no_dhcp(self):
        self._test_router_vlan_interface_ndprofile(
            nsx_plugin.NO_SLAAC_NDRA_PROFILE_ID,
            enable_dhcp=False, mode=None)

    def test_router_vlan_interface_ndprofile_slaac(self):
        self._test_router_vlan_interface_ndprofile(
            nsx_plugin.SLAAC_NDRA_PROFILE_ID,
            enable_dhcp=True, mode=constants.IPV6_SLAAC)

    def test_router_vlan_interface_ndprofile_stateful(self):
        self._test_router_vlan_interface_ndprofile(
            nsx_plugin.STATEFUL_DHCP_NDRA_PROFILE_ID,
            enable_dhcp=True, mode=constants.DHCPV6_STATEFUL)

    def test_router_vlan_interface_ndprofile_stateless(self):
        self._test_router_vlan_interface_ndprofile(
            nsx_plugin.STATELESS_DHCP_NDRA_PROFILE_ID,
            enable_dhcp=True, mode=constants.DHCPV6_STATELESS)

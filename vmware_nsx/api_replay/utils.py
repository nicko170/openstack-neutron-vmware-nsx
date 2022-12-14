# Copyright 2016 VMware, Inc.
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
import logging

from neutron_lib.api import attributes as lib_attrs
from oslo_config import cfg
from oslo_utils import uuidutils
import webob.exc

from vmware_nsx.common import nsxv_constants
from vmware_nsxlib.v3 import nsx_constants as nsxlib_consts

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)


def _fixup_res_dict(context, attr_name, res_dict, check_allow_post=True):
    # This method is a replacement of _fixup_res_dict which is used in
    # neutron_lib.plugin.utils. All this mock does is insert a uuid
    # for the id field if one is not found ONLY if running in api_replay_mode.
    if cfg.CONF.api_replay_mode and 'id' not in res_dict:
        res_dict['id'] = uuidutils.generate_uuid()
    attr_info = lib_attrs.RESOURCES[attr_name]
    attr_ops = lib_attrs.AttributeInfo(attr_info)
    try:
        attr_ops.populate_project_id(context, res_dict, True)
        lib_attrs.populate_project_info(attr_info)
        attr_ops.verify_attributes(res_dict)
    except webob.exc.HTTPBadRequest as e:
        # convert webob exception into ValueError as these functions are
        # for internal use. webob exception doesn't make sense.
        raise ValueError(e.detail)

    attr_ops.fill_post_defaults(res_dict, check_allow_post=check_allow_post)
    attr_ops.convert_values(res_dict)
    return res_dict


class PrepareObjectForMigration(object):
    """Helper class to modify source objects before creating them in dest"""
    # Remove some fields before creating the new object.
    # Some fields are not supported for a new object, and some are not
    # supported by the destination plugin
    basic_ignore_fields = ['updated_at',
                           'created_at',
                           'tags',
                           'revision',
                           'revision_number']

    drop_sg_rule_fields = basic_ignore_fields
    drop_sg_fields = basic_ignore_fields + ['policy']
    drop_quota_fields = basic_ignore_fields + [
        'tenant_id',
        'project_id',
        'housekeeper',
        'nsx_policy',
        'l2-gateway-connection']
    drop_router_fields = basic_ignore_fields + [
        'status',
        'routes',
        'ha',
        'external_gateway_info',
        'router_type',
        'availability_zones',
        'distributed',
        'flavor_id']
    drop_subnetpool_fields = basic_ignore_fields + [
        'id',
        'ip_version']

    drop_subnet_fields = basic_ignore_fields + [
        'advanced_service_providers',
        'service_types']

    drop_port_fields = basic_ignore_fields + [
        'status',
        'binding:vif_details',
        'binding:vif_type',
        'binding:host_id',
        'vnic_index',
        'dns_assignment',
        'resource_request']

    drop_network_fields = basic_ignore_fields + [
        'status',
        'subnets',
        'availability_zones',
        'ipv4_address_scope',
        'ipv6_address_scope',
        'mtu']

    drop_fip_fields = basic_ignore_fields + [
        'status', 'router_id', 'id', 'revision']

    drop_qos_rule_fields = ['revision', 'type', 'qos_policy_id', 'id']
    drop_qos_policy_fields = basic_ignore_fields

    drop_fwaas_rule_fields = ['firewall_policy_id']
    drop_fwaas_policy_fields = []
    drop_fwaas_group_fields = ['status']

    lb_ignore_fields = ['created_at', 'updated_at', 'operating_status',
                        'provisioning_status']
    drop_lb_loadbalancer_fields = lb_ignore_fields + [
        'listeners', 'pools',  # Those objects will be created later
        'flavor_id',  # not supported by the driver
        'vip_qos_policy_id',  # not supported by the driver
    ]
    drop_lb_listener_fields = lb_ignore_fields + [
        'l7policies', 'default_pool_id']
    drop_lb_pool_fields = lb_ignore_fields + [
        'loadbalancers', 'healthmonitor_id', 'listeners', 'members']
    drop_lb_member_fields = lb_ignore_fields
    drop_lb_hm_fields = lb_ignore_fields + ['pools']
    drop_lb_l7policy_fields = lb_ignore_fields + ['rules']
    drop_lb_l7rule_fields = lb_ignore_fields

    def drop_fields(self, item, drop_fields):
        body = {}
        for k, v in item.items():
            if k in drop_fields:
                continue
            body[k] = v
        return body

    def fix_description(self, body):
        # neutron doesn't like description being None even though its
        # what it returns to us.
        if 'description' in body and body['description'] is None:
            body['description'] = ''

    def check_and_apply_tags(self, client, resource_type,
                             resource_id, resource_data):
        """Check if a resource has tags, and apply them.

        The routine calls tag API once for each tag as Neutron API does not
        support bulk addition of tags.
        """
        tags = resource_data.get('tags', [])
        for tag in tags:
            client.add_tag(resource_type, resource_id, tag)

    # direct_call arg means that the object is prepared for calling the plugin
    # create method directly
    def prepare_security_group_rule(self, sg_rule, direct_call=False):
        self.fix_description(sg_rule)
        return self.drop_fields(sg_rule, self.drop_sg_rule_fields)

    def prepare_security_group(self, sg, direct_call=False):
        self.fix_description(sg)
        return self.drop_fields(sg, self.drop_sg_fields)

    def prepare_quota(self, quota):
        body = self.drop_fields(quota, self.drop_quota_fields)
        return body

    def prepare_router(self, rtr, dest_azs=None, direct_call=False):
        self.fix_description(rtr)
        body = self.drop_fields(rtr, self.drop_router_fields)
        if dest_azs:
            if body.get('availability_zone_hints'):
                az = body['availability_zone_hints'][0]
                if az not in dest_azs:
                    if az != 'default':
                        LOG.warning("Ignoring AZ %s in router %s as it is not "
                                    "defined in destination", az, rtr['id'])
                    body['availability_zone_hints'] = []
        elif direct_call:
            body['availability_zone_hints'] = []
        return body

    def prepare_subnetpool(self, pool, direct_call=False):
        self.fix_description(pool)
        return self.drop_fields(pool, self.drop_subnetpool_fields)

    def prepare_network(self, net, dest_default_public_net=True,
                        remove_qos=False, dest_azs=None, direct_call=False,
                        ext_net_map=None, net_vni_map=None):
        self.fix_description(net)
        body = self.drop_fields(net, self.drop_network_fields)

        if remove_qos:
            body = self.drop_fields(body, ['qos_policy_id'])

        # neutron doesn't like some fields being None even though its
        # what it returns to us.
        for field in ['provider:physical_network',
                      'provider:segmentation_id',
                      'vlan_transparent']:
            if field in body and body[field] is None:
                del body[field]

        # vxlan network with segmentation id should be translated to a regular
        # network in nsx-v3/P.
        if (body.get('provider:network_type') == 'vxlan' and
            body.get('provider:segmentation_id') is not None):
            del body['provider:network_type']
            del body['provider:segmentation_id']
            if 'provider:physical_network' in body:
                del body['provider:physical_network']

        # flat network should be translated to a regular network in nsx-v3/P.
        if (body.get('provider:network_type') == 'flat'):
            del body['provider:network_type']
            if 'provider:physical_network' in body:
                del body['provider:physical_network']
            if 'provider:segmentation_id' in body:
                del body['provider:segmentation_id']

        # For VLAN network we are removing the physical_network so the default
        # vlan TZ will be used by the plugin
        if (body.get('provider:network_type') == 'vlan'):
            if 'provider:physical_network' in body:
                del body['provider:physical_network']

        # external networks need some special care
        if body.get('router:external'):
            fields_reset = False
            # TODO(asarfaty): map external network neutron ids to Policy tier0
            for field in ['provider:network_type', 'provider:segmentation_id',
                          'provider:physical_network']:
                if field in body:
                    if body[field] is not None:
                        fields_reset = True
                    del body[field]
            if fields_reset:
                LOG.warning("Ignoring provider network fields while migrating "
                            "external network %s", body['id'])
            # Get the tier0 into the physical_network
            if ext_net_map and body['id'] in ext_net_map:
                body['provider:physical_network'] = ext_net_map[body['id']]
            else:
                LOG.warning("Using default Tier0 as provider:physical_network "
                            "while migrating external network %s", body['id'])
                if 'provider:physical_network' in body:
                    del body['provider:physical_network']

            if body.get('is_default') and dest_default_public_net:
                body['is_default'] = False
                LOG.warning("Public network %s was set to non default network",
                            body['id'])
        if dest_azs:
            if body.get('availability_zone_hints'):
                az = body['availability_zone_hints'][0]
                if az not in dest_azs:
                    if az != 'default':
                        LOG.warning("Ignoring AZ %s in net %s as it is not "
                                    "defined in destination", az, body['id'])
                    body['availability_zone_hints'] = []
        elif direct_call:
            body['availability_zone_hints'] = []

        if net_vni_map and body['id'] in net_vni_map:
            body['vni'] = net_vni_map[body['id']]

        if (body.get('project_id') == nsxv_constants.INTERNAL_TENANT_ID and
            body.get('name').startswith('inter-edge-net')):
            # rename the internal network
            body['name'] = "Internal network for mdproxy migration"

        return body

    def prepare_subnet(self, subnet, direct_call=False):
        self.fix_description(subnet)
        body = self.drop_fields(subnet, self.drop_subnet_fields)

        # Drop v6 fields on subnets that are v4 as server doesn't allow them.
        v6_fields_to_remove = ['ipv6_address_mode', 'ipv6_ra_mode']
        if body['ip_version'] == 4:
            for field in v6_fields_to_remove:
                if field in body:
                    body.pop(field)
        else:
            # For ipv6 mode - remove those only if empty
            for field in v6_fields_to_remove:
                if field in body and body[field] is None:
                    body.pop(field)
        return body

    def prepare_port(self, port, remove_qos=False, vif_ids_map=None,
                     direct_call=False):
        self.fix_description(port)
        body = self.drop_fields(port, self.drop_port_fields)
        if remove_qos:
            body = self.drop_fields(body, ['qos_policy_id'])

        num_allowed_pairs = nsxlib_consts.NUM_ALLOWED_IP_ADDRESSES_v4 - 1
        if 'allowed_address_pairs' in body:
            if not body['allowed_address_pairs']:
                # remove allowed_address_pairs if empty:
                del body['allowed_address_pairs']
            else:
                if len(body['allowed_address_pairs']) > num_allowed_pairs:
                    body['allowed_address_pairs'] = body[
                        'allowed_address_pairs'][:num_allowed_pairs]
                    LOG.warning("ignoring extra allowed_address_pair for "
                                "port %s as only %s are allowed",
                                port['id'], num_allowed_pairs)

        # remove port security if mac learning is enabled
        if (body.get('mac_learning_enabled') and
            body.get('port_security_enabled')):
            LOG.warning("Disabling port security of port %s: The plugin "
                        "doesn't support mac learning with port security",
                        body['id'])
            body['port_security_enabled'] = False
            body['security_groups'] = []

        if vif_ids_map and body['id'] in vif_ids_map:
            body['vif_id'] = vif_ids_map[body['id']]

        if direct_call:
            if 'device_id' not in body:
                body['device_id'] = ""
            if 'device_owner' not in body:
                body['device_owner'] = ""

        return body

    def prepare_floatingip(self, fip, direct_call=False):
        self.fix_description(fip)
        return self.drop_fields(fip, self.drop_fip_fields)

    def prepare_qos_rule(self, rule, tenant_id=None, direct_call=False):
        self.fix_description(rule)
        if tenant_id and not rule.get('tenant_id'):
            rule['tenant_id'] = tenant_id
        return self.drop_fields(rule, self.drop_qos_rule_fields)

    def prepare_qos_policy(self, policy, direct_call=False):
        self.fix_description(policy)
        return self.drop_fields(policy, self.drop_qos_policy_fields)

    def prepare_fwaas_rule(self, rule):
        self.fix_description(rule)
        return self.drop_fields(rule, self.drop_fwaas_rule_fields)

    def prepare_fwaas_policy(self, policy):
        self.fix_description(policy)
        return self.drop_fields(policy, self.drop_fwaas_policy_fields)

    def prepare_fwaas_group(self, group):
        self.fix_description(group)
        return self.drop_fields(group, self.drop_fwaas_group_fields)

    def prepare_lb_loadbalancer(self, lb_obj):
        return self.drop_fields(lb_obj, self.drop_lb_loadbalancer_fields)

    def prepare_lb_listener(self, listener_obj, lb_body):
        body = self.drop_fields(listener_obj, self.drop_lb_listener_fields)
        body['loadbalancer'] = lb_body
        body['loadbalancer']['listeners'] = []
        body['loadbalancer_id'] = lb_body['id']
        return body

    def prepare_lb_pool(self, pool_obj, lb_body):
        body = self.drop_fields(pool_obj, self.drop_lb_pool_fields)
        body['loadbalancer'] = lb_body
        body['loadbalancer']['listeners'] = []
        body['loadbalancer_id'] = lb_body['id']
        return body

    def prepare_lb_member(self, mem_obj, lb_body):
        body = self.drop_fields(mem_obj, self.drop_lb_member_fields)
        body['loadbalancer'] = lb_body
        body['loadbalancer']['listeners'] = []
        body['loadbalancer_id'] = lb_body['id']
        return body

    def prepare_lb_hm(self, lb_obj):
        return self.drop_fields(lb_obj, self.drop_lb_hm_fields)

    def prepare_lb_l7policy(self, lb_obj):
        body = self.drop_fields(lb_obj, self.drop_lb_l7policy_fields)
        body['rules'] = []
        return body

    def prepare_lb_l7rule(self, lb_obj):
        return self.drop_fields(lb_obj, self.drop_lb_l7rule_fields)

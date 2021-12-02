# Copyright 2020 VMware, Inc.  All rights reserved.
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
import sys

import netaddr

from neutron_lib.callbacks import registry
from neutron_lib import context
from oslo_log import log as logging
from oslo_serialization import jsonutils

from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxp.resources import utils as p_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import migration
from vmware_nsx.shell import resources as shell
from vmware_nsxlib.v3.policy import constants as policy_constants

LOG = logging.getLogger(__name__)


@admin_utils.output_header
def cleanup_db_mappings(resource, event, trigger, **kwargs):
    """Delete all entries from nsx-t mapping tables in DB"""
    # Don't annotate with unpack_payload because this is just a wrapper for
    # another callback!
    return migration.MP2Policy_cleanup_db_mappings(
         resource, event, trigger, **kwargs)


@admin_utils.output_header
@admin_utils.unpack_payload
def post_v2t_migration_cleanups(resource, event, trigger, **kwargs):
    """Cleanup unneeded migrated resources after v2t migration is done"""
    nsxpolicy = p_utils.get_connected_nsxpolicy()
    # Clean all migrated DFW sections
    sections = nsxpolicy.comm_map.list(policy_constants.DEFAULT_DOMAIN)
    for section in sections:
        # Look for the tag marking the migrated sections
        for tag in section.get('tags', []):
            if tag['scope'] == 'v_origin':
                LOG.info("Deleting migrated: %s", tag['tag'])
                nsxpolicy.comm_map.delete(policy_constants.DEFAULT_DOMAIN,
                                          section['id'])
                continue

    # Cleanup migrated DVS ports (belong to the edges that are not in use)
    segments = nsxpolicy.segment.list()
    for seg in segments:
        # Skip non-neutron segments
        if not p_utils.is_neutron_resource(seg):
            continue
        ports = nsxpolicy.segment_port.list(seg['id'])
        # Find the non-neutron ports and delete them
        for port in ports:
            if not p_utils.is_neutron_resource(port):
                nsxpolicy.segment_port.delete(seg['id'], port['id'])
                LOG.error("Deleted migrated non-neutron port %s", port['id'])


@admin_utils.output_header
@admin_utils.unpack_payload
def migration_tier0_redistribute(resource, event, trigger, **kwargs):
    """Disable/Restore tier0s route redistribution during V2T migration"""
    errmsg = ("Need to specify --property action=disable/restore and a comma "
              "separated tier0 list as --property tier0s")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    action = properties.get('action')
    tier0string = properties.get('tier0s')
    state_filename = properties.get('state-file')
    if not tier0string or not action or not state_filename:
        LOG.error("%s", errmsg)
        return

    tier0s = tier0string.split(",")
    nsxpolicy = p_utils.get_connected_nsxpolicy()

    if action.lower() == 'disable':
        try:
            f = open(state_filename, "r")
            orig_conf_map = jsonutils.loads(f.read())
            f.close()
        except Exception:
            LOG.info("State file %s not found:", state_filename)
            orig_conf_map = {}
        for tier0 in tier0s:
            # get the current config
            try:
                orig_conf = nsxpolicy.tier0.get_route_redistribution_config(
                    tier0)
            except Exception:
                LOG.error("Did not find Tier0 %s", tier0)
                continue
            if not orig_conf:
                LOG.info("Tier0 %s does not have route redistribution config",
                         tier0)
                continue
            fixed_conf = copy.deepcopy(orig_conf)
            if (not (orig_conf['bgp_enabled'] or
                     orig_conf['ospf_enabled'] or
                     orig_conf.get('redistribution_rules'))):
                # Already disabled
                LOG.info("Tier0 %s route redistribution config was not "
                         "changed because it is disabled", tier0)
                continue
            # Check if any of the rules have tier1 flags enabled
            rule_num = 0
            for rule in orig_conf.get('redistribution_rules', []):
                fixed_types = []
                for route_type in rule['route_redistribution_types']:
                    if not route_type.startswith('TIER1'):
                        fixed_types.append(route_type)
                fixed_conf['redistribution_rules'][rule_num][
                    'route_redistribution_types'] = fixed_types
                rule_num = rule_num + 1
            # Save the original config so it can be reverted later
            orig_conf_map[tier0] = orig_conf
            fixed_conf['bgp_enabled'] = False
            fixed_conf['ospf_enabled'] = False
            nsxpolicy.tier0.update_route_redistribution_config(
                tier0, fixed_conf)
            LOG.info("Disabled Tier0 %s route redistribution config for "
                     "Tier1 routes", tier0)
        f = open(state_filename, "w")
        f.write("%s" % jsonutils.dumps(orig_conf_map))
        f.close()
    elif action.lower() == 'restore':
        try:
            f = open(state_filename, "r")
            orig_conf_map = jsonutils.loads(f.read())
            f.close()
        except Exception:
            LOG.warning("State file %s not found:", state_filename)
            sys.exit(1)
        for tier0 in tier0s:
            if tier0 in orig_conf_map:
                # Restore its original config:
                try:
                    nsxpolicy.tier0.update_route_redistribution_config(
                        tier0, orig_conf_map[tier0])
                    LOG.info("Restored Tier0 %s original route redistribution "
                             "config", tier0)
                except Exception:
                    LOG.error("Failed to update redistribution of Tier0 %s",
                              tier0)
            else:
                LOG.info("Tier0 %s route redistribution config was not "
                         "changed", tier0)
    else:
        LOG.error("%s", errmsg)
        sys.exit(1)


def _cidrs_overlap(cidr0, cidr1):
    return cidr0.first <= cidr1.last and cidr1.first <= cidr0.last


@admin_utils.output_header
@admin_utils.unpack_payload
def migration_validate_external_cidrs(resource, event, trigger, **kwargs):
    """Before V2T migration, validate that the external subnets cidrs
    do not overlap the tier0 uplinks
    """
    errmsg = ("Need to specify --property ext-net=<path> --property "
              "ext-cidr=<path>")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return

    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    ext_net_file = properties.get('ext-net')
    ext_cidr_file = properties.get('ext-cidr')
    if not ext_net_file or not ext_cidr_file:
        LOG.error("%s", errmsg)
        return

    with open(ext_net_file, 'r') as myfile:
        # maps external network neutron id to tier0
        data = myfile.read()
        external_networks = jsonutils.loads(data)
    with open(ext_cidr_file, 'r') as myfile:
        # maps external network neutron id to its cidr
        data = myfile.read()
        external_cidrs = jsonutils.loads(data)

    nsxpolicy = p_utils.get_connected_nsxpolicy()

    for net_id in external_cidrs:
        net_cidr = netaddr.IPNetwork(external_cidrs[net_id]).cidr
        tier0 = external_networks.get(net_id)
        if not tier0:
            LOG.error("Could not find network %s in %s. Please ensure "
                      "external networks are correctly listed in "
                      "migrator configuration ", net_id, ext_net_file)
            sys.exit(1)
        else:
            tier0_cidrs = nsxpolicy.tier0.get_uplink_cidrs(tier0)
            for cidr in tier0_cidrs:
                tier0_subnet = netaddr.IPNetwork(cidr).cidr
                if _cidrs_overlap(tier0_subnet, net_cidr):
                    LOG.error("External subnet of network %s cannot overlap "
                              "with T0 %s uplink cidr %s", net_id, tier0, cidr)
                    sys.exit(1)
    sys.exit(0)


@admin_utils.output_header
@admin_utils.unpack_payload
def patch_routers_without_gateway(resource, event, trigger, **kwargs):
    state_filename = None
    tier0_id = None
    if kwargs.get('property'):
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        state_filename = properties.get('state-file')
        tier0_id = properties.get('tier0')

    if not state_filename:
        LOG.error("Must provide a filename for saving T1 GW state")
        return
    if not tier0_id:
        LOG.error("Cannot execute if a Tier-0 GW uuid is not provided")
        return

    nsxpolicy = p_utils.get_connected_nsxpolicy()
    try:
        nsxpolicy.tier0.get(tier0_id)
    except Exception as e:
        LOG.error("An error occurred while retrieving Tier0 gw router %s: %s",
                  tier0_id, e)
        raise SystemExit(e)

    ctx = context.get_admin_context()
    fixed_routers = []

    # Open state file, if exists, read data
    try:
        with open(state_filename) as f:
            state_data = jsonutils.load(f)
    except FileNotFoundError:
        LOG.debug("State file not created yet")
        state_data = {}

    with p_utils.NsxPolicyPluginWrapper() as plugin:
        routers = plugin.get_routers(ctx)
        try:
            for router in routers:
                router_id = router['id']
                if plugin._extract_external_gw(ctx, {'router': router}):
                    continue

                # Skip router if already fixed up
                if router_id in state_data:
                    LOG.info("It seems router %s has already been patched. "
                             "Skipping it.", router_id)
                    continue

                # Fetch T1
                t1_data = nsxpolicy.tier1.get(router_id)
                route_adv_data = t1_data.get('route_advertisement_types', [])
                # append state data
                state_data[router_id] = route_adv_data
                # Update T1: connect to T0, disable route advertisment
                nsxpolicy.tier1.update_route_advertisement(
                    router_id,
                    static_routes=False,
                    subnets=False,
                    nat=False,
                    lb_vip=False,
                    lb_snat=False,
                    ipsec_endpoints=False,
                    tier0=tier0_id)
                fixed_routers.append(router)
        except Exception as e:
            LOG.error("Failure while patching routers without "
                      "gateway: %s", e)
            # do not call sys.exit here
        finally:
            # Save state data
            with open(state_filename, 'w') as f:
                # Pretty print in case someone needs to insepct it
                jsonutils.dump(state_data, f, indent=4)

    LOG.info(formatters.output_formatter(
        "Attached following routers to T0 %s" % tier0_id,
        fixed_routers,
        ['id', 'name', 'project_id']))
    return fixed_routers


@admin_utils.output_header
@admin_utils.unpack_payload
def restore_routers_without_gateway(resource, event, trigger, **kwargs):
    state_filename = None
    if kwargs.get('property'):
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        state_filename = properties.get('state-file')

    if not state_filename:
        LOG.error("Must provide a filename for saving T1 GW state")
        return

    nsxpolicy = p_utils.get_connected_nsxpolicy()
    ctx = context.get_admin_context()
    restored_routers = []

    # Open state file,read data
    # Fail if file does not exist
    try:
        with open(state_filename) as f:
            state_data = jsonutils.load(f)
    except FileNotFoundError:
        LOG.error("State file %s was not found. Aborting", state_filename)
        sys.exit(1)

    with p_utils.NsxPolicyPluginWrapper() as plugin:
        routers = plugin.get_routers(ctx)
        try:
            for router in routers:
                router_id = router['id']
                if plugin._extract_external_gw(ctx, {'router': router}):
                    continue

                adv_info = state_data.get(router_id)
                # Disconnect T0, set route adv from state file
                if adv_info:
                    nsxpolicy.tier1.update_route_advertisement(
                        router_id,
                        static_routes=("TIER1_STATIC_ROUTES" in adv_info),
                        subnets=("TIER1_CONNECTED" in adv_info),
                        nat=("TIER1_NAT" in adv_info),
                        lb_vip=("TIER1_LB_VIP" in adv_info),
                        lb_snat=("TIER1_LB_SNAT" in adv_info),
                        ipsec_endpoints=("TIER1_IPSEC_LOCAL_ENDPOINT" in
                            adv_info),
                        tier0=None)
                else:
                    # Only disconnect T0
                    LOG.info("Router advertisment info not found in state "
                             "file for router %s", router_id)
                    nsxpolicy.tier1.update_route_advertisement(
                            router_id, tier0=None)

                state_data.pop(router_id, None)
                restored_routers.append(router)
        except Exception as e:
            LOG.error("Failure while restoring routers without "
                      "gateway: %s", e)
        finally:
            with open(state_filename, 'w') as f:
                # Pretty print in case someone needs to insepct it
                jsonutils.dump(state_data, f, indent=4)
        LOG.info(formatters.output_formatter(
            "Restored following routers",
            restored_routers,
            ['id', 'name', 'project_id']))
        return restored_routers


registry.subscribe(cleanup_db_mappings,
                   constants.NSX_MIGRATE_T_P,
                   shell.Operations.CLEAN_ALL.value)

registry.subscribe(post_v2t_migration_cleanups,
                   constants.NSX_MIGRATE_V_T,
                   shell.Operations.CLEAN_ALL.value)

registry.subscribe(migration_tier0_redistribute,
                   constants.NSX_MIGRATE_V_T,
                   shell.Operations.NSX_REDISTRIBUTE.value)

registry.subscribe(migration_validate_external_cidrs,
                   constants.NSX_MIGRATE_V_T,
                   shell.Operations.VALIDATE.value)

registry.subscribe(patch_routers_without_gateway,
                   constants.NSX_MIGRATE_V_T,
                   shell.Operations.PATCH_RTR_NOGW.value)

registry.subscribe(restore_routers_without_gateway,
                   constants.NSX_MIGRATE_V_T,
                   shell.Operations.RESTORE_RTR_NOGW.value)

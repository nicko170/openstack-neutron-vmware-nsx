# Copyright 2016 VMware, Inc.  All rights reserved.
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

import re

from neutron_lib.callbacks import registry
from neutron_lib import context
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_vmware import vim_util

from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import nsxv_db
from vmware_nsx.dvs import dvs
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv.resources import utils
from vmware_nsx.shell import resources as shell

LOG = logging.getLogger(__name__)


def get_virtual_wires():
    """Return a hash of the backend virtual wires by their id"""
    nsxv = utils.get_nsxv_client()
    vw_list = nsxv.get_virtual_wires()
    vw_hash = {}
    for vw in vw_list:
        vw_hash[vw['objectId']] = vw
    return vw_hash


def get_networks_name_map():
    """Create a dictionary mapping moref->backend name
    """
    root = utils.get_networks_from_backend()
    networks = {}
    for obj in root.iter('object'):
        if obj.find('objectTypeName').text in utils.network_types:
            networks[obj.find('objectId').text] = obj.find('name').text
    return networks


@admin_utils.output_header
@admin_utils.unpack_payload
def neutron_list_networks(resource, event, trigger,
                          **kwargs):
    LOG.info(formatters.output_formatter(constants.NETWORKS,
                                         utils.get_networks(),
                                         ['type', 'moref', 'name']))


@admin_utils.output_header
@admin_utils.unpack_payload
def nsx_update_switch(resource, event, trigger, **kwargs):
    nsxv_c = utils.get_nsxv_client()
    if not kwargs.get('property'):
        LOG.error("Need to specify dvs-id parameter and "
                  "attribute to update. Add --property dvs-id=<dvs-id> "
                  "--property teamingpolicy=<policy>")
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    dvs_id = properties.get('dvs-id')
    if not dvs_id:
        LOG.error("Need to specify dvs-id. "
                  "Add --property dvs-id=<dvs-id>")
        return
    try:
        h, switch = nsxv_c.get_vdn_switch(dvs_id)
    except exceptions.ResourceNotFound:
        LOG.error("DVS %s not found", dvs_id)
        return
    supported_policies = ['ETHER_CHANNEL', 'LOADBALANCE_LOADBASED',
                          'LOADBALANCE_SRCID', 'LOADBALANCE_SRCMAC',
                          'FAILOVER_ORDER', 'LACP_ACTIVE', 'LACP_PASSIVE',
                          'LACP_V2']
    policy = properties.get('teamingpolicy')
    if policy in supported_policies:
        if switch['teamingPolicy'] == policy:
            LOG.info("Policy already set!")
            return
        LOG.info("Updating NSXv switch %(dvs)s teaming policy to "
                 "%(policy)s", {'dvs': dvs_id, 'policy': policy})
        switch['teamingPolicy'] = policy
        try:
            switch = nsxv_c.update_vdn_switch(switch)
        except exceptions.VcnsApiException as e:
            desc = jsonutils.loads(e.response)
            details = desc.get('details')
            if details.startswith("No enum constant"):
                LOG.error("Unknown teaming policy %s", policy)
            else:
                LOG.error("Unexpected error occurred: %s", details)
            return

        LOG.info("Switch value after update: %s", switch)
    else:
        LOG.info("Current switch value is: %s", switch)
        LOG.error("Invalid teaming policy. "
                  "Add --property teamingpolicy=<policy>")
        LOG.error("Possible values: %s", ', '.join(supported_policies))


@admin_utils.output_header
@admin_utils.unpack_payload
def list_missing_networks(resource, event, trigger, **kwargs):
    """List the neutron networks which are missing the backend moref
    """
    # get the neutron-nsx networks mapping from DB
    admin_context = context.get_admin_context()
    mappings = nsx_db.get_nsx_networks_mapping(admin_context.session)
    # get the list of backend networks:
    backend_networks = get_networks_name_map()
    missing_networks = []

    # For each neutron network - check if there is a matching backend network
    for entry in mappings:
        nsx_id = entry['nsx_id']
        dvs_id = entry['dvs_id']
        if nsx_id not in backend_networks.keys():
            missing_networks.append({'neutron_id': entry['neutron_id'],
                                     'moref': nsx_id,
                                     'dvs_id': dvs_id})
        elif dvs_id:
            netname = backend_networks[nsx_id]
            if not netname.startswith(dvs_id):
                missing_networks.append({'neutron_id': entry['neutron_id'],
                                         'moref': nsx_id,
                                         'dvs_id': dvs_id})

    LOG.info(formatters.output_formatter(constants.MISSING_NETWORKS,
                                         missing_networks,
                                         ['neutron_id', 'moref', 'dvs_id']))


@admin_utils.output_header
@admin_utils.unpack_payload
def list_orphaned_networks(resource, event, trigger, **kwargs):
    """List the NSX networks which are missing the neutron DB
    """
    backend_networks = utils.get_networks()
    orphaned_networks = utils.get_orphaned_networks(backend_networks)

    LOG.info(formatters.output_formatter(constants.ORPHANED_NETWORKS,
                                         orphaned_networks,
                                         ['type', 'moref', 'name']))


def _get_nsx_portgroups(dvs_id):
    dvsManager = dvs.VCManager()
    dvs_moref = dvsManager._get_dvs_moref_by_id(dvs_id)
    port_groups = dvsManager._session.invoke_api(vim_util,
                                                 'get_object_properties',
                                                 dvsManager._session.vim,
                                                 dvs_moref,
                                                 ['portgroup'])
    nsx_portgroups = []
    if len(port_groups) and hasattr(port_groups[0], 'propSet'):
        for prop in port_groups[0].propSet:
            for val in prop.val[0]:
                nsx_portgroups.append({'moref': val.value, 'type': val._type})

    return nsx_portgroups


@admin_utils.output_header
@admin_utils.unpack_payload
def list_nsx_portgroups(resource, event, trigger, **kwargs):
    if not cfg.CONF.dvs.host_ip:
        LOG.info("Please configure the dvs section in the nsx configuration "
                 "file")
        return

    dvs_id = cfg.CONF.nsxv.dvs_id
    port_groups = _get_nsx_portgroups(dvs_id)
    LOG.info(formatters.output_formatter(
        constants.NSX_PORTGROUPS + " for %s" % dvs_id,
        port_groups, ['moref', 'type']))


@admin_utils.output_header
@admin_utils.unpack_payload
def delete_nsx_portgroups(resource, event, trigger, **kwargs):
    if not cfg.CONF.dvs.host_ip:
        LOG.info("Please configure the dvs section in the nsx configuration "
                 "file")
        return

    dvs_id = cfg.CONF.nsxv.dvs_id
    portgroups = _get_nsx_portgroups(dvs_id)
    if not portgroups:
        LOG.info("No NSX portgroups found for %s", dvs_id)
        return

    if not kwargs.get('force'):
        #ask for the user confirmation
        confirm = admin_utils.query_yes_no(
            "Do you want to delete all NSX portgroups for %s" % dvs_id,
            default="no")
        if not confirm:
            LOG.info("NSX portgroups deletion aborted by user")
            return

    vcns = utils.get_nsxv_client()
    for portgroup in portgroups:
        try:
            vcns.delete_port_group(dvs_id, portgroup['moref'])
        except Exception as e:
            LOG.error("Failed to delete portgroup %(pg)s: %(e)s",
                      {'pg': portgroup['moref'], 'e': e})
        else:
            LOG.info("Successfully deleted portgroup %(pg)s",
                     {'pg': portgroup['moref']})
    LOG.info("Done.")


def get_dvs_id_from_backend_name(backend_name):
    reg = re.search(r"^dvs-\d*", backend_name)
    if reg:
        return reg.group(0)


def list_internal_virtual_wires(vws):
    # List the virtualwires matching plr-dlr connection with their vni
    table_results = []
    map_results = {}
    admin_context = context.get_admin_context()

    # Get all the plr-dlr virtual wires
    like_filters = {'lswitch_id': 'virtualwire-%'}
    edge_bindings = nsxv_db.get_nsxv_router_bindings(
        admin_context.session, like_filters=like_filters)

    for binding in edge_bindings:
        # get the nsx id:
        moref = binding.lswitch_id
        vni = vws.get(moref, {}).get('vdnId')
        table_results.append({'neutron_id': binding['router_id'],
                              'nsx_id': moref,
                              'vni': vni})
        map_results[binding['router_id']] = vni
    return table_results, map_results


def list_neutron_virtual_wires(vws):
    # List the virtualwires matching neutron networks with their vni
    table_results = []
    map_results = {}
    admin_context = context.get_admin_context()
    with utils.NsxVPluginWrapper() as plugin:
        neutron_networks = plugin.get_networks(admin_context, fields=['id'])
        for net in neutron_networks:
            # get the nsx id:
            net_morefs = nsx_db.get_nsx_switch_ids(admin_context.session,
                                                   net['id'])
            for moref in net_morefs:
                if not moref.startswith('virtualwire'):
                    continue
                vni = vws.get(moref, {}).get('vdnId')
                table_results.append({'neutron_id': net['id'],
                                'nsx_id': moref,
                                'vni': vni})
                map_results[net['id']] = vni
    return table_results, map_results


@admin_utils.output_header
@admin_utils.unpack_payload
def list_nsx_virtual_wires(resource, event, trigger, **kwargs):
    filename = None
    internal = False
    if kwargs.get('property'):
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        filename = properties.get('map-file')
        internal = bool(properties.get('internal', 'false').lower() == 'true')

    vws = get_virtual_wires()
    if internal:
        table_results, map_results = list_internal_virtual_wires(vws)
    else:
        table_results, map_results = list_neutron_virtual_wires(vws)

    LOG.info(formatters.output_formatter(constants.NSX_VIRTUALWIRES,
                                         table_results,
                                         ['neutron_id', 'nsx_id', 'vni']))
    if filename:
        f = open(filename, "w")
        f.write("%s" % jsonutils.dumps(map_results))
        f.close()
        LOG.info("Mapping data saved into %s", filename)


@admin_utils.output_header
@admin_utils.unpack_payload
def delete_backend_network(resource, event, trigger, **kwargs):
    """Delete a backend network by its moref
    """
    errmsg = ("Need to specify moref property. Add --property moref=<moref>")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    moref = properties.get('moref')
    if not moref:
        LOG.error("%s", errmsg)
        return

    backend_name = get_networks_name_map().get(moref)
    if not backend_name:
        LOG.error("Failed to find the backend network %(moref)s",
                  {'moref': moref})
        return

    # Note: in case the backend network is attached to other backend objects,
    # like VM, the deleting may fail and through an exception

    nsxv_c = utils.get_nsxv_client()
    if moref.startswith(utils.PORTGROUP_PREFIX):
        # get the dvs id from the backend name:
        dvs_id = get_dvs_id_from_backend_name(backend_name)
        if not dvs_id:
            LOG.error("Failed to find the DVS id of backend network "
                      "%(moref)s", {'moref': moref})
        else:
            try:
                nsxv_c.delete_port_group(dvs_id, moref)
            except Exception as e:
                LOG.error("Failed to delete backend network %(moref)s : "
                          "%(e)s", {'moref': moref, 'e': e})
            else:
                LOG.info("Backend network %(moref)s was deleted",
                         {'moref': moref})
    else:
        # Virtual wire
        try:
            nsxv_c.delete_virtual_wire(moref)
        except Exception as e:
            LOG.error("Failed to delete backend network %(moref)s : "
                      "%(e)s", {'moref': moref, 'e': e})
        else:
            LOG.info("Backend network %(moref)s was deleted",
                     {'moref': moref})


registry.subscribe(neutron_list_networks,
                   constants.NETWORKS,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_update_switch,
                   constants.NETWORKS,
                   shell.Operations.NSX_UPDATE.value)
registry.subscribe(list_missing_networks,
                   constants.MISSING_NETWORKS,
                   shell.Operations.LIST.value)
registry.subscribe(list_orphaned_networks,
                   constants.ORPHANED_NETWORKS,
                   shell.Operations.LIST.value)
registry.subscribe(delete_backend_network,
                   constants.ORPHANED_NETWORKS,
                   shell.Operations.NSX_CLEAN.value)
registry.subscribe(list_nsx_portgroups,
                   constants.NSX_PORTGROUPS,
                   shell.Operations.LIST.value)
registry.subscribe(delete_nsx_portgroups,
                   constants.NSX_PORTGROUPS,
                   shell.Operations.NSX_CLEAN.value)
registry.subscribe(list_nsx_virtual_wires,
                   constants.NSX_VIRTUALWIRES,
                   shell.Operations.LIST.value)

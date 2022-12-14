# Copyright 2015 VMware, Inc.  All rights reserved.
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

from neutron.db import securitygroups_db
from neutron.extensions import securitygroup as ext_sg
from neutron_lib.callbacks import registry
from neutron_lib import context as neutron_context
from neutron_lib.db import api as db_api
from oslo_log import log as logging

from vmware_nsx.common import nsx_constants
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import nsx_models
from vmware_nsx.extensions import providersecuritygroup as provider_sg
from vmware_nsx.extensions import securitygrouplogging as sg_logging
from vmware_nsx.plugins.nsx_v3 import plugin as v3_plugin
from vmware_nsx.plugins.nsx_v3 import utils as plugin_utils
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils as v3_utils
from vmware_nsx.shell import resources as shell
from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import nsx_constants as consts

LOG = logging.getLogger(__name__)


class NeutronSecurityGroupApi(securitygroups_db.SecurityGroupDbMixin):
    def __init__(self):
        super(NeutronSecurityGroupApi, self)
        self.context = neutron_context.get_admin_context()
        self.filters = v3_utils.get_plugin_filters(self.context)
        admin_utils._init_plugin_mock_quota()

    def get_security_groups(self):
        return super(NeutronSecurityGroupApi,
                     self).get_security_groups(self.context,
                                               filters=self.filters)

    def get_security_group(self, sg_id):
        return super(NeutronSecurityGroupApi,
                     self).get_security_group(self.context, sg_id)

    def create_security_group(self, sg, default_sg=False):
        return super(NeutronSecurityGroupApi,
                     self).create_security_group(self.context, sg,
                                                 default_sg=default_sg)

    def delete_security_group(self, sg_id):
        return super(NeutronSecurityGroupApi,
                     self).delete_security_group(self.context, sg_id)

    def get_nsgroup_id(self, sg_id):
        return nsx_db.get_nsx_security_group_id(
            self.context.session, sg_id)

    def get_port_security_groups(self, port_id):
        secgroups_bindings = self._get_port_security_group_bindings(
            self.context, {'port_id': [port_id]})
        return [b['security_group_id'] for b in secgroups_bindings]

    def get_ports_in_security_group(self, security_group_id):
        secgroups_bindings = self._get_port_security_group_bindings(
            self.context, {'security_group_id': [security_group_id]})
        return [b['port_id'] for b in secgroups_bindings]

    def delete_security_group_section_mapping(self, sg_id):
        with db_api.CONTEXT_WRITER.using(self.context):
            fw_mapping = self.context.session.query(
                nsx_models.NeutronNsxFirewallSectionMapping).filter_by(
                    neutron_id=sg_id).one_or_none()
            if fw_mapping:
                self.context.session.delete(fw_mapping)

    def delete_security_group_backend_mapping(self, sg_id):
        with db_api.CONTEXT_WRITER.using(self.context):
            sg_mapping = self.context.session.query(
                nsx_models.NeutronNsxSecurityGroupMapping).filter_by(
                    neutron_id=sg_id).one_or_none()
            if sg_mapping:
                self.context.session.delete(sg_mapping)

    def get_logical_port_id(self, port_id):
        mapping = self.context.session.query(
            nsx_models.NeutronNsxPortMapping).filter_by(
                neutron_id=port_id).one_or_none()
        if mapping:
            return mapping.nsx_id


neutron_sg = NeutronSecurityGroupApi()
neutron_db = v3_utils.NeutronDbClient()


def _log_info(resource, data, attrs=['display_name', 'id']):
    LOG.info(formatters.output_formatter(resource, data, attrs))


@admin_utils.list_handler(constants.SECURITY_GROUPS)
@admin_utils.output_header
@admin_utils.unpack_payload
def list_security_groups_mappings(resource, event, trigger, **kwargs):
    """List neutron security groups"""
    sg_mappings = plugin_utils.get_security_groups_mappings(neutron_sg.context)
    _log_info(constants.SECURITY_GROUPS,
              sg_mappings,
              attrs=['name', 'id', 'section-id', 'nsx-securitygroup-id'])
    return bool(sg_mappings)


@admin_utils.list_handler(constants.FIREWALL_SECTIONS)
@admin_utils.output_header
@admin_utils.unpack_payload
def nsx_list_dfw_sections(resource, event, trigger, **kwargs):
    """List NSX backend firewall sections"""
    nsxlib = v3_utils.get_connected_nsxlib()
    fw_sections = nsxlib.firewall_section.list()
    _log_info(constants.FIREWALL_SECTIONS, fw_sections)
    return bool(fw_sections)


@admin_utils.list_handler(constants.FIREWALL_NSX_GROUPS)
@admin_utils.output_header
@admin_utils.unpack_payload
def nsx_list_security_groups(resource, event, trigger, **kwargs):
    """List NSX backend security groups"""
    nsxlib = v3_utils.get_connected_nsxlib()
    nsx_secgroups = nsxlib.ns_group.list()
    _log_info(constants.FIREWALL_NSX_GROUPS, nsx_secgroups)
    return bool(nsx_secgroups)


def _find_missing_security_groups():
    nsxlib = v3_utils.get_connected_nsxlib()
    nsx_secgroups = nsxlib.ns_group.list()
    sg_mappings = plugin_utils.get_security_groups_mappings(neutron_sg.context)
    missing_secgroups = {}
    for sg_db in sg_mappings:
        for nsx_sg in nsx_secgroups:
            if nsx_sg['id'] == sg_db['nsx-securitygroup-id']:
                break
        else:
            missing_secgroups[sg_db['id']] = sg_db
    return missing_secgroups


@admin_utils.list_mismatches_handler(constants.FIREWALL_NSX_GROUPS)
@admin_utils.output_header
@admin_utils.unpack_payload
def list_missing_security_groups(resource, event, trigger, **kwargs):
    """List security groups with sections missing on the NSX backend"""
    sgs_with_missing_nsx_group = _find_missing_security_groups()
    missing_securitgroups_info = [
        {'securitygroup-name': sg['name'],
         'securitygroup-id': sg['id'],
         'nsx-securitygroup-id':
         sg['nsx-securitygroup-id']}
        for sg in sgs_with_missing_nsx_group.values()]
    _log_info(constants.FIREWALL_NSX_GROUPS, missing_securitgroups_info,
              attrs=['securitygroup-name', 'securitygroup-id',
                     'nsx-securitygroup-id'])
    return bool(missing_securitgroups_info)


def _find_missing_sections():
    nsxlib = v3_utils.get_connected_nsxlib()
    fw_sections = nsxlib.firewall_section.list()
    sg_mappings = plugin_utils.get_security_groups_mappings(neutron_sg.context)
    missing_sections = {}
    for sg_db in sg_mappings:
        for fw_section in fw_sections:
            if fw_section['id'] == sg_db['section-id']:
                break
        else:
            missing_sections[sg_db['id']] = sg_db
    return missing_sections


@admin_utils.list_mismatches_handler(constants.FIREWALL_SECTIONS)
@admin_utils.output_header
@admin_utils.unpack_payload
def list_missing_firewall_sections(resource, event, trigger, **kwargs):
    """List security groups with missing sections on the NSX backend"""
    sgs_with_missing_section = _find_missing_sections()
    missing_sections_info = [{'securitygroup-name': sg['name'],
                              'securitygroup-id': sg['id'],
                              'section-id': sg['section-id']}
                             for sg in sgs_with_missing_section.values()]
    _log_info(constants.FIREWALL_SECTIONS, missing_sections_info,
              attrs=['securitygroup-name', 'securitygroup-id', 'section-id'])
    return bool(missing_sections_info)


@admin_utils.fix_mismatches_handler(constants.SECURITY_GROUPS)
@admin_utils.output_header
@admin_utils.unpack_payload
def fix_security_groups(resource, event, trigger, **kwargs):
    """Fix mismatch security groups by recreating missing sections & NS groups
    on the NSX backend
    """
    context_ = neutron_context.get_admin_context()
    inconsistent_secgroups = _find_missing_sections()
    inconsistent_secgroups.update(_find_missing_security_groups())

    nsxlib = v3_utils.get_connected_nsxlib()
    with v3_utils.NsxV3PluginWrapper() as plugin:
        for sg_id, sg in inconsistent_secgroups.items():
            secgroup = plugin.get_security_group(context_, sg_id)

            try:
                # FIXME(roeyc): try..except clause should be removed once the
                # api will return 404 response code instead 400 for trying to
                # delete a non-existing firewall section.
                nsxlib.firewall_section.delete(sg['section-id'])
            except Exception:
                pass

            try:
                nsxlib.ns_group.delete(sg['nsx-securitygroup-id'])
            except Exception:
                LOG.debug("NSGroup %s does not exists for delete request.",
                          sg['nsx-securitygroup-id'])

            neutron_sg.delete_security_group_section_mapping(sg_id)
            neutron_sg.delete_security_group_backend_mapping(sg_id)
            nsgroup, fw_section = (
                plugin._create_security_group_backend_resources(secgroup))
            nsx_db.save_sg_mappings(
                context_, sg_id, nsgroup['id'], fw_section['id'])
            # If version > 1.1 then we use dynamic criteria tags, and the port
            # should already have them.
            if not nsxlib.feature_supported(consts.FEATURE_DYNAMIC_CRITERIA):
                members = []
                for port_id in neutron_sg.get_ports_in_security_group(sg_id):
                    lport_id = neutron_sg.get_logical_port_id(port_id)
                    members.append(lport_id)
                nsxlib.ns_group.add_members(
                    nsgroup['id'], consts.TARGET_TYPE_LOGICAL_PORT, members)

            for rule in secgroup['security_group_rules']:
                rule_mapping = (context_.session.query(
                    nsx_models.NeutronNsxRuleMapping).filter_by(
                        neutron_id=rule['id']).one())
                with context_.session.begin(subtransactions=True):
                    context_.session.delete(rule_mapping)
            action = (consts.FW_ACTION_DROP
                      if secgroup.get(provider_sg.PROVIDER)
                      else consts.FW_ACTION_ALLOW)
            rules = plugin._create_firewall_rules(
                context_, fw_section['id'], nsgroup['id'],
                secgroup.get(sg_logging.LOGGING, False), action,
                secgroup['security_group_rules'])
            plugin.save_security_group_rule_mappings(context_, rules['rules'])


@admin_utils.unpack_payload
def list_orphaned_sections(resource, event, trigger, **kwargs):
    """List orphaned firewall sections"""
    nsxlib = v3_utils.get_connected_nsxlib()
    orphaned_sections = plugin_utils.get_orphaned_firewall_sections(
        neutron_sg.context, nsxlib)
    _log_info(constants.ORPHANED_FIREWALL_SECTIONS, orphaned_sections,
              attrs=['id', 'display_name'])


@admin_utils.unpack_payload
def list_orphaned_section_rules(resource, event, trigger, **kwargs):
    """List orphaned firewall section rules"""
    nsxlib = v3_utils.get_connected_nsxlib()
    orphaned_rules = plugin_utils.get_orphaned_firewall_section_rules(
        neutron_sg.context, nsxlib)
    _log_info("orphaned-firewall-section-rules", orphaned_rules,
              attrs=['security-group-name', 'security-group-id',
                     'section-id', 'rule-id'])


@admin_utils.unpack_payload
def clean_orphaned_sections(resource, event, trigger, **kwargs):
    """Delete orphaned firewall sections from the NSX backend"""
    nsxlib = v3_utils.get_connected_nsxlib()
    orphaned_sections = plugin_utils.get_orphaned_firewall_sections(
        neutron_sg.context, nsxlib)
    if not orphaned_sections:
        LOG.info("No orphaned nsx sections were found.")
    for sec in orphaned_sections:
        try:
            nsxlib.firewall_section.delete(sec['id'])
        except Exception as e:
            LOG.error("Failed to delete backend firewall section %(id)s : "
                      "%(e)s.", {'id': sec['id'], 'e': e})
        else:
            LOG.info("Backend firewall section %s was deleted.", sec['id'])


@admin_utils.unpack_payload
def clean_orphaned_section_rules(resource, event, trigger, **kwargs):
    """Delete orphaned firewall section rules from the NSX backend"""
    nsxlib = v3_utils.get_connected_nsxlib()
    orphaned_rules = plugin_utils.get_orphaned_firewall_section_rules(
        neutron_sg.context, nsxlib)
    if not orphaned_rules:
        LOG.info("No orphaned nsx rules were found.")
    for rule in orphaned_rules:
        try:
            nsxlib.firewall_section.delete_rule(
                rule['section-id'], rule['rule-id'])
        except Exception as e:
            LOG.error("Failed to delete backend firewall section %(sect)s "
                      "rule %(rule)s: %(e)s.", {'sect': rule['section-id'],
                                                'rule': rule['rule-id'],
                                                'e': e})
        else:
            LOG.info("Backend firewall rule %s was deleted.", rule['rule-id'])


@admin_utils.unpack_payload
def update_security_groups_logging(resource, event, trigger, **kwargs):
    """Update allowed traffic logging for all neutron security group rules"""
    errmsg = ("Need to specify log-allowed-traffic property. Add --property "
              "log-allowed-traffic=true/false")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    log_allowed_str = properties.get('log-allowed-traffic')
    if not log_allowed_str or log_allowed_str.lower() not in ['true', 'false']:
        LOG.error("%s", errmsg)
        return
    log_allowed = log_allowed_str.lower() == 'true'

    context = neutron_context.get_admin_context()
    nsxlib = v3_utils.get_connected_nsxlib()

    with v3_utils.NsxV3PluginWrapper() as plugin:
        secgroups = plugin.get_security_groups(context,
                                             fields=['id',
                                             sg_logging.LOGGING])
        LOG.info("Going to update logging of %s sections",
                 len(secgroups))
        for sg in [sg for sg in secgroups
                   if sg.get(sg_logging.LOGGING) is False]:
            nsgroup_id, section_id = nsx_db.get_sg_mappings(
                context.session, sg['id'])
            if section_id:
                try:
                    nsxlib.firewall_section.set_rule_logging(
                        section_id, logging=log_allowed)
                except nsx_lib_exc.ManagerError:
                    LOG.error("Failed to update firewall rule logging "
                              "for rule in section %s", section_id)


@admin_utils.unpack_payload
def reuse_default_section(resource, event, trigger, **kwargs):
    """Reuse existing NSX default section & NS group that might already exist
    on the NSX from a previous installation.
    """
    # first check if the backend has a default OS section
    nsxlib = v3_utils.get_connected_nsxlib()
    fw_sections = nsxlib.firewall_section.list()
    section_name = v3_plugin.NSX_V3_FW_DEFAULT_SECTION
    section_id = None
    for section in fw_sections:
        if section['display_name'] == section_name:
            if section_id is not None:
                # Multiple sections already exist!
                LOG.error("Multiple default OS NSX sections already exist. "
                          "Please delete unused ones")
                return False
            section_id = section['id']

    if not section_id:
        LOG.error("No OS NSX section found")
        return False

    # Get existing default NS group from the NSX
    ns_groups = nsxlib.ns_group.find_by_display_name(
        v3_plugin.NSX_V3_FW_DEFAULT_NS_GROUP)
    if len(ns_groups) > 1:
        LOG.error("Multiple default OS NS groups already exist. "
                  "Please delete unused ones")
        return False
    if not ns_groups:
        LOG.error("No OS NS group found")
        return False
    nsgroup_id = ns_groups[0]['id']

    # Reuse this section by adding it to the DB mapping
    context = neutron_context.get_admin_context()
    # Add global SG to the neutron DB
    try:
        neutron_sg.get_security_group(plugin_utils.NSX_V3_OS_DFW_UUID)
    except ext_sg.SecurityGroupNotFound:
        sec_group = {'security_group':
                     {'id': plugin_utils.NSX_V3_OS_DFW_UUID,
                      'tenant_id': nsx_constants.INTERNAL_V3_TENANT_ID,
                      'name': 'NSX Internal',
                      'description': ''}}
        neutron_sg.create_security_group(
            sec_group, default_sg=True)

    # Get existing mapping from the DB
    db_nsgroup_id, db_section_id = nsx_db.get_sg_mappings(
        context.session, plugin_utils.NSX_V3_OS_DFW_UUID)
    if db_nsgroup_id or db_section_id:
        if db_nsgroup_id == nsgroup_id and db_section_id == section_id:
            LOG.info('Neutron DB is already configured correctly with section '
                     '%s and NS group %s', section_id, nsgroup_id)
            return True
        LOG.info('Deleting old DB mappings for section %s and NS group %s',
            db_section_id, db_nsgroup_id)
        nsx_db.delete_sg_mappings(
            context, plugin_utils.NSX_V3_OS_DFW_UUID,
            db_nsgroup_id, db_section_id)

    # Add mappings to the neutron DB
    LOG.info('Creating new DB mappings for section %s and NS group %s',
             section_id, nsgroup_id)
    nsx_db.save_sg_mappings(
        context, plugin_utils.NSX_V3_OS_DFW_UUID,
        nsgroup_id, section_id)

    # The DB mappings were changed.
    # The user must restart neutron to avoid failures.
    LOG.info("Please restart neutron service")
    return True


registry.subscribe(update_security_groups_logging,
                   constants.SECURITY_GROUPS,
                   shell.Operations.UPDATE_LOGGING.value)

registry.subscribe(fix_security_groups,
                   constants.FIREWALL_SECTIONS,
                   shell.Operations.NSX_UPDATE.value)

registry.subscribe(list_orphaned_sections,
                   constants.ORPHANED_FIREWALL_SECTIONS,
                   shell.Operations.NSX_LIST.value)

registry.subscribe(list_orphaned_section_rules,
                   constants.ORPHANED_FIREWALL_SECTIONS,
                   shell.Operations.NSX_LIST.value)

registry.subscribe(clean_orphaned_sections,
                   constants.ORPHANED_FIREWALL_SECTIONS,
                   shell.Operations.NSX_CLEAN.value)

registry.subscribe(clean_orphaned_section_rules,
                   constants.ORPHANED_FIREWALL_SECTIONS,
                   shell.Operations.NSX_CLEAN.value)

registry.subscribe(reuse_default_section,
                   constants.FIREWALL_SECTIONS,
                   shell.Operations.REUSE.value)

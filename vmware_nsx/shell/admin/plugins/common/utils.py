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

import sys
from unittest import mock

from neutron import quota
from vmware_nsx._i18n import _
from vmware_nsx.db import db
from vmware_nsx.shell import resources as nsxadmin

from neutron.common import profiler  # noqa
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class MetadataEventPayload(events.EventPayload):
    """An event type where only metadata metters.

    Event metadata will be accessed like a dictionary.
    """

    def __init__(self, metadata):
        super().__init__(None, metadata=metadata)

    def __getitem__(self, key):
        return self.metadata[key]


def unpack_payload(func):
    """Decorator to run admin shell functions.

    Unpacks payload metadata and passess them as kwargs to the
    actual callback
    """

    def wrapper(resource, event, trigger, payload):
        # Use only with MetadataEventPayload
        if payload:
            func(resource, event, trigger, **payload.metadata)
        else:
            func(resource, event, trigger)
    return wrapper


def output_header(func):
    """Decorator to demarcate the output of various hooks.

    Based on the callback function name we add a header to the
    cli output. Callback name's should follow the convention of
    component_operation_it_does to leverage the decorator
    """
    def func_desc(*args, **kwargs):
        component = '[%s]' % func.__name__.split('_')[0].upper()
        op_desc = [n.capitalize() for n in func.__name__.split('_')[1:]]
        LOG.info('==== %(component)s %(operation)s ====',
                 {'component': component, 'operation': ' '.join(op_desc)})
        return func(*args, **kwargs)
    func_desc.__name__ = func.__name__
    return func_desc


def parse_multi_keyval_opt(opt_list):
    """Converts a MutliStrOpt to a key-value dict"""

    result = {}
    opt_list = opt_list if opt_list else []
    for opt_value in opt_list:
        try:
            key, value = opt_value.split('=')
            result[key] = value
        except ValueError:
            raise ValueError(_("Illegal argument [%s]: input should have the "
                               "format of '--property key=value'") % opt_value)
    return result


def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError(_("invalid default answer: '%s'") % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        if choice in valid:
            return valid[choice]
        sys.stdout.write("Please respond with 'yes' or 'no' "
                         "(or 'y' or 'n').\n")


def list_handler(resource):
    def wrap(func):
        registry.subscribe(func, resource,
                           nsxadmin.Operations.LIST.value)
        return func
    return wrap


def list_mismatches_handler(resource):
    def wrap(func):
        registry.subscribe(func, resource,
                           nsxadmin.Operations.LIST_MISMATCHES.value)
        return func
    return wrap


def fix_mismatches_handler(resource):
    def wrap(func):
        registry.subscribe(func, resource,
                           nsxadmin.Operations.FIX_MISMATCH.value)
        return func
    return wrap


def get_plugin_filters(context, plugin):
    # Return filters for the neutron list apis so that only resources from
    # a specific plugin will be returned.
    filters = {}
    core_plugin = nsxadmin.get_plugin()
    if core_plugin == 'nsxtvd':
        maps = db.get_project_plugin_mappings_by_plugin(
            context.session, plugin)
        if maps:
            filters['project_id'] = [m.project for m in maps]
    return filters


def _init_plugin_mock_quota():
    mock.patch.object(quota.QuotaEngine, 'make_reservation').start()
    mock.patch.object(quota.QuotaEngine, 'commit_reservation').start()

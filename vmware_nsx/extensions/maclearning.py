# Copyright 2013 VMware, Inc.  All rights reserved.
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

from neutron_lib.api import converters
from neutron_lib.api import extensions
from neutron_lib import constants


ALIAS = 'mac-learning'
MAC_LEARNING = 'mac_learning_enabled'
EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        MAC_LEARNING: {'allow_post': True, 'allow_put': True,
                       'convert_to': converters.convert_to_boolean,
                       'default': constants.ATTR_NOT_SPECIFIED,
                       'is_visible': True},
    }
}


class Maclearning(extensions.ExtensionDescriptor):
    """Extension class supporting port mac learning."""

    @classmethod
    def get_name(cls):
        return "MAC Learning"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return "Provides MAC learning capabilities."

    @classmethod
    def get_updated(cls):
        return "2013-05-1T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        return []

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        return {}

# Copyright (c) 2009, 2010, 2011, 2016 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
import uuid

import ovs.db.parser
from ovs.db import error

import six
from six.moves import range

uuidRE = re.compile("^xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx$"
                    .replace('x', '[0-9a-fA-F]'))


def zero():
    return uuid.UUID(int=0)


def is_valid_string(s):
    return uuidRE.match(s) is not None


def from_string(s):
    if not is_valid_string(s):
        raise error.Error("%s is not a valid UUID" % s)
    return uuid.UUID(s)


def from_json(json, symtab=None):
    try:
        s = ovs.db.parser.unwrap_json(json, "uuid", six.string_types, "string")
        if not uuidRE.match(s):
            raise error.Error("\"%s\" is not a valid UUID" % s, json)
        return uuid.UUID(s)
    except error.Error as e:
        if not symtab:
            raise e
        try:
            name = ovs.db.parser.unwrap_json(json, "named-uuid",
                                             six.string_types, "string")
        except error.Error:
            raise e

        if name not in symtab:
            symtab[name] = uuid.uuid4()
        return symtab[name]


def to_json(uuid_):
    return ["uuid", str(uuid_)]


def to_c_initializer(uuid_, var):
    hex_string = uuid_.hex
    parts = ["0x%s" % (hex_string[x * 8:(x + 1) * 8])
            for x in range(4)]
    return "{ %s }," % ", ".join(parts)

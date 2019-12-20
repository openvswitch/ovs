# Copyright (c) 2010, 2011 Nicira, Inc.
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

from ovs.db import error


class Parser(object):
    def __init__(self, json, name):
        self.name = name
        self.json = json
        if not isinstance(json, dict):
            self.__raise_error("Object expected.")
        self.used = set()

    def __get(self, name, types, optional, default=None):
        if name in self.json:
            self.used.add(name)
            member = float_to_int(self.json[name])
            if is_identifier(member) and "id" in types:
                return member
            try:
                if len(types) and not isinstance(member, tuple(types)):
                    self.__raise_error("Type mismatch for member '%s'." % name)
            except TypeError:
                self.__raise_error("Type mismatch for member '%s'." % name)
            return member
        else:
            if not optional:
                self.__raise_error("Required '%s' member is missing." % name)
            return default

    def get(self, name, types):
        return self.__get(name, types, False)

    def get_optional(self, name, types, default=None):
        return self.__get(name, types, True, default)

    def __raise_error(self, message):
        raise error.Error("Parsing %s failed: %s" % (self.name, message),
                          self.json)

    def finish(self):
        missing = set(self.json) - set(self.used)
        if missing:
            name = missing.pop()
            if len(missing) > 1:
                present = "and %d other members are" % len(missing)
            elif missing:
                present = "and 1 other member are"
            else:
                present = "is"
            self.__raise_error("Member '%s' %s present but not allowed here" %
                               (name, present))


def float_to_int(x):
    # XXX still needed?
    if isinstance(x, float):
        integer = int(x)
        if integer == x and -2 ** 53 <= integer < 2 ** 53:
            return integer
    return x


id_re = re.compile("[_a-zA-Z][_a-zA-Z0-9]*$")


def is_identifier(s):
    return isinstance(s, str) and id_re.match(s)


def json_type_to_string(type_):
    number_types = [int]
    number_types.extend([float])
    number_types = tuple(number_types)
    if type_ is None:
        return "null"
    elif issubclass(type_, bool):
        return "boolean"
    elif issubclass(type_, dict):
        return "object"
    elif issubclass(type_, list):
        return "array"
    elif issubclass(type_, number_types):
        return "number"
    elif issubclass(type_, str):
        return "string"
    else:
        return "<invalid>"


def unwrap_json(json, name, types, desc):
    if (not isinstance(json, (list, tuple))
            or len(json) != 2 or json[0] != name
            or not isinstance(json[1], tuple(types))):
        raise error.Error('expected ["%s", <%s>]' % (name, desc), json)
    return json[1]


def parse_json_pair(json):
    if not isinstance(json, list) or len(json) != 2:
        raise error.Error("expected 2-element array", json)
    return json

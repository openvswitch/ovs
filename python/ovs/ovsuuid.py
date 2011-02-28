# Copyright (c) 2009, 2010, 2011 Nicira Networks
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

from ovs.db import error
import ovs.db.parser

class UUID(uuid.UUID):
    x = "[0-9a-fA-f]"
    uuidRE = re.compile("^(%s{8})-(%s{4})-(%s{4})-(%s{4})-(%s{4})(%s{8})$"
                        % (x, x, x, x, x, x))

    def __init__(self, s):
        uuid.UUID.__init__(self, hex=s)

    @staticmethod
    def zero():
        return UUID('00000000-0000-0000-0000-000000000000')

    def is_zero(self):
        return self.int == 0

    @staticmethod
    def is_valid_string(s):
        return UUID.uuidRE.match(s) != None

    @staticmethod
    def from_string(s):
        if not UUID.is_valid_string(s):
            raise error.Error("%s is not a valid UUID" % s)
        return UUID(s)

    @staticmethod
    def from_json(json, symtab=None):
        try:
            s = ovs.db.parser.unwrap_json(json, "uuid", unicode)
            if not UUID.uuidRE.match(s):
                raise error.Error("\"%s\" is not a valid UUID" % s, json)
            return UUID(s)
        except error.Error, e:
            if not symtab:
                raise e
            try:
                name = ovs.db.parser.unwrap_json(json, "named-uuid", unicode)
            except error.Error:
                raise e

            if name not in symtab:
                symtab[name] = uuid4()
            return symtab[name]

    def to_json(self):
        return ["uuid", str(self)]

    def cInitUUID(self, var):
        m = re.match(str(self))
        return ["%s.parts[0] = 0x%s;" % (var, m.group(1)),
                "%s.parts[1] = 0x%s%s;" % (var, m.group(2), m.group(3)),
                "%s.parts[2] = 0x%s%s;" % (var, m.group(4), m.group(5)),
                "%s.parts[3] = 0x%s;" % (var, m.group(6))]


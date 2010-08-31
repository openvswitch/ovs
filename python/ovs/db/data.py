# Copyright (c) 2009, 2010 Nicira Networks
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

import errno
import logging
import os
import re
import select
import sys
import uuid

import ovs.poller
import ovs.socket_util
import ovs.json
import ovs.jsonrpc
import ovs.ovsuuid

import ovs.db.parser
from ovs.db import error
import ovs.db.types

class ConstraintViolation(error.Error):
    def __init__(self, msg, json=None):
        error.Error.__init__(self, msg, json, tag="constraint violation")

def escapeCString(src):
    dst = ""
    for c in src:
        if c in "\\\"":
            dst += "\\" + c
        elif ord(c) < 32:
            if c == '\n':
                dst += '\\n'
            elif c == '\r':
                dst += '\\r'
            elif c == '\a':
                dst += '\\a'
            elif c == '\b':
                dst += '\\b'
            elif c == '\f':
                dst += '\\f'
            elif c == '\t':
                dst += '\\t'
            elif c == '\v':
                dst += '\\v'
            else:
                dst += '\\%03o' % ord(c)
        else:
            dst += c
    return dst

def returnUnchanged(x):
    return x

class Atom(object):
    def __init__(self, type, value=None):
        self.type = type
        if value is not None:
            self.value = value
        else:
            self.value = type.default_atom()

    def __cmp__(self, other):
        if not isinstance(other, Atom) or self.type != other.type:
            return NotImplemented
        elif self.value < other.value:
            return -1
        elif self.value > other.value:
            return 1
        else:
            return 0

    def __hash__(self):
        return hash(self.value)

    @staticmethod
    def default(type):
        return Atom(type)

    def is_default(self):
        return self == default(self.type)

    @staticmethod
    def from_json(base, json, symtab=None):
        type_ = base.type
        json = ovs.db.parser.float_to_int(json)
        if ((type_ == ovs.db.types.IntegerType and type(json) in [int, long])
            or (type_ == ovs.db.types.RealType and type(json) in [int, long, float])
            or (type_ == ovs.db.types.BooleanType and type(json) == bool)
            or (type_ == ovs.db.types.StringType and type(json) in [str, unicode])):
            atom = Atom(type_, json)
        elif type_ == ovs.db.types.UuidType:
            atom = Atom(type_, ovs.ovsuuid.UUID.from_json(json, symtab))
        else:
            raise error.Error("expected %s" % type_.to_string(), json)
        atom.check_constraints(base)
        return atom

    def check_constraints(self, base):
        """Checks whether 'atom' meets the constraints (if any) defined in
        'base' and raises an ovs.db.error.Error if any constraint is violated.

        'base' and 'atom' must have the same type.

        Checking UUID constraints is deferred to transaction commit time, so
        this function does nothing for UUID constraints."""
        assert base.type == self.type
        if base.enum is not None and self not in base.enum:
            raise ConstraintViolation(
                "%s is not one of the allowed values (%s)"
                % (self.to_string(), base.enum.to_string()))
        elif base.type in [ovs.db.types.IntegerType, ovs.db.types.RealType]:
            if ((base.min is None or self.value >= base.min) and
                (base.max is None or self.value <= base.max)):
                pass
            elif base.min is not None and base.max is not None:
                raise ConstraintViolation(
                    "%s is not in the valid range %.15g to %.15g (inclusive)"
                    % (self.to_string(), base.min, base.max))
            elif base.min is not None:
                raise ConstraintViolation(
                    "%s is less than minimum allowed value %.15g"
                            % (self.to_string(), base.min))
            else:
                raise ConstraintViolation(
                    "%s is greater than maximum allowed value %.15g"
                    % (self.to_string(), base.max))
        elif base.type == ovs.db.types.StringType:
            # XXX The C version validates that the string is valid UTF-8 here.
            # Do we need to do that in Python too?
            s = self.value
            length = len(s)
            if length < base.min_length:
                raise ConstraintViolation(
                    "\"%s\" length %d is less than minimum allowed length %d"
                    % (s, length, base.min_length))
            elif length > base.max_length:
                raise ConstraintViolation(
                    "\"%s\" length %d is greater than maximum allowed "
                    "length %d" % (s, length, base.max_length))
    
    def to_json(self):
        if self.type == ovs.db.types.UuidType:
            return self.value.to_json()
        else:
            return self.value

    def cInitAtom(self, var):
        if self.type == ovs.db.types.IntegerType:
            return ['%s.integer = %d;' % (var, self.value)]
        elif self.type == ovs.db.types.RealType:
            return ['%s.real = %.15g;' % (var, self.value)]
        elif self.type == ovs.db.types.BooleanType:
            if self.value:
                return ['%s.boolean = true;']
            else:
                return ['%s.boolean = false;']
        elif self.type == ovs.db.types.StringType:
            return ['%s.string = xstrdup("%s");'
                    % (var, escapeCString(self.value))]
        elif self.type == ovs.db.types.UuidType:
            return self.value.cInitUUID(var)

    def toEnglish(self, escapeLiteral=returnUnchanged):
        if self.type == ovs.db.types.IntegerType:
            return '%d' % self.value
        elif self.type == ovs.db.types.RealType:
            return '%.15g' % self.value
        elif self.type == ovs.db.types.BooleanType:
            if self.value:
                return 'true'
            else:
                return 'false'
        elif self.type == ovs.db.types.StringType:
            return escapeLiteral(self.value)
        elif self.type == ovs.db.types.UuidType:
            return self.value.value

    __need_quotes_re = re.compile("$|true|false|[^_a-zA-Z]|.*[^-._a-zA-Z]")
    @staticmethod
    def __string_needs_quotes(s):
        return Atom.__need_quotes_re.match(s)

    def to_string(self):
        if self.type == ovs.db.types.IntegerType:
            return '%d' % self.value
        elif self.type == ovs.db.types.RealType:
            return '%.15g' % self.value
        elif self.type == ovs.db.types.BooleanType:
            if self.value:
                return 'true'
            else:
                return 'false'
        elif self.type == ovs.db.types.StringType:
            if Atom.__string_needs_quotes(self.value):
                return ovs.json.to_string(self.value)
            else:
                return self.value
        elif self.type == ovs.db.types.UuidType:
            return str(self.value)

    @staticmethod
    def new(x):
        if type(x) in [int, long]:
            t = ovs.db.types.IntegerType
        elif type(x) == float:
            t = ovs.db.types.RealType
        elif x in [False, True]:
            t = ovs.db.types.RealType
        elif type(x) in [str, unicode]:
            t = ovs.db.types.StringType
        elif isinstance(x, uuid):
            t = ovs.db.types.UuidType
        else:
            raise TypeError
        return Atom(t, x)

class Datum(object):
    def __init__(self, type, values={}):
        self.type = type
        self.values = values

    def __cmp__(self, other):
        if not isinstance(other, Datum):
            return NotImplemented
        elif self.values < other.values:
            return -1
        elif self.values > other.values:
            return 1
        else:
            return 0

    __hash__ = None

    def __contains__(self, item):
        return item in self.values

    def clone(self):
        return Datum(self.type, dict(self.values))

    @staticmethod
    def default(type):
        if type.n_min == 0:
            values = {}
        elif type.is_map():
            values = {type.key.default(): type.value.default()}
        else:
            values = {type.key.default(): None}
        return Datum(type, values)

    @staticmethod
    def is_default(self):
        return self == default(self.type)

    def check_constraints(self):
        """Checks that each of the atoms in 'datum' conforms to the constraints
        specified by its 'type' and raises an ovs.db.error.Error.

        This function is not commonly useful because the most ordinary way to
        obtain a datum is ultimately via Datum.from_json() or Atom.from_json(),
        which check constraints themselves."""
        for keyAtom, valueAtom in self.values:
            keyAtom.check_constraints()
            if valueAtom is not None:
                valueAtom.check_constraints()

    @staticmethod
    def from_json(type_, json, symtab=None):
        """Parses 'json' as a datum of the type described by 'type'.  If
        successful, returns a new datum.  On failure, raises an
        ovs.db.error.Error.
        
        Violations of constraints expressed by 'type' are treated as errors.
        
        If 'symtab' is nonnull, then named UUIDs in 'symtab' are accepted.
        Refer to ovsdb/SPECS for information about this, and for the syntax
        that this function accepts."""
        is_map = type_.is_map()
        if (is_map or
            (type(json) == list and len(json) > 0 and json[0] == "set")):
            if is_map:
                class_ = "map"
            else:
                class_ = "set"

            inner = ovs.db.parser.unwrap_json(json, class_, list)
            n = len(inner)
            if n < type_.n_min or n > type_.n_max:
                raise error.Error("%s must have %d to %d members but %d are "
                                  "present" % (class_, type_.n_min,
                                               type_.n_max, n),
                                  json)

            values = {}
            for element in inner:
                if is_map:
                    key, value = ovs.db.parser.parse_json_pair(element)
                    keyAtom = Atom.from_json(type_.key, key, symtab)
                    valueAtom = Atom.from_json(type_.value, value, symtab)
                else:
                    keyAtom = Atom.from_json(type_.key, element, symtab)
                    valueAtom = None

                if keyAtom in values:
                    if is_map:
                        raise error.Error("map contains duplicate key")
                    else:
                        raise error.Error("set contains duplicate")

                values[keyAtom] = valueAtom

            return Datum(type_, values)
        else:
            keyAtom = Atom.from_json(type_.key, json, symtab)
            return Datum(type_, {keyAtom: None})

    def to_json(self):
        if len(self.values) == 1 and not self.type.is_map():
            key = self.values.keys()[0]
            return key.to_json()
        elif not self.type.is_map():
            return ["set", [k.to_json() for k in sorted(self.values.keys())]]
        else:
            return ["map", [[k.to_json(), v.to_json()]
                            for k, v in sorted(self.values.items())]]

    def to_string(self):
        if self.type.n_max > 1 or len(self.values) == 0:
            if self.type.is_map():
                s = "{"
            else:
                s = "["
        else:
            s = ""

        i = 0
        for key in sorted(self.values):
            if i > 0:
                s += ", "
            i += 1

            if self.type.is_map():
                s += "%s=%s" % (key.to_string(), self.values[key].to_string())
            else:
                s += key.to_string()

        if self.type.n_max > 1 or len(self.values) == 0:
            if self.type.is_map():
                s += "}"
            else:
                s += "]"
        return s

    def as_list(self):
        if self.type.is_map():
            return [[k.value, v.value] for k, v in self.values.iteritems()]
        else:
            return [k.value for k in self.values.iterkeys()]
        
    def as_scalar(self):
        if len(self.values) == 1:
            if self.type.is_map():
                k, v = self.values.iteritems()[0]
                return [k.value, v.value]
            else:
                return self.values.keys()[0].value
        else:
            return None

    def __getitem__(self, key):
        if not isinstance(key, Atom):
            key = Atom.new(key)
        if not self.type.is_map():
            raise IndexError
        elif key not in self.values:
            raise KeyError
        else:
            return self.values[key].value

    def get(self, key, default=None):
        if not isinstance(key, Atom):
            key = Atom.new(key)
        if key in self.values:
            return self.values[key].value
        else:
            return default
        
    def __str__(self):
        return self.to_string()

    def conforms_to_type(self):
        n = len(self.values)
        return n >= self.type.n_min and n <= self.type.n_max

    def cInitDatum(self, var):
        if len(self.values) == 0:
            return ["ovsdb_datum_init_empty(%s);" % var]

        s = ["%s->n = %d;" % (var, len(self.values))]
        s += ["%s->keys = xmalloc(%d * sizeof *%s->keys);"
              % (var, len(self.values), var)]

        i = 0
        for key, value in sorted(self.values.items()):
            s += key.cInitAtom("%s->keys[%d]" % (var, i))
            i += 1
        
        if self.type.value:
            s += ["%s->values = xmalloc(%d * sizeof *%s->values);"
                  % (var, len(self.values), var)]
            i = 0
            for key, value in sorted(self.values.items()):
                s += value.cInitAtom("%s->values[%d]" % (var, i))
                i += 1
        else:
            s += ["%s->values = NULL;" % var]

        if len(self.values) > 1:
            s += ["ovsdb_datum_sort_assert(%s, OVSDB_TYPE_%s);"
                  % (var, self.type.key.type.to_string().upper())]

        return s

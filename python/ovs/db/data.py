# Copyright (c) 2009, 2010, 2011, 2014, 2016 Nicira, Inc.
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

import functools
import re
import uuid

import ovs.db.parser
import ovs.db.types
import ovs.json
import ovs.jsonrpc
import ovs.ovsuuid
import ovs.poller
import ovs.socket_util
from ovs.db import error


class ConstraintViolation(error.Error):
    def __init__(self, msg, json=None):
        error.Error.__init__(self, msg, json, tag="constraint violation")


def escapeCString(src):
    dst = []
    for c in src:
        if c in "\\\"":
            dst.append("\\" + c)
        elif ord(c) < 32:
            if c == '\n':
                dst.append('\\n')
            elif c == '\r':
                dst.append('\\r')
            elif c == '\a':
                dst.append('\\a')
            elif c == '\b':
                dst.append('\\b')
            elif c == '\f':
                dst.append('\\f')
            elif c == '\t':
                dst.append('\\t')
            elif c == '\v':
                dst.append('\\v')
            else:
                dst.append('\\%03o' % ord(c))
        else:
            dst.append(c)
    return ''.join(dst)


def returnUnchanged(x):
    return x


@functools.total_ordering
class Atom(object):
    def __init__(self, type_, value=None):
        self.type = type_
        if value is not None:
            self.value = value
        else:
            self.value = type_.default_atom()

    def __eq__(self, other):
        if not isinstance(other, Atom) or self.type != other.type:
            return NotImplemented
        return True if self.value == other.value else False

    def __lt__(self, other):
        if not isinstance(other, Atom) or self.type != other.type:
            return NotImplemented
        return True if self.value < other.value else False

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
    def default(type_):
        """Returns the default value for the given type_, which must be an
        instance of ovs.db.types.AtomicType.

        The default value for each atomic type is;

          - 0, for integer or real atoms.

          - False, for a boolean atom.

          - "", for a string atom.

          - The all-zeros UUID, for a UUID atom."""
        return Atom(type_)

    def is_default(self):
        return self == self.default(self.type)

    @staticmethod
    def from_json(base, json, symtab=None):
        type_ = base.type
        json = ovs.db.parser.float_to_int(json)
        real_types = [int]
        real_types.extend([float])
        real_types = tuple(real_types)
        if ((type_ == ovs.db.types.IntegerType
                and isinstance(json, int))
            or (type_ == ovs.db.types.RealType
                and isinstance(json, real_types))
            or (type_ == ovs.db.types.BooleanType and isinstance(json, bool))
            or (type_ == ovs.db.types.StringType
                and isinstance(json, str))):
            atom = Atom(type_, json)
        elif type_ == ovs.db.types.UuidType:
            atom = Atom(type_, ovs.ovsuuid.from_json(json, symtab))
        else:
            raise error.Error("expected %s" % type_.to_string(), json)
        atom.check_constraints(base)
        return atom

    @staticmethod
    def from_python(base, value):
        value = ovs.db.parser.float_to_int(value)
        if isinstance(value, base.type.python_types):
            atom = Atom(base.type, value)
        else:
            raise error.Error("expected %s, got %s" % (base.type, type(value)))
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
                    '"%s" length %d is less than minimum allowed length %d'
                    % (s, length, base.min_length))
            elif length > base.max_length:
                raise ConstraintViolation(
                    '"%s" length %d is greater than maximum allowed '
                    'length %d' % (s, length, base.max_length))

    def to_json(self):
        if self.type == ovs.db.types.UuidType:
            return ovs.ovsuuid.to_json(self.value)
        else:
            return self.value

    def cInitAtom(self, var):
        if self.type == ovs.db.types.IntegerType:
            return '.integer = %d' % self.value
        elif self.type == ovs.db.types.RealType:
            return '.real = %.15g' % self.value
        elif self.type == ovs.db.types.BooleanType:
            if self.value:
                return '.boolean = true'
            else:
                return '.boolean = false'
        elif self.type == ovs.db.types.StringType:
            return '.string = "%s"' % escapeCString(self.value)
        elif self.type == ovs.db.types.UuidType:
            return '.uuid = %s' % ovs.ovsuuid.to_c_assignment(self.value)

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
        if isinstance(x, int):
            t = ovs.db.types.IntegerType
        elif isinstance(x, float):
            t = ovs.db.types.RealType
        elif isinstance(x, bool):
            t = ovs.db.types.BooleanType
        elif isinstance(x, str):
            t = ovs.db.types.StringType
        elif isinstance(x, uuid):
            t = ovs.db.types.UuidType
        else:
            raise TypeError
        return Atom(t, x)


@functools.total_ordering
class Datum(object):
    def __init__(self, type_, values={}):
        self.type = type_
        self.values = values

    def __eq__(self, other):
        if not isinstance(other, Datum):
            return NotImplemented
        return True if self.values == other.values else False

    def __lt__(self, other):
        if not isinstance(other, Datum):
            return NotImplemented
        return True if self.values < other.values else False

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

    def copy(self):
        return Datum(self.type, dict(self.values))

    @staticmethod
    def default(type_):
        if type_.n_min == 0:
            values = {}
        elif type_.is_map():
            values = {type_.key.default(): type_.value.default()}
        else:
            values = {type_.key.default(): None}
        return Datum(type_, values)

    def is_default(self):
        return self == Datum.default(self.type)

    def check_constraints(self):
        """Checks that each of the atoms in 'datum' conforms to the constraints
        specified by its 'type' and raises an ovs.db.error.Error.

        This function is not commonly useful because the most ordinary way to
        obtain a datum is ultimately via Datum.from_json() or Atom.from_json(),
        which check constraints themselves."""
        for keyAtom, valueAtom in self.values.items():
            keyAtom.check_constraints(self.type.key)
            if valueAtom is not None:
                valueAtom.check_constraints(self.type.value)

    @staticmethod
    def from_json(type_, json, symtab=None):
        """Parses 'json' as a datum of the type described by 'type'.  If
        successful, returns a new datum.  On failure, raises an
        ovs.db.error.Error.

        Violations of constraints expressed by 'type' are treated as errors.

        If 'symtab' is nonnull, then named UUIDs in 'symtab' are accepted.
        Refer to RFC 7047 for information about this, and for the syntax
        that this function accepts."""
        is_map = type_.is_map()
        if (is_map or
            (isinstance(json, list) and len(json) > 0 and json[0] == "set")):
            if is_map:
                class_ = "map"
            else:
                class_ = "set"

            inner = ovs.db.parser.unwrap_json(json, class_, [list, tuple],
                                              "array")
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
        if self.type.is_map():
            return ["map", [[k.to_json(), v.to_json()]
                            for k, v in sorted(self.values.items())]]
        elif len(self.values) == 1:
            key = next(iter(self.values.keys()))
            return key.to_json()
        else:
            return ["set", [k.to_json() for k in sorted(self.values.keys())]]

    def to_string(self):
        head = tail = None
        if self.type.n_max > 1 or len(self.values) == 0:
            if self.type.is_map():
                head = "{"
                tail = "}"
            else:
                head = "["
                tail = "]"

        s = []
        if head:
            s.append(head)

        for i, key in enumerate(sorted(self.values)):
            if i:
                s.append(", ")

            s.append(key.to_string())
            if self.type.is_map():
                s.append("=")
                s.append(self.values[key].to_string())

        if tail:
            s.append(tail)
        return ''.join(s)

    def diff(self, datum):
        if self.type.n_max > 1 or len(self.values) == 0:
            for k, v in datum.values.items():
                if k in self.values and v == self.values[k]:
                    del self.values[k]
                else:
                    self.values[k] = v
        else:
            return datum

        return self

    def as_list(self):
        if self.type.is_map():
            return [[k.value, v.value] for k, v in self.values.items()]
        else:
            return [k.value for k in self.values.keys()]

    def as_dict(self):
        return dict(self.values)

    def as_scalar(self):
        if len(self.values) == 1:
            if self.type.is_map():
                k, v = next(iter(self.values.items()))
                return [k.value, v.value]
            else:
                return next(iter(self.values.keys())).value
        else:
            return None

    def to_python(self, uuid_to_row):
        """Returns this datum's value converted into a natural Python
        representation of this datum's type, according to the following
        rules:

        - If the type has exactly one value and it is not a map (that is,
          self.type.is_scalar() returns True), then the value is:

            * An int or long, for an integer column.

            * An int or long or float, for a real column.

            * A bool, for a boolean column.

            * A str or unicode object, for a string column.

            * A uuid.UUID object, for a UUID column without a ref_table.

            * An object represented the referenced row, for a UUID column with
              a ref_table.  (For the Idl, this object will be an ovs.db.idl.Row
              object.)

          If some error occurs (e.g. the database server's idea of the column
          is different from the IDL's idea), then the default value for the
          scalar type is used (see Atom.default()).

        - Otherwise, if the type is not a map, then the value is a Python list
          whose elements have the types described above.

        - Otherwise, the type is a map, and the value is a Python dict that
          maps from key to value, with key and value types determined as
          described above.

        'uuid_to_row' must be a function that takes a value and an
        ovs.db.types.BaseType and translates UUIDs into row objects."""
        if self.type.is_scalar():
            value = uuid_to_row(self.as_scalar(), self.type.key)
            if value is None:
                return self.type.key.default()
            else:
                return value
        elif self.type.is_map():
            value = {}
            for k, v in self.values.items():
                dk = uuid_to_row(k.value, self.type.key)
                dv = uuid_to_row(v.value, self.type.value)
                if dk is not None and dv is not None:
                    value[dk] = dv
            return value
        else:
            s = set()
            for k in self.values:
                dk = uuid_to_row(k.value, self.type.key)
                if dk is not None:
                    s.add(dk)
            return sorted(s)

    @staticmethod
    def from_python(type_, value, row_to_uuid):
        """Returns a new Datum with the given ovs.db.types.Type 'type_'.  The
        new datum's value is taken from 'value', which must take the form
        described as a valid return value from Datum.to_python() for 'type'.

        Each scalar value within 'value' is initially passed through
        'row_to_uuid', which should convert objects that represent rows (if
        any) into uuid.UUID objects and return other data unchanged.

        Raises ovs.db.error.Error if 'value' is not in an appropriate form for
        'type_'."""
        d = {}
        if isinstance(value, dict):
            for k, v in value.items():
                ka = Atom.from_python(type_.key, row_to_uuid(k))
                va = Atom.from_python(type_.value, row_to_uuid(v))
                d[ka] = va
        elif isinstance(value, (list, set, tuple)):
            for k in value:
                ka = Atom.from_python(type_.key, row_to_uuid(k))
                d[ka] = None
        else:
            ka = Atom.from_python(type_.key, row_to_uuid(value))
            d[ka] = None

        datum = Datum(type_, d)
        datum.check_constraints()
        if not datum.conforms_to_type():
            raise error.Error("%d values when type requires between %d and %d"
                              % (len(d), type_.n_min, type_.n_max))

        return datum

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
        return self.type.n_min <= n <= self.type.n_max

    def cDeclareDatum(self, name):
        n = len(self.values)
        if n == 0:
            return ["static struct ovsdb_datum %s = { .n = 0 };"]

        s = ["static union ovsdb_atom %s_keys[%d] = {" % (name, n)]
        for key in sorted(self.values):
            s += ["    { %s }," % key.cInitAtom(key)]
        s += ["};"]

        if self.type.value:
            s = ["static union ovsdb_atom %s_values[%d] = {" % (name, n)]
            for k, v in sorted(self.values.items()):
                s += ["    { %s }," % v.cInitAtom(v)]
            s += ["};"]

        s += ["static struct ovsdb_datum %s = {" % name]
        s += ["    .n = %d," % n]
        s += ["    .keys = %s_keys," % name]
        if self.type.value:
            s += ["    .values = %s_values," % name]
        s += ["};"]
        return s

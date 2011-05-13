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

import codecs
import getopt
import re
import os
import signal
import sys

from ovs.db import error
import ovs.db.idl
import ovs.db.schema
from ovs.db import data
from ovs.db import types
import ovs.ovsuuid
import ovs.poller
import ovs.util

def unbox_json(json):
    if type(json) == list and len(json) == 1:
        return json[0]
    else:
        return json

def do_default_atoms():
    for type in types.ATOMIC_TYPES:
        if type == types.VoidType:
            continue

        sys.stdout.write("%s: " % type.to_string())

        atom = data.Atom.default(type)
        if atom != data.Atom.default(type):
            sys.stdout.write("wrong\n")
            sys.exit(1)

        sys.stdout.write("OK\n")

def do_default_data():
    any_errors = False
    for n_min in 0, 1:
        for key in types.ATOMIC_TYPES:
            if key == types.VoidType:
                continue
            for value in types.ATOMIC_TYPES:
                if value == types.VoidType:
                    valueBase = None
                else:
                    valueBase = types.BaseType(value)
                type = types.Type(types.BaseType(key), valueBase, n_min, 1)
                assert type.is_valid()

                sys.stdout.write("key %s, value %s, n_min %d: "
                                 % (key.to_string(), value.to_string(), n_min))

                datum = data.Datum.default(type)
                if datum != data.Datum.default(type):
                    sys.stdout.write("wrong\n")
                    any_errors = True
                else:
                    sys.stdout.write("OK\n")
    if any_errors:
        sys.exit(1)

def do_parse_atomic_type(type_string):
    type_json = unbox_json(ovs.json.from_string(type_string))
    atomic_type = types.AtomicType.from_json(type_json)
    print ovs.json.to_string(atomic_type.to_json(), sort_keys=True)

def do_parse_base_type(type_string):
    type_json = unbox_json(ovs.json.from_string(type_string))
    base_type = types.BaseType.from_json(type_json)
    print ovs.json.to_string(base_type.to_json(), sort_keys=True)

def do_parse_type(type_string):
    type_json = unbox_json(ovs.json.from_string(type_string))
    type = types.Type.from_json(type_json)
    print ovs.json.to_string(type.to_json(), sort_keys=True)

def do_parse_atoms(type_string, *atom_strings):
    type_json = unbox_json(ovs.json.from_string(type_string))
    base = types.BaseType.from_json(type_json)
    for atom_string in atom_strings:
        atom_json = unbox_json(ovs.json.from_string(atom_string))
        try:
            atom = data.Atom.from_json(base, atom_json)
            print ovs.json.to_string(atom.to_json())
        except error.Error, e:
            print unicode(e)

def do_parse_data(type_string, *data_strings):
    type_json = unbox_json(ovs.json.from_string(type_string))
    type = types.Type.from_json(type_json)
    for datum_string in data_strings:
        datum_json = unbox_json(ovs.json.from_string(datum_string))
        datum = data.Datum.from_json(type, datum_json)
        print ovs.json.to_string(datum.to_json())

def do_sort_atoms(type_string, atom_strings):
    type_json = unbox_json(ovs.json.from_string(type_string))
    base = types.BaseType.from_json(type_json)
    atoms = [data.Atom.from_json(base, atom_json)
             for atom_json in unbox_json(ovs.json.from_string(atom_strings))]
    print ovs.json.to_string([data.Atom.to_json(atom)
                              for atom in sorted(atoms)])

def do_parse_column(name, column_string):
    column_json = unbox_json(ovs.json.from_string(column_string))
    column = ovs.db.schema.ColumnSchema.from_json(column_json, name)
    print ovs.json.to_string(column.to_json(), sort_keys=True)

def do_parse_table(name, table_string, default_is_root_string='false'):
    default_is_root = default_is_root_string == 'true'
    table_json = unbox_json(ovs.json.from_string(table_string))
    table = ovs.db.schema.TableSchema.from_json(table_json, name)
    print ovs.json.to_string(table.to_json(default_is_root), sort_keys=True)

def do_parse_rows(table_string, *rows):
    table_json = unbox_json(ovs.json.from_string(table_string))
    table = ovs.db.schema.TableSchema.from_json(table_json, name)

def do_parse_schema(schema_string):
    schema_json = unbox_json(ovs.json.from_string(schema_string))
    schema = ovs.db.schema.DbSchema.from_json(schema_json)
    print ovs.json.to_string(schema.to_json(), sort_keys=True)

def print_idl(idl, step):
    n = 0
    for uuid, row in idl.data["simple"].iteritems():
        s = ("%03d: i=%s r=%s b=%s s=%s u=%s "
             "ia=%s ra=%s ba=%s sa=%s ua=%s uuid=%s"
             % (step, row.i, row.r, row.b, row.s, row.u,
                row.ia, row.ra, row.ba, row.sa, row.ua, uuid))
        print(re.sub('""|,', "", s))
        n += 1
    if not n:
        print("%03d: empty" % step)

def substitute_uuids(json, symtab):
    if type(json) in [str, unicode]:
        symbol = symtab.get(json)
        if symbol:
            return str(symbol)
    elif type(json) == list:
        return [substitute_uuids(element, symtab) for element in json]
    elif type(json) == dict:
        d = {}
        for key, value in json.iteritems():
            d[key] = substitute_uuids(value, symtab)
        return d
    return json

def parse_uuids(json, symtab):
    if type(json) in [str, unicode] and ovs.ovsuuid.UUID.is_valid_string(json):
        name = "#%d#" % len(symtab)
        sys.stderr.write("%s = %s\n" % (name, json))
        symtab[name] = json
    elif type(json) == list:
        for element in json:
            parse_uuids(element, symtab)
    elif type(json) == dict:
        for value in json.itervalues():
            parse_uuids(value, symtab)

def do_idl(remote, *commands):
    idl = ovs.db.idl.Idl(remote, "idltest")

    if commands:
        error, stream = ovs.stream.Stream.open_block(
            ovs.stream.Stream.open(remote))
        if error:
            sys.stderr.write("failed to connect to \"%s\"" % remote)
            sys.exit(1)
        rpc = ovs.jsonrpc.Connection(stream)
    else:
        rpc = None

    symtab = {}
    seqno = 0
    step = 0
    for command in commands:
        if command.startswith("+"):
            # The previous transaction didn't change anything.
            command = command[1:]
        else:
            # Wait for update.
            while idl.get_seqno() == seqno and not idl.run():
                rpc.run()

                poller = ovs.poller.Poller()
                idl.wait(poller)
                rpc.wait(poller)
                poller.block()
                
            print_idl(idl, step)
            step += 1

        seqno = idl.get_seqno()

        if command == "reconnect":
            print("%03d: reconnect" % step)
            step += 1
            idl.force_reconnect()
        elif not command.startswith("["):
            idl_set(idl, command, step)
            step += 1
        else:
            json = ovs.json.from_string(command)
            if type(json) in [str, unicode]:
                sys.stderr.write("\"%s\": %s\n" % (command, json))
                sys.exit(1)
            json = substitute_uuids(json, symtab)
            request = ovs.jsonrpc.Message.create_request("transact", json)
            error, reply = rpc.transact_block(request)
            if error:
                sys.stderr.write("jsonrpc transaction failed: %s"
                                 % os.strerror(error))
                sys.exit(1)
            sys.stdout.write("%03d: " % step)
            sys.stdout.flush()
            step += 1
            if reply.result is not None:
                parse_uuids(reply.result, symtab)
            reply.id = None
            sys.stdout.write("%s\n" % ovs.json.to_string(reply.to_json()))

    if rpc:
        rpc.close()
    while idl.get_seqno() == seqno and not idl.run():
        poller = ovs.poller.Poller()
        idl.wait(poller)
        poller.block()
    print_idl(idl, step)
    step += 1
    idl.close()
    print("%03d: done" % step)

def usage():
    print """\
%(program_name)s: test utility for Open vSwitch database Python bindings
usage: %(program_name)s [OPTIONS] COMMAND ARG...

The following commands are supported:
default-atoms
  test ovsdb_atom_default()
default-data
  test ovsdb_datum_default()
parse-atomic-type TYPE
  parse TYPE as OVSDB atomic type, and re-serialize
parse-base-type TYPE
  parse TYPE as OVSDB base type, and re-serialize
parse-type JSON
  parse JSON as OVSDB type, and re-serialize
parse-atoms TYPE ATOM...
  parse JSON ATOMs as atoms of TYPE, and re-serialize
parse-atom-strings TYPE ATOM...
  parse string ATOMs as atoms of given TYPE, and re-serialize
sort-atoms TYPE ATOM...
  print JSON ATOMs in sorted order
parse-data TYPE DATUM...
  parse JSON DATUMs as data of given TYPE, and re-serialize
parse-column NAME OBJECT
  parse column NAME with info OBJECT, and re-serialize
parse-table NAME OBJECT [DEFAULT-IS-ROOT]
  parse table NAME with info OBJECT
parse-schema JSON
  parse JSON as an OVSDB schema, and re-serialize
idl SERVER [TRANSACTION...]
  connect to SERVER and dump the contents of the database
  as seen initially by the IDL implementation and after
  executing each TRANSACTION.  (Each TRANSACTION must modify
  the database or this command will hang.)

The following options are also available:
  -t, --timeout=SECS          give up after SECS seconds
  -h, --help                  display this help message\
""" % {'program_name': ovs.util.PROGRAM_NAME}
    sys.exit(0)

def main(argv):
    try:
        options, args = getopt.gnu_getopt(argv[1:], 't:h',
                                          ['timeout',
                                           'help'])
    except getopt.GetoptError, geo:
        sys.stderr.write("%s: %s\n" % (ovs.util.PROGRAM_NAME, geo.msg))
        sys.exit(1)

    for key, value in options:
        if key in ['-h', '--help']:
            usage()
        elif key in ['-t', '--timeout']:
            try:
                timeout = int(value)
                if timeout < 1:
                    raise TypeError
            except TypeError:
                raise error.Error("value %s on -t or --timeout is not at "
                                  "least 1" % value)
            signal.alarm(timeout)
        else:
            sys.exit(0)

    optKeys = [key for key, value in options]

    if not args:
        sys.stderr.write("%s: missing command argument "
                         "(use --help for help)\n" % ovs.util.PROGRAM_NAME)
        sys.exit(1)

    commands = {"default-atoms": (do_default_atoms, 0),
                "default-data": (do_default_data, 0),
                "parse-atomic-type": (do_parse_atomic_type, 1),
                "parse-base-type": (do_parse_base_type, 1),
                "parse-type": (do_parse_type, 1),
                "parse-atoms": (do_parse_atoms, (2,)),
                "parse-data": (do_parse_data, (2,)),
                "sort-atoms": (do_sort_atoms, 2),
                "parse-column": (do_parse_column, 2),
                "parse-table": (do_parse_table, (2, 3)),
                "parse-schema": (do_parse_schema, 1),
                "idl": (do_idl, (1,))}

    command_name = args[0]
    args = args[1:]
    if not command_name in commands:
        sys.stderr.write("%s: unknown command \"%s\" "
                         "(use --help for help)\n" % (ovs.util.PROGRAM_NAME,
                                                      command_name))
        sys.exit(1)

    func, n_args = commands[command_name]
    if type(n_args) == tuple:
        if len(args) < n_args[0]:
            sys.stderr.write("%s: \"%s\" requires at least %d arguments but "
                             "only %d provided\n"
                             % (ovs.util.PROGRAM_NAME, command_name,
                                n_args, len(args)))
            sys.exit(1)
    elif type(n_args) == int:
        if len(args) != n_args:
            sys.stderr.write("%s: \"%s\" requires %d arguments but %d "
                             "provided\n"
                             % (ovs.util.PROGRAM_NAME, command_name,
                                n_args, len(args)))
            sys.exit(1)
    else:
        assert False

    func(*args)

if __name__ == '__main__':
    try:
        main(sys.argv)
    except error.Error, e:
        sys.stderr.write("%s\n" % e)
        sys.exit(1)

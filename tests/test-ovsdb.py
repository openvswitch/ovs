# Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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

import getopt
import re
import os
import signal
import sys
import uuid

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
    for type_ in types.ATOMIC_TYPES:
        if type_ == types.VoidType:
            continue

        sys.stdout.write("%s: " % type_.to_string())

        atom = data.Atom.default(type_)
        if atom != data.Atom.default(type_):
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
                type_ = types.Type(types.BaseType(key), valueBase, n_min, 1)
                assert type_.is_valid()

                sys.stdout.write("key %s, value %s, n_min %d: "
                                 % (key.to_string(), value.to_string(), n_min))

                datum = data.Datum.default(type_)
                if datum != data.Datum.default(type_):
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
    type_ = types.Type.from_json(type_json)
    print ovs.json.to_string(type_.to_json(), sort_keys=True)


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
    type_ = types.Type.from_json(type_json)
    for datum_string in data_strings:
        datum_json = unbox_json(ovs.json.from_string(datum_string))
        datum = data.Datum.from_json(type_, datum_json)
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


def do_parse_schema(schema_string):
    schema_json = unbox_json(ovs.json.from_string(schema_string))
    schema = ovs.db.schema.DbSchema.from_json(schema_json)
    print ovs.json.to_string(schema.to_json(), sort_keys=True)


def print_idl(idl, step):
    simple = idl.tables["simple"].rows
    l1 = idl.tables["link1"].rows
    l2 = idl.tables["link2"].rows

    n = 0
    for row in simple.itervalues():
        s = ("%03d: i=%s r=%s b=%s s=%s u=%s "
             "ia=%s ra=%s ba=%s sa=%s ua=%s uuid=%s"
             % (step, row.i, row.r, row.b, row.s, row.u,
                row.ia, row.ra, row.ba, row.sa, row.ua, row.uuid))
        s = re.sub('""|,|u?\'', "", s)
        s = re.sub('UUID\(([^)]+)\)', r'\1', s)
        s = re.sub('False', 'false', s)
        s = re.sub('True', 'true', s)
        s = re.sub(r'(ba)=([^[][^ ]*) ', r'\1=[\2] ', s)
        print(s)
        n += 1

    for row in l1.itervalues():
        s = ["%03d: i=%s k=" % (step, row.i)]
        if row.k:
            s.append(str(row.k.i))
        s.append(" ka=[")
        s.append(' '.join(sorted(str(ka.i) for ka in row.ka)))
        s.append("] l2=")
        if row.l2:
            s.append(str(row.l2[0].i))
        s.append(" uuid=%s" % row.uuid)
        print(''.join(s))
        n += 1

    for row in l2.itervalues():
        s = ["%03d: i=%s l1=" % (step, row.i)]
        if row.l1:
            s.append(str(row.l1[0].i))
        s.append(" uuid=%s" % row.uuid)
        print(''.join(s))
        n += 1

    if not n:
        print("%03d: empty" % step)
    sys.stdout.flush()


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
    if type(json) in [str, unicode] and ovs.ovsuuid.is_valid_string(json):
        name = "#%d#" % len(symtab)
        sys.stderr.write("%s = %s\n" % (name, json))
        symtab[name] = json
    elif type(json) == list:
        for element in json:
            parse_uuids(element, symtab)
    elif type(json) == dict:
        for value in json.itervalues():
            parse_uuids(value, symtab)


def idltest_find_simple(idl, i):
    for row in idl.tables["simple"].rows.itervalues():
        if row.i == i:
            return row
    return None


def idl_set(idl, commands, step):
    txn = ovs.db.idl.Transaction(idl)
    increment = False
    for command in commands.split(','):
        words = command.split()
        name = words[0]
        args = words[1:]

        if name == "set":
            if len(args) != 3:
                sys.stderr.write('"set" command requires 3 arguments\n')
                sys.exit(1)

            s = idltest_find_simple(idl, int(args[0]))
            if not s:
                sys.stderr.write('"set" command asks for nonexistent i=%d\n'
                                 % int(args[0]))
                sys.exit(1)

            if args[1] == "b":
                s.b = args[2] == "1"
            elif args[1] == "s":
                s.s = args[2]
            elif args[1] == "u":
                s.u = uuid.UUID(args[2])
            elif args[1] == "r":
                s.r = float(args[2])
            else:
                sys.stderr.write('"set" comamnd asks for unknown column %s\n'
                                 % args[2])
                sys.stderr.exit(1)
        elif name == "insert":
            if len(args) != 1:
                sys.stderr.write('"set" command requires 1 argument\n')
                sys.exit(1)

            s = txn.insert(idl.tables["simple"])
            s.i = int(args[0])
        elif name == "delete":
            if len(args) != 1:
                sys.stderr.write('"delete" command requires 1 argument\n')
                sys.exit(1)

            s = idltest_find_simple(idl, int(args[0]))
            if not s:
                sys.stderr.write('"delete" command asks for nonexistent i=%d\n'
                                 % int(args[0]))
                sys.exit(1)
            s.delete()
        elif name == "verify":
            if len(args) != 2:
                sys.stderr.write('"verify" command requires 2 arguments\n')
                sys.exit(1)

            s = idltest_find_simple(idl, int(args[0]))
            if not s:
                sys.stderr.write('"verify" command asks for nonexistent i=%d\n'
                                 % int(args[0]))
                sys.exit(1)

            if args[1] in ("i", "b", "s", "u", "r"):
                s.verify(args[1])
            else:
                sys.stderr.write('"verify" command asks for unknown column '
                                 '"%s"\n' % args[1])
                sys.exit(1)
        elif name == "increment":
            if len(args) != 1:
                sys.stderr.write('"increment" command requires 1 argument\n')
                sys.exit(1)

            s = idltest_find_simple(idl, int(args[0]))
            if not s:
                sys.stderr.write('"set" command asks for nonexistent i=%d\n'
                                 % int(args[0]))
                sys.exit(1)

            s.increment("i")
            increment = True
        elif name == "abort":
            txn.abort()
            break
        elif name == "destroy":
            print "%03d: destroy" % step
            sys.stdout.flush()
            txn.abort()
            return
        elif name == "linktest":
            l1_0 = txn.insert(idl.tables["link1"])
            l1_0.i = 1
            l1_0.k = [l1_0]
            l1_0.ka = [l1_0]
            l1_1 = txn.insert(idl.tables["link1"])
            l1_1.i = 2
            l1_1.k = [l1_0]
            l1_1.ka = [l1_0, l1_1]
        elif name == 'getattrtest':
            l1 = txn.insert(idl.tables["link1"])
            i = getattr(l1, 'i', 1)
            assert i == 1
            l1.i = 2
            i = getattr(l1, 'i', 1)
            assert i == 2
            l1.k = [l1]
        else:
            sys.stderr.write("unknown command %s\n" % name)
            sys.exit(1)

    status = txn.commit_block()
    sys.stdout.write("%03d: commit, status=%s"
                     % (step, ovs.db.idl.Transaction.status_to_string(status)))
    if increment and status == ovs.db.idl.Transaction.SUCCESS:
        sys.stdout.write(", increment=%d" % txn.get_increment_new_value())
    sys.stdout.write("\n")
    sys.stdout.flush()


def do_idl(schema_file, remote, *commands):
    schema_helper = ovs.db.idl.SchemaHelper(schema_file)
    schema_helper.register_all()
    idl = ovs.db.idl.Idl(remote, schema_helper)

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
            while idl.change_seqno == seqno and not idl.run():
                rpc.run()

                poller = ovs.poller.Poller()
                idl.wait(poller)
                rpc.wait(poller)
                poller.block()

            print_idl(idl, step)
            step += 1

        seqno = idl.change_seqno

        if command == "reconnect":
            print("%03d: reconnect" % step)
            sys.stdout.flush()
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
            elif reply.error is not None:
                sys.stderr.write("jsonrpc transaction failed: %s"
                                 % reply.error)
                sys.exit(1)

            sys.stdout.write("%03d: " % step)
            sys.stdout.flush()
            step += 1
            if reply.result is not None:
                parse_uuids(reply.result, symtab)
            reply.id = None
            sys.stdout.write("%s\n" % ovs.json.to_string(reply.to_json()))
            sys.stdout.flush()

    if rpc:
        rpc.close()
    while idl.change_seqno == seqno and not idl.run():
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
idl SCHEMA SERVER [TRANSACTION...]
  connect to SERVER (which has the specified SCHEMA) and dump the
  contents of the database as seen initially by the IDL implementation
  and after executing each TRANSACTION.  (Each TRANSACTION must modify
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
                "idl": (do_idl, (2,))}

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

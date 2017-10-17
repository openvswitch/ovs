# Copyright (c) 2009, 2010, 2011, 2012, 2016 Nicira, Inc.
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

from __future__ import print_function

import getopt
import os
import re
import sys
import uuid

import ovs.db.idl
import ovs.db.schema
import ovs.db.types
import ovs.ovsuuid
import ovs.poller
import ovs.stream
import ovs.util
from ovs.db import data
from ovs.db import error
from ovs.fatal_signal import signal_alarm

import six


def unbox_json(json):
    if type(json) == list and len(json) == 1:
        return json[0]
    else:
        return json


def do_default_atoms():
    for type_ in ovs.db.types.ATOMIC_TYPES:
        if type_ == ovs.db.types.VoidType:
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
        for key in ovs.db.types.ATOMIC_TYPES:
            if key == ovs.db.types.VoidType:
                continue
            for value in ovs.db.types.ATOMIC_TYPES:
                if value == ovs.db.types.VoidType:
                    valueBase = None
                else:
                    valueBase = ovs.db.types.BaseType(value)
                type_ = ovs.db.types.Type(ovs.db.types.BaseType(key),
                                          valueBase, n_min, 1)
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
    atomic_type = ovs.db.types.AtomicType.from_json(type_json)
    print(ovs.json.to_string(atomic_type.to_json(), sort_keys=True))


def do_parse_base_type(type_string):
    type_json = unbox_json(ovs.json.from_string(type_string))
    base_type = ovs.db.types.BaseType.from_json(type_json)
    print(ovs.json.to_string(base_type.to_json(), sort_keys=True))


def do_parse_type(type_string):
    type_json = unbox_json(ovs.json.from_string(type_string))
    type_ = ovs.db.types.Type.from_json(type_json)
    print(ovs.json.to_string(type_.to_json(), sort_keys=True))


def do_parse_atoms(type_string, *atom_strings):
    type_json = unbox_json(ovs.json.from_string(type_string))
    base = ovs.db.types.BaseType.from_json(type_json)
    for atom_string in atom_strings:
        atom_json = unbox_json(ovs.json.from_string(atom_string))
        try:
            atom = data.Atom.from_json(base, atom_json)
            print(ovs.json.to_string(atom.to_json()))
        except error.Error as e:
            print(e.args[0])


def do_parse_data(type_string, *data_strings):
    type_json = unbox_json(ovs.json.from_string(type_string))
    type_ = ovs.db.types.Type.from_json(type_json)
    for datum_string in data_strings:
        datum_json = unbox_json(ovs.json.from_string(datum_string))
        datum = data.Datum.from_json(type_, datum_json)
        print(ovs.json.to_string(datum.to_json()))


def do_sort_atoms(type_string, atom_strings):
    type_json = unbox_json(ovs.json.from_string(type_string))
    base = ovs.db.types.BaseType.from_json(type_json)
    atoms = [data.Atom.from_json(base, atom_json)
             for atom_json in unbox_json(ovs.json.from_string(atom_strings))]
    print(ovs.json.to_string([data.Atom.to_json(atom)
                              for atom in sorted(atoms)]))


def do_parse_column(name, column_string):
    column_json = unbox_json(ovs.json.from_string(column_string))
    column = ovs.db.schema.ColumnSchema.from_json(column_json, name)
    print(ovs.json.to_string(column.to_json(), sort_keys=True))


def do_parse_table(name, table_string, default_is_root_string='false'):
    default_is_root = default_is_root_string == 'true'
    table_json = unbox_json(ovs.json.from_string(table_string))
    table = ovs.db.schema.TableSchema.from_json(table_json, name)
    print(ovs.json.to_string(table.to_json(default_is_root), sort_keys=True))


def do_parse_schema(schema_string):
    schema_json = unbox_json(ovs.json.from_string(schema_string))
    schema = ovs.db.schema.DbSchema.from_json(schema_json)
    print(ovs.json.to_string(schema.to_json(), sort_keys=True))


def get_simple_printable_row_string(row, columns):
    s = ""
    for column in columns:
        if hasattr(row, column) and not (type(getattr(row, column))
                                         is ovs.db.data.Atom):
            value = getattr(row, column)
            if isinstance(value, dict):
                value = sorted(value.items())
            s += "%s=%s " % (column, value)
    s = s.strip()
    s = re.sub('""|,|u?\'', "", s)
    s = re.sub('UUID\(([^)]+)\)', r'\1', s)
    s = re.sub('False', 'false', s)
    s = re.sub('True', 'true', s)
    s = re.sub(r'(ba)=([^[][^ ]*) ', r'\1=[\2] ', s)
    return s


def get_simple_table_printable_row(row):
    simple_columns = ["i", "r", "b", "s", "u", "ia",
                      "ra", "ba", "sa", "ua", "uuid"]
    return get_simple_printable_row_string(row, simple_columns)


def get_simple2_table_printable_row(row):
    simple2_columns = ["name", "smap", "imap"]
    return get_simple_printable_row_string(row, simple2_columns)


def get_simple3_table_printable_row(row):
    simple3_columns = ["name", "uset"]
    return get_simple_printable_row_string(row, simple3_columns)


def print_idl(idl, step):
    n = 0
    if "simple" in idl.tables:
        simple = idl.tables["simple"].rows
        for row in six.itervalues(simple):
            s = "%03d: " % step
            s += get_simple_table_printable_row(row)
            print(s)
            n += 1

    if "simple2" in idl.tables:
        simple2 = idl.tables["simple2"].rows
        for row in six.itervalues(simple2):
            s = "%03d: " % step
            s += get_simple2_table_printable_row(row)
            print(s)
            n += 1

    if "simple3" in idl.tables:
        simple3 = idl.tables["simple3"].rows
        for row in six.itervalues(simple3):
            s = "%03d: " % step
            s += get_simple3_table_printable_row(row)
            print(s)
            n += 1

    if "link1" in idl.tables:
        l1 = idl.tables["link1"].rows
        for row in six.itervalues(l1):
            s = ["%03d: i=%s k=" % (step, row.i)]
            if hasattr(row, "k") and row.k:
                s.append(str(row.k.i))
            if hasattr(row, "ka"):
                s.append(" ka=[")
                s.append(' '.join(sorted(str(ka.i) for ka in row.ka)))
                s.append("] l2=")
            if hasattr(row, "l2") and row.l2:
                s.append(str(row.l2[0].i))
            if hasattr(row, "uuid"):
                s.append(" uuid=%s" % row.uuid)
            print(''.join(s))
            n += 1

    if "link2" in idl.tables:
        l2 = idl.tables["link2"].rows
        for row in six.itervalues(l2):
            s = ["%03d:" % step]
            s.append(" i=%s l1=" % row.i)
            if hasattr(row, "l1") and row.l1:
                s.append(str(row.l1[0].i))
            if hasattr(row, "uuid"):
                s.append(" uuid=%s" % row.uuid)
            print(''.join(s))
            n += 1

    if not n:
        print("%03d: empty" % step)
    sys.stdout.flush()


def substitute_uuids(json, symtab):
    if isinstance(json, six.string_types):
        symbol = symtab.get(json)
        if symbol:
            return str(symbol)
    elif type(json) == list:
        return [substitute_uuids(element, symtab) for element in json]
    elif type(json) == dict:
        d = {}
        for key, value in six.iteritems(json):
            d[key] = substitute_uuids(value, symtab)
        return d
    return json


def parse_uuids(json, symtab):
    if (isinstance(json, six.string_types)
            and ovs.ovsuuid.is_valid_string(json)):
        name = "#%d#" % len(symtab)
        sys.stderr.write("%s = %s\n" % (name, json))
        symtab[name] = json
    elif type(json) == list:
        for element in json:
            parse_uuids(element, symtab)
    elif type(json) == dict:
        for value in six.itervalues(json):
            parse_uuids(value, symtab)


def idltest_find_simple(idl, i):
    for row in six.itervalues(idl.tables["simple"].rows):
        if row.i == i:
            return row
    return None


def idltest_find_simple2(idl, i):
    for row in six.itervalues(idl.tables["simple2"].rows):
        if row.name == i:
            return row
    return None


def idltest_find_simple3(idl, i):
    for row in six.itervalues(idl.tables["simple3"].rows):
        if row.name == i:
            return row
    return None


def idl_set(idl, commands, step):
    txn = ovs.db.idl.Transaction(idl)
    increment = False
    fetch_cmds = []
    events = []
    for command in commands.split(','):
        words = command.split()
        name = words[0]
        args = words[1:]

        if name == "notifytest":
            name = args[0]
            args = args[1:]
            old_notify = idl.notify

            def notify(event, row, updates=None):
                if updates:
                    upcol = list(updates._data.keys())[0]
                else:
                    upcol = None
                events.append("%s|%s|%s" % (event, row.i, upcol))
                idl.notify = old_notify

            idl.notify = notify

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
                if six.PY2:
                    s.s = args[2].decode('utf-8')
                else:
                    s.s = args[2].encode(sys.getfilesystemencoding(),
                                         'surrogateescape') \
                                 .decode('utf-8', 'replace')
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
        elif name == "fetch":
            if len(args) != 2:
                sys.stderr.write('"fetch" command requires 2 argument\n')
                sys.exit(1)

            row = idltest_find_simple(idl, int(args[0]))
            if not row:
                sys.stderr.write('"fetch" command asks for nonexistent i=%d\n'
                                 % int(args[0]))
                sys.exit(1)

            column = args[1]
            row.fetch(column)
            fetch_cmds.append([row, column])
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
            print("%03d: destroy" % step)
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
        elif name == 'partialmapinsertelement':
            row = idltest_find_simple2(idl, 'myString1')
            len_smap = len(getattr(row, 'smap'))
            row.setkey('smap', 'key1', 'myList1')
            len_imap = len(getattr(row, 'imap'))
            row.setkey('imap', 3, 'myids2')
            row.__setattr__('name', 'String2')
            assert len(getattr(row, 'smap')) == len_smap
            assert len(getattr(row, 'imap')) == len_imap + 1
        elif name == 'partialmapinsertmultipleelements':
            row = idltest_find_simple2(idl, 'String2')
            len_smap = len(getattr(row, 'smap'))
            row.setkey('smap', 'key2', 'myList2')
            row.setkey('smap', 'key3', 'myList3')
            row.setkey('smap', 'key4', 'myList4')
            assert len(getattr(row, 'smap')) == len_smap + 2
        elif name == 'partialmapdelelements':
            row = idltest_find_simple2(idl, 'String2')
            len_smap = len(getattr(row, 'smap'))
            row.delkey('smap', 'key1', 'myList1')
            row.delkey('smap', 'key2', 'wrongvalue')
            row.delkey('smap', 'key3')
            row.delkey('smap', 'key4')
            assert len(getattr(row, 'smap')) == len_smap - 3
        elif name == 'partialmapmutatenew':
            new_row2 = txn.insert(idl.tables["simple2"])
            setattr(new_row2, 'name', 'String2New')
            new_row2.setkey('smap', 'key1', 'newList1')
            assert len(getattr(new_row2, 'smap')) == 1
            new_row2.setkey('smap', 'key2', 'newList2')
            assert len(getattr(new_row2, 'smap')) == 2
        elif name == 'partialrenamesetadd':
            row = idltest_find_simple3(idl, 'mySet1')
            old_size = len(getattr(row, 'uset', []))
            row.addvalue('uset',
                         uuid.UUID("001e43d2-dd3f-4616-ab6a-83a490bb0991"))
            row.__setattr__('name', 'String2')
            assert len(getattr(row, 'uset', [])) == old_size + 1
        elif name == 'partialduplicateadd':
            row = idltest_find_simple3(idl, 'String2')
            old_size = len(getattr(row, 'uset', []))
            row.addvalue('uset',
                         uuid.UUID("0026b3ba-571b-4729-8227-d860a5210ab8"))
            row.addvalue('uset',
                         uuid.UUID("0026b3ba-571b-4729-8227-d860a5210ab8"))
            assert len(getattr(row, 'uset', [])) == old_size + 1
        elif name == 'partialsetdel':
            row = idltest_find_simple3(idl, 'String2')
            old_size = len(getattr(row, 'uset', []))
            row.delvalue('uset',
                         uuid.UUID("001e43d2-dd3f-4616-ab6a-83a490bb0991"))
            assert len(getattr(row, 'uset', [])) == old_size - 1
        elif name == 'partialsetref':
            new_row = txn.insert(idl.tables["simple4"])
            new_row.__setattr__('name', 'test')
            row = idltest_find_simple3(idl, 'String2')
            old_size = len(getattr(row, 'uref', []))
            row.addvalue('uref', new_row.uuid)
            assert len(getattr(row, 'uref', [])) == old_size + 1
        elif name == 'partialsetoverrideops':
            row = idltest_find_simple3(idl, 'String2')
            row.addvalue('uset',
                         uuid.UUID("579e978d-776c-4f19-a225-268e5890e670"))
            row.delvalue('uset',
                         uuid.UUID("0026b3ba-571b-4729-8227-d860a5210ab8"))
            row.__setattr__('uset',
                [uuid.UUID("0026b3ba-571b-4729-8227-d860a5210ab8")])
            assert len(getattr(row, 'uset', [])) == 1
        elif name == 'partialsetadddelete':
            row = idltest_find_simple3(idl, 'String2')
            row.addvalue('uset',
                         uuid.UUID('b6272353-af9c-40b7-90fe-32a43e6518a1'))
            row.addvalue('uset',
                         uuid.UUID('1d6a71a2-dffb-426e-b2fa-b727091f9901'))
            row.delvalue('uset',
                         uuid.UUID('0026b3ba-571b-4729-8227-d860a5210ab8'))
            assert len(getattr(row, 'uset', [])) == 2
        elif name == 'partialsetmutatenew':
            new_row41 = txn.insert(idl.tables["simple4"])
            new_row41.__setattr__('name', 'new_row41')
            new_row3 = txn.insert(idl.tables["simple3"])
            setattr(new_row3, 'name', 'String3')
            new_row3.addvalue('uset', new_row41.uuid)
            assert len(getattr(new_row3, 'uset', [])) == 1
        else:
            sys.stderr.write("unknown command %s\n" % name)
            sys.exit(1)

    status = txn.commit_block()
    sys.stdout.write("%03d: commit, status=%s"
                     % (step, ovs.db.idl.Transaction.status_to_string(status)))
    if increment and status == ovs.db.idl.Transaction.SUCCESS:
        sys.stdout.write(", increment=%d" % txn.get_increment_new_value())
    if events:
        # Event notifications from operations in a single transaction are
        # not in a gauranteed order due to update messages being dicts
        sys.stdout.write(", events=" + ", ".join(sorted(events)))
    sys.stdout.write("\n")
    sys.stdout.flush()


def update_condition(idl, commands):
    commands = commands[len("condition "):].split(";")
    for command in commands:
        command = command.split(" ")
        if(len(command) != 2):
            sys.stderr.write("Error parsing condition %s\n" % command)
            sys.exit(1)

        table = command[0]
        cond = ovs.json.from_string(command[1])

        idl.cond_change(table, cond)


def do_idl(schema_file, remote, *commands):
    schema_helper = ovs.db.idl.SchemaHelper(schema_file)
    track_notify = False

    if remote.startswith("ssl:"):
        ovs.stream.Stream.ssl_set_private_key_file(commands[0])
        ovs.stream.Stream.ssl_set_certificate_file(commands[1])
        ovs.stream.Stream.ssl_set_ca_cert_file(commands[2])
        commands = commands[3:]

    if commands and commands[0] == "track-notify":
        commands = commands[1:]
        track_notify = True

    if commands and commands[0].startswith("?"):
        readonly = {}
        for x in commands[0][1:].split("?"):
            readonly = []
            table, columns = x.split(":")
            columns = columns.split(",")
            for index, column in enumerate(columns):
                if column[-1] == '!':
                    columns[index] = columns[index][:-1]
                    readonly.append(columns[index])
            schema_helper.register_columns(table, columns, readonly)
        commands = commands[1:]
    else:
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

    def mock_notify(event, row, updates=None):
        output = "%03d: " % step
        output += "event:" + str(event) + ", row={"
        output += get_simple_table_printable_row(row) + "}, updates="
        if updates is None:
            output += "None"
        else:
            output += "{" + get_simple_table_printable_row(updates) + "}"

        output += '\n'
        sys.stdout.write(output)
        sys.stdout.flush()

    if track_notify and "simple" in idl.tables:
        idl.notify = mock_notify

    commands = list(commands)
    if len(commands) >= 1 and "condition" in commands[0]:
        update_condition(idl, commands.pop(0))
        sys.stdout.write("%03d: change conditions\n" % step)
        sys.stdout.flush()
        step += 1

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
        elif "condition" in command:
            update_condition(idl, command)
            sys.stdout.write("%03d: change conditions\n" % step)
            sys.stdout.flush()
            step += 1
        elif not command.startswith("["):
            idl_set(idl, command, step)
            step += 1
        else:
            json = ovs.json.from_string(command)
            if isinstance(json, six.string_types):
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


def do_idl_passive(schema_file, remote, *commands):
    symtab = {}
    step = 0
    schema_helper = ovs.db.idl.SchemaHelper(schema_file)
    schema_helper.register_all()
    idl = ovs.db.idl.Idl(remote, schema_helper)

    while idl._session.rpc is None:
        idl.run()

    rpc = idl._session.rpc

    print_idl(idl, step)
    step += 1

    for command in commands:
        json = ovs.json.from_string(command)
        if isinstance(json, six.string_types):
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

    idl.close()
    print("%03d: done" % step)


def usage():
    print("""\
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
idl SCHEMA SERVER [?T1:C1,C2...[?T2:C1,C2,...]...] [TRANSACTION...]
  connect to SERVER (which has the specified SCHEMA) and dump the
  contents of the database as seen initially by the IDL implementation
  and after executing each TRANSACTION.  (Each TRANSACTION must modify
  the database or this command will hang.)
  By default, all columns of all tables are monitored. The "?" option
  can be used to monitor specific Table:Column(s). The table and their
  columns are listed as a string of the form starting with "?":
      ?<table-name>:<column-name>,<column-name>,...
  e.g.:
      ?simple:b - Monitor column "b" in table "simple"
  Entries for multiple tables are seperated by "?":
      ?<table-name>:<column-name>,...?<table-name>:<column-name>,...
  e.g.:
      ?simple:b?link1:i,k - Monitor column "b" in table "simple",
                            and column "i", "k" in table "link1"
  Readonly columns: Suffixing a "!" after a column indicates that the
  column is to be registered "readonly".
  e.g.:
      ?simple:i,b!  - Register interest in column "i" (monitoring) and
                      column "b" (readonly).


The following options are also available:
  -t, --timeout=SECS          give up after SECS seconds
  -h, --help                  display this help message\
""" % {'program_name': ovs.util.PROGRAM_NAME})
    sys.exit(0)


def main(argv):
    try:
        options, args = getopt.gnu_getopt(argv[1:], 't:h',
                                          ['timeout',
                                           'help'])
    except getopt.GetoptError as geo:
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
            signal_alarm(timeout)
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
                "idl": (do_idl, (2,)),
                "idl_passive": (do_idl_passive, (2,))}

    command_name = args[0]
    args = args[1:]
    if command_name not in commands:
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
    except error.Error as e:
        sys.stderr.write("%s\n" % e)
        sys.exit(1)

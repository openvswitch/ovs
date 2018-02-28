# Copyright (c) 2009, 2010, 2011, 2012, 2013, 2016 Nicira, Inc.
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
import uuid

import ovs.db.data as data
import ovs.db.parser
import ovs.db.schema
import ovs.jsonrpc
import ovs.ovsuuid
import ovs.poller
import ovs.vlog
from ovs.db import error

import six

vlog = ovs.vlog.Vlog("idl")

__pychecker__ = 'no-classattr no-objattrs'

ROW_CREATE = "create"
ROW_UPDATE = "update"
ROW_DELETE = "delete"

OVSDB_UPDATE = 0
OVSDB_UPDATE2 = 1


class Idl(object):
    """Open vSwitch Database Interface Definition Language (OVSDB IDL).

    The OVSDB IDL maintains an in-memory replica of a database.  It issues RPC
    requests to an OVSDB database server and parses the responses, converting
    raw JSON into data structures that are easier for clients to digest.

    The IDL also assists with issuing database transactions.  The client
    creates a transaction, manipulates the IDL data structures, and commits or
    aborts the transaction.  The IDL then composes and issues the necessary
    JSON-RPC requests and reports to the client whether the transaction
    completed successfully.

    The client is allowed to access the following attributes directly, in a
    read-only fashion:

    - 'tables': This is the 'tables' map in the ovs.db.schema.DbSchema provided
      to the Idl constructor.  Each ovs.db.schema.TableSchema in the map is
      annotated with a new attribute 'rows', which is a dict from a uuid.UUID
      to a Row object.

      The client may directly read and write the Row objects referenced by the
      'rows' map values.  Refer to Row for more details.

    - 'change_seqno': A number that represents the IDL's state.  When the IDL
      is updated (by Idl.run()), its value changes.  The sequence number can
      occasionally change even if the database does not.  This happens if the
      connection to the database drops and reconnects, which causes the
      database contents to be reloaded even if they didn't change.  (It could
      also happen if the database server sends out a "change" that reflects
      what the IDL already thought was in the database.  The database server is
      not supposed to do that, but bugs could in theory cause it to do so.)

    - 'lock_name': The name of the lock configured with Idl.set_lock(), or None
      if no lock is configured.

    - 'has_lock': True, if the IDL is configured to obtain a lock and owns that
      lock, and False otherwise.

      Locking and unlocking happens asynchronously from the database client's
      point of view, so the information is only useful for optimization
      (e.g. if the client doesn't have the lock then there's no point in trying
      to write to the database).

    - 'is_lock_contended': True, if the IDL is configured to obtain a lock but
      the database server has indicated that some other client already owns the
      requested lock, and False otherwise.

    - 'txn': The ovs.db.idl.Transaction object for the database transaction
      currently being constructed, if there is one, or None otherwise.
"""

    IDL_S_INITIAL = 0
    IDL_S_MONITOR_REQUESTED = 1
    IDL_S_MONITOR_COND_REQUESTED = 2

    def __init__(self, remote, schema, probe_interval=None):
        """Creates and returns a connection to the database named 'db_name' on
        'remote', which should be in a form acceptable to
        ovs.jsonrpc.session.open().  The connection will maintain an in-memory
        replica of the remote database.

        'schema' should be the schema for the remote database.  The caller may
        have cut it down by removing tables or columns that are not of
        interest.  The IDL will only replicate the tables and columns that
        remain.  The caller may also add a attribute named 'alert' to selected
        remaining columns, setting its value to False; if so, then changes to
        those columns will not be considered changes to the database for the
        purpose of the return value of Idl.run() and Idl.change_seqno.  This is
        useful for columns that the IDL's client will write but not read.

        As a convenience to users, 'schema' may also be an instance of the
        SchemaHelper class.

        The IDL uses and modifies 'schema' directly.

        If "probe_interval" is zero it disables the connection keepalive
        feature. If non-zero the value will be forced to at least 1000
        milliseconds. If None it will just use the default value in OVS.
        """

        assert isinstance(schema, SchemaHelper)
        schema = schema.get_idl_schema()

        self.tables = schema.tables
        self.readonly = schema.readonly
        self._db = schema
        self._session = ovs.jsonrpc.Session.open(remote,
            probe_interval=probe_interval)
        self._monitor_request_id = None
        self._last_seqno = None
        self.change_seqno = 0
        self.uuid = uuid.uuid1()
        self.state = self.IDL_S_INITIAL

        # Database locking.
        self.lock_name = None          # Name of lock we need, None if none.
        self.has_lock = False          # Has db server said we have the lock?
        self.is_lock_contended = False  # Has db server said we can't get lock?
        self._lock_request_id = None   # JSON-RPC ID of in-flight lock request.

        # Transaction support.
        self.txn = None
        self._outstanding_txns = {}

        for table in six.itervalues(schema.tables):
            for column in six.itervalues(table.columns):
                if not hasattr(column, 'alert'):
                    column.alert = True
            table.need_table = False
            table.rows = {}
            table.idl = self
            table.condition = [True]
            table.cond_changed = False

    def close(self):
        """Closes the connection to the database.  The IDL will no longer
        update."""
        self._session.close()

    def run(self):
        """Processes a batch of messages from the database server.  Returns
        True if the database as seen through the IDL changed, False if it did
        not change.  The initial fetch of the entire contents of the remote
        database is considered to be one kind of change.  If the IDL has been
        configured to acquire a database lock (with Idl.set_lock()), then
        successfully acquiring the lock is also considered to be a change.

        This function can return occasional false positives, that is, report
        that the database changed even though it didn't.  This happens if the
        connection to the database drops and reconnects, which causes the
        database contents to be reloaded even if they didn't change.  (It could
        also happen if the database server sends out a "change" that reflects
        what we already thought was in the database, but the database server is
        not supposed to do that.)

        As an alternative to checking the return value, the client may check
        for changes in self.change_seqno."""
        assert not self.txn
        initial_change_seqno = self.change_seqno

        self.send_cond_change()
        self._session.run()
        i = 0
        while i < 50:
            i += 1
            if not self._session.is_connected():
                break

            seqno = self._session.get_seqno()
            if seqno != self._last_seqno:
                self._last_seqno = seqno
                self.__txn_abort_all()
                self.__send_monitor_request()
                if self.lock_name:
                    self.__send_lock_request()
                break

            msg = self._session.recv()
            if msg is None:
                break
            if (msg.type == ovs.jsonrpc.Message.T_NOTIFY
                    and msg.method == "update2"
                    and len(msg.params) == 2):
                # Database contents changed.
                self.__parse_update(msg.params[1], OVSDB_UPDATE2)
            elif (msg.type == ovs.jsonrpc.Message.T_NOTIFY
                    and msg.method == "update"
                    and len(msg.params) == 2):
                # Database contents changed.
                self.__parse_update(msg.params[1], OVSDB_UPDATE)
            elif (msg.type == ovs.jsonrpc.Message.T_REPLY
                  and self._monitor_request_id is not None
                  and self._monitor_request_id == msg.id):
                # Reply to our "monitor" request.
                try:
                    self.change_seqno += 1
                    self._monitor_request_id = None
                    self.__clear()
                    if self.state == self.IDL_S_MONITOR_COND_REQUESTED:
                        self.__parse_update(msg.result, OVSDB_UPDATE2)
                    else:
                        assert self.state == self.IDL_S_MONITOR_REQUESTED
                        self.__parse_update(msg.result, OVSDB_UPDATE)

                except error.Error as e:
                    vlog.err("%s: parse error in received schema: %s"
                             % (self._session.get_name(), e))
                    self.__error()
            elif (msg.type == ovs.jsonrpc.Message.T_REPLY
                  and self._lock_request_id is not None
                  and self._lock_request_id == msg.id):
                # Reply to our "lock" request.
                self.__parse_lock_reply(msg.result)
            elif (msg.type == ovs.jsonrpc.Message.T_NOTIFY
                  and msg.method == "locked"):
                # We got our lock.
                self.__parse_lock_notify(msg.params, True)
            elif (msg.type == ovs.jsonrpc.Message.T_NOTIFY
                  and msg.method == "stolen"):
                # Someone else stole our lock.
                self.__parse_lock_notify(msg.params, False)
            elif msg.type == ovs.jsonrpc.Message.T_NOTIFY and msg.id == "echo":
                # Reply to our echo request.  Ignore it.
                pass
            elif (msg.type == ovs.jsonrpc.Message.T_ERROR and
                  self.state == self.IDL_S_MONITOR_COND_REQUESTED and
                  self._monitor_request_id == msg.id):
                if msg.error == "unknown method":
                    self.__send_monitor_request()
            elif (msg.type in (ovs.jsonrpc.Message.T_ERROR,
                               ovs.jsonrpc.Message.T_REPLY)
                  and self.__txn_process_reply(msg)):
                # __txn_process_reply() did everything needed.
                pass
            else:
                # This can happen if a transaction is destroyed before we
                # receive the reply, so keep the log level low.
                vlog.dbg("%s: received unexpected %s message"
                         % (self._session.get_name(),
                             ovs.jsonrpc.Message.type_to_string(msg.type)))

        return initial_change_seqno != self.change_seqno

    def send_cond_change(self):
        if not self._session.is_connected():
            return

        for table in six.itervalues(self.tables):
            if table.cond_changed:
                self.__send_cond_change(table, table.condition)
                table.cond_changed = False

    def cond_change(self, table_name, cond):
        """Sets the condition for 'table_name' to 'cond', which should be a
        conditional expression suitable for use directly in the OVSDB
        protocol, with the exception that the empty condition []
        matches no rows (instead of matching every row).  That is, []
        is equivalent to [False], not to [True].
        """

        table = self.tables.get(table_name)
        if not table:
            raise error.Error('Unknown table "%s"' % table_name)

        if cond == []:
            cond = [False]
        if table.condition != cond:
            table.condition = cond
            table.cond_changed = True

    def wait(self, poller):
        """Arranges for poller.block() to wake up when self.run() has something
        to do or when activity occurs on a transaction on 'self'."""
        self._session.wait(poller)
        self._session.recv_wait(poller)

    def has_ever_connected(self):
        """Returns True, if the IDL successfully connected to the remote
        database and retrieved its contents (even if the connection
        subsequently dropped and is in the process of reconnecting).  If so,
        then the IDL contains an atomic snapshot of the database's contents
        (but it might be arbitrarily old if the connection dropped).

        Returns False if the IDL has never connected or retrieved the
        database's contents.  If so, the IDL is empty."""
        return self.change_seqno != 0

    def force_reconnect(self):
        """Forces the IDL to drop its connection to the database and reconnect.
        In the meantime, the contents of the IDL will not change."""
        self._session.force_reconnect()

    def set_lock(self, lock_name):
        """If 'lock_name' is not None, configures the IDL to obtain the named
        lock from the database server and to avoid modifying the database when
        the lock cannot be acquired (that is, when another client has the same
        lock).

        If 'lock_name' is None, drops the locking requirement and releases the
        lock."""
        assert not self.txn
        assert not self._outstanding_txns

        if self.lock_name and (not lock_name or lock_name != self.lock_name):
            # Release previous lock.
            self.__send_unlock_request()
            self.lock_name = None
            self.is_lock_contended = False

        if lock_name and not self.lock_name:
            # Acquire new lock.
            self.lock_name = lock_name
            self.__send_lock_request()

    def notify(self, event, row, updates=None):
        """Hook for implementing create/update/delete notifications

        :param event:   The event that was triggered
        :type event:    ROW_CREATE, ROW_UPDATE, or ROW_DELETE
        :param row:     The row as it is after the operation has occured
        :type row:      Row
        :param updates: For updates, row with only old values of the changed
                        columns
        :type updates:  Row
        """

    def __send_cond_change(self, table, cond):
        monitor_cond_change = {table.name: [{"where": cond}]}
        old_uuid = str(self.uuid)
        self.uuid = uuid.uuid1()
        params = [old_uuid, str(self.uuid), monitor_cond_change]
        msg = ovs.jsonrpc.Message.create_request("monitor_cond_change", params)
        self._session.send(msg)

    def __clear(self):
        changed = False

        for table in six.itervalues(self.tables):
            if table.rows:
                changed = True
                table.rows = {}

        if changed:
            self.change_seqno += 1

    def __update_has_lock(self, new_has_lock):
        if new_has_lock and not self.has_lock:
            if self._monitor_request_id is None:
                self.change_seqno += 1
            else:
                # We're waiting for a monitor reply, so don't signal that the
                # database changed.  The monitor reply will increment
                # change_seqno anyhow.
                pass
            self.is_lock_contended = False
        self.has_lock = new_has_lock

    def __do_send_lock_request(self, method):
        self.__update_has_lock(False)
        self._lock_request_id = None
        if self._session.is_connected():
            msg = ovs.jsonrpc.Message.create_request(method, [self.lock_name])
            msg_id = msg.id
            self._session.send(msg)
        else:
            msg_id = None
        return msg_id

    def __send_lock_request(self):
        self._lock_request_id = self.__do_send_lock_request("lock")

    def __send_unlock_request(self):
        self.__do_send_lock_request("unlock")

    def __parse_lock_reply(self, result):
        self._lock_request_id = None
        got_lock = isinstance(result, dict) and result.get("locked") is True
        self.__update_has_lock(got_lock)
        if not got_lock:
            self.is_lock_contended = True

    def __parse_lock_notify(self, params, new_has_lock):
        if (self.lock_name is not None
            and isinstance(params, (list, tuple))
            and params
            and params[0] == self.lock_name):
            self.__update_has_lock(new_has_lock)
            if not new_has_lock:
                self.is_lock_contended = True

    def __send_monitor_request(self):
        if self.state == self.IDL_S_INITIAL:
            self.state = self.IDL_S_MONITOR_COND_REQUESTED
            method = "monitor_cond"
        else:
            self.state = self.IDL_S_MONITOR_REQUESTED
            method = "monitor"

        monitor_requests = {}
        for table in six.itervalues(self.tables):
            columns = []
            for column in six.iterkeys(table.columns):
                if ((table.name not in self.readonly) or
                        (table.name in self.readonly) and
                        (column not in self.readonly[table.name])):
                    columns.append(column)
            monitor_requests[table.name] = {"columns": columns}
            if method == "monitor_cond" and table.condition != [True]:
                monitor_requests[table.name]["where"] = table.condition
                table.cond_change = False

        msg = ovs.jsonrpc.Message.create_request(
            method, [self._db.name, str(self.uuid), monitor_requests])
        self._monitor_request_id = msg.id
        self._session.send(msg)

    def __parse_update(self, update, version):
        try:
            self.__do_parse_update(update, version)
        except error.Error as e:
            vlog.err("%s: error parsing update: %s"
                     % (self._session.get_name(), e))

    def __do_parse_update(self, table_updates, version):
        if not isinstance(table_updates, dict):
            raise error.Error("<table-updates> is not an object",
                              table_updates)

        for table_name, table_update in six.iteritems(table_updates):
            table = self.tables.get(table_name)
            if not table:
                raise error.Error('<table-updates> includes unknown '
                                  'table "%s"' % table_name)

            if not isinstance(table_update, dict):
                raise error.Error('<table-update> for table "%s" is not '
                                  'an object' % table_name, table_update)

            for uuid_string, row_update in six.iteritems(table_update):
                if not ovs.ovsuuid.is_valid_string(uuid_string):
                    raise error.Error('<table-update> for table "%s" '
                                      'contains bad UUID "%s" as member '
                                      'name' % (table_name, uuid_string),
                                      table_update)
                uuid = ovs.ovsuuid.from_string(uuid_string)

                if not isinstance(row_update, dict):
                    raise error.Error('<table-update> for table "%s" '
                                      'contains <row-update> for %s that '
                                      'is not an object'
                                      % (table_name, uuid_string))

                if version == OVSDB_UPDATE2:
                    if self.__process_update2(table, uuid, row_update):
                        self.change_seqno += 1
                    continue

                parser = ovs.db.parser.Parser(row_update, "row-update")
                old = parser.get_optional("old", [dict])
                new = parser.get_optional("new", [dict])
                parser.finish()

                if not old and not new:
                    raise error.Error('<row-update> missing "old" and '
                                      '"new" members', row_update)

                if self.__process_update(table, uuid, old, new):
                    self.change_seqno += 1

    def __process_update2(self, table, uuid, row_update):
        row = table.rows.get(uuid)
        changed = False
        if "delete" in row_update:
            if row:
                del table.rows[uuid]
                self.notify(ROW_DELETE, row)
                changed = True
            else:
                # XXX rate-limit
                vlog.warn("cannot delete missing row %s from table"
                          "%s" % (uuid, table.name))
        elif "insert" in row_update or "initial" in row_update:
            if row:
                vlog.warn("cannot add existing row %s from table"
                          " %s" % (uuid, table.name))
                del table.rows[uuid]
            row = self.__create_row(table, uuid)
            if "insert" in row_update:
                row_update = row_update['insert']
            else:
                row_update = row_update['initial']
            self.__add_default(table, row_update)
            if self.__row_update(table, row, row_update):
                changed = True
                self.notify(ROW_CREATE, row)
        elif "modify" in row_update:
            if not row:
                raise error.Error('Modify non-existing row')

            old_row = self.__apply_diff(table, row, row_update['modify'])
            self.notify(ROW_UPDATE, row, Row(self, table, uuid, old_row))
            changed = True
        else:
            raise error.Error('<row-update> unknown operation',
                              row_update)
        return changed

    def __process_update(self, table, uuid, old, new):
        """Returns True if a column changed, False otherwise."""
        row = table.rows.get(uuid)
        changed = False
        if not new:
            # Delete row.
            if row:
                del table.rows[uuid]
                changed = True
                self.notify(ROW_DELETE, row)
            else:
                # XXX rate-limit
                vlog.warn("cannot delete missing row %s from table %s"
                          % (uuid, table.name))
        elif not old:
            # Insert row.
            if not row:
                row = self.__create_row(table, uuid)
                changed = True
            else:
                # XXX rate-limit
                vlog.warn("cannot add existing row %s to table %s"
                          % (uuid, table.name))
            if self.__row_update(table, row, new):
                changed = True
                self.notify(ROW_CREATE, row)
        else:
            op = ROW_UPDATE
            if not row:
                row = self.__create_row(table, uuid)
                changed = True
                op = ROW_CREATE
                # XXX rate-limit
                vlog.warn("cannot modify missing row %s in table %s"
                          % (uuid, table.name))
            if self.__row_update(table, row, new):
                changed = True
                self.notify(op, row, Row.from_json(self, table, uuid, old))
        return changed

    def __column_name(self, column):
        if column.type.key.type == ovs.db.types.UuidType:
            return ovs.ovsuuid.to_json(column.type.key.type.default)
        else:
            return column.type.key.type.default

    def __add_default(self, table, row_update):
        for column in six.itervalues(table.columns):
            if column.name not in row_update:
                if ((table.name not in self.readonly) or
                        (table.name in self.readonly) and
                        (column.name not in self.readonly[table.name])):
                    if column.type.n_min != 0 and not column.type.is_map():
                        row_update[column.name] = self.__column_name(column)

    def __apply_diff(self, table, row, row_diff):
        old_row = {}
        for column_name, datum_diff_json in six.iteritems(row_diff):
            column = table.columns.get(column_name)
            if not column:
                # XXX rate-limit
                vlog.warn("unknown column %s updating table %s"
                          % (column_name, table.name))
                continue

            try:
                datum_diff = data.Datum.from_json(column.type, datum_diff_json)
            except error.Error as e:
                # XXX rate-limit
                vlog.warn("error parsing column %s in table %s: %s"
                          % (column_name, table.name, e))
                continue

            old_row[column_name] = row._data[column_name].copy()
            datum = row._data[column_name].diff(datum_diff)
            if datum != row._data[column_name]:
                row._data[column_name] = datum

        return old_row

    def __row_update(self, table, row, row_json):
        changed = False
        for column_name, datum_json in six.iteritems(row_json):
            column = table.columns.get(column_name)
            if not column:
                # XXX rate-limit
                vlog.warn("unknown column %s updating table %s"
                          % (column_name, table.name))
                continue

            try:
                datum = data.Datum.from_json(column.type, datum_json)
            except error.Error as e:
                # XXX rate-limit
                vlog.warn("error parsing column %s in table %s: %s"
                          % (column_name, table.name, e))
                continue

            if datum != row._data[column_name]:
                row._data[column_name] = datum
                if column.alert:
                    changed = True
            else:
                # Didn't really change but the OVSDB monitor protocol always
                # includes every value in a row.
                pass
        return changed

    def __create_row(self, table, uuid):
        data = {}
        for column in six.itervalues(table.columns):
            data[column.name] = ovs.db.data.Datum.default(column.type)
        row = table.rows[uuid] = Row(self, table, uuid, data)
        return row

    def __error(self):
        self._session.force_reconnect()

    def __txn_abort_all(self):
        while self._outstanding_txns:
            txn = self._outstanding_txns.popitem()[1]
            txn._status = Transaction.TRY_AGAIN

    def __txn_process_reply(self, msg):
        txn = self._outstanding_txns.pop(msg.id, None)
        if txn:
            txn._process_reply(msg)
            return True


def _uuid_to_row(atom, base):
    if base.ref_table:
        return base.ref_table.rows.get(atom)
    else:
        return atom


def _row_to_uuid(value):
    if isinstance(value, Row):
        return value.uuid
    else:
        return value


@functools.total_ordering
class Row(object):
    """A row within an IDL.

    The client may access the following attributes directly:

    - 'uuid': a uuid.UUID object whose value is the row's database UUID.

    - An attribute for each column in the Row's table, named for the column,
      whose values are as returned by Datum.to_python() for the column's type.

      If some error occurs (e.g. the database server's idea of the column is
      different from the IDL's idea), then the attribute values is the
      "default" value return by Datum.default() for the column's type.  (It is
      important to know this because the default value may violate constraints
      for the column's type, e.g. the default integer value is 0 even if column
      contraints require the column's value to be positive.)

      When a transaction is active, column attributes may also be assigned new
      values.  Committing the transaction will then cause the new value to be
      stored into the database.

      *NOTE*: In the current implementation, the value of a column is a *copy*
      of the value in the database.  This means that modifying its value
      directly will have no useful effect.  For example, the following:
        row.mycolumn["a"] = "b"              # don't do this
      will not change anything in the database, even after commit.  To modify
      the column, instead assign the modified column value back to the column:
        d = row.mycolumn
        d["a"] = "b"
        row.mycolumn = d
"""
    def __init__(self, idl, table, uuid, data):
        # All of the explicit references to self.__dict__ below are required
        # to set real attributes with invoking self.__getattr__().
        self.__dict__["uuid"] = uuid

        self.__dict__["_idl"] = idl
        self.__dict__["_table"] = table

        # _data is the committed data.  It takes the following values:
        #
        #   - A dictionary that maps every column name to a Datum, if the row
        #     exists in the committed form of the database.
        #
        #   - None, if this row is newly inserted within the active transaction
        #     and thus has no committed form.
        self.__dict__["_data"] = data

        # _changes describes changes to this row within the active transaction.
        # It takes the following values:
        #
        #   - {}, the empty dictionary, if no transaction is active or if the
        #     row has yet not been changed within this transaction.
        #
        #   - A dictionary that maps a column name to its new Datum, if an
        #     active transaction changes those columns' values.
        #
        #   - A dictionary that maps every column name to a Datum, if the row
        #     is newly inserted within the active transaction.
        #
        #   - None, if this transaction deletes this row.
        self.__dict__["_changes"] = {}

        # _mutations describes changes to this row to be handled via a
        # mutate operation on the wire.  It takes the following values:
        #
        #   - {}, the empty dictionary, if no transaction is active or if the
        #     row has yet not been mutated within this transaction.
        #
        #   - A dictionary that contains two keys:
        #
        #     - "_inserts" contains a dictionary that maps column names to
        #       new keys/key-value pairs that should be inserted into the
        #       column
        #     - "_removes" contains a dictionary that maps column names to
        #       the keys/key-value pairs that should be removed from the
        #       column
        #
        #   - None, if this transaction deletes this row.
        self.__dict__["_mutations"] = {}

        # A dictionary whose keys are the names of columns that must be
        # verified as prerequisites when the transaction commits.  The values
        # in the dictionary are all None.
        self.__dict__["_prereqs"] = {}

    def __lt__(self, other):
        if not isinstance(other, Row):
            return NotImplemented
        return bool(self.__dict__['uuid'] < other.__dict__['uuid'])

    def __eq__(self, other):
        if not isinstance(other, Row):
            return NotImplemented
        return bool(self.__dict__['uuid'] == other.__dict__['uuid'])

    def __hash__(self):
        return int(self.__dict__['uuid'])

    def __getattr__(self, column_name):
        assert self._changes is not None
        assert self._mutations is not None

        column = self._table.columns[column_name]
        datum = self._changes.get(column_name)
        inserts = None
        if '_inserts' in self._mutations.keys():
            inserts = self._mutations['_inserts'].get(column_name)
        removes = None
        if '_removes' in self._mutations.keys():
            removes = self._mutations['_removes'].get(column_name)
        if datum is None:
            if self._data is None:
                if inserts is None:
                    raise AttributeError("%s instance has no attribute '%s'" %
                                         (self.__class__.__name__,
                                          column_name))
                else:
                    datum = data.Datum.from_python(column.type,
                                                   inserts,
                                                   _row_to_uuid)
            elif column_name in self._data:
                datum = self._data[column_name]
                if column.type.is_set():
                    dlist = datum.as_list()
                    if inserts is not None:
                        dlist.extend(list(inserts))
                    if removes is not None:
                        removes_datum = data.Datum.from_python(column.type,
                                                              removes,
                                                              _row_to_uuid)
                        removes_list = removes_datum.as_list()
                        dlist = [x for x in dlist if x not in removes_list]
                    datum = data.Datum.from_python(column.type, dlist,
                                                   _row_to_uuid)
                elif column.type.is_map():
                    dmap = datum.to_python(_uuid_to_row)
                    if inserts is not None:
                        dmap.update(inserts)
                    if removes is not None:
                        for key in removes:
                            if key not in (inserts or {}):
                                del dmap[key]
                    datum = data.Datum.from_python(column.type, dmap,
                                                   _row_to_uuid)
            else:
                if inserts is None:
                    raise AttributeError("%s instance has no attribute '%s'" %
                                         (self.__class__.__name__,
                                          column_name))
                else:
                    datum = inserts

        return datum.to_python(_uuid_to_row)

    def __setattr__(self, column_name, value):
        assert self._changes is not None
        assert self._idl.txn

        if ((self._table.name in self._idl.readonly) and
                (column_name in self._idl.readonly[self._table.name])):
            vlog.warn("attempting to write to readonly column %s"
                      % column_name)
            return

        column = self._table.columns[column_name]
        try:
            datum = data.Datum.from_python(column.type, value, _row_to_uuid)
        except error.Error as e:
            # XXX rate-limit
            vlog.err("attempting to write bad value to column %s (%s)"
                     % (column_name, e))
            return
        self._idl.txn._write(self, column, datum)

    def addvalue(self, column_name, key):
        self._idl.txn._txn_rows[self.uuid] = self
        column = self._table.columns[column_name]
        try:
            data.Datum.from_python(column.type, key, _row_to_uuid)
        except error.Error as e:
            # XXX rate-limit
            vlog.err("attempting to write bad value to column %s (%s)"
                     % (column_name, e))
            return
        inserts = self._mutations.setdefault('_inserts', {})
        column_value = inserts.setdefault(column_name, set())
        column_value.add(key)

    def delvalue(self, column_name, key):
        self._idl.txn._txn_rows[self.uuid] = self
        column = self._table.columns[column_name]
        try:
            data.Datum.from_python(column.type, key, _row_to_uuid)
        except error.Error as e:
            # XXX rate-limit
            vlog.err("attempting to delete bad value from column %s (%s)"
                     % (column_name, e))
            return
        removes = self._mutations.setdefault('_removes', {})
        column_value = removes.setdefault(column_name, set())
        column_value.add(key)

    def setkey(self, column_name, key, value):
        self._idl.txn._txn_rows[self.uuid] = self
        column = self._table.columns[column_name]
        try:
            data.Datum.from_python(column.type, {key: value}, _row_to_uuid)
        except error.Error as e:
            # XXX rate-limit
            vlog.err("attempting to write bad value to column %s (%s)"
                     % (column_name, e))
            return
        if self._data and column_name in self._data:
            # Remove existing key/value before updating.
            removes = self._mutations.setdefault('_removes', {})
            column_value = removes.setdefault(column_name, set())
            column_value.add(key)
        inserts = self._mutations.setdefault('_inserts', {})
        column_value = inserts.setdefault(column_name, {})
        column_value[key] = value

    def delkey(self, column_name, key, value=None):
        self._idl.txn._txn_rows[self.uuid] = self
        if value:
            try:
                old_value = data.Datum.to_python(self._data[column_name],
                                                 _uuid_to_row)
            except error.Error:
                return
            if key not in old_value:
                return
            if old_value[key] != value:
                return
        removes = self._mutations.setdefault('_removes', {})
        column_value = removes.setdefault(column_name, set())
        column_value.add(key)
        return

    @classmethod
    def from_json(cls, idl, table, uuid, row_json):
        data = {}
        for column_name, datum_json in six.iteritems(row_json):
            column = table.columns.get(column_name)
            if not column:
                # XXX rate-limit
                vlog.warn("unknown column %s in table %s"
                          % (column_name, table.name))
                continue
            try:
                datum = ovs.db.data.Datum.from_json(column.type, datum_json)
            except error.Error as e:
                # XXX rate-limit
                vlog.warn("error parsing column %s in table %s: %s"
                          % (column_name, table.name, e))
                continue
            data[column_name] = datum
        return cls(idl, table, uuid, data)

    def verify(self, column_name):
        """Causes the original contents of column 'column_name' in this row to
        be verified as a prerequisite to completing the transaction.  That is,
        if 'column_name' changed in this row (or if this row was deleted)
        between the time that the IDL originally read its contents and the time
        that the transaction commits, then the transaction aborts and
        Transaction.commit() returns Transaction.TRY_AGAIN.

        The intention is that, to ensure that no transaction commits based on
        dirty reads, an application should call Row.verify() on each data item
        read as part of a read-modify-write operation.

        In some cases Row.verify() reduces to a no-op, because the current
        value of the column is already known:

          - If this row is a row created by the current transaction (returned
            by Transaction.insert()).

          - If the column has already been modified within the current
            transaction.

        Because of the latter property, always call Row.verify() *before*
        modifying the column, for a given read-modify-write.

        A transaction must be in progress."""
        assert self._idl.txn
        assert self._changes is not None
        if not self._data or column_name in self._changes:
            return

        self._prereqs[column_name] = None

    def delete(self):
        """Deletes this row from its table.

        A transaction must be in progress."""
        assert self._idl.txn
        assert self._changes is not None
        if self._data is None:
            del self._idl.txn._txn_rows[self.uuid]
        else:
            self._idl.txn._txn_rows[self.uuid] = self
        self.__dict__["_changes"] = None
        del self._table.rows[self.uuid]

    def fetch(self, column_name):
        self._idl.txn._fetch(self, column_name)

    def increment(self, column_name):
        """Causes the transaction, when committed, to increment the value of
        'column_name' within this row by 1.  'column_name' must have an integer
        type.  After the transaction commits successfully, the client may
        retrieve the final (incremented) value of 'column_name' with
        Transaction.get_increment_new_value().

        The client could accomplish something similar by reading and writing
        and verify()ing columns.  However, increment() will never (by itself)
        cause a transaction to fail because of a verify error.

        The intended use is for incrementing the "next_cfg" column in
        the Open_vSwitch table."""
        self._idl.txn._increment(self, column_name)


def _uuid_name_from_uuid(uuid):
    return "row%s" % str(uuid).replace("-", "_")


def _where_uuid_equals(uuid):
    return [["_uuid", "==", ["uuid", str(uuid)]]]


class _InsertedRow(object):
    def __init__(self, op_index):
        self.op_index = op_index
        self.real = None


class Transaction(object):
    """A transaction may modify the contents of a database by modifying the
    values of columns, deleting rows, inserting rows, or adding checks that
    columns in the database have not changed ("verify" operations), through
    Row methods.

    Reading and writing columns and inserting and deleting rows are all
    straightforward.  The reasons to verify columns are less obvious.
    Verification is the key to maintaining transactional integrity.  Because
    OVSDB handles multiple clients, it can happen that between the time that
    OVSDB client A reads a column and writes a new value, OVSDB client B has
    written that column.  Client A's write should not ordinarily overwrite
    client B's, especially if the column in question is a "map" column that
    contains several more or less independent data items.  If client A adds a
    "verify" operation before it writes the column, then the transaction fails
    in case client B modifies it first.  Client A will then see the new value
    of the column and compose a new transaction based on the new contents
    written by client B.

    When a transaction is complete, which must be before the next call to
    Idl.run(), call Transaction.commit() or Transaction.abort().

    The life-cycle of a transaction looks like this:

    1. Create the transaction and record the initial sequence number:

        seqno = idl.change_seqno(idl)
        txn = Transaction(idl)

    2. Modify the database with Row and Transaction methods.

    3. Commit the transaction by calling Transaction.commit().  The first call
       to this function probably returns Transaction.INCOMPLETE.  The client
       must keep calling again along as this remains true, calling Idl.run() in
       between to let the IDL do protocol processing.  (If the client doesn't
       have anything else to do in the meantime, it can use
       Transaction.commit_block() to avoid having to loop itself.)

    4. If the final status is Transaction.TRY_AGAIN, wait for Idl.change_seqno
       to change from the saved 'seqno' (it's possible that it's already
       changed, in which case the client should not wait at all), then start
       over from step 1.  Only a call to Idl.run() will change the return value
       of Idl.change_seqno.  (Transaction.commit_block() calls Idl.run().)"""

    # Status values that Transaction.commit() can return.

    # Not yet committed or aborted.
    UNCOMMITTED = "uncommitted"
    # Transaction didn't include any changes.
    UNCHANGED = "unchanged"
    # Commit in progress, please wait.
    INCOMPLETE = "incomplete"
    # ovsdb_idl_txn_abort() called.
    ABORTED = "aborted"
    # Commit successful.
    SUCCESS = "success"
    # Commit failed because a "verify" operation
    # reported an inconsistency, due to a network
    # problem, or other transient failure.  Wait
    # for a change, then try again.
    TRY_AGAIN = "try again"
    # Server hasn't given us the lock yet.
    NOT_LOCKED = "not locked"
    # Commit failed due to a hard error.
    ERROR = "error"

    @staticmethod
    def status_to_string(status):
        """Converts one of the status values that Transaction.commit() can
        return into a human-readable string.

        (The status values are in fact such strings already, so
        there's nothing to do.)"""
        return status

    def __init__(self, idl):
        """Starts a new transaction on 'idl' (an instance of ovs.db.idl.Idl).
        A given Idl may only have a single active transaction at a time.

        A Transaction may modify the contents of a database by assigning new
        values to columns (attributes of Row), deleting rows (with
        Row.delete()), or inserting rows (with Transaction.insert()).  It may
        also check that columns in the database have not changed with
        Row.verify().

        When a transaction is complete (which must be before the next call to
        Idl.run()), call Transaction.commit() or Transaction.abort()."""
        assert idl.txn is None

        idl.txn = self
        self._request_id = None
        self.idl = idl
        self.dry_run = False
        self._txn_rows = {}
        self._status = Transaction.UNCOMMITTED
        self._error = None
        self._comments = []

        self._inc_row = None
        self._inc_column = None

        self._fetch_requests = []

        self._inserted_rows = {}  # Map from UUID to _InsertedRow

    def add_comment(self, comment):
        """Appends 'comment' to the comments that will be passed to the OVSDB
        server when this transaction is committed.  (The comment will be
        committed to the OVSDB log, which "ovsdb-tool show-log" can print in a
        relatively human-readable form.)"""
        self._comments.append(comment)

    def wait(self, poller):
        """Causes poll_block() to wake up if this transaction has completed
        committing."""
        if self._status not in (Transaction.UNCOMMITTED,
                                Transaction.INCOMPLETE):
            poller.immediate_wake()

    def _substitute_uuids(self, json):
        if isinstance(json, (list, tuple)):
            if (len(json) == 2
                    and json[0] == 'uuid'
                    and ovs.ovsuuid.is_valid_string(json[1])):
                uuid = ovs.ovsuuid.from_string(json[1])
                row = self._txn_rows.get(uuid, None)
                if row and row._data is None:
                    return ["named-uuid", _uuid_name_from_uuid(uuid)]
            else:
                return [self._substitute_uuids(elem) for elem in json]
        return json

    def __disassemble(self):
        self.idl.txn = None

        for row in six.itervalues(self._txn_rows):
            if row._changes is None:
                row._table.rows[row.uuid] = row
            elif row._data is None:
                del row._table.rows[row.uuid]
            row.__dict__["_changes"] = {}
            row.__dict__["_mutations"] = {}
            row.__dict__["_prereqs"] = {}
        self._txn_rows = {}

    def commit(self):
        """Attempts to commit 'txn'.  Returns the status of the commit
        operation, one of the following constants:

          Transaction.INCOMPLETE:

              The transaction is in progress, but not yet complete.  The caller
              should call again later, after calling Idl.run() to let the
              IDL do OVSDB protocol processing.

          Transaction.UNCHANGED:

              The transaction is complete.  (It didn't actually change the
              database, so the IDL didn't send any request to the database
              server.)

          Transaction.ABORTED:

              The caller previously called Transaction.abort().

          Transaction.SUCCESS:

              The transaction was successful.  The update made by the
              transaction (and possibly other changes made by other database
              clients) should already be visible in the IDL.

          Transaction.TRY_AGAIN:

              The transaction failed for some transient reason, e.g. because a
              "verify" operation reported an inconsistency or due to a network
              problem.  The caller should wait for a change to the database,
              then compose a new transaction, and commit the new transaction.

              Use Idl.change_seqno to wait for a change in the database.  It is
              important to use its value *before* the initial call to
              Transaction.commit() as the baseline for this purpose, because
              the change that one should wait for can happen after the initial
              call but before the call that returns Transaction.TRY_AGAIN, and
              using some other baseline value in that situation could cause an
              indefinite wait if the database rarely changes.

          Transaction.NOT_LOCKED:

              The transaction failed because the IDL has been configured to
              require a database lock (with Idl.set_lock()) but didn't
              get it yet or has already lost it.

        Committing a transaction rolls back all of the changes that it made to
        the IDL's copy of the database.  If the transaction commits
        successfully, then the database server will send an update and, thus,
        the IDL will be updated with the committed changes."""
        # The status can only change if we're the active transaction.
        # (Otherwise, our status will change only in Idl.run().)
        if self != self.idl.txn:
            return self._status

        # If we need a lock but don't have it, give up quickly.
        if self.idl.lock_name and not self.idl.has_lock:
            self._status = Transaction.NOT_LOCKED
            self.__disassemble()
            return self._status

        operations = [self.idl._db.name]

        # Assert that we have the required lock (avoiding a race).
        if self.idl.lock_name:
            operations.append({"op": "assert",
                               "lock": self.idl.lock_name})

        # Add prerequisites and declarations of new rows.
        for row in six.itervalues(self._txn_rows):
            if row._prereqs:
                rows = {}
                columns = []
                for column_name in row._prereqs:
                    columns.append(column_name)
                    rows[column_name] = row._data[column_name].to_json()
                operations.append({"op": "wait",
                                   "table": row._table.name,
                                   "timeout": 0,
                                   "where": _where_uuid_equals(row.uuid),
                                   "until": "==",
                                   "columns": columns,
                                   "rows": [rows]})

        # Add updates.
        any_updates = False
        for row in six.itervalues(self._txn_rows):
            if row._changes is None:
                if row._table.is_root:
                    operations.append({"op": "delete",
                                       "table": row._table.name,
                                       "where": _where_uuid_equals(row.uuid)})
                    any_updates = True
                else:
                    # Let ovsdb-server decide whether to really delete it.
                    pass
            elif row._changes:
                op = {"table": row._table.name}
                if row._data is None:
                    op["op"] = "insert"
                    op["uuid-name"] = _uuid_name_from_uuid(row.uuid)
                    any_updates = True

                    op_index = len(operations) - 1
                    self._inserted_rows[row.uuid] = _InsertedRow(op_index)
                else:
                    op["op"] = "update"
                    op["where"] = _where_uuid_equals(row.uuid)

                row_json = {}
                op["row"] = row_json

                for column_name, datum in six.iteritems(row._changes):
                    if row._data is not None or not datum.is_default():
                        row_json[column_name] = (
                            self._substitute_uuids(datum.to_json()))

                        # If anything really changed, consider it an update.
                        # We can't suppress not-really-changed values earlier
                        # or transactions would become nonatomic (see the big
                        # comment inside Transaction._write()).
                        if (not any_updates and row._data is not None and
                                row._data[column_name] != datum):
                            any_updates = True

                if row._data is None or row_json:
                    operations.append(op)
            if row._mutations:
                addop = False
                op = {"table": row._table.name}
                op["op"] = "mutate"
                if row._data is None:
                    # New row
                    op["where"] = self._substitute_uuids(
                        _where_uuid_equals(row.uuid))
                else:
                    # Existing row
                    op["where"] = _where_uuid_equals(row.uuid)
                op["mutations"] = []
                if '_removes' in row._mutations.keys():
                    for col, dat in six.iteritems(row._mutations['_removes']):
                        column = row._table.columns[col]
                        if column.type.is_map():
                            opdat = ["set"]
                            opdat.append(list(dat))
                        else:
                            opdat = ["set"]
                            inner_opdat = []
                            for ele in dat:
                                try:
                                    datum = data.Datum.from_python(column.type,
                                        ele, _row_to_uuid)
                                except error.Error:
                                    return
                                inner_opdat.append(
                                    self._substitute_uuids(datum.to_json()))
                            opdat.append(inner_opdat)
                        mutation = [col, "delete", opdat]
                        op["mutations"].append(mutation)
                        addop = True
                if '_inserts' in row._mutations.keys():
                    for col, val in six.iteritems(row._mutations['_inserts']):
                        column = row._table.columns[col]
                        if column.type.is_map():
                            opdat = ["map"]
                            datum = data.Datum.from_python(column.type, val,
                                                           _row_to_uuid)
                            opdat.append(datum.as_list())
                        else:
                            opdat = ["set"]
                            inner_opdat = []
                            for ele in val:
                                try:
                                    datum = data.Datum.from_python(column.type,
                                        ele, _row_to_uuid)
                                except error.Error:
                                    return
                                inner_opdat.append(
                                    self._substitute_uuids(datum.to_json()))
                            opdat.append(inner_opdat)
                        mutation = [col, "insert", opdat]
                        op["mutations"].append(mutation)
                        addop = True
                if addop:
                    operations.append(op)
                    any_updates = True

        if self._fetch_requests:
            for fetch in self._fetch_requests:
                fetch["index"] = len(operations) - 1
                operations.append({"op": "select",
                                   "table": fetch["row"]._table.name,
                                   "where": self._substitute_uuids(
                                       _where_uuid_equals(fetch["row"].uuid)),
                                   "columns": [fetch["column_name"]]})
            any_updates = True

        # Add increment.
        if self._inc_row and any_updates:
            self._inc_index = len(operations) - 1

            operations.append({"op": "mutate",
                               "table": self._inc_row._table.name,
                               "where": self._substitute_uuids(
                                   _where_uuid_equals(self._inc_row.uuid)),
                               "mutations": [[self._inc_column, "+=", 1]]})
            operations.append({"op": "select",
                               "table": self._inc_row._table.name,
                               "where": self._substitute_uuids(
                                   _where_uuid_equals(self._inc_row.uuid)),
                               "columns": [self._inc_column]})

        # Add comment.
        if self._comments:
            operations.append({"op": "comment",
                               "comment": "\n".join(self._comments)})

        # Dry run?
        if self.dry_run:
            operations.append({"op": "abort"})

        if not any_updates:
            self._status = Transaction.UNCHANGED
        else:
            msg = ovs.jsonrpc.Message.create_request("transact", operations)
            self._request_id = msg.id
            if not self.idl._session.send(msg):
                self.idl._outstanding_txns[self._request_id] = self
                self._status = Transaction.INCOMPLETE
            else:
                self._status = Transaction.TRY_AGAIN

        self.__disassemble()
        return self._status

    def commit_block(self):
        """Attempts to commit this transaction, blocking until the commit
        either succeeds or fails.  Returns the final commit status, which may
        be any Transaction.* value other than Transaction.INCOMPLETE.

        This function calls Idl.run() on this transaction'ss IDL, so it may
        cause Idl.change_seqno to change."""
        while True:
            status = self.commit()
            if status != Transaction.INCOMPLETE:
                return status

            self.idl.run()

            poller = ovs.poller.Poller()
            self.idl.wait(poller)
            self.wait(poller)
            poller.block()

    def get_increment_new_value(self):
        """Returns the final (incremented) value of the column in this
        transaction that was set to be incremented by Row.increment.  This
        transaction must have committed successfully."""
        assert self._status == Transaction.SUCCESS
        return self._inc_new_value

    def abort(self):
        """Aborts this transaction.  If Transaction.commit() has already been
        called then the transaction might get committed anyhow."""
        self.__disassemble()
        if self._status in (Transaction.UNCOMMITTED,
                            Transaction.INCOMPLETE):
            self._status = Transaction.ABORTED

    def get_error(self):
        """Returns a string representing this transaction's current status,
        suitable for use in log messages."""
        if self._status != Transaction.ERROR:
            return Transaction.status_to_string(self._status)
        elif self._error:
            return self._error
        else:
            return "no error details available"

    def __set_error_json(self, json):
        if self._error is None:
            self._error = ovs.json.to_string(json)

    def get_insert_uuid(self, uuid):
        """Finds and returns the permanent UUID that the database assigned to a
        newly inserted row, given the UUID that Transaction.insert() assigned
        locally to that row.

        Returns None if 'uuid' is not a UUID assigned by Transaction.insert()
        or if it was assigned by that function and then deleted by Row.delete()
        within the same transaction.  (Rows that are inserted and then deleted
        within a single transaction are never sent to the database server, so
        it never assigns them a permanent UUID.)

        This transaction must have completed successfully."""
        assert self._status in (Transaction.SUCCESS,
                                Transaction.UNCHANGED)
        inserted_row = self._inserted_rows.get(uuid)
        if inserted_row:
            return inserted_row.real
        return None

    def _increment(self, row, column):
        assert not self._inc_row
        self._inc_row = row
        self._inc_column = column

    def _fetch(self, row, column_name):
        self._fetch_requests.append({"row": row, "column_name": column_name})

    def _write(self, row, column, datum):
        assert row._changes is not None
        assert row._mutations is not None

        txn = row._idl.txn

        # If this is a write-only column and the datum being written is the
        # same as the one already there, just skip the update entirely.  This
        # is worth optimizing because we have a lot of columns that get
        # periodically refreshed into the database but don't actually change
        # that often.
        #
        # We don't do this for read/write columns because that would break
        # atomicity of transactions--some other client might have written a
        # different value in that column since we read it.  (But if a whole
        # transaction only does writes of existing values, without making any
        # real changes, we will drop the whole transaction later in
        # ovsdb_idl_txn_commit().)
        if (not column.alert and row._data and
                row._data.get(column.name) == datum):
            new_value = row._changes.get(column.name)
            if new_value is None or new_value == datum:
                return

        txn._txn_rows[row.uuid] = row
        if '_inserts' in row._mutations:
            row._mutations['_inserts'].pop(column.name, None)
        if '_removes' in row._mutations:
            row._mutations['_removes'].pop(column.name, None)
        row._changes[column.name] = datum.copy()

    def insert(self, table, new_uuid=None):
        """Inserts and returns a new row in 'table', which must be one of the
        ovs.db.schema.TableSchema objects in the Idl's 'tables' dict.

        The new row is assigned a provisional UUID.  If 'uuid' is None then one
        is randomly generated; otherwise 'uuid' should specify a randomly
        generated uuid.UUID not otherwise in use.  ovsdb-server will assign a
        different UUID when 'txn' is committed, but the IDL will replace any
        uses of the provisional UUID in the data to be to be committed by the
        UUID assigned by ovsdb-server."""
        assert self._status == Transaction.UNCOMMITTED
        if new_uuid is None:
            new_uuid = uuid.uuid4()
        row = Row(self.idl, table, new_uuid, None)
        table.rows[row.uuid] = row
        self._txn_rows[row.uuid] = row
        return row

    def _process_reply(self, msg):
        if msg.type == ovs.jsonrpc.Message.T_ERROR:
            self._status = Transaction.ERROR
        elif not isinstance(msg.result, (list, tuple)):
            # XXX rate-limit
            vlog.warn('reply to "transact" is not JSON array')
        else:
            hard_errors = False
            soft_errors = False
            lock_errors = False

            ops = msg.result
            for op in ops:
                if op is None:
                    # This isn't an error in itself but indicates that some
                    # prior operation failed, so make sure that we know about
                    # it.
                    soft_errors = True
                elif isinstance(op, dict):
                    error = op.get("error")
                    if error is not None:
                        if error == "timed out":
                            soft_errors = True
                        elif error == "not owner":
                            lock_errors = True
                        elif error == "aborted":
                            pass
                        else:
                            hard_errors = True
                            self.__set_error_json(op)
                else:
                    hard_errors = True
                    self.__set_error_json(op)
                    # XXX rate-limit
                    vlog.warn("operation reply is not JSON null or object")

            if not soft_errors and not hard_errors and not lock_errors:
                if self._inc_row and not self.__process_inc_reply(ops):
                    hard_errors = True
                if self._fetch_requests:
                    if self.__process_fetch_reply(ops):
                        self.idl.change_seqno += 1
                    else:
                        hard_errors = True

                for insert in six.itervalues(self._inserted_rows):
                    if not self.__process_insert_reply(insert, ops):
                        hard_errors = True

            if hard_errors:
                self._status = Transaction.ERROR
            elif lock_errors:
                self._status = Transaction.NOT_LOCKED
            elif soft_errors:
                self._status = Transaction.TRY_AGAIN
            else:
                self._status = Transaction.SUCCESS

    @staticmethod
    def __check_json_type(json, types, name):
        if not json:
            # XXX rate-limit
            vlog.warn("%s is missing" % name)
            return False
        elif not isinstance(json, tuple(types)):
            # XXX rate-limit
            vlog.warn("%s has unexpected type %s" % (name, type(json)))
            return False
        else:
            return True

    def __process_fetch_reply(self, ops):
        update = False
        for fetch_request in self._fetch_requests:
            row = fetch_request["row"]
            column_name = fetch_request["column_name"]
            index = fetch_request["index"]
            table = row._table

            select = ops[index]
            fetched_rows = select.get("rows")
            if not Transaction.__check_json_type(fetched_rows, (list, tuple),
                                                 '"select" reply "rows"'):
                return False
            if len(fetched_rows) != 1:
                # XXX rate-limit
                vlog.warn('"select" reply "rows" has %d elements '
                          'instead of 1' % len(fetched_rows))
                continue
            fetched_row = fetched_rows[0]
            if not Transaction.__check_json_type(fetched_row, (dict,),
                                                 '"select" reply row'):
                continue

            column = table.columns.get(column_name)
            datum_json = fetched_row.get(column_name)
            datum = data.Datum.from_json(column.type, datum_json)

            row._data[column_name] = datum
            update = True

        return update

    def __process_inc_reply(self, ops):
        if self._inc_index + 2 > len(ops):
            # XXX rate-limit
            vlog.warn("reply does not contain enough operations for "
                      "increment (has %d, needs %d)" %
                      (len(ops), self._inc_index + 2))

        # We know that this is a JSON object because the loop in
        # __process_reply() already checked.
        mutate = ops[self._inc_index]
        count = mutate.get("count")
        if not Transaction.__check_json_type(count, six.integer_types,
                                             '"mutate" reply "count"'):
            return False
        if count != 1:
            # XXX rate-limit
            vlog.warn('"mutate" reply "count" is %d instead of 1' % count)
            return False

        select = ops[self._inc_index + 1]
        rows = select.get("rows")
        if not Transaction.__check_json_type(rows, (list, tuple),
                                             '"select" reply "rows"'):
            return False
        if len(rows) != 1:
            # XXX rate-limit
            vlog.warn('"select" reply "rows" has %d elements '
                      'instead of 1' % len(rows))
            return False
        row = rows[0]
        if not Transaction.__check_json_type(row, (dict,),
                                             '"select" reply row'):
            return False
        column = row.get(self._inc_column)
        if not Transaction.__check_json_type(column, six.integer_types,
                                             '"select" reply inc column'):
            return False
        self._inc_new_value = column
        return True

    def __process_insert_reply(self, insert, ops):
        if insert.op_index >= len(ops):
            # XXX rate-limit
            vlog.warn("reply does not contain enough operations "
                      "for insert (has %d, needs %d)"
                      % (len(ops), insert.op_index))
            return False

        # We know that this is a JSON object because the loop in
        # __process_reply() already checked.
        reply = ops[insert.op_index]
        json_uuid = reply.get("uuid")
        if not Transaction.__check_json_type(json_uuid, (tuple, list),
                                             '"insert" reply "uuid"'):
            return False

        try:
            uuid_ = ovs.ovsuuid.from_json(json_uuid)
        except error.Error:
            # XXX rate-limit
            vlog.warn('"insert" reply "uuid" is not a JSON UUID')
            return False

        insert.real = uuid_
        return True


class SchemaHelper(object):
    """IDL Schema helper.

    This class encapsulates the logic required to generate schemas suitable
    for creating 'ovs.db.idl.Idl' objects.  Clients should register columns
    they are interested in using register_columns().  When finished, the
    get_idl_schema() function may be called.

    The location on disk of the schema used may be found in the
    'schema_location' variable."""

    def __init__(self, location=None, schema_json=None):
        """Creates a new Schema object.

        'location' file path to ovs schema. None means default location
        'schema_json' schema in json preresentation in memory
        """

        if location and schema_json:
            raise ValueError("both location and schema_json can't be "
                             "specified. it's ambiguous.")
        if schema_json is None:
            if location is None:
                location = "%s/vswitch.ovsschema" % ovs.dirs.PKGDATADIR
            schema_json = ovs.json.from_file(location)

        self.schema_json = schema_json
        self._tables = {}
        self._readonly = {}
        self._all = False

    def register_columns(self, table, columns, readonly=[]):
        """Registers interest in the given 'columns' of 'table'.  Future calls
        to get_idl_schema() will include 'table':column for each column in
        'columns'. This function automatically avoids adding duplicate entries
        to the schema.
        A subset of 'columns' can be specified as 'readonly'. The readonly
        columns are not replicated but can be fetched on-demand by the user
        with Row.fetch().

        'table' must be a string.
        'columns' must be a list of strings.
        'readonly' must be a list of strings.
        """

        assert isinstance(table, six.string_types)
        assert isinstance(columns, list)

        columns = set(columns) | self._tables.get(table, set())
        self._tables[table] = columns
        self._readonly[table] = readonly

    def register_table(self, table):
        """Registers interest in the given all columns of 'table'. Future calls
        to get_idl_schema() will include all columns of 'table'.

        'table' must be a string
        """
        assert isinstance(table, six.string_types)
        self._tables[table] = set()  # empty set means all columns in the table

    def register_all(self):
        """Registers interest in every column of every table."""
        self._all = True

    def get_idl_schema(self):
        """Gets a schema appropriate for the creation of an 'ovs.db.id.IDL'
        object based on columns registered using the register_columns()
        function."""

        schema = ovs.db.schema.DbSchema.from_json(self.schema_json)
        self.schema_json = None

        if not self._all:
            schema_tables = {}
            for table, columns in six.iteritems(self._tables):
                schema_tables[table] = (
                    self._keep_table_columns(schema, table, columns))

            schema.tables = schema_tables
        schema.readonly = self._readonly
        return schema

    def _keep_table_columns(self, schema, table_name, columns):
        assert table_name in schema.tables
        table = schema.tables[table_name]

        if not columns:
            # empty set means all columns in the table
            return table

        new_columns = {}
        for column_name in columns:
            assert isinstance(column_name, six.string_types)
            assert column_name in table.columns

            new_columns[column_name] = table.columns[column_name]

        table.columns = new_columns
        return table

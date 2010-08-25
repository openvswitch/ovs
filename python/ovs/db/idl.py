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

import logging

import ovs.jsonrpc
import ovs.db.schema
from ovs.db import error
import ovs.ovsuuid

class Idl:
    """Open vSwitch Database Interface Definition Language (OVSDB IDL).

    The OVSDB IDL maintains an in-memory replica of a database.  It issues RPC
    requests to an OVSDB database server and parses the responses, converting
    raw JSON into data structures that are easier for clients to digest.

    The IDL also assists with issuing database transactions.  The client
    creates a transaction, manipulates the IDL data structures, and commits or
    aborts the transaction.  The IDL then composes and issues the necessary
    JSON-RPC requests and reports to the client whether the transaction
    completed successfully.

    If 'schema_cb' is provided, it should be a callback function that accepts
    an ovs.db.schema.DbSchema as its argument.  It should determine whether the
    schema is acceptable and raise an ovs.db.error.Error if it is not.  It may
    also delete any tables or columns from the schema that the client has no
    interest in monitoring, to save time and bandwidth during monitoring.  Its
    return value is ignored."""

    def __init__(self, remote, db_name, schema_cb=None):
        """Creates and returns a connection to the database named 'db_name' on
        'remote', which should be in a form acceptable to
        ovs.jsonrpc.session.open().  The connection will maintain an in-memory
        replica of the remote database."""
        self.remote = remote
        self.session = ovs.jsonrpc.Session.open(remote)
        self.db_name = db_name
        self.last_seqno = None
        self.schema = None
        self.state = None
        self.change_seqno = 0
        self.data = {}
        self.schema_cb = schema_cb

    def close(self):
        self.session.close()

    def run(self):
        """Processes a batch of messages from the database server.  Returns
        True if the database as seen through the IDL changed, False if it did
        not change.  The initial fetch of the entire contents of the remote
        database is considered to be one kind of change.

        This function can return occasional false positives, that is, report
        that the database changed even though it didn't.  This happens if the
        connection to the database drops and reconnects, which causes the
        database contents to be reloaded even if they didn't change.  (It could
        also happen if the database server sends out a "change" that reflects
        what we already thought was in the database, but the database server is
        not supposed to do that.)

        As an alternative to checking the return value, the client may check
        for changes in the value returned by self.get_seqno()."""
        initial_change_seqno = self.change_seqno
        self.session.run()
        if self.session.is_connected():
            seqno = self.session.get_seqno()
            if seqno != self.last_seqno:
                self.last_seqno = seqno
                self.state = (self.__send_schema_request, None)
            if self.state:
                self.state[0]()
        return initial_change_seqno != self.change_seqno

    def wait(self, poller):
        """Arranges for poller.block() to wake up when self.run() has something
        to do or when activity occurs on a transaction on 'self'."""
        self.session.wait(poller)
        if self.state and self.state[1]:
            self.state[1](poller)

    def get_seqno(self):
        """Returns a number that represents the IDL's state.  When the IDL
        updated (by self.run()), the return value changes."""
        return self.change_seqno
        
    def __send_schema_request(self):
        msg = ovs.jsonrpc.Message.create_request("get_schema", [self.db_name])
        self.session.send(msg)
        self.state = (lambda: self.__recv_schema(msg.id), self.__recv_wait)

    def __recv_schema(self, id):
        msg = self.session.recv()
        if msg and msg.type == ovs.jsonrpc.Message.T_REPLY and msg.id == id:
            try:
                self.schema = ovs.db.schema.DbSchema.from_json(msg.result)
            except error.Error, e:
                logging.error("%s: parse error in received schema: %s"
                              % (self.remote, e))
                self.__error()
                return

            if self.schema_cb:
                try:
                    self.schema_cb(self.schema)
                except error.Error, e:
                    logging.error("%s: error validating schema: %s"
                                  % (self.remote, e))
                    self.__error()
                    return

            self.__send_monitor_request()
        elif msg:
            logging.error("%s: unexpected message expecting schema: %s"
                          % (self.remote, msg))
            self.__error()
            
    def __recv_wait(self, poller):
        self.session.recv_wait(poller)

    def __send_monitor_request(self):
        monitor_requests = {}
        for table in self.schema.tables.itervalues():
            monitor_requests[table.name] = {"columns": table.columns.keys()}
        msg = ovs.jsonrpc.Message.create_request(
            "monitor", [self.db_name, None, monitor_requests])
        self.session.send(msg)
        self.state = (lambda: self.__recv_monitor_reply(msg.id),
                      self.__recv_wait)

    def __recv_monitor_reply(self, id):
        msg = self.session.recv()
        if msg and msg.type == ovs.jsonrpc.Message.T_REPLY and msg.id == id:
            try:
                self.change_seqno += 1
                self.state = (self.__recv_update, self.__recv_wait)
                self.__clear()
                self.__parse_update(msg.result)
            except error.Error, e:
                logging.error("%s: parse error in received schema: %s"
                              % (self.remote, e))
                self.__error()
        elif msg:
            logging.error("%s: unexpected message expecting schema: %s"
                          % (self.remote, msg))
            self.__error()

    def __recv_update(self):
        msg = self.session.recv()
        if (msg and msg.type == ovs.jsonrpc.Message.T_NOTIFY and
            type(msg.params) == list and len(msg.params) == 2 and
            msg.params[0] is None):
            self.__parse_update(msg.params[1])
        elif msg:
            logging.error("%s: unexpected message expecting update: %s"
                          % (self.remote, msg))
            self.__error()

    def __error(self):
        self.session.force_reconnect()

    def __parse_update(self, update):
        try:
            self.__do_parse_update(update)
        except error.Error, e:
            logging.error("%s: error parsing update: %s" % (self.remote, e))

    def __do_parse_update(self, table_updates):
        if type(table_updates) != dict:
            raise error.Error("<table-updates> is not an object",
                              table_updates)

        for table_name, table_update in table_updates.iteritems():
            table = self.schema.tables.get(table_name)
            if not table:
                raise error.Error("<table-updates> includes unknown "
                                  "table \"%s\"" % table_name)

            if type(table_update) != dict:
                raise error.Error("<table-update> for table \"%s\" is not "
                                  "an object" % table_name, table_update)

            for uuid_string, row_update in table_update.iteritems():
                if not ovs.ovsuuid.UUID.is_valid_string(uuid_string):
                    raise error.Error("<table-update> for table \"%s\" "
                                      "contains bad UUID \"%s\" as member "
                                      "name" % (table_name, uuid_string),
                                      table_update)
                uuid = ovs.ovsuuid.UUID.from_string(uuid_string)

                if type(row_update) != dict:
                    raise error.Error("<table-update> for table \"%s\" "
                                      "contains <row-update> for %s that "
                                      "is not an object"
                                      % (table_name, uuid_string))

                old = row_update.get("old", None)
                new = row_update.get("new", None)

                if old is not None and type(old) != dict:
                    raise error.Error("\"old\" <row> is not object", old)
                if new is not None and type(new) != dict:
                    raise error.Error("\"new\" <row> is not object", new)
                if (old is not None) + (new is not None) != len(row_update):
                    raise error.Error("<row-update> contains unexpected "
                                      "member", row_update)
                if not old and not new:
                    raise error.Error("<row-update> missing \"old\" and "
                                      "\"new\" members", row_update)

                if self.__parse_row_update(table, uuid, old, new):
                    self.change_seqno += 1

    def __parse_row_update(self, table, uuid, old, new):
        """Returns True if a column changed, False otherwise."""
        row = self.data[table.name].get(uuid)
        if not new:
            # Delete row.
            if row:
                del self.data[table.name][uuid]
            else:
                # XXX rate-limit
                logging.warning("cannot delete missing row %s from table %s"
                                % (uuid, table.name))
                return False
        elif not old:
            # Insert row.
            if not row:
                row = self.__create_row(table, uuid)
            else:
                # XXX rate-limit
                logging.warning("cannot add existing row %s to table %s"
                                % (uuid, table.name))
            self.__modify_row(table, row, new)
        else:
            if not row:
                row = self.__create_row(table, uuid)
                # XXX rate-limit
                logging.warning("cannot modify missing row %s in table %s"
                                % (uuid, table_name))
            self.__modify_row(table, row, new)
        return True

    def __modify_row(self, table, row, row_json):
        changed = False
        for column_name, datum_json in row_json.iteritems():
            column = table.columns.get(column_name)
            if not column:
                # XXX rate-limit
                logging.warning("unknown column %s updating table %s"
                                % (column_name, table.name))
                continue

            try:
                datum = ovs.db.data.Datum.from_json(column.type, datum_json)
            except error.Error, e:
                # XXX rate-limit
                logging.warning("error parsing column %s in table %s: %s"
                                % (column_name, table_name, e))
                continue

            if datum != row.__dict__[column_name]:
                row.__dict__[column_name] = datum
                changed = True
            else:
                # Didn't really change but the OVSDB monitor protocol always
                # includes every value in a row.
                pass
        return changed

    def __clear(self):
        if self.data != {}:
            for table_name in self.schema.tables:
                if self.data[table_name] != {}:
                    self.change_seqno += 1
                    break

        self.data = {}
        for table_name in self.schema.tables:
            self.data[table_name] = {}

    def __create_row(self, table, uuid):
        class Row(object):
            pass
        row = self.data[table.name][uuid] = Row()
        for column in table.columns.itervalues():
            row.__dict__[column.name] = ovs.db.data.Datum.default(column.type)
        return row

    def force_reconnect(self):
        """Forces the IDL to drop its connection to the database and reconnect.
        In the meantime, the contents of the IDL will not change."""
        self.session.force_reconnect()

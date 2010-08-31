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

import sys

from ovs.db import error
import ovs.db.parser
from ovs.db import types

class DbSchema(object):
    """Schema for an OVSDB database."""

    def __init__(self, name, tables):
        self.name = name
        self.tables = tables

        # Validate that all ref_tables refer to the names of tables
        # that exist.
        for table in self.tables.itervalues():
            for column in table.columns.itervalues():
                self.__check_ref_table(column, column.type.key, "key")
                self.__check_ref_table(column, column.type.value, "value")

    @staticmethod
    def from_json(json):
        parser = ovs.db.parser.Parser(json, "database schema")
        name = parser.get("name", ['id'])
        tablesJson = parser.get("tables", [dict])
        parser.finish()

        tables = {}
        for tableName, tableJson in tablesJson.iteritems():
            if tableName.startswith('_'):
                raise error.Error("names beginning with \"_\" are reserved",
                                  json)
            elif not ovs.db.parser.is_identifier(tableName):
                raise error.Error("name must be a valid id", json)
            tables[tableName] = TableSchema.from_json(tableJson, tableName)

        return DbSchema(name, tables)

    def to_json(self):
        tables = {}
        for table in self.tables.itervalues():
            tables[table.name] = table.to_json()
        return {"name": self.name, "tables": tables}

    def __check_ref_table(self, column, base, base_name):
        if (base and base.type == types.UuidType and base.ref_table and
            base.ref_table not in self.tables):
            raise error.Error("column %s %s refers to undefined table %s"
                              % (column.name, base_name, base.ref_table),
                              tag="syntax error")

class IdlSchema(DbSchema):
    def __init__(self, name, tables, idlPrefix, idlHeader):
        DbSchema.__init__(self, name, tables)
        self.idlPrefix = idlPrefix
        self.idlHeader = idlHeader

    @staticmethod
    def from_json(json):
        parser = ovs.db.parser.Parser(json, "IDL schema")
        idlPrefix = parser.get("idlPrefix", [unicode])
        idlHeader = parser.get("idlHeader", [unicode])

        subjson = dict(json)
        del subjson["idlPrefix"]
        del subjson["idlHeader"]
        schema = DbSchema.from_json(subjson)

        return IdlSchema(schema.name, schema.tables, idlPrefix, idlHeader)

class TableSchema(object):
    def __init__(self, name, columns, mutable=True, max_rows=sys.maxint):
        self.name = name
        self.columns = columns
        self.mutable = mutable
        self.max_rows = max_rows        

    @staticmethod
    def from_json(json, name):
        parser = ovs.db.parser.Parser(json, "table schema for table %s" % name)
        columnsJson = parser.get("columns", [dict])
        mutable = parser.get_optional("mutable", [bool], True)
        max_rows = parser.get_optional("maxRows", [int])
        parser.finish()

        if max_rows == None:
            max_rows = sys.maxint
        elif max_rows <= 0:
            raise error.Error("maxRows must be at least 1", json)

        if not columnsJson:
            raise error.Error("table must have at least one column", json)

        columns = {}
        for columnName, columnJson in columnsJson.iteritems():
            if columnName.startswith('_'):
                raise error.Error("names beginning with \"_\" are reserved",
                                  json)
            elif not ovs.db.parser.is_identifier(columnName):
                raise error.Error("name must be a valid id", json)
            columns[columnName] = ColumnSchema.from_json(columnJson,
                                                         columnName)

        return TableSchema(name, columns, mutable, max_rows)

    def to_json(self):
        json = {}
        if not self.mutable:
            json["mutable"] = False

        json["columns"] = columns = {}
        for column in self.columns.itervalues():
            if not column.name.startswith("_"):
                columns[column.name] = column.to_json()

        if self.max_rows != sys.maxint:
            json["maxRows"] = self.max_rows

        return json

class ColumnSchema(object):
    def __init__(self, name, mutable, persistent, type):
        self.name = name
        self.mutable = mutable
        self.persistent = persistent
        self.type = type

    @staticmethod
    def from_json(json, name):
        parser = ovs.db.parser.Parser(json, "schema for column %s" % name)
        mutable = parser.get_optional("mutable", [bool], True)
        ephemeral = parser.get_optional("ephemeral", [bool], False)
        type = types.Type.from_json(parser.get("type", [dict, unicode]))
        parser.finish()

        return ColumnSchema(name, mutable, not ephemeral, type)

    def to_json(self):
        json = {"type": self.type.to_json()}
        if not self.mutable:
            json["mutable"] = False
        if not self.persistent:
            json["ephemeral"] = True
        return json


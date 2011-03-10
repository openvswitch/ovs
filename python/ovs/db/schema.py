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
import sys

from ovs.db import error
import ovs.db.parser
from ovs.db import types

class DbSchema(object):
    """Schema for an OVSDB database."""

    def __init__(self, name, version, tables):
        self.name = name
        self.version = version
        self.tables = tables

        # Validate that all ref_tables refer to the names of tables
        # that exist.
        for table in self.tables.itervalues():
            for column in table.columns.itervalues():
                self.__check_ref_table(column, column.type.key, "key")
                self.__check_ref_table(column, column.type.value, "value")

        # "isRoot" was not part of the original schema definition.  Before it
        # was added, there was no support for garbage collection.  So, for
        # backward compatibility, if the root set is empty then assume that
        # every table is in the root set.
        if self.__root_set_size() == 0:
            for table in self.tables.itervalues():
                table.is_root = True

    def __root_set_size(self):
        """Returns the number of tables in the schema's root set."""
        n_root = 0
        for table in self.tables.itervalues():
            if table.is_root:
                n_root += 1
        return n_root

    @staticmethod
    def from_json(json):
        parser = ovs.db.parser.Parser(json, "database schema")
        name = parser.get("name", ['id'])
        version = parser.get_optional("version", [unicode])
        parser.get_optional("cksum", [unicode])
        tablesJson = parser.get("tables", [dict])
        parser.finish()

        if (version is not None and
            not re.match('[0-9]+\.[0-9]+\.[0-9]+$', version)):
            raise error.Error("schema version \"%s\" not in format x.y.z"
                              % version)

        tables = {}
        for tableName, tableJson in tablesJson.iteritems():
            if tableName.startswith('_'):
                raise error.Error("names beginning with \"_\" are reserved",
                                  json)
            elif not ovs.db.parser.is_identifier(tableName):
                raise error.Error("name must be a valid id", json)
            tables[tableName] = TableSchema.from_json(tableJson, tableName)

        return DbSchema(name, version, tables)

    def to_json(self):
        # "isRoot" was not part of the original schema definition.  Before it
        # was added, there was no support for garbage collection.  So, for
        # backward compatibility, if every table is in the root set then do not
        # output "isRoot" in table schemas.
        default_is_root = self.__root_set_size() == len(self.tables)

        tables = {}
        for table in self.tables.itervalues():
            tables[table.name] = table.to_json(default_is_root)
        json = {"name": self.name, "tables": tables}
        if self.version:
            json["version"] = self.version
        return json

    def __check_ref_table(self, column, base, base_name):
        if (base and base.type == types.UuidType and base.ref_table and
            base.ref_table not in self.tables):
            raise error.Error("column %s %s refers to undefined table %s"
                              % (column.name, base_name, base.ref_table),
                              tag="syntax error")

class IdlSchema(DbSchema):
    def __init__(self, name, version, tables, idlPrefix, idlHeader):
        DbSchema.__init__(self, name, version, tables)
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

        return IdlSchema(schema.name, schema.version, schema.tables,
                         idlPrefix, idlHeader)

class TableSchema(object):
    def __init__(self, name, columns, mutable=True, max_rows=sys.maxint,
                 is_root=True):
        self.name = name
        self.columns = columns
        self.mutable = mutable
        self.max_rows = max_rows
        self.is_root = is_root

    @staticmethod
    def from_json(json, name):
        parser = ovs.db.parser.Parser(json, "table schema for table %s" % name)
        columnsJson = parser.get("columns", [dict])
        mutable = parser.get_optional("mutable", [bool], True)
        max_rows = parser.get_optional("maxRows", [int])
        is_root = parser.get_optional("isRoot", [bool], False)
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

        return TableSchema(name, columns, mutable, max_rows, is_root)

    def to_json(self, default_is_root=False):
        """Returns this table schema serialized into JSON.

        The "isRoot" member is included in the JSON only if its value would
        differ from 'default_is_root'.  Ordinarily 'default_is_root' should be
        false, because ordinarily a table would be not be part of the root set
        if its "isRoot" member is omitted.  However, garbage collection was not
        orginally included in OVSDB, so in older schemas that do not include
        any "isRoot" members, every table is implicitly part of the root set.
        To serialize such a schema in a way that can be read by older OVSDB
        tools, specify 'default_is_root' as True.
        """
        json = {}
        if not self.mutable:
            json["mutable"] = False
        if default_is_root != self.is_root:
            json["isRoot"] = self.is_root

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


# Copyright (c) 2009, 2010, 2011, 2016 Nicira, Inc.
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

import ovs.db.parser
import ovs.db.types
from ovs.db import error

import six


def _check_id(name, json):
    if name.startswith('_'):
        raise error.Error('names beginning with "_" are reserved', json)
    elif not ovs.db.parser.is_identifier(name):
        raise error.Error("name must be a valid id", json)


class DbSchema(object):
    """Schema for an OVSDB database."""

    def __init__(self, name, version, tables):
        self.name = name
        self.version = version
        self.tables = tables

        # "isRoot" was not part of the original schema definition.  Before it
        # was added, there was no support for garbage collection.  So, for
        # backward compatibility, if the root set is empty then assume that
        # every table is in the root set.
        if self.__root_set_size() == 0:
            for table in six.itervalues(self.tables):
                table.is_root = True

        # Find the "ref_table"s referenced by "ref_table_name"s.
        #
        # Also force certain columns to be persistent, as explained in
        # __check_ref_table().  This requires 'is_root' to be known, so this
        # must follow the loop updating 'is_root' above.
        for table in six.itervalues(self.tables):
            for column in six.itervalues(table.columns):
                self.__follow_ref_table(column, column.type.key, "key")
                self.__follow_ref_table(column, column.type.value, "value")

    def __root_set_size(self):
        """Returns the number of tables in the schema's root set."""
        n_root = 0
        for table in six.itervalues(self.tables):
            if table.is_root:
                n_root += 1
        return n_root

    @staticmethod
    def from_json(json):
        parser = ovs.db.parser.Parser(json, "database schema")
        name = parser.get("name", ['id'])
        version = parser.get_optional("version", six.string_types)
        parser.get_optional("cksum", six.string_types)
        tablesJson = parser.get("tables", [dict])
        parser.finish()

        if (version is not None and
            not re.match('[0-9]+\.[0-9]+\.[0-9]+$', version)):
            raise error.Error('schema version "%s" not in format x.y.z'
                              % version)

        tables = {}
        for tableName, tableJson in six.iteritems(tablesJson):
            _check_id(tableName, json)
            tables[tableName] = TableSchema.from_json(tableJson, tableName)

        return DbSchema(name, version, tables)

    def to_json(self):
        # "isRoot" was not part of the original schema definition.  Before it
        # was added, there was no support for garbage collection.  So, for
        # backward compatibility, if every table is in the root set then do not
        # output "isRoot" in table schemas.
        default_is_root = self.__root_set_size() == len(self.tables)

        tables = {}
        for table in six.itervalues(self.tables):
            tables[table.name] = table.to_json(default_is_root)
        json = {"name": self.name, "tables": tables}
        if self.version:
            json["version"] = self.version
        return json

    def copy(self):
        return DbSchema.from_json(self.to_json())

    def __follow_ref_table(self, column, base, base_name):
        if (not base or base.type != ovs.db.types.UuidType
                or not base.ref_table_name):
            return

        base.ref_table = self.tables.get(base.ref_table_name)
        if not base.ref_table:
            raise error.Error("column %s %s refers to undefined table %s"
                              % (column.name, base_name, base.ref_table_name),
                              tag="syntax error")

        if base.is_strong_ref() and not base.ref_table.is_root:
            # We cannot allow a strong reference to a non-root table to be
            # ephemeral: if it is the only reference to a row, then replaying
            # the database log from disk will cause the referenced row to be
            # deleted, even though it did exist in memory.  If there are
            # references to that row later in the log (to modify it, to delete
            # it, or just to point to it), then this will yield a transaction
            # error.
            column.persistent = True


class IdlSchema(DbSchema):
    def __init__(self, name, version, tables, idlPrefix, idlHeader):
        DbSchema.__init__(self, name, version, tables)
        self.idlPrefix = idlPrefix
        self.idlHeader = idlHeader

    @staticmethod
    def from_json(json):
        parser = ovs.db.parser.Parser(json, "IDL schema")
        idlPrefix = parser.get("idlPrefix", six.string_types)
        idlHeader = parser.get("idlHeader", six.string_types)

        subjson = dict(json)
        del subjson["idlPrefix"]
        del subjson["idlHeader"]
        schema = DbSchema.from_json(subjson)

        return IdlSchema(schema.name, schema.version, schema.tables,
                         idlPrefix, idlHeader)


def column_set_from_json(json, columns):
    if json is None:
        return tuple(columns)
    elif not isinstance(json, list):
        raise error.Error("array of distinct column names expected", json)
    else:
        for column_name in json:
            if not isinstance(column_name, six.string_types):
                raise error.Error("array of distinct column names expected",
                                  json)
            elif column_name not in columns:
                raise error.Error("%s is not a valid column name"
                                  % column_name, json)
        if len(set(json)) != len(json):
            # Duplicate.
            raise error.Error("array of distinct column names expected", json)
        return tuple([columns[column_name] for column_name in json])


class TableSchema(object):
    def __init__(self, name, columns, mutable=True, max_rows=sys.maxsize,
                 is_root=True, indexes=[]):
        self.name = name
        self.columns = columns
        self.mutable = mutable
        self.max_rows = max_rows
        self.is_root = is_root
        self.indexes = indexes

    @staticmethod
    def from_json(json, name):
        parser = ovs.db.parser.Parser(json, "table schema for table %s" % name)
        columns_json = parser.get("columns", [dict])
        mutable = parser.get_optional("mutable", [bool], True)
        max_rows = parser.get_optional("maxRows", [int])
        is_root = parser.get_optional("isRoot", [bool], False)
        indexes_json = parser.get_optional("indexes", [list], [])
        parser.finish()

        if max_rows is None:
            max_rows = sys.maxsize
        elif max_rows <= 0:
            raise error.Error("maxRows must be at least 1", json)

        if not columns_json:
            raise error.Error("table must have at least one column", json)

        columns = {}
        for column_name, column_json in six.iteritems(columns_json):
            _check_id(column_name, json)
            columns[column_name] = ColumnSchema.from_json(column_json,
                                                          column_name)

        indexes = []
        for index_json in indexes_json:
            index = column_set_from_json(index_json, columns)
            if not index:
                raise error.Error("index must have at least one column", json)
            elif len(index) == 1:
                index[0].unique = True
            for column in index:
                if not column.persistent:
                    raise error.Error("ephemeral columns (such as %s) may "
                                      "not be indexed" % column.name, json)
            indexes.append(index)

        return TableSchema(name, columns, mutable, max_rows, is_root, indexes)

    def to_json(self, default_is_root=False):
        """Returns this table schema serialized into JSON.

        The "isRoot" member is included in the JSON only if its value would
        differ from 'default_is_root'.  Ordinarily 'default_is_root' should be
        false, because ordinarily a table would be not be part of the root set
        if its "isRoot" member is omitted.  However, garbage collection was not
        originally included in OVSDB, so in older schemas that do not include
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
        for column in six.itervalues(self.columns):
            if not column.name.startswith("_"):
                columns[column.name] = column.to_json()

        if self.max_rows != sys.maxsize:
            json["maxRows"] = self.max_rows

        if self.indexes:
            json["indexes"] = []
            for index in self.indexes:
                json["indexes"].append([column.name for column in index])

        return json


class ColumnSchema(object):
    def __init__(self, name, mutable, persistent, type_):
        self.name = name
        self.mutable = mutable
        self.persistent = persistent
        self.type = type_
        self.unique = False

    @staticmethod
    def from_json(json, name):
        parser = ovs.db.parser.Parser(json, "schema for column %s" % name)
        mutable = parser.get_optional("mutable", [bool], True)
        ephemeral = parser.get_optional("ephemeral", [bool], False)
        _types = list(six.string_types)
        _types.extend([dict])
        type_ = ovs.db.types.Type.from_json(parser.get("type", _types))
        parser.finish()

        if not mutable and (type_.key.is_weak_ref()
                            or (type_.value and type_.value.is_weak_ref())):
            # We cannot allow a weak reference to be immutable: if referenced
            # rows are deleted, then the weak reference needs to change.
            mutable = True

        return ColumnSchema(name, mutable, not ephemeral, type_)

    def to_json(self):
        json = {"type": self.type.to_json()}
        if not self.mutable:
            json["mutable"] = False
        if not self.persistent:
            json["ephemeral"] = True
        return json

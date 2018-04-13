import collections
import functools
import operator
try:
    from UserDict import IterableUserDict as DictBase
except ImportError:
    from collections import UserDict as DictBase

try:
    import sortedcontainers
except ImportError:
    from ovs.compat import sortedcontainers

from ovs.db import data

OVSDB_INDEX_ASC = "ASC"
OVSDB_INDEX_DESC = "DESC"
ColumnIndex = collections.namedtuple('ColumnIndex',
                                     ['column', 'direction', 'key'])


class MultiColumnIndex(object):
    def __init__(self, name):
        self.name = name
        self.columns = []
        self.clear()

    def __repr__(self):
        return "{}(name={})".format(self.__class__.__name__, self.name)

    def __str__(self):
        return repr(self) + " columns={} values={}".format(
            self.columns, [str(v) for v in self.values])

    def add_column(self, column, direction=OVSDB_INDEX_ASC, key=None):
        self.columns.append(ColumnIndex(column, direction,
                             key or operator.attrgetter(column)))

    def add_columns(self, *columns):
        self.columns.extend(ColumnIndex(col, OVSDB_INDEX_ASC,
                                        operator.attrgetter(col))
                            for col in columns)

    def _cmp(self, a, b):
        for col, direction, key in self.columns:
            aval, bval = key(a), key(b)
            if aval == bval:
                continue
            result = (aval > bval) - (aval < bval)
            return result if direction == OVSDB_INDEX_ASC else -result
        return 0

    def index_entry_from_row(self, row):
        return row._table.rows.IndexEntry(
            uuid=row.uuid,
            **{c.column: getattr(row, c.column) for c in self.columns})

    def add(self, row):
        if not all(hasattr(row, col.column) for col in self.columns):
            # This is a new row, but it hasn't had the necessary columns set
            # We'll add it later
            return
        self.values.add(self.index_entry_from_row(row))

    def remove(self, row):
        self.values.remove(self.index_entry_from_row(row))

    def clear(self):
        self.values = sortedcontainers.SortedListWithKey(
            key=functools.cmp_to_key(self._cmp))

    def irange(self, start, end):
        return iter(r._table.rows[r.uuid]
                    for r in self.values.irange(start, end))

    def __iter__(self):
        return iter(r._table.rows[r.uuid] for r in self.values)


class IndexedRows(DictBase, object):
    def __init__(self, table, *args, **kwargs):
        super(IndexedRows, self).__init__(*args, **kwargs)
        self.table = table
        self.indexes = {}
        self.IndexEntry = IndexEntryClass(table)

    def index_create(self, name):
        if name in self.indexes:
            raise ValueError("An index named {} already exists".format(name))
        index = self.indexes[name] = MultiColumnIndex(name)
        return index

    def __setitem__(self, key, item):
        self.data[key] = item
        for index in self.indexes.values():
            index.add(item)

    def __delitem__(self, key):
        val = self.data[key]
        del self.data[key]
        for index in self.indexes.values():
            index.remove(val)

    def clear(self):
        self.data.clear()
        for index in self.indexes.values():
            index.clear()

    # Nothing uses the methods below, though they'd be easy to implement
    def update(self, dict=None, **kwargs):
        raise NotImplementedError()

    def setdefault(self, key, failobj=None):
        raise NotImplementedError()

    def pop(self, key, *args):
        raise NotImplementedError()

    def popitem(self):
        raise NotImplementedError()

    @classmethod
    def fromkeys(cls, iterable, value=None):
        raise NotImplementedError()


def IndexEntryClass(table):
    """Create a class used represent Rows in indexes

    ovs.db.idl.Row, being inherently tied to transaction processing and being
    initialized with dicts of Datums, is not really useable as an object to
    pass to and store in indexes. This method will create a class named after
    the table's name that is initialized with that Table Row's default values.
    For example:

    Port = IndexEntryClass(idl.tables['Port'])

    will create a Port class. This class can then be used to search custom
    indexes. For example:

    for port in idx.iranage(Port(name="test1"), Port(name="test9")):
       ...
    """

    def defaults_uuid_to_row(atom, base):
        return atom.value

    columns = ['uuid'] + list(table.columns.keys())
    cls = collections.namedtuple(table.name, columns)
    cls._table = table
    cls.__new__.__defaults__ = (None,) + tuple(
        data.Datum.default(c.type).to_python(defaults_uuid_to_row)
        for c in table.columns.values())
    return cls

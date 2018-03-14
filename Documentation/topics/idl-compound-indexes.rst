..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

======================
C IDL Compound Indexes
======================

Introduction
------------

This document describes the design and usage of the C IDL Compound
Indexes feature, which allows OVSDB client applications to efficiently
search table contents using arbitrary sets of column values in a generic
way.

This feature is implemented entirely in the client IDL, requiring no changes
to the OVSDB Server, OVSDB Protocol (OVSDB RFC (RFC 7047)) or additional
interaction with the OVSDB server.

Please note that in this document, the term "index" refers to the common
database term defined as "a data structure that facilitates data
retrieval". Unless stated otherwise, the definition for index from the
OVSDB RFC (RFC 7047) is not used.

Typical Use Cases
-----------------

Fast lookups
~~~~~~~~~~~~

Depending on the topology, the route table of a network device could
manage thousands of routes. Commands such as "show ip route <*specific
route*>" would need to do a sequential lookup of the routing table to
find the specific route. With an index created, the lookup time could be
faster.

This same scenario could be applied to other features such as Access
List rules and even interfaces lists.

Lexicographic order
~~~~~~~~~~~~~~~~~~~

There are a number of cases in which retrieving data in a particular
lexicographic order is needed. For example, SNMP. When an administrator
or even a NMS would like to retrieve data from a specific device, it's
possible that they will request data from full tables instead of just
specific values.  Also, they would like to have this information displayed
in lexicographic order. This operation could be done by the SNMP daemon or
by the CLI, but it would be better if the database could provide the
data ready for consumption. Also, duplicate efforts by different
processes will be avoided. Another use case for requesting data in
lexicographic order is for user interfaces (web or CLI) where it would
be better and quicker if the DB sends the data sorted instead of letting
each process to sort the data by itself.

Implementation Design
---------------------

This feature maintains a collection of indexes per table. The application
can create any number of indexes per table.

An index can be defined over any number of columns, and supports the
following options:

-  Add a column with type string, boolean, uuid, integer or real (using
   default comparators).
-  Select ordering direction of a column (ascending or descending, must
   be selected when creating the index).
-  Use a custom ordering comparator (eg: treat a string column like a IP,
   or sort by the value of the "config" key in a map column).

For querying the index the user needs to create a cursor. That cursor
points to a position in the index. The user can then use the cursor to
perform lookups (by key) and/or get the subsequent rows. The user can
also compare the current value of the cursor to a record.

For lookups, the user needs to provide a key to be used for locating the
specific rows that meet his criteria. This key could be an IP address, a
MAC address, an ACL rule, etc. When the information is found in the data
structure the user's cursor is updated to point to the row. If several
rows match the query then the user can easily get the next row in sequence
by updating the cursor.

For accessing data in lexicographic order, the user can use the ranged
iterators. Those iterators need a cursor and "from" and "to" values to
define a range.

The indexes maintain a pointer to the row in the local replica, avoiding
the need to make additional copies of the data and thereby minimizing any
additional memory and CPU overhead for their maintenance. It is intended
that creating and maintaining indexes should be very cheap.

Another potential issue is the time needed to create the data structure
and the time needed to add/remove elements. The indexes are always
synchronized with the replica. For this reason is VERY IMPORTANT that
the comparison functions (built-in and user provided) are FAST.

Skiplists are used as the primary data structure for the implementation of
indexes. Indexes therefore have an expected ``O(log(n))`` cost when
inserting, deleting or modifying a row, ``O(log(n))`` when retrieving
a row by key, and O(1) when retrieving the first or next row.

Indexes are maintained incrementally in the replica as notifications of
database changes are received from the OVSDB server, as shown in the
following diagram.

::

                   +---------------------------------------------------------+
                   |                                                         |
        +-------------+Client changes to data                            IDL |
        |          |                                                         |
    +---v---+      |                                                         |
    | OVSDB +--------->OVSDB Notification                                    |
    +-------+      |   +                                                     |
                   |   |   +------------+                                    |
                   |   |   |            |                                    |
                   |   |   | Insert Row +----> Insert row to indexes         |
                   |   |   |            |                   ^                |
                   |   +-> | Modify Row +-------------------+                |
                   |       |            |                   v                |
                   |       | Delete Row +----> Delete row from indexes       |
                   |       |            |                                    |
                   |       +----+-------+                                    |
                   |            |                                            |
                   |            +-> IDL Replica                              |
                   |                                                         |
                   +---------------------------------------------------------+

C IDL API
---------

Index Creation
~~~~~~~~~~~~~~

Each index must be created with the function ``ovsdb_idl_create_index()``.
After an index has been created the user can add one or more columns to it,
using ``ovsdb_idl_index_add_column``. All indexes must be created with all
columns added BEFORE the first call to ovsdb\_idl\_run().

Index Creation Example
^^^^^^^^^^^^^^^^^^^^^^

::

    /* Define a custom comparator for the column "stringField" in table
     * "Test". (Note that custom comparison functions are not often
     * necessary.)
     */
    int stringField_comparator(const void *a, const void *b)
    {
        struct ovsrec_test *AAA, *BBB;
        AAA = (struct ovsrec_test *)a;
        BBB = (struct ovsrec_test *)b;
        return strcmp(AAA->stringField, BBB->stringField);
    }

    void init_idl(struct ovsdb_idl **, char *remote)
    {
        /* Add the columns to the IDL */
        *idl = ovsdb_idl_create(remote, &ovsrec_idl_class, false, true);
        ovsdb_idl_add_table(*idl, &ovsrec_table_test);
        ovsdb_idl_add_column(*idl, &ovsrec_test_col_stringField);
        ovsdb_idl_add_column(*idl, &ovsrec_test_col_numericField);
        ovsdb_idl_add_column(*idl, &ovsrec_test_col_enumField);
        ovsdb_idl_add_column(*idl, &ovsrec_test_col_boolField);

        /* Create an index.
         * This index is created using (stringField, numericField) as key.
         * Also shows the usage of some arguments of add column, although
         * for a string column it is unnecesary to pass a custom comparator.
         */
        struct ovsdb_idl_index *index;
        index = ovsdb_idl_create_index(*idl, &ovsrec_table_test,
                                       "by_stringField");
        ovsdb_idl_index_add_column(index, &ovsrec_test_col_stringField,
                                   OVSDB_INDEX_ASC, stringField_comparator);
        ovsdb_idl_index_add_column(index, &ovsrec_test_col_numericField,
                                   OVSDB_INDEX_DESC, NULL);
        /* Done. */
    }

Index Usage
-----------

Iterators
~~~~~~~~~

The recommended way to do queries is using a "ranged foreach", an "equal
foreach" or a "full foreach" over an index. The mechanism works as
follows:

1. Create a cursor.
2. Create index row objects with index columns set to desired search key
   values (one is needed for equality iterators, two for range iterators,
   a search key is not needed for the full index iterator).
3. Pass the cursor, an iteration variable, and the key values to the iterator.
4. Use the values within iterator loop.

To create the cursor for the example, we use the following code:

::

    ovsdb_idl_index_cursor my_cursor;
    ovsdb_idl_initialize_cursor(idl, &ovsrec_table_test, "by_stringField",
                                &my_cursor);

Now the cursor can be used to perform queries. The library implements three
different iterators: a range iterator, an equality iterator and a full index
iterator. The range iterator receives two values and iterates over all
rows with values that are within that range (inclusive of the two values
defining the range). The equality iterator iterates over all rows that exactly
match the value passed. The full index iterator iterates over all rows in the
index, in an order determined by the comparison function and configured
direction (ascending or descending).

Note that indexes are *sorted by the "concatenation" of the values in
all indexed columns*, so the ranged iterator returns all the values
between "from.col1 from.col2 ... from.coln" and "to.col1 to.col2 ...
to.coln", *NOT the rows with a value in column 1 between from.col1 and
to.col1, and so on*.

The iterators are macros specific to each table. An example of the use of
these iterators follows:

::

    /*
     * Equality iterator; iterates over all the records equal to "value".
     */
    ovsrec_test *value, *record;
    value = ovsrec_test_index_init_row(idl, &ovsrec_table_test);
    ovsrec_test_index_set_stringField(value, "hello world");
    OVSREC_TEST_FOR_EACH_EQUAL (record, &my_cursor, value) {
        /* Can return zero, one or more records */
        assert(strcmp(record->stringField, "hello world") == 0);
        printf("Found one record with %s", record->stringField);
    }
    ovsrec_test_index_destroy_row(value);

    /*
     * Range iterator; iterates over all records between two values
     * (inclusive).
     */
    ovsrec_test *value_from, *value_to;
    value_from = ovsrec_test_index_init_row(idl, &ovsrec_table_test);
    value_to = ovsrec_test_index_init_row(idl, &ovsrec_table_test);

    ovsrec_test_index_set_stringField(value_from, "aaa");
    ovsrec_test_index_set_stringField(value_to, "mmm");
    OVSREC_TEST_FOR_EACH_RANGE (record, &my_cursor, value_from, value_to) {
        /* Can return zero, one or more records */
        assert(strcmp("aaa", record->stringField) <= 0);
        assert(strcmp(record->stringField, "mmm") <= 0);
        printf("Found one record with %s", record->stringField);
    }
    ovsrec_test_index_destroy_row(value_from);
    ovsrec_test_index_destroy_row(value_to);

    /*
     * Index iterator; iterates over all nodes in the index, in order
     * determined by comparison function and configured order (ascending
     * or descending).
     */
    OVSREC_TEST_FOR_EACH_BYINDEX (record, &my_cursor) {
        /* Can return zero, one or more records */
        printf("Found one record with %s", record->stringField);
    }

General Index Access
~~~~~~~~~~~~~~~~~~~~

While the currently defined iterators are suitable for many use cases, it is
also possible to create custom iterators using the more general API on which
the existing iterators have been built. This API includes the following
functions, declared in "lib/ovsdb-idl.h":

1. ``ovsrec_<table>_index_compare()``
2. ``ovsrec_<table>_index_next()``
3. ``ovsrec_<table>_index_find()``
4. ``ovsrec_<table>_index_forward_to()``
5. ``ovsrec_<table>_index_get_data()``

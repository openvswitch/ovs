C IDL Compound Indexes
======================

## Introduction

This document describes the design and usage of the C IDL Compound Indexes
feature that allows the developer to create indexes over any number of columns
on the IDL side, and query them.

This feature works completely on the IDL, without requiring changes to the
OVSDB Server, OVSDB Protocol (OVSDB RFC (RFC 7047)) or
performing additional communication with the server.

Please note that in this document, the term "index" refers to the common
database term defined as "a data structure that improves data retrieval". Unless
stated otherwise, the definition for index from the OVSDB RFC (RFC 7047) is not
used.

## Typical Use Cases

### Fast lookups

Depending on the topology, the route table of a network device could manage
thousands of routes. Commands such as "show ip route <*specific route*>" would
need to do a sequential lookup of the routing table to find the specific route.
With an index created, the lookup time could be faster.

This same scenario could be applied to other features such as Access List rules
and even interfaces lists.

### Lexicographic order

There are several cases where retrieving data in lexicographic order is needed.
For example, SNMP. When an administrator or even a NMS would like to retrieve
data from a specific device, it's possible that they will request data from full
tables instead of just specific values. Also, they would like to have this
information displayed in lexicographic order. This operation could be done by
the SNMP daemon or by the CLI, but it would be better if the database could
provide the data ready for consumption. Also, duplicate efforts by different
processes will be avoided. Another use case for requesting data in lexicographic
order is for user interfaces (web or CLI) where it would be better and quicker
if the DB sends the data sorted instead of letting each process to sort the data
by itself.

## Implementation Design

This feature maintains a collection of indexes per table. The developer can
define any number of indexes per table.

An index can be defined over any number of columns, and support the following
options:

-   Add a column with type string, int or real (using default comparators).
-   Select ordering direction of a column (must be selected when creating the
    index).
-   Use a custom iterator (eg: treat a string column like a IP, or sort by the
    value of "config" key in a map).

For querying the index the user needs to create a cursor. That cursor points to
a position in the index. With that, the user can perform lookups
(by key) and/or get the following rows. The user can also compare the current
value of the cursor to a record.

For faster lookups, user would need to provide a key which will be used for finding
the specific rows that meet this criteria. This key could be an IP address, a
MAC address, an ACL rule, etc. When the information is found in the data
structure the user's cursor is updated to point to the row. If several rows
match the query then the user can get easily the next row updating the cursor.

For accessing data in lexicographic order, the user can use the ranged iterators.
Those iterators needs a cursor, and a "from" and "to" value.

The indexes keep just a pointer to the row in the replica, it doesn't make
additional copies of the data, so it's not expected that it consumes too much
additional memory. The idea is that creating indexes should be very cheap.

Another potential issue is the time needed to create the data structure and the
time needed to add/remove elements. The indexes are always synchronized with the
replica. For this reason is VERY IMPORTANT that the comparison functions
(built-in and user provided) are FAST.

At this point, a skiplist is the data structure selected as the best fit.
Because of this, the indexes has a `O(log(n))` behaviour when inserting,
deleting and modifiying rows, a `O(log(n))` when retrieving a row by key, and
O(1) when retrieving the first or next row.

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

## C IDL API

### Index Creation

Each index must be created with the function `ovsdb_idl_create_index`,
and then the developer adds columns to it, using `ovsdb_idl_index_add_column`.
This must be done BEFORE the first call to ovsdb_idl_run.

#### Index Creation Example

    /* Custom comparator for the column stringField at table Test */
    int stringField_comparator(const void *a, const void *b) {
        struct ovsrec_test *AAA, *BBB;
        AAA = (struct ovsrec_test *)a;
        BBB = (struct ovsrec_test *)b;
        return strcmp(AAA->stringField, BBB->stringField);
    }

    void init_idl(struct ovsdb_idl **, char *remote) {
        /* Add the columns to the IDL */
        *idl = ovsdb_idl_create(remote, &ovsrec_idl_class, false, true);
        ovsdb_idl_add_table(*idl, &ovsrec_table_test);
        ovsdb_idl_add_column(*idl, &ovsrec_test_col_stringField);
        ovsdb_idl_add_column(*idl, &ovsrec_test_col_numericField);
        ovsdb_idl_add_column(*idl, &ovsrec_test_col_enumField);
        ovsdb_idl_add_column(*idl, &ovsrec_test_col_boolField);

        /* Create an index
         * This index is created using (stringField, numericField) as key. Also shows the usage
         * of some arguments of add column, althought for a string column is unnecesary to pass
         * a custom comparator.
         */
        struct ovsdb_idl_index *index;
        index = ovsdb_idl_create_index(*idl, &ovsrec_table_test, "by_stringField");
        ovsdb_idl_index_add_column(index, &ovsrec_test_col_stringField, OVSDB_INDEX_ASC, stringField_comparator);
        ovsdb_idl_index_add_column(index, &ovsrec_test_col_numericField, OVSDB_INDEX_DESC, NULL);
        /* Done. */
    }

## Indexes Querying

### Iterators

The recommended way to do queries is using a "ranged foreach", an "equal
foreach" or a "full foreach" over an index. The mechanism works as follow:

1. Create a cursor
2. Pass the cursor, a row (ovsrec_...) and the values to the
iterator
3. Use the values

To create the cursor use the following code:

    ovsdb_idl_index_cursor my_cursor;
    ovsdb_idl_initialize_cursor(idl, &ovsrec_table_test, "by_stringField", &my_cursor);

Then that cursor can be used to do additional queries. The library implements
three different iterators: a range iterator, an equal iterator and iterator
over all the index. The range iterator receives two values and iterates over
all the records that are within that range (including both). The equal iterator
only iterates over the records that exactly match the value passed. The full
iterator iterates over all the rows in the index, in order.

Note that the index are *sorted by the "concatenation" of the values in each
indexed column*, so the ranged iterators returns all the values between
"from.col1 from.col2 ... from.coln" and "to.col1 to.col2 ... to.coln", *NOT
the rows with a value in column 1 between from.col1 and to.col1, and so on*.

The iterators are macros especific to each table. To use those iterators
consider the following code:

    /* Equal Iterator
     * Iterates over all the records equal to value (by the indexed value)
     */
    ovsrec_test *record;
    ovsrec_test value;
    value.stringField = "hello world";
    OVSREC_TEST_FOR_EACH_EQUAL(record, &my_cursor, &value) {
        /* Can return zero, one or more records */
        assert(strcmp(record->stringField, "hello world") == 0);
        printf("Found one record with %s", record->stringField);
    }

    /*
     * Ranged iterator
     * Iterates over all the records between two values (including both)
     */
    ovsrec_test value_from, value_to;
    value_from.stringField = "aaa";
    value_from.stringField = "mmm";
    OVSREC_TEST_FOR_EACH_RANGE(record, &my_cursor, &value_from, &value_to) {
        /* Can return zero, one or more records */
        assert(strcmp("aaa", record->stringField) <= 0);
        assert(strcmp(record->stringField, "mmm") <= 0);
        printf("Found one record with %s", record->stringField);
    }

    /*
     * Iterator over all the index
     * Iterates over all the records in the index
     */
    OVSREC_TEST_FOR_EACH_BYINDEX(record, &my_cursor) {
        /* Can return zero, one or more records */
        printf("Found one record with %s", record->stringField);
    }

### General Index Access

Although the iterators allow many use cases eventually thay may not fit some. In
that case the indexes can be queried by a more general API. In fact, the
iterators were built over that functions.

The functions are:

1. `ovsrec_<table>_index_compare`
2. `ovsrec_<table>_index_next`
3. `ovsrec_<table>_index_find`
4. `ovsrec_<table>_index_forward_to`
5. `ovsrec_<table>_index_get_data`

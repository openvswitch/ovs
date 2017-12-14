..
      Copyright (c) 2017 Nicira, Inc.

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

=====
ovsdb
=====

Description
===========

OVSDB, the Open vSwitch Database, is a database system whose network
protocol is specified by RFC 7047.  The RFC does not specify an on-disk
storage format. This manpage documents the format used by Open vSwitch.

Most users do not need to be concerned with this specification.  Instead,
to manipulate OVSDB files, refer to `ovsdb-tool(1)`.  For an
introduction to OVSDB as a whole, read `ovsdb(7)`.

OVSDB files explicitly record changes that are implied by the database schema.
For example, the OVSDB "garbage collection" feature means that when a client
removes the last reference to a garbage-collected row, the database server
automatically removes that row.  The database file explicitly records the
deletion of the garbage-collected row, so that the reader does not need to
infer it.

OVSDB files do not include the values of ephemeral columns.

Database files are text files encoded in UTF-8 with LF (U+000A) line ends,
organized as append-only series of records.  Each record consists of 2
lines of text.

The first line in each record has the format ``OVSDB JSON`` *length* *hash*,
where *length* is a positive decimal integer and *hash* is a SHA-1 checksum
expressed as 40 hexadecimal digits.  Words in the first line must be separated
by exactly one space.

The second line must be exactly *length* bytes long (including the LF) and its
SHA-1 checksum (including the LF) must match *hash* exactly.  The line's
contents must be a valid JSON object as specified by RFC 4627.  Strings in the
JSON object must be valid UTF-8.  To ensure that the second line is exactly one
line of text, the OVSDB implementation expresses any LF characters within a
JSON string as ``\n``.  For the same reason, and to save space, the OVSDB
implementation does not "pretty print" the JSON object with spaces and LFs.
(The OVSDB implementation tolerates LFs when reading an OVSDB database file, as
long as *length* and *hash* are correct.)

JSON Notation
-------------

We use notation from RFC 7047 here to describe the JSON data in records.
In addition to the notation defined there, we add the following:

<raw-uuid>
    A 36-character JSON string that contains a UUID in the format described by
    RFC 4122, e.g. ``"550e8400-e29b-41d4-a716-446655440000"``

Standalone Format
-----------------

The first record in a standalone database contains the JSON schema for the
database, as specified in RFC 7047.  Only this record is mandatory (a
standalone file that contains only a schema represents an empty database).

The second and subsequent records in a standalone database are transaction
records.  Each record may have the following optional special members,
which do not have any semantics but are often useful to administrators
looking through a database log with ``ovsdb-tool show-log``:

``"_date": <integer>``
    The time at which the transaction was committed, as an integer number of
    milliseconds since the Unix epoch.  Early versions of OVSDB counted seconds
    instead of milliseconds; these can be detected by noticing that their
    values are less than 2**32.

    OVSDB always writes a ``_date`` member.

``"_comment": <string>``
    A JSON string that specifies the comment provided in a transaction
    ``comment`` operation.  If a transaction has multiple ``comment``
    operations, OVSDB concatenates them into a single ``_comment`` member,
    separated by a new-line.

    OVSDB only writes a ``_comment`` member if it would be
    a nonempty string.

Each of these records also has one or more additional members, each of which
maps from the name of a database table to a <table-txn>:

<table-txn>
    A JSON object that describes the effects of a transaction on a database
    table.  Its names are <raw-uuid>s for rows in the table and its values are
    <row-txn>s.

<row-txn>
    Either ``null``, which indicates that the transaction deleted this row, or
    a JSON object that describes how the transaction inserted or modified the
    row, whose names are the names of columns and whose values are <value>s
    that give the column's new value.

    For new rows, the OVSDB implementation omits columns whose values have the
    default values for their types defined in RFC 7047 section 5.2.1; for
    modified rows, the OVSDB implementation omits columns whose values are
    unchanged.

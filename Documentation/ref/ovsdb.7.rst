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

OVSDB, the Open vSwitch Database, is a network database system.  Schemas in
OVSDB specify the tables in a database and their columns' types and can
include data, uniqueness, and referential integrity constraints.  OVSDB
offers atomic, consistent, isolated, durable transactions.  RFC 7047
specifies the JSON-RPC based protocol that OVSDB clients and servers use to
communicate.

The OVSDB protocol is well suited for state synchronization because it
allows each client to monitor the contents of a whole database or a subset
of it.  Whenever a monitored portion of the database changes, the server
tells the client what rows were added or modified (including the new
contents) or deleted.  Thus, OVSDB clients can easily keep track of the
newest contents of any part of the database.

While OVSDB is general-purpose and not particularly specialized for use with
Open vSwitch, Open vSwitch does use it for multiple purposes.  The leading use
of OVSDB is for configuring and monitoring ``ovs-vswitchd(8)``, the Open
vSwitch switch daemon, using the schema documented in
``ovs-vswitchd.conf.db(5)``.  The Open Virtual Network (OVN) sub-project of OVS
uses two OVSDB schemas, documented in ``ovn-nb(5)`` and ``ovn-sb(5)``.
Finally, Open vSwitch includes the "VTEP" schema, documented in
``vtep(5)`` that many third-party hardware switches support for
configuring VXLAN, although OVS itself does not directly use this schema.

The OVSDB protocol specification allows independent, interoperable
implementations of OVSDB to be developed.  Open vSwitch includes an OVSDB
server implementation named ``ovsdb-server(1)``, which supports several
protocol extensions documented in its manpage, and a basic command-line OVSDB
client named ``ovsdb-client(1)``, as well as OVSDB client libraries for C and
for Python.  Open vSwitch documentation often speaks of these OVSDB
implementations in Open vSwitch as simply "OVSDB," even though that is distinct
from the OVSDB protocol; we make the distinction explicit only when it might
otherwise be unclear from the context.

In addition to these generic OVSDB server and client tools, Open vSwitch
includes tools for working with databases that have specific schemas:
``ovs-vsctl`` works with the ``ovs-vswitchd`` configuration database,
``vtep-ctl`` works with the VTEP database, ``ovn-nbctl`` works with
the OVN Northbound database, and so on.

RFC 7047 specifies the OVSDB protocol but it does not specify an on-disk
storage format.  Open vSwitch includes ``ovsdb-tool(1)`` for working with its
own on-disk database formats.  The most notable feature of this format is that
``ovsdb-tool(1)`` makes it easy for users to print the transactions that have
changed a database since the last time it was compacted.  This feature is often
useful for troubleshooting.

Schemas
=======

Schemas in OVSDB have a JSON format that is specified in RFC 7047.  They
are often stored in files with an extension ``.ovsschema``.  An
on-disk database in OVSDB includes a schema and data, embedding both into a
single file.  The Open vSwitch utility ``ovsdb-tool`` has commands
that work with schema files and with the schemas embedded in database
files.

An Open vSwitch schema has three important identifiers.  The first is its
name, which is also the name used in JSON-RPC calls to identify a database
based on that schema.  For example, the schema used to configure Open
vSwitch has the name ``Open_vSwitch``.  Schema names begin with a
letter or an underscore, followed by any number of letters, underscores, or
digits.  The ``ovsdb-tool`` commands ``schema-name`` and
``db-name`` extract the schema name from a schema or database
file, respectively.

An OVSDB schema also has a version of the form ``x.y.z`` e.g. ``1.2.3``.
Schemas managed within the Open vSwitch project manage version numbering in the
following way (but OVSDB does not mandate this approach).  Whenever we change
the database schema in a non-backward compatible way (e.g. when we delete a
column or a table), we increment <x> and set <y> and <z> to 0.  When we change
the database schema in a backward compatible way (e.g. when we add a new
column), we increment <y> and set <z> to 0.  When we change the database schema
cosmetically (e.g. we reindent its syntax), we increment <z>.  The
``ovsdb-tool`` commands ``schema-version`` and ``db-version`` extract the
schema version from a schema or database file, respectively.

Very old OVSDB schemas do not have a version, but RFC 7047 mandates it.

An OVSDB schema optionally has a "checksum."  RFC 7047 does not specify the use
of the checksum and recommends that clients ignore it.  Open vSwitch uses the
checksum to remind developers to update the version: at build time, if the
schema's embedded checksum, ignoring the checksum field itself, does not match
the schema's content, then it fails the build with a recommendation to update
the version and the checksum.  Thus, a developer who changes the schema, but
does not update the version, receives an automatic reminder.  In practice this
has been an effective way to ensure compliance with the version number policy.
The ``ovsdb-tool`` commands ``schema-cksum`` and ``db-cksum`` extract the
schema checksum from a schema or database file, respectively.

Service Models
==============

OVSDB supports two service models for databases: **standalone**, and
**active-backup**.  The service models provide different compromises
among consistency and availability.

RFC 7047, which specifies the OVSDB protocol, does not mandate or specify
any particular service model.

The following sections describe the individual service models.

Standalone Database Service Model
---------------------------------

A **standalone** database runs a single server.  If the server stops running,
the database becomes inaccessible, and if the server's storage is lost or
corrupted, the database's content is lost.  This service model is appropriate
when the database controls a process or activity to which it is linked via
"fate-sharing."  For example, an OVSDB instance that controls an Open vSwitch
virtual switch daemon, ``ovs-vswitchd``, is a standalone database because a
server failure would take out both the database and the virtual switch.

To set up a standalone database, use ``ovsdb-tool create`` to
create a database file, then run ``ovsdb-server`` to start the
database service.

Active-Backup Database Service Model
------------------------------------

An **active-backup** database runs two servers (on different hosts).  At any
given time, one of the servers is designated with the **active** role and the
other the **backup** role.  An active server behaves just like a standalone
server.  A backup server makes an OVSDB connection to the active server and
uses it to continuously replicate its content as it changes in real time.
OVSDB clients can connect to either server but only the active server allows
data modification or lock transactions.

Setup for an active-backup database starts from a working standalone database
service, which is initially the active server.  On another node, to set up a
backup server, create a database file with the same schema as the active
server.  The initial contents of the database file do not matter, as long as
the schema is correct, so ``ovsdb-tool create`` will work, as will copying the
database file from the active server.  Then use
``ovsdb-server --sync-from=<active>`` to start the backup server, where
<active> is an OVSDB connection method (see `Connection Methods`_ below) that
connects to the active server.  At that point, the backup server will fetch a
copy of the active database and keep it up-to-date until it is killed.

When the active server in an active-backup server pair fails, an administrator
can switch the backup server to an active role with the ``ovs-appctl`` command
``ovsdb-server/disconnect-active-ovsdb-server``.  Clients then have read/write
access to the now-active server.  Of course, administrators are slow to respond
compared to software, so in practice external management software detects the
active server's failure and changes the backup server's role.  For example, the
"Integration Guide for Centralized Control" in the Open vSwitch documentation
describes how to use Pacemaker for this purpose in OVN.

Suppose an active server fails and its backup is promoted to active.  If the
failed server is revived, it must be started as a backup server.  Otherwise, if
both servers are active, then they may start out of sync, if the database
changed while the server was down, and they will continue to diverge over time.
This also happens if the software managing the database servers cannot reach
the active server and therefore switches the backup to active, but other hosts
can reach both servers.  These "split-brain" problems are unsolvable in general
for server pairs.

Compared to a standalone server, the active-backup service model
somewhat increases availability, at a risk of split-brain.  It adds
generally insignificant performance overhead.

Open vSwitch 2.6 introduced support for the active-backup service model.

Database Replication
====================

OVSDB can layer **replication** on top of any of its service models.
Replication, in this context, means to make, and keep up-to-date, a read-only
copy of the contents of a database (the ``replica``).  One use of replication
is to keep an up-to-date backup of a database.  A replica used solely for
backup would not need to support clients of its own.  A set of replicas that do
serve clients could be used to scale out read access to the primary database.

A database replica is set up in the same way as a backup server in an
active-backup pair, with the difference that the replica is never promoted to
an active role.

A database can have multiple replicas.

Open vSwitch 2.6 introduced support for database replication.

Connection Methods
==================

An OVSDB **connection method** is a string that specifies how to make a
JSON-RPC connection between an OVSDB client and server.  Connection methods are
part of the Open vSwitch implementation of OVSDB and not specified by RFC 7047.
``ovsdb-server`` uses connection methods to specify how it should listen for
connections from clients and ``ovsdb-client`` uses them to specify how it
should connect to a server.  Connections in the opposite direction, where
``ovsdb-server`` connects to a client that is configured to listen for an
incoming connection, are also possible.

Connection methods are classified as **active** or **passive**.  An active
connection method makes an outgoing connection to a remote host; a passive
connection method listens for connections from remote hosts.  The most common
arrangement is to configure an OVSDB server with passive connection methods and
clients with active ones, but the OVSDB implementation in Open vSwitch supports
the opposite arrangement as well.

OVSDB supports the following active connection methods:

ssl:<ip>:<port>
    The specified SSL or TLS <port> on the host at the given <ip>.

tcp:<ip>:<port>
    The specified TCP <port> on the host at the given <ip>.

unix:<file>
    On Unix-like systems, connect to the Unix domain server socket named
    <file>.

    On Windows, connect to a local named pipe that is represented by a file
    created in the path <file> to mimic the behavior of a Unix domain socket.

OVSDB supports the following passive connection methods:

pssl:<port>[:<ip>]
    Listen on the given TCP <port> for SSL or TLS connections.  By default,
    connections are not bound to a particular local IP address.  Specifying
    <ip> limits connections to those from the given IP.

ptcp:<port>[:<ip>]
    Listen on the given TCP <port>.  By default, connections are not bound to a
    particular local IP address.  Specifying <ip> limits connections to those
    from the given IP.

punix:<file>
    On Unix-like systems, listens for connections on the Unix domain socket
    named <file>.

    On Windows, listens on a local named pipe, creating a named pipe
    <file> to mimic the behavior of a Unix domain socket.

All IP-based connection methods accept IPv4 and IPv6 addresses.  To specify an
IPv6 address, wrap it in square brackets, e.g.  ``ssl:[::1]:6640``.  Passive
IP-based connection methods by default listen for IPv4 connections only; use
``[::]`` as the address to accept both IPv4 and IPv6 connections,
e.g. ``pssl:6640:[::]``.  DNS names are not accepted.  On Linux, use
``%<device>`` to designate a scope for IPv6 link-level addresses,
e.g. ``ssl:[fe80::1234%eth0]:6653``.

The <port> may be omitted from connection methods that use a port number.  The
default <port> for TCP-based connection methods is 6640, e.g. ``pssl:`` is
equivalent to ``pssl:6640``.  In Open vSwitch prior to version 2.4.0, the
default port was 6632.  To avoid incompatibility between older and newer
versions, we encourage users to specify a port number.

The ``ssl`` and ``pssl`` connection methods requires additional configuration
through ``--private-key``, ``--certificate``, and ``--ca-cert`` command line
options.  Open vSwitch can be built without SSL support, in which case these
connection methods are not supported.

Database Life Cycle
===================

This section describes how to handle various events in the life cycle of
a database using the Open vSwitch implementation of OVSDB.

Creating a Database
-------------------

Creating and starting up the service for a new database was covered
separately for each database service model in the `Service
Models`_ section, above.

Backing Up and Restoring a Database
-----------------------------------

OVSDB is often used in contexts where the database contents are not
particularly valuable.  For example, in many systems, the database for
configuring ``ovs-vswitchd`` is essentially rebuilt from scratch
at boot time.  It is not worthwhile to back up these databases.

When OVSDB is used for valuable data, a backup strategy is worth
considering.  One way is to use database replication, discussed above in
`Database Replication`_ which keeps an online, up-to-date
copy of a database, possibly on a remote system.  This works with all OVSDB
service models.

A more common backup strategy is to periodically take and store a snapshot.
For the standalone and active-backup service models, making a copy of the
database file, e.g. using ``cp``, effectively makes a snapshot, and because
OVSDB database files are append-only, it works even if the database is being
modified when the snapshot takes place.

Another way to make a backup is to use ``ovsdb-client backup``, which
connects to a running database server and outputs an atomic snapshot of its
schema and content, in the same format used for on-disk databases.

Multiple options are also available when the time comes to restore a database
from a backup.  One option is to stop the database server or servers, overwrite
the database file with the backup (e.g. with ``cp``), and then restart the
servers.  Another way is to use ``ovsdb-client restore``, which connects to a
running database server and replaces the data in one of its databases by a
provided snapshot.  The advantage of ``ovsdb-client restore`` is that it causes
zero downtime for the database and its server.  It has the downside that UUIDs
of rows in the restored database will differ from those in the snapshot,
because the OVSDB protocol does not allow clients to specify row UUIDs.

None of these approaches saves and restores data in columns that the schema
designates as ephemeral.  This is by design: the designer of a schema only
marks a column as ephemeral if it is acceptable for its data to be lost
when a database server restarts.

Upgrading or Downgrading a Database
-----------------------------------

The evolution of a piece of software can require changes to the schemas of the
databases that it uses.  For example, new features might require new tables or
new columns in existing tables, or conceptual changes might require a database
to be reorganized in other ways.  In some cases, the easiest way to deal with a
change in a database schema is to delete the existing database and start fresh
with the new schema, especially if the data in the database is easy to
reconstruct.  But in many other cases, it is better to convert the database
from one schema to another.

The OVSDB implementation in Open vSwitch has built-in support for some simple
cases of converting a database from one schema to another.  This support can
handle changes that add or remove database columns or tables or that eliminate
constraints (for example, changing a column that must have exactly one value
into one that has one or more values).  It can also handle changes that add
constraints or make them stricter, but only if the existing data in the
database satisfies the new constraints (for example, changing a column that has
one or more values into a column with exactly one value, if every row in the
column has exactly one value).  The built-in conversion can cause data loss in
obvious ways, for example if the new schema removes tables or columns, or
indirectly, for example by deleting unreferenced rows in tables that the new
schema marks for garbage collection.

Converting a database can lose data, so it is wise to make a backup beforehand.

To use OVSDB's built-in support for schema conversion with a standalone or
active-backup database, first stop the database server or servers, then use
``ovsdb-tool convert`` to convert it to the new schema, and then restart the
database server.

Schema versions and checksums (see Schemas_ above) can give hints about whether
a database needs to be converted to a new schema.  If there is any question,
though, the ``needs-conversion`` command on ``ovsdb-tool`` can provide a
definitive answer.

Working with Database History
-----------------------------

Both on-disk database formats that OVSDB supports are organized as a stream of
transaction records.  Each record describes a change to the database as a list
of rows that were inserted or deleted or modified, along with the details.
Therefore, in normal operation, a database file only grows, as each change
causes another record to be appended at the end.  Usually, a user has no need
to understand this file structure.  This section covers some exceptions.

Compacting Databases
--------------------

If OVSDB database files were truly append-only, then over time they would grow
without bound.  To avoid this problem, OVSDB can **compact** a database file,
that is, replace it by a new version that contains only the current database
contents, as if it had been inserted by a single transaction.  From time to
time, ``ovsdb-server`` automatically compacts a database that grows much larger
than its minimum size.

Because ``ovsdb-server`` automatically compacts databases, it is usually not
necessary to compact them manually, but OVSDB still offers a few ways to do it.
First, ``ovsdb-tool compact`` can compact a standalone or active-backup
database that is not currently being served by ``ovsdb-server`` (or otherwise
locked for writing by another process).  To compact any database that is
currently being served by ``ovsdb-server``, use ``ovs-appctl`` to send the
``ovsdb-server/compact`` command.  Each server in an active-backup database
maintains its database file independently, so to compact all of them, issue
this command separately on each server.

Viewing History
---------------

The ``ovsdb-tool`` utility's ``show-log`` command displays the transaction
records in an OVSDB database file in a human-readable format.  By default, it
shows minimal detail, but adding the option ``-m`` once or twice increases the
level of detail.  In addition to the transaction data, it shows the time and
date of each transaction and any "comment" added to the transaction by the
client.  The comments can be helpful for quickly understanding a transaction;
for example, ``ovs-vsctl`` adds its command line to the transactions that it
makes.

For active-backup databases, the sequence of transactions in each server's log
will differ, even at points when they reflect the same data.

Truncating History
------------------

It may occasionally be useful to "roll back" a database file to an earlier
point.  Because of the organization of OVSDB records, this is easy to do.
Start by noting the record number <i> of the first record to delete in
``ovsdb-tool show-log`` output.  Each record is two lines of plain text, so
trimming the log is as simple as running ``head -n <j>``, where <j> = 2 * <i>.

Corruption
----------

When ``ovsdb-server`` opens an OVSDB database file, of any kind, it reads as
many transaction records as it can from the file until it reaches the end of
the file or it encounters a corrupted record.  At that point it stops reading
and regards the data that it has read to this point as the full contents of the
database file, effectively rolling the database back to an earlier point.

Each transaction record contains an embedded SHA-1 checksum, which the server
verifies as it reads a database file.  It detects corruption when a checksum
fails to verify.  Even though SHA-1 is no longer considered secure for use in
cryptography, it is acceptable for this purpose because it is not used to
defend against malicious attackers.

The first record in a standalone or active-backup database file specifies the
schema.  ``ovsdb-server`` will refuse to work with a database whose first
record is corrupted.  Delete and recreate such a database, or restore it from a
backup.

When ``ovsdb-server`` adds records to a database file in which it detected
corruption, it first truncates the file just after the last good record.

See Also
========

RFC 7047, "The Open vSwitch Database Management Protocol."

Open vSwitch implementations of generic OVSDB functionality:
``ovsdb-server(1)``, ``ovsdb-client(1)``, ``ovsdb-tool(1)``.

Tools for working with databases that have specific OVSDB schemas:
``ovs-vsctl(8)``, ``vtep-ctl(8)``, ``ovn-nbctl(8)``, ``ovn-sbctl(8)``.

OVSDB schemas for Open vSwitch and related functionality:
``ovs-vswitchd.conf.db(5)``, ``vtep(5)``, ``ovn-nb(5)``, ``ovn-sb(5)``.

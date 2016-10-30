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

================================
OVSDB Replication Implementation
================================

Given two Open vSwitch databases with the same schema, OVSDB replication keeps
these databases in the same state, i.e. each of the databases have the same
contents at any given time even if they are not running in the same host.  This
document elaborates on the implementation details to provide this
functionality.

Terminology
-----------

Source of truth database
  database whose content will be replicated to another database.

Active server
  ovsdb-server providing RPC interface to the source of truth database.

Standby server
  ovsdb-server providing RPC interface to the database that is not the source
  of truth.

Design
------

The overall design of replication consists of one ovsdb-server (active server)
communicating the state of its databases to another ovsdb-server (standby
server) so that the latter keep its own databases in that same state.  To
achieve this, the standby server acts as a client of the active server, in the
sense that it sends a monitor request to keep up to date with the changes in
the active server databases. When a notification from the active server
arrives, the standby server executes the necessary set of operations so its
databases reach the same state as the the active server databases. Below is the
design represented as a diagram.::

    +--------------+    replication     +--------------+
    |    Active    |<-------------------|   Standby    |
    | OVSDB-server |                    | OVSDB-server |
    +--------------+                    +--------------+
            |                                  |
            |                                  |
        +-------+                          +-------+
        |  SoT  |                          |       |
        | OVSDB |                          | OVSDB |
        +-------+                          +-------+

Setting Up The Replication
--------------------------

To initiate the replication process, the standby server must be executed
indicating the location of the active server via the command line option
``--sync-from=server``, where server can take any form described in the
ovsdb-client manpage and it must specify an active connection type (tcp, unix,
ssl). This option will cause the standby server to attempt to send a monitor
request to the active server in every main loop iteration, until the active
server responds.

When sending a monitor request the standby server is doing the following:

1. Erase the content of the databases for which it is providing a RPC
   interface.

2. Open the jsonrpc channel to communicate with the active server.

3. Fetch all the databases located in the active server.

4. For each database with the same schema in both the active and standby
   servers: construct and send a monitor request message specifying the tables
   that will be monitored (i.e all the tables on the database except the ones
   blacklisted [*]).

5. Set the standby database to the current state of the active database.

Once the monitor request message is sent, the standby server will continuously
receive notifications of changes occurring to the tables specified in the
request. The process of handling this notifications is detailed in the next
section.

[*] A set of tables that will be excluded from replication can be configure as
a blacklist of tables via the command line option
``--sync-exclude-tables=db:table[,db:table]...``, where db corresponds to the
database where the table resides.

Replication Process
-------------------

The replication process consists on handling the update notifications received
in the standby server caused by the monitor request that was previously sent to
the active server. In every loop iteration, the standby server attempts to
receive a message from the active server which can be an error, an echo message
(used to keep the connection alive) or an update notification. In case the
message is a fatal error, the standby server will disconnect from the active
without dropping the replicated data. If it is an echo message, the standby
server will reply with an echo message as well. If the message is an update
notification, the following process occurs:

1. Create a new transaction.

2. Get the ``<table-updates>`` object from the ``params`` member of the
   notification.

3. For each ``<table-update>`` in the ``<table-updates>`` object do:

    1. For each ``<row-update>`` in ``<table-update>`` check what kind of
       operation should be executed according to the following criteria
       about the presence of the object members:

       - If ``old`` member is not present, execute an insert operation using
         ``<row>`` from the ``new`` member.

       - If ``old`` member is present and ``new`` member is not present,
         execute a delete operation using ``<row>`` from the ``old`` member

       - If both ``old`` and ``new`` members are present, execute an update
         operation using ``<row>`` from the ``new`` member.

4. Commit the transaction.

   If an error occurs during the replication process, all replication is
   restarted by resending a new monitor request as described in the section
   "Setting up the replication".

Runtime Management Commands
---------------------------

Runtime management commands can be sent to a running standby server via
ovs-appctl in order to configure the replication functionality. The available
commands are the following.

``ovsdb-server/set-remote-ovsdb-server {server}``
  sets the name of the active server

``ovsdb-server/get-remote-ovsdb-server``
  gets the name of the active server

``ovsdb-server/connect-remote-ovsdb-server``
  causes the server to attempt to send a monitor request every main loop
  iteration

``ovsdb-server/disconnect-remote-ovsdb-server``
  closes the jsonrpc channel between the active server and frees the memory
  used for the replication configuration.

``ovsdb-server/set-sync-exclude-tables {db:table,...}``
  sets the tables list that will be excluded from being replicated

``ovsdb-server/get-sync-excluded-tables``
  gets the tables list that is currently excluded from replication

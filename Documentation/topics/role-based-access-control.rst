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

=========================
Role Based Access Control
=========================

Where SSL provides authentication when connecting to an OVS database, role
based access control (RBAC) provides authorization to operations performed
by clients connecting to an OVS database. RBAC allows for administrators to
restrict the database operations a client may perform and thus enhance the
security already provided by SSL.

In theory, any OVS database could define RBAC roles and permissions, but at
present only the OVN southbound database has the appropriate tables defined to
facilitate RBAC.

Mechanics
---------
RBAC is intended to supplement SSL. In order to enable RBAC, the connection to
the database must use SSL. Some permissions in RBAC are granted based on the
certificate common name (CN) of the connecting client.

RBAC is controlled with two database tables, RBAC_Role and RBAC_Permission.
The RBAC_Permission table contains records that describe a set of permissions
for a given table in the database.

The RBAC_Permission table contains the following columns:

table
  The table in the database for which permissions are being described.
insert_delete
  Describes whether insertion and deletion of records is allowed.
update
  A list of columns that are allowed to be updated.
authorization
  A list of column names. One of the listed columns must match the SSL
  certificate CN in order for the attempted operation on the table to
  succeed. If a key-value pair is provided, then the key is the column name,
  and the value is the name of a key in that column. An empty string gives
  permission to all clients to perform operations.

The RBAC_Role table contains the following columns:

name
  The name of the role being defined
permissions
  A list of key-value pairs. The key is the name of a table in the database,
  and the value is a UUID of a record in the RBAC_Permission table that
  describes the permissions the role has for that table.

.. note::

   All tables not explicitly referenced in an RBAC_Role record are read-only

In order to enable RBAC, specify the role name as an argument to the
set-connection command for the database. As an example, to enable the
"ovn-controller" role on the OVN southbound database, use the following
command:

::

   $ ovn-sbctl set-connection role=ovn-controller ssl:192.168.0.1:6642

Pre-defined Roles
-----------------
This section describes roles that have been defined internally by OVS/OVN.

ovn-controller
~~~~~~~~~~~~~~
The ovn-controller role is specified in the OVN southbound database and is
intended for use by hypervisors running the ovn-controller daemon.
ovn-controller connects to the OVN southbound database mostly to read
information, but there are a few cases where ovn-controller also needs to
write. The ovn-controller role was designed to allow for ovn-controllers
to write to the southbound database only in places where it makes sense to do
so. This way, if an intruder were to take over a hypervisor running
ovn-controller, it is more difficult to compromise the entire overlay network.

It is strongly recommended to set the ovn-controller role for the OVN
southbound database to enhance security.

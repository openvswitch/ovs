..
      Copyright 2021, Red Hat, Inc.

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

===============================
Scaling OVSDB Access With Relay
===============================

Open vSwitch 2.16 introduced support for OVSDB Relay mode with the goal to
increase database scalability for a big deployments.  Mainly, OVN (Open Virtual
Network) Southbound Database deployments.  This document describes the main
concept and provides the configuration examples.

What is OVSDB Relay?
--------------------

Relay is a database service model in which one ``ovsdb-server`` (``relay``)
connects to another standalone or clustered database server
(``relay source``) and maintains in-memory copy of its data, receiving
all the updates via this OVSDB connection.  Relay server handles all the
read-only requests (monitors and transactions) on its own and forwards all the
transactions that requires database modifications to the relay source.

Why is this needed?
-------------------

Some OVN deployment could have hundreds or even thousands of nodes.  On each of
these nodes there is an ovn-controller, which is connected to the
OVN_Southbound database that is served by a standalone or clustered OVSDB.
Standalone database is handled by a single ovsdb-server process and clustered
could consist of 3 to 5 ovsdb-server processes.  For the clustered database,
higher number of servers may significantly increase transaction latency due
to necessity for these servers to reach consensus.  So, in the end limited
number of ovsdb-server processes serves ever growing number of clients and this
leads to performance issues.

Read-only access could be scaled up with OVSDB replication on top of
active-backup service model, but ovn-controller is a read-mostly client, not
a read-only, i.e. it needs to execute write transactions from time to time.
Here relay service model comes into play.

2-Tier Deployment
-----------------

Solution for the scaling issue could look like a 2-tier deployment, where
a set of relay servers is connected to the main database cluster
(OVN_Southbound) and clients (ovn-conrtoller) connected to these relay
servers::

                                    172.16.0.1
   +--------------------+   +----+ ovsdb-relay-1 +--+---+ client-1
   |                    |   |                       |
   |    Clustered       |   |                       +---+ client-2
   |     Database       |   |                        ...
   |                    |   |                       +---+ client-N
   |    10.0.0.2        |   |
   |  ovsdb-server-2    |   |       172.16.0.2
   |   +        +       |   +----+ ovsdb-relay-2 +--+---+ client-N+1
   |   |        |       |   |                       |
   |   |        +       +---+                       +---+ client-N+2
   |   |   10.0.0.1     |   |                        ...
   |   | ovsdb-server-1 |   |                       +---+ client-2N
   |   |        +       |   |
   |   |        |       |   |
   |   +        +       |   +      ... ... ... ... ...
   |  ovsdb-server-3    |   |
   |    10.0.0.3        |   |                       +---+ client-KN-1
   |                    |   |       172.16.0.K      |
   +--------------------+   +----+ ovsdb-relay-K +--+---+ client-KN

In practice, the picture might look a bit more complex, because all relay
servers might connect to any member of a main cluster and clients might
connect to any relay server of their choice.

Assuming that servers of a main cluster started like this::

  $ ovsdb-server --remote=ptcp:6642:10.0.0.1 ovn-sb-1.db

The same for other two servers.  In this case relay servers could be
started like this::

  $ REMOTES=tcp:10.0.0.1:6642,tcp:10.0.0.2:6642,tcp:10.0.0.3:6642
  $ ovsdb-server --remote=ptcp:6642:172.16.0.1 relay:OVN_Southbound:$REMOTES
  $ ...
  $ ovsdb-server --remote=ptcp:6642:172.16.0.K relay:OVN_Southbound:$REMOTES

Open vSwitch 3.3 introduced support for configuration files via
``--config-file`` command line option.  The configuration file for relay
database servers in this case may look like this::

  {
      "remotes": { "ptcp:6642:172.16.0.X": {} },
      "databases": {
          "OVN_Southbound": {
              "service-model": "relay",
              "source": {
                  "$REMOTES": {}
              }
          }
      }
  }

See ``ovsdb-server(1)`` and  ``Relay Service Model`` in ``ovsdb(7)`` for more
configuration options.

Every relay server could connect to any of the cluster members of their choice,
fairness of load distribution is achieved by shuffling remotes.

For the actual clients, they could be configured to connect to any of the
relay servers.  For ovn-controllers the configuration could look like this::

  $ REMOTES=tcp:172.16.0.1:6642,...,tcp:172.16.0.K:6642
  $ ovs-vsctl set Open_vSwitch . external-ids:ovn-remote=$REMOTES

Setup like this allows the system to serve ``K * N`` clients while having only
``K`` actual connections on the main clustered database keeping it in a
stable state.

It's also possible to create multi-tier deployments by connecting one set
of relay servers to another (smaller) set of relay servers, or even create
tree-like structures with the cost of increased latency for write transactions,
because they will be forwarded multiple times.

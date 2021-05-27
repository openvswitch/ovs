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

============================
Debugging with Record/Replay
============================

The ``ovs-replay`` library provides a set of internal functions for recording
certain events for later replay.  This library is integrated into the
``stream`` and some other modules to record all incoming data across all
streams (ssl, tcp, unixctl) of applications based on Open vSwitch libraries
and play these streams later for debugging or performance testing purposes.

Support for this feature is currently integrated into the ``ovsdb-server`` and
``ovsdb-client`` applications.  As a result, this allows to record lifecycle
of the ``ovsdb-server`` process in large OVN deployments.  Later, by using only
the recorded data, the user can replay transactions and connections that
occurred in a large deployment on their local PC.  At the same time it is
possible to tweak various log levels, run a process under debugger or tracer,
measure performance with ``perf``, and so on.

 .. note::

    The current version of record/replay engine does not work correctly with
    internal time-based events that leats to communications with other
    processes.  For this reason it can not be used with clustered databases
    (RAFT implementation is heavily time dependent).
    In addition, recording automatically disables inactivity probes on
    JSONRPC connections and updates for the Manager status in a _Server
    database.

High-level feature overview was presented on Open vSwitch and OVN 2020 Fall
Conference: `Debugging OVSDB with stream record/replay`__

__ https://www.openvswitch.org/support/ovscon2020/slides/Debugging-OVSDB-with-stream-record_replay.pdf

Recording ovsdb-server events
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To start recording events for the ``ovsdb-server`` process, there is a special
command line argument ``--record``.  Before starting the database server, make
sure that you have a copy of a database file, so you can use it for replay
later.  Here are the general steps to take:

1. Create a directory where the replay files will be stored::

    $ mkdir replay-dir
    $ REPLAY_DIR=$(pwd)/replay-dir

2. Copy the current database file for later use::

    $ cp my_database $REPLAY_DIR/

3. Run ``ovsdb-server`` with recording enabled::

    $ ovsdb-server --record=$REPLAY_DIR <other arguments> my_database

4. Work with the database as usual.

5. Stop the ``ovsdb-server`` process at the end (it is important to send an
   ``exit`` command so that during replay the process will exit in the end
   too)::

    $ ovs-appctl -t ovsdb-server exit

After that ``$REPLAY_DIR`` should contain replay files with recorded data.

Replay of recorded session
~~~~~~~~~~~~~~~~~~~~~~~~~~

During replay, the ``ovsdb-server`` will receive all the same connections,
transactions and commands as it had at the time of recording, but it will not
create any actual network/socket connections and will not communicate with
any other process.  Everything will be read from the replay files.

Since there is no need to wait for IPC, all events will be received one by one
without any delays, so the application will process them as quickly as
possible. This can be used as a performance test where the user can measure how
quickly the ``ovsdb-server`` can handle some workload recorded in a real
deployment.

The command line argument to start a replay session is ``--replay``.  The steps
will look like this:

1. Restore the database file from a previous copy::

    $ cp $REPLAY_DIR/my_database my_database

2. Start ``ovsdb-server`` with the same set of arguments as in the recording
   stage, except for ``--record``::

    $ ovsdb-server --replay=$REPLAY_DIR <other arguments> my_database

3. The process should exit in the end when the ``exit`` command is replayed.

On step 2 it is possible to add extra logging arguments to debug some recorded
issue, or run the process under debugger.  It's also possible to replay with
a different version of ``ovsdb-server`` binary as long as this does not affect
the data that goes in and out of the process, e.g. pure performance
optimizations.

~~~~~~~~~~~
Limitations
~~~~~~~~~~~

The record/replay engine has the following limitations:

1. Record/Replay of clustered databases is not supported.

2. Inactivity probes on JSONRPC connections are suppressed.

3. Manager status updates suppressed in ``ovsdb-server``.

To remove above limitations, it is necessary to implement correct handling of
internally generated time-based events. (possibly by recording of time and
subsequent time warping).

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

==============================
Open vSwitch Advanced Features
==============================

Many tutorials cover the basics of OpenFlow.  This is not such a tutorial.
Rather, a knowledge of the basics of OpenFlow is a prerequisite.  If you do not
already understand how an OpenFlow flow table works, please go read a basic
tutorial and then continue reading here afterward.

It is also important to understand the basics of Open vSwitch before you begin.
If you have never used ovs-vsctl or ovs-ofctl before, you should learn a little
about them before proceeding.

Most of the features covered in this tutorial are Open vSwitch extensions to
OpenFlow.  Also, most of the features in this tutorial are specific to the
software Open vSwitch implementation.  If you are using an Open vSwitch port to
an ASIC-based hardware switch, this tutorial will not help you.

This tutorial does not cover every aspect of the features that it mentions.
You can find the details elsewhere in the Open vSwitch documentation,
especially ``ovs-ofctl(8)`` and the comments in the
``include/openflow/nicira-ext.h`` and ``include/openvswitch/meta-flow.h``
header files.

Getting Started
---------------

This is a hands-on tutorial.  To get the most out of it, you will need Open
vSwitch binaries.  You do not, on the other hand, need any physical networking
hardware or even supervisor privilege on your system.  Instead, we will use a
script called ``ovs-sandbox``, which accompanies the tutorial, that constructs
a software simulated network environment based on Open vSwitch.

You can use ``ovs-sandbox`` three ways:

* If you have already installed Open vSwitch on your system, then you should be
  able to just run ``ovs-sandbox`` from this directory without any options.

* If you have not installed Open vSwitch (and you do not want to install it),
  then you can build Open vSwitch according to the instructions in
  :doc:`/intro/install/general`, without installing it.  Then run
  ``./ovs-sandbox -b DIRECTORY`` from this directory, substituting the Open
  vSwitch build directory for ``DIRECTORY``.

* As a slight variant on the latter, you can run ``make sandbox`` from an Open
  vSwitch build directory.

When you run ``ovs-sandbox``, it does the following:

1. **CAUTION:** Deletes any subdirectory of the current directory named
   "sandbox" and any files in that directory.

2. Creates a new directory "sandbox" in the current directory.

3. Sets up special environment variables that ensure that Open vSwitch programs
   will look inside the "sandbox" directory instead of in the Open vSwitch
   installation directory.

4. If you are using a built but not installed Open vSwitch, installs the Open
   vSwitch manpages in a subdirectory of "sandbox" and adjusts the ``MANPATH``
   environment variable to point to this directory.  This means that you can
   use, for example, ``man ovs-vsctl`` to see a manpage for the ``ovs-vsctl``
   program that you built.

5. Creates an empty Open vSwitch configuration database under "sandbox".

6. Starts ``ovsdb-server`` running under "sandbox".

7. Starts ``ovs-vswitchd`` running under "sandbox", passing special options
   that enable a special "dummy" mode for testing.

8. Starts a nested interactive shell inside "sandbox".

At this point, you can run all the usual Open vSwitch utilities from the nested
shell environment.  You can, for example, use ``ovs-vsctl`` to create a bridge::

    $ ovs-vsctl add-br br0

From Open vSwitch's perspective, the bridge that you create this way is as real
as any other.  You can, for example, connect it to an OpenFlow controller or
use ``ovs-ofctl`` to examine and modify it and its OpenFlow flow table.  On the
other hand, the bridge is not visible to the operating system's network stack,
so ``ip`` cannot see it or affect it, which means that utilities like ``ping``
and ``tcpdump`` will not work either.  (That has its good side, too: you can't
screw up your computer's network stack by manipulating a sandboxed OVS.)

When you're done using OVS from the sandbox, exit the nested shell (by entering
the "exit" shell command or pressing Control+D).  This will kill the daemons
that ``ovs-sandbox`` started, but it leaves the "sandbox" directory and its
contents in place.

The sandbox directory contains log files for the Open vSwitch dameons.  You can
examine them while you're running in the sandboxed environment or after you
exit.

Using GDB
---------

GDB support is not required to go through the tutorial. It is added in case
user wants to explore the internals of OVS programs.

GDB can already be used to debug any running process, with the usual
``gdb <program> <process-id>`` command.

``ovs-sandbox`` also has a ``-g`` option for launching ovs-vswitchd under GDB.
This option can be handy for setting break points before ovs-vswitchd runs, or
for catching early segfaults. Similarly, a ``-d`` option can be used to run
ovsdb-server under GDB. Both options can be specified at the same time.

In addition, a ``-e`` option also launches ovs-vswitchd under GDB. However,
instead of displaying a ``gdb>`` prompt and waiting for user input,
ovs-vswitchd will start to execute immediately. ``-r`` option is the
corresponding option for running ovsdb-server under gdb with immediate
execution.

To avoid GDB mangling with the sandbox sub shell terminal, ``ovs-sandbox``
starts a new xterm to run each GDB session.  For systems that do not support X
windows, GDB support is effectively disabled.

When launching sandbox through the build tree's make file, the ``-g`` option
can be passed via the ``SANDBOXFLAGS`` environment variable.  ``make sandbox
SANDBOXFLAGS=-g`` will start the sandbox with ovs-vswitchd running under GDB in
its own xterm if X is available.

In addition, a set of GDB macros are available in ``utilities/gdb/ovs_gdb.py``.
Which are able to dump various internal data structures. See the header of the
file itself for some more details and an example.

Motivation
----------

The goal of this tutorial is to demonstrate the power of Open vSwitch flow
tables.  The tutorial works through the implementation of a MAC-learning switch
with VLAN trunk and access ports.  Outside of the Open vSwitch features that we
will discuss, OpenFlow provides at least two ways to implement such a switch:

1. An OpenFlow controller to implement MAC learning in a "reactive" fashion.
   Whenever a new MAC appears on the switch, or a MAC moves from one switch
   port to another, the controller adjusts the OpenFlow flow table to match.

2. The "normal" action.  OpenFlow defines this action to submit a packet to
   "the traditional non-OpenFlow pipeline of the switch".  That is, if a flow
   uses this action, then the packets in the flow go through the switch in the
   same way that they would if OpenFlow was not configured on the switch.

Each of these approaches has unfortunate pitfalls.  In the first approach,
using an OpenFlow controller to implement MAC learning, has a significant cost
in terms of network bandwidth and latency.  It also makes the controller more
difficult to scale to large numbers of switches, which is especially important
in environments with thousands of hypervisors (each of which contains a virtual
OpenFlow switch).  MAC learning at an OpenFlow controller also behaves poorly
if the OpenFlow controller fails, slows down, or becomes unavailable due to
network problems.

The second approach, using the "normal" action, has different problems.  First,
little about the "normal" action is standardized, so it behaves differently on
switches from different vendors, and the available features and how those
features are configured (usually not through OpenFlow) varies widely.  Second,
"normal" does not work well with other OpenFlow actions.  It is
"all-or-nothing", with little potential to adjust its behavior slightly or to
compose it with other features.

Scenario
--------

We will construct Open vSwitch flow tables for a VLAN-capable,
MAC-learning switch that has four ports:

p1
  a trunk port that carries all VLANs, on OpenFlow port 1.

p2
  an access port for VLAN 20, on OpenFlow port 2.

p3, p4
  both access ports for VLAN 30, on OpenFlow ports 3 and 4, respectively.

.. note::
  The ports' names are not significant.  You could call them eth1 through eth4,
  or any other names you like.

.. note::
  An OpenFlow switch always has a "local" port as well.  This scenario won't
  use the local port.

Our switch design will consist of five main flow tables, each of which
implements one stage in the switch pipeline:

Table 0
  Admission control.

Table 1
  VLAN input processing.

Table 2
  Learn source MAC and VLAN for ingress port.

Table 3
  Look up learned port for destination MAC and VLAN.

Table 4
  Output processing.

The section below describes how to set up the scenario, followed by a section
for each OpenFlow table.

You can cut and paste the ``ovs-vsctl`` and ``ovs-ofctl`` commands in each of
the sections below into your ``ovs-sandbox`` shell.  They are also available as
shell scripts in this directory, named ``t-setup``, ``t-stage0``, ``t-stage1``,
..., ``t-stage4``.  The ``ovs-appctl`` test commands are intended for cutting
and pasting and are not supplied separately.

Setup
-----

To get started, start ``ovs-sandbox``.  Inside the interactive shell that it
starts, run this command::

    $ ovs-vsctl add-br br0 -- set Bridge br0 fail-mode=secure

This command creates a new bridge "br0" and puts "br0" into so-called
"fail-secure" mode.  For our purpose, this just means that the OpenFlow flow
table starts out empty.

.. note::
  If we did not do this, then the flow table would start out with a single flow
  that executes the "normal" action.  We could use that feature to yield a
  switch that behaves the same as the switch we are currently building, but
  with the caveats described under "Motivation" above.)

The new bridge has only one port on it so far, the "local port" br0.  We need
to add ``p1``, ``p2``, ``p3``, and ``p4``.  A shell ``for`` loop is one way to
do it::

    for i in 1 2 3 4; do
        ovs-vsctl add-port br0 p$i -- set Interface p$i ofport_request=$i
        ovs-ofctl mod-port br0 p$i up
    done

In addition to adding a port, the ``ovs-vsctl`` command above sets its
``ofport_request`` column to ensure that port ``p1`` is assigned OpenFlow port
1, ``p2`` is assigned OpenFlow port 2, and so on.

.. note::
  We could omit setting the ofport_request and let Open vSwitch choose port
  numbers for us, but it's convenient for the purposes of this tutorial because
  we can talk about OpenFlow port 1 and know that it corresponds to ``p1``.

The ``ovs-ofctl`` command above brings up the simulated interfaces, which are
down initially, using an OpenFlow request.  The effect is similar to ``ip link
up``, but the sandbox's interfaces are not visible to the operating system and
therefore ``ip`` would not affect them.

We have not configured anything related to VLANs or MAC learning.  That's
because we're going to implement those features in the flow table.

To see what we've done so far to set up the scenario, you can run a command
like ``ovs-vsctl show`` or ``ovs-ofctl show br0``.

Implementing Table 0: Admission control
---------------------------------------

Table 0 is where packets enter the switch.  We use this stage to discard
packets that for one reason or another are invalid.  For example, packets with
a multicast source address are not valid, so we can add a flow to drop them at
ingress to the switch with::

    $ ovs-ofctl add-flow br0 \
        "table=0, dl_src=01:00:00:00:00:00/01:00:00:00:00:00, actions=drop"

A switch should also not forward IEEE 802.1D Spanning Tree Protocol (STP)
packets, so we can also add a flow to drop those and other packets with
reserved multicast protocols::

    $ ovs-ofctl add-flow br0 \
        "table=0, dl_dst=01:80:c2:00:00:00/ff:ff:ff:ff:ff:f0, actions=drop"

We could add flows to drop other protocols, but these demonstrate the pattern.

We need one more flow, with a priority lower than the default, so that flows
that don't match either of the "drop" flows we added above go on to pipeline
stage 1 in OpenFlow table 1::

    $ ovs-ofctl add-flow br0 "table=0, priority=0, actions=resubmit(,1)"

.. note::
  The "resubmit" action is an Open vSwitch extension to OpenFlow.

Testing Table 0
---------------

If we were using Open vSwitch to set up a physical or a virtual switch, then we
would naturally test it by sending packets through it one way or another,
perhaps with common network testing tools like ``ping`` and ``tcpdump`` or more
specialized tools like Scapy.  That's difficult with our simulated switch,
since it's not visible to the operating system.

But our simulated switch has a few specialized testing tools.  The most
powerful of these tools is ``ofproto/trace``.  Given a switch and the
specification of a flow, ``ofproto/trace`` shows, step-by-step, how such a flow
would be treated as it goes through the switch.

Example 1
~~~~~~~~~

Try this command::

    $ ovs-appctl ofproto/trace br0 in_port=1,dl_dst=01:80:c2:00:00:05

The output should look something like this::

    Flow: in_port=1,vlan_tci=0x0000,dl_src=00:00:00:00:00:00,dl_dst=01:80:c2:00:00:05,dl_type=0x0000

    bridge("br0")
    -------------
     0. dl_dst=01:80:c2:00:00:00/ff:ff:ff:ff:ff:f0, priority 32768
        drop

    Final flow: unchanged
    Megaflow: recirc_id=0,in_port=1,dl_src=00:00:00:00:00:00/01:00:00:00:00:00,dl_dst=01:80:c2:00:00:00/ff:ff:ff:ff:ff:f0,dl_type=0x0000
    Datapath actions: drop

The first line shows the flow being traced, in slightly greater detail
than specified on the command line.  It is mostly zeros because
unspecified fields default to zeros.

The second group of lines shows the packet's trip through bridge br0.
We see, in table 0, the OpenFlow flow that the fields matched, along
with its priority, followed by its actions, one per line.  In this
case, we see that this packet that has a reserved multicast
destination address matches the flow that drops those packets.

The final block of lines summarizes the results, which are not very
interesting here.

Example 2
~~~~~~~~~

Try another command::

    $ ovs-appctl ofproto/trace br0 in_port=1,dl_dst=01:80:c2:00:00:10

The output should be::

    Flow: in_port=1,vlan_tci=0x0000,dl_src=00:00:00:00:00:00,dl_dst=01:80:c2:00:00:10,dl_type=0x0000

    bridge("br0")
    -------------
     0. priority 0
        resubmit(,1)
     1. No match.
        drop

    Final flow: unchanged
    Megaflow: recirc_id=0,in_port=1,dl_src=00:00:00:00:00:00/01:00:00:00:00:00,dl_dst=01:80:c2:00:00:10/ff:ff:ff:ff:ff:f0,dl_type=0x0000
    Datapath actions: drop

This time the flow we handed to ``ofproto/trace`` doesn't match any of
our "drop" flows in table 0, so it falls through to the low-priority
"resubmit" flow.  The "resubmit" causes a second lookup in OpenFlow
table 1, described by the block of text that starts with "1."  We
haven't yet added any flows to OpenFlow table 1, so no flow actually
matches in the second lookup.  Therefore, the packet is still actually
dropped, which means that the externally observable results would be
identical to our first example.

Implementing Table 1: VLAN Input Processing
-------------------------------------------

A packet that enters table 1 has already passed basic validation in table 0.
The purpose of table 1 is validate the packet's VLAN, based on the VLAN
configuration of the switch port through which the packet entered the switch.
We will also use it to attach a VLAN header to packets that arrive on an access
port, which allows later processing stages to rely on the packet's VLAN always
being part of the VLAN header, reducing special cases.

Let's start by adding a low-priority flow that drops all packets, before we add
flows that pass through acceptable packets.  You can think of this as a
"default drop" flow::

    $ ovs-ofctl add-flow br0 "table=1, priority=0, actions=drop"

Our trunk port ``p1``, on OpenFlow port 1, is an easy case.  ``p1`` accepts any
packet regardless of whether it has a VLAN header or what the VLAN was, so we
can add a flow that resubmits everything on input port 1 to the next table::

    $ ovs-ofctl add-flow br0 \
        "table=1, priority=99, in_port=1, actions=resubmit(,2)"

On the access ports, we want to accept any packet that has no VLAN header, tag
it with the access port's VLAN number, and then pass it along to the next
stage::

    $ ovs-ofctl add-flows br0 - <<'EOF'
    table=1, priority=99, in_port=2, vlan_tci=0, actions=mod_vlan_vid:20, resubmit(,2)
    table=1, priority=99, in_port=3, vlan_tci=0, actions=mod_vlan_vid:30, resubmit(,2)
    table=1, priority=99, in_port=4, vlan_tci=0, actions=mod_vlan_vid:30, resubmit(,2)
    EOF

We don't write any flows that match packets with 802.1Q that enter this stage
on any of the access ports, so the "default drop" flow we added earlier causes
them to be dropped, which is ordinarily what we want for access ports.

.. note::
  Another variation of access ports allows ingress of packets tagged with VLAN
  0 (aka 802.1p priority tagged packets).  To allow such packets, replace
  ``vlan_tci=0`` by ``vlan_tci=0/0xfff`` above.

Testing Table 1
---------------

``ofproto/trace`` allows us to test the ingress VLAN flows that we added above.

Example 1: Packet on Trunk Port
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Here's a test of a packet coming in on the trunk port::

    $ ovs-appctl ofproto/trace br0 in_port=1,vlan_tci=5

The output shows the lookup in table 0, the resubmit to table 1, and the
resubmit to table 2 (which does nothing because we haven't put anything there
yet)::

    Flow: in_port=1,vlan_tci=0x0005,dl_src=00:00:00:00:00:00,dl_dst=00:00:00:00:00:00,dl_type=0x0000

    bridge("br0")
    -------------
     0. priority 0
        resubmit(,1)
     1. in_port=1, priority 99
        resubmit(,2)
     2. No match.
        drop

    Final flow: unchanged
    Megaflow: recirc_id=0,in_port=1,dl_src=00:00:00:00:00:00/01:00:00:00:00:00,dl_dst=00:00:00:00:00:00/ff:ff:ff:ff:ff:f0,dl_type=0x0000
    Datapath actions: drop

Example 2: Valid Packet on Access Port
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Here's a test of a valid packet (a packet without an 802.1Q header) coming in
on access port ``p2``::

    $ ovs-appctl ofproto/trace br0 in_port=2

The output is similar to that for the previous case, except that it
additionally tags the packet with ``p2``'s VLAN 20 before it passes it along to
table 2::

    Flow: in_port=2,vlan_tci=0x0000,dl_src=00:00:00:00:00:00,dl_dst=00:00:00:00:00:00,dl_type=0x0000

    bridge("br0")
    -------------
     0. priority 0
        resubmit(,1)
     1. in_port=2,vlan_tci=0x0000, priority 99
        mod_vlan_vid:20
        resubmit(,2)
     2. No match.
        drop

    Final flow: in_port=2,dl_vlan=20,dl_vlan_pcp=0,dl_src=00:00:00:00:00:00,dl_dst=00:00:00:00:00:00,dl_type=0x0000
    Megaflow: recirc_id=0,in_port=2,vlan_tci=0x0000,dl_src=00:00:00:00:00:00/01:00:00:00:00:00,dl_dst=00:00:00:00:00:00/ff:ff:ff:ff:ff:f0,dl_type=0x0000
    Datapath actions: drop

Example 3: Invalid Packet on Access Port
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This tests an invalid packet (one that includes an 802.1Q header) coming in on
access port ``p2``::

    $ ovs-appctl ofproto/trace br0 in_port=2,vlan_tci=5

The output shows the packet matching the default drop flow::

    Flow: in_port=2,vlan_tci=0x0005,dl_src=00:00:00:00:00:00,dl_dst=00:00:00:00:00:00,dl_type=0x0000

    bridge("br0")
    -------------
     0. priority 0
        resubmit(,1)
     1. priority 0
        drop

    Final flow: unchanged
    Megaflow: recirc_id=0,in_port=2,vlan_tci=0x0005,dl_src=00:00:00:00:00:00/01:00:00:00:00:00,dl_dst=00:00:00:00:00:00/ff:ff:ff:ff:ff:f0,dl_type=0x0000
    Datapath actions: drop

Implementing Table 2: MAC+VLAN Learning for Ingress Port
--------------------------------------------------------

This table allows the switch we're implementing to learn that the packet's
source MAC is located on the packet's ingress port in the packet's VLAN.

.. note::
  This table is a good example why table 1 added a VLAN tag to packets that
  entered the switch through an access port.  We want to associate a MAC+VLAN
  with a port regardless of whether the VLAN in question was originally part of
  the packet or whether it was an assumed VLAN associated with an access port.

It only takes a single flow to do this.  The following command adds it::

    $ ovs-ofctl add-flow br0 \
        "table=2 actions=learn(table=10, NXM_OF_VLAN_TCI[0..11], \
                               NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[], \
                               load:NXM_OF_IN_PORT[]->NXM_NX_REG0[0..15]), \
                         resubmit(,3)"

The "learn" action (an Open vSwitch extension to OpenFlow) modifies a flow
table based on the content of the flow currently being processed.  Here's how
you can interpret each part of the "learn" action above:

``table=10``
    Modify flow table 10.  This will be the MAC learning table.

``NXM_OF_VLAN_TCI[0..11]``
    Make the flow that we add to flow table 10 match the same VLAN ID that the
    packet we're currently processing contains.  This effectively scopes the
    MAC learning entry to a single VLAN, which is the ordinary behavior for a
    VLAN-aware switch.

``NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[]``
    Make the flow that we add to flow table 10 match, as Ethernet destination,
    the Ethernet source address of the packet we're currently processing.

``load:NXM_OF_IN_PORT[]->NXM_NX_REG0[0..15]``
    Whereas the preceding parts specify fields for the new flow to match, this
    specifies an action for the flow to take when it matches.  The action is
    for the flow to load the ingress port number of the current packet into
    register 0 (a special field that is an Open vSwitch extension to OpenFlow).

.. note::
  A real use of "learn" for MAC learning would probably involve two additional
  elements.  First, the "learn" action would specify a hard_timeout for the new
  flow, to enable a learned MAC to eventually expire if no new packets were
  seen from a given source within a reasonable interval.  Second, one would
  usually want to limit resource consumption by using the Flow_Table table in
  the Open vSwitch configuration database to specify a maximum number of flows
  in table 10.

This definitely calls for examples.

Testing Table 2
---------------

Example 1
~~~~~~~~~

Try the following test command::

    $ ovs-appctl ofproto/trace br0 \
        in_port=1,vlan_tci=20,dl_src=50:00:00:00:00:01 -generate

The output shows that "learn" was executed in table 2 and the
particular flow that was added::

    Flow: in_port=1,vlan_tci=0x0014,dl_src=50:00:00:00:00:01,dl_dst=00:00:00:00:00:00,dl_type=0x0000

    bridge("br0")
    -------------
     0. priority 0
        resubmit(,1)
     1. in_port=1, priority 99
        resubmit(,2)
     2. priority 32768
        learn(table=10,NXM_OF_VLAN_TCI[0..11],NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],load:NXM_OF_IN_PORT[]->NXM_NX_REG0[0..15])
         -> table=10 vlan_tci=0x0014/0x0fff,dl_dst=50:00:00:00:00:01 priority=32768 actions=load:0x1->NXM_NX_REG0[0..15]
        resubmit(,3)
     3. No match.
        drop

    Final flow: unchanged
    Megaflow: recirc_id=0,in_port=1,vlan_tci=0x0014/0x1fff,dl_src=50:00:00:00:00:01,dl_dst=00:00:00:00:00:00/ff:ff:ff:ff:ff:f0,dl_type=0x0000
    Datapath actions: drop

The ``-generate`` keyword is new.  Ordinarily, ``ofproto/trace`` has no side
effects: "output" actions do not actually output packets, "learn" actions do
not actually modify the flow table, and so on.  With ``-generate``, though,
``ofproto/trace`` does execute "learn" actions.  That's important now, because
we want to see the effect of the "learn" action on table 10.  You can see that
by running::

    $ ovs-ofctl dump-flows br0 table=10

which (omitting the ``duration`` and ``idle_age`` fields, which will vary based
on how soon you ran this command after the previous one, as well as some other
uninteresting fields) prints something like::

    NXST_FLOW reply (xid=0x4):
     table=10, vlan_tci=0x0014/0x0fff,dl_dst=50:00:00:00:00:01 actions=load:0x1->NXM_NX_REG0[0..15]

You can see that the packet coming in on VLAN ``20`` with source MAC
``50:00:00:00:00:01`` became a flow that matches VLAN ``20`` (written in
hexadecimal) and destination MAC ``50:00:00:00:00:01``.  The flow loads port
number ``1``, the input port for the flow we tested, into register 0.

Example 2
~~~~~~~~~

Here's a second test command::

    $ ovs-appctl ofproto/trace br0 \
        in_port=2,dl_src=50:00:00:00:00:01 -generate

The flow that this command tests has the same source MAC and VLAN as example 1,
although the VLAN comes from an access port VLAN rather than an 802.1Q header.
If we again dump the flows for table 10 with::

    $ ovs-ofctl dump-flows br0 table=10

then we see that the flow we saw previously has changed to indicate that the
learned port is port 2, as we would expect::

    NXST_FLOW reply (xid=0x4):
     table=10, vlan_tci=0x0014/0x0fff,dl_dst=50:00:00:00:00:01 actions=load:0x2->NXM_NX_REG0[0..15]

Implementing Table 3: Look Up Destination Port
----------------------------------------------

This table figures out what port we should send the packet to based on the
destination MAC and VLAN.  That is, if we've learned the location of the
destination (from table 2 processing some previous packet with that destination
as its source), then we want to send the packet there.

We need only one flow to do the lookup::

    $ ovs-ofctl add-flow br0 \
        "table=3 priority=50 actions=resubmit(,10), resubmit(,4)"

The flow's first action resubmits to table 10, the table that the "learn"
action modifies.  As you saw previously, the learned flows in this table write
the learned port into register 0.  If the destination for our packet hasn't
been learned, then there will be no matching flow, and so the "resubmit" turns
into a no-op.  Because registers are initialized to 0, we can use a register 0
value of 0 in our next pipeline stage as a signal to flood the packet.

The second action resubmits to table 4, continuing to the next pipeline stage.

We can add another flow to skip the learning table lookup for multicast and
broadcast packets, since those should always be flooded::

    $ ovs-ofctl add-flow br0 \
        "table=3 priority=99 dl_dst=01:00:00:00:00:00/01:00:00:00:00:00 \
          actions=resubmit(,4)"

.. note::
  We don't strictly need to add this flow, because multicast addresses will
  never show up in our learning table.  (In turn, that's because we put a flow
  into table 0 to drop packets that have a multicast source address.)

Testing Table 3
---------------

Example
~~~~~~~

Here's a command that should cause OVS to learn that ``f0:00:00:00:00:01`` is
on ``p1`` in VLAN ``20``::

    $ ovs-appctl ofproto/trace br0 \
        in_port=1,dl_vlan=20,dl_src=f0:00:00:00:00:01,dl_dst=90:00:00:00:00:01 \
        -generate

The output shows (from the "no match" looking up the resubmit to
table 10) that the flow's destination was unknown::

    Flow: in_port=1,dl_vlan=20,dl_vlan_pcp=0,dl_src=f0:00:00:00:00:01,dl_dst=90:00:00:00:00:01,dl_type=0x0000

    bridge("br0")
    -------------
     0. priority 0
        resubmit(,1)
     1. in_port=1, priority 99
        resubmit(,2)
     2. priority 32768
        learn(table=10,NXM_OF_VLAN_TCI[0..11],NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],load:NXM_OF_IN_PORT[]->NXM_NX_REG0[0..15])
         -> table=10 vlan_tci=0x0014/0x0fff,dl_dst=f0:00:00:00:00:01 priority=32768 actions=load:0x1->NXM_NX_REG0[0..15]
        resubmit(,3)
     3. priority 50
        resubmit(,10)
        10. No match.
                drop
        resubmit(,4)
     4. No match.
        drop

    Final flow: unchanged
    Megaflow: recirc_id=0,in_port=1,dl_vlan=20,dl_src=f0:00:00:00:00:01,dl_dst=90:00:00:00:00:01,dl_type=0x0000
    Datapath actions: drop

There are two ways that you can verify that the packet's source was
learned.  The most direct way is to dump the learning table with::

    $ ovs-ofctl dump-flows br0 table=10

which ought to show roughly the following, with extraneous details removed::

    table=10, vlan_tci=0x0014/0x0fff,dl_dst=f0:00:00:00:00:01 actions=load:0x1->NXM_NX_REG0[0..15]

.. note::
    If you tried the examples for the previous step, or if you did some of your
    own experiments, then you might see additional flows there.  These
    additional flows are harmless.  If they bother you, then you can remove
    them with `ovs-ofctl del-flows br0 table=10`.

The other way is to inject a packet to take advantage of the learning entry.
For example, we can inject a packet on p2 whose destination is the MAC address
that we just learned on p1::

    $ ovs-appctl ofproto/trace br0 \
        in_port=2,dl_src=90:00:00:00:00:01,dl_dst=f0:00:00:00:00:01 -generate

Here is this command's output.  Take a look at the lines that trace
the ``resubmit(,10)``, showing that the packet matched the learned
flow for the first MAC we used, loading the OpenFlow port number for
the learned port ``p1`` into register ``0``::

    Flow: in_port=2,vlan_tci=0x0000,dl_src=90:00:00:00:00:01,dl_dst=f0:00:00:00:00:01,dl_type=0x0000

    bridge("br0")
    -------------
     0. priority 0
        resubmit(,1)
     1. in_port=2,vlan_tci=0x0000, priority 99
        mod_vlan_vid:20
        resubmit(,2)
     2. priority 32768
        learn(table=10,NXM_OF_VLAN_TCI[0..11],NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],load:NXM_OF_IN_PORT[]->NXM_NX_REG0[0..15])
         -> table=10 vlan_tci=0x0014/0x0fff,dl_dst=90:00:00:00:00:01 priority=32768 actions=load:0x2->NXM_NX_REG0[0..15]
        resubmit(,3)
     3. priority 50
        resubmit(,10)
        10. vlan_tci=0x0014/0x0fff,dl_dst=f0:00:00:00:00:01, priority 32768
                load:0x1->NXM_NX_REG0[0..15]
        resubmit(,4)
     4. No match.
        drop

    Final flow: reg0=0x1,in_port=2,dl_vlan=20,dl_vlan_pcp=0,dl_src=90:00:00:00:00:01,dl_dst=f0:00:00:00:00:01,dl_type=0x0000
    Megaflow: recirc_id=0,in_port=2,vlan_tci=0x0000,dl_src=90:00:00:00:00:01,dl_dst=f0:00:00:00:00:01,dl_type=0x0000
    Datapath actions: drop

If you read the commands above carefully, then you might have noticed that they
simply have the Ethernet source and destination addresses exchanged.  That
means that if we now rerun the first ``ovs-appctl`` command above, e.g.::

    $ ovs-appctl ofproto/trace br0 \
        in_port=1,dl_vlan=20,dl_src=f0:00:00:00:00:01,dl_dst=90:00:00:00:00:01 \
        -generate

then we see in the output, looking at the indented "load" action
executed in table 10, that the destination has now been learned::

    Flow: in_port=1,dl_vlan=20,dl_vlan_pcp=0,dl_src=f0:00:00:00:00:01,dl_dst=90:00:00:00:00:01,dl_type=0x0000

    bridge("br0")
    -------------
     0. priority 0
        resubmit(,1)
     1. in_port=1, priority 99
        resubmit(,2)
     2. priority 32768
        learn(table=10,NXM_OF_VLAN_TCI[0..11],NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],load:NXM_OF_IN_PORT[]->NXM_NX_REG0[0..15])
         -> table=10 vlan_tci=0x0014/0x0fff,dl_dst=f0:00:00:00:00:01 priority=32768 actions=load:0x1->NXM_NX_REG0[0..15]
        resubmit(,3)
     3. priority 50
        resubmit(,10)
        10. vlan_tci=0x0014/0x0fff,dl_dst=90:00:00:00:00:01, priority 32768
                load:0x2->NXM_NX_REG0[0..15]
        resubmit(,4)
     4. No match.
        drop


Implementing Table 4: Output Processing
---------------------------------------

At entry to stage 4, we know that register 0 contains either the desired output
port or is zero if the packet should be flooded.  We also know that the
packet's VLAN is in its 802.1Q header, even if the VLAN was implicit because
the packet came in on an access port.

The job of the final pipeline stage is to actually output packets.  The job is
trivial for output to our trunk port ``p1``::

    $ ovs-ofctl add-flow br0 "table=4 reg0=1 actions=1"

For output to the access ports, we just have to strip the VLAN header before
outputting the packet::

    $ ovs-ofctl add-flows br0 - <<'EOF'
    table=4 reg0=2 actions=strip_vlan,2
    table=4 reg0=3 actions=strip_vlan,3
    table=4 reg0=4 actions=strip_vlan,4
    EOF

The only slightly tricky part is flooding multicast and broadcast packets and
unicast packets with unlearned destinations.  For those, we need to make sure
that we only output the packets to the ports that carry our packet's VLAN, and
that we include the 802.1Q header in the copy output to the trunk port but not
in copies output to access ports::

    $ ovs-ofctl add-flows br0 - <<'EOF'
    table=4 reg0=0 priority=99 dl_vlan=20 actions=1,strip_vlan,2
    table=4 reg0=0 priority=99 dl_vlan=30 actions=1,strip_vlan,3,4
    table=4 reg0=0 priority=50            actions=1
    EOF

.. note::
  Our flows rely on the standard OpenFlow behavior that an output action will
  not forward a packet back out the port it came in on.  That is, if a packet
  comes in on p1, and we've learned that the packet's destination MAC is also
  on p1, so that we end up with ``actions=1`` as our actions, the switch will
  not forward the packet back out its input port.  The
  multicast/broadcast/unknown destination cases above also rely on this
  behavior.

Testing Table 4
---------------

Example 1: Broadcast, Multicast, and Unknown Destination
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Try tracing a broadcast packet arriving on ``p1`` in VLAN ``30``::

    $ ovs-appctl ofproto/trace br0 \
        in_port=1,dl_dst=ff:ff:ff:ff:ff:ff,dl_vlan=30

The interesting part of the output is the final line, which shows that the
switch would remove the 802.1Q header and then output the packet to ``p3``
and ``p4``, which are access ports for VLAN ``30``::

    Datapath actions: pop_vlan,3,4

Similarly, if we trace a broadcast packet arriving on ``p3``::

    $ ovs-appctl ofproto/trace br0 in_port=3,dl_dst=ff:ff:ff:ff:ff:ff

then we see that it is output to ``p1`` with an 802.1Q tag and then to ``p4``
without one::

    Datapath actions: push_vlan(vid=30,pcp=0),1,pop_vlan,4

.. note::
  Open vSwitch could simplify the datapath actions here to just
  ``4,push_vlan(vid=30,pcp=0),1`` but it is not smart enough to do so.

The following are also broadcasts, but the result is to drop the packets
because the VLAN only belongs to the input port::

    $ ovs-appctl ofproto/trace br0 \
        in_port=1,dl_dst=ff:ff:ff:ff:ff:ff
    $ ovs-appctl ofproto/trace br0 \
        in_port=1,dl_dst=ff:ff:ff:ff:ff:ff,dl_vlan=55

Try some other broadcast cases on your own::

    $ ovs-appctl ofproto/trace br0 \
        in_port=1,dl_dst=ff:ff:ff:ff:ff:ff,dl_vlan=20
    $ ovs-appctl ofproto/trace br0 \
        in_port=2,dl_dst=ff:ff:ff:ff:ff:ff
    $ ovs-appctl ofproto/trace br0 \
        in_port=4,dl_dst=ff:ff:ff:ff:ff:ff

You can see the same behavior with multicast packets and with unicast
packets whose destination has not been learned, e.g.::

    $ ovs-appctl ofproto/trace br0 \
        in_port=4,dl_dst=01:00:00:00:00:00
    $ ovs-appctl ofproto/trace br0 \
        in_port=1,dl_dst=90:12:34:56:78:90,dl_vlan=20
    $ ovs-appctl ofproto/trace br0 \
        in_port=1,dl_dst=90:12:34:56:78:90,dl_vlan=30

Example 2: MAC Learning
~~~~~~~~~~~~~~~~~~~~~~~

Let's follow the same pattern as we did for table 3.  First learn a MAC on port
``p1`` in VLAN ``30``::

    $ ovs-appctl ofproto/trace br0 \
        in_port=1,dl_vlan=30,dl_src=10:00:00:00:00:01,dl_dst=20:00:00:00:00:01 \
        -generate

You can see from the last line of output that the packet's destination is
unknown, so it gets flooded to both ``p3`` and ``p4``, the other ports in VLAN
``30``::

    Datapath actions: pop_vlan,3,4

Then reverse the MACs and learn the first flow's destination on port ``p4``::

    $ ovs-appctl ofproto/trace br0 \
        in_port=4,dl_src=20:00:00:00:00:01,dl_dst=10:00:00:00:00:01 -generate

The last line of output shows that the this packet's destination is known to be
``p1``, as learned from our previous command::

    Datapath actions: push_vlan(vid=30,pcp=0),1

Now, if we rerun our first command::

    $ ovs-appctl ofproto/trace br0 \
        in_port=1,dl_vlan=30,dl_src=10:00:00:00:00:01,dl_dst=20:00:00:00:00:01 \
        -generate

...we can see that the result is no longer a flood but to the specified learned
destination port ``p4``::

    Datapath actions: pop_vlan,4

Contact
=======

bugs@openvswitch.org
http://openvswitch.org/

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
OVS Conntrack Tutorial
======================

OVS can be used with the Connection tracking system
where OpenFlow flow can be used to match on the state of a TCP, UDP, ICMP,
etc., connections. (Connection tracking system supports tracking of both
statefull and stateless protocols)

This tutorial demonstrates how OVS can use the connection tracking system
to match on the TCP segments from connection setup to connection tear down.
It will use OVS with the Linux kernel module as the datapath for this
tutorial. (The datapath that utilizes the openvswitch kernel module to do
the packet processing in the Linux kernel)
It was tested with the “master” branch of Open vSwitch.

Definitions
-----------

**conntrack**: is a connection tracking module for stateful packet
inspection.

**pipeline**: is the packet processing pipeline which is the path taken by
the packet when traversing through the tables where the packet matches the
match fields of a flow in the table and performs the actions present in
the matched flow.

**network namespace**: is a way to create virtual routing domains within
a single instance of linux kernel.  Each network namespace has it's own
instance of network tables (arp, routing) and certain interfaces attached
to it.

**flow**: used in this tutorial refers to the OpenFlow flow which can be
programmed using an OpenFlow controller or OVS command line tools like
ovs-ofctl which is used here.  A flow will have match fields and actions.

Conntrack Related Fields
------------------------

Match Fields
~~~~~~~~~~~~
OVS supports following match fields related to conntrack:

1. **ct_state**:
The state of a connection matching the packet.
Possible values:

    - *new*
    - *est*
    - *rel*
    - *rpl*
    - *inv*
    - *trk*
    - *snat*
    - *dnat*

Each of these flags is preceded by either a "+" for a flag that
must be set, or a "-" for a flag that must be unset.
Multiple flags can also be specified e.g. ct_state=+trk+new.
We will see the usage of some of these flags below. For a detailed
description, please see the OVS fields documentation at:
http://openvswitch.org/support/dist-docs/ovs-fields.7.txt

2. **ct_zone**: A zone is an independent connection tracking context which can
be set by a ct action.
A 16-bit ct_zone set by the most recent ct action (by an OpenFlow
flow on a conntrack entry) can be used as a match field in
another flow entry.

3. **ct_mark**:
The 32-bit metadata committed, by an action within the exec
parameter to the ct action, to the connection to which the
current packet belongs.

4. **ct_label**:
The 128-bit label committed by an action within the exec parameter to
the ct action, to the connection to which the current packet
belongs.

5.  **ct_nw_src** /  **ct_ipv6_src**:
Matches IPv4/IPv6 conntrack original direction tuple
source address.

6.  **ct_nw_dst** / **ct_ipv6_dst**:
Matches IPv4/IPv6 conntrack original direction tuple destination address.

7. **ct_nw_proto**:
Matches conntrack original direction tuple IP protocol type.

8. **ct_tp_src**:
Matches on the conntrack original direction tuple
transport source port.

9. **ct_tp_dst**:
Matches on the conntrack original direction tuple
transport destination port.


Actions
~~~~~~~
OVS supports "ct" action related to conntrack.

*ct([argument][,argument...])*

The **ct** action sends the packet through the connection tracker.

The following arguments are supported:

1. **commit**:
Commit the connection to the connection tracking module which
will be stored beyond the lifetime of packet in the pipeline.

2. **force**:
The force flag may be used in addition to commit flag to effectively
terminate the existing connection and start a new one in the
current direction.

3. **table=number**:
Fork pipeline processing in two. The original instance of the packet
will continue processing the current actions list as an untracked packet.
An additional instance of the packet will be sent to the connection
tracker, which will be re-injected into the OpenFlow pipeline to resume
processing in table number, with the ct_state and other ct match fields set.

4. **zone=value OR
zone=src[start..end]**:
A 16-bit context id that can be used to isolate connections into separate
domains, allowing over‐lapping network addresses in different zones. If a
zone is not provided, then the default is to use zone zero.

5. **exec([action][,action...])**:
Perform restricted set of actions within the context of connection tracking.
Only actions which modify the *ct_mark* or *ct_label* fields are accepted
within the exec action.

6. **alg=<ftp/tftp>**:
Specify alg (application layer gateway) to track specific connection
types.

7. **nat**:
Specifies the address and port translation for the connection being tracked.



Sample Topology
---------------
This tutorial uses the following topology to carry out the tests.

::

         +                                                       +
         |                                                       |
         |                       +-----+                         |
         |                       |     |                         |
         |                       |     |                         |
         |     +----------+      | OVS |     +----------+        |
         |     |   left   |      |     |     |  right   |        |
         |     | namespace|      |     |     |namespace |        |
         +-----+        A +------+     +-----+ B        +--------+
         |     |          |    A'|     | B'  |          |        |
         |     |          |      |     |     |          |        |
         |     +----------+      |     |     +----------+        |
         |                       |     |                         |
         |                       |     |                         |
         |                       |     |                         |
         |                       +-----+                         |
         |                                                       |
         |                                                       |
         +                                                       +
     192.168.0.X n/w                                          10.0.0.X n/w

     A  = veth_l1
     A' = veth_l0
     B  = veth_r1
     B' = veth_r0

     Diagram: Sample Topology for conntrack testing


The steps for creation of the setup are mentioned below.

Create "left" network namespace::

  $ ip netns add left

Create "right" network namespace::

  $ ip netns add right

Create first pair of veth interfaces::

  $ ip link add veth_l0 type veth peer name veth_l1

Add veth_l1 to "left" network namespace::

  $ ip link set veth_l1 netns left

Create second pair of veth interfaces::

  $ ip link add veth_r0 type veth peer name veth_r1

Add veth_r1 to "right" network namespace::

  $ ip link set veth_r1 netns right

Create a bridge br0::

  $ ovs-vsctl add-br br0

Add veth_l0 and veth_r0 to br0::

  $ ovs-vsctl add-port br0 veth_l0
  $ ovs-vsctl add-port br0 veth_r0


Packets generated with src/dst IP set to 192.168.0.X / 10.0.0.X
in the "left" and the inverse in the "right" namespaces
will appear to OVS as hosts in two networks (192.168.0.X and 10.0.0.X)
communicating with each other.
This is basically a simulation of two networks / subnets with hosts
communicating with each other with OVS in middle.

Tool used to generate TCP segments
----------------------------------
You can use scapy to generate the TCP segments. We used scapy on Ubuntu 16.04
for the steps carried out in this testing.
(Installation of scapy is not discussed and is out of scope of this document.)

You can keep two scapy sessions active on each of the namespaces::

     $ sudo ip netns exec left sudo `which scapy`

     $ sudo ip netns exec right sudo `which scapy`

Note: In case you encounter this error::

    ifreq = ioctl(s, SIOCGIFADDR,struct.pack("16s16x",LOOPBACK_NAME))

    IOError: [Errno 99] Cannot assign requested address

run the command::

    $ sudo ip netns exec <namespace> sudo ip link set lo up


Matching TCP packets
--------------------

TCP Connection setup
~~~~~~~~~~~~~~~~~~~~
Two simple flows can be added in OVS which will forward
packets from "left" to "right" and from "right" to "left"::

     $ ovs-ofctl add-flow br0 \
              "table=0, priority=10, in_port=veth_l0, actions=veth_r0"

     $ ovs-ofctl add-flow br0 \
              "table=0, priority=10, in_port=veth_r0, actions=veth_l0"

Instead of adding these two flows, we will add flows to match on the
states of the TCP segments.

We will send the TCP connection setup segments namely:
syn, syn-ack and ack between hosts 192.168.0.2 in the "left" namespace and
10.0.0.2 in the "right" namespace.

First, let's add a flow to start "tracking" a packet received at OVS.

*How do we start tracking a packet?*

To start tracking a packet, it first needs to match a flow, which has action
as "ct".  This action sends the packet through the connection tracker.  To
identify that a packet is an "untracked" packet, the ct_state in the flow
match field must be set to "-trk", which means it is not a tracked packet.
Once the packet is sent to the connection tracker, then only we will know about
its conntrack state.  (i.e. whether this packet represents start of a new
connection or the packet belongs to an existing connection or it is
a malformed packet and so on.)

Let's add that flow::

     (flow #1)
     $ ovs-ofctl add-flow br0 \
        "table=0, priority=50, ct_state=-trk, tcp, in_port=veth_l0, actions=ct(table=0)"

A TCP syn packet sent from "left" namespace will match flow #1
because the packet is coming to OVS from veth_l0 port and it is not being
tracked.  This is because the packet just entered OVS. When a packet
enters a namespace for the first time, a new connection tracker context
is entered, hence, the packet will be initially "untracked" in that
namespace.
When a packet (re)enters the same datapath that it already belongs to
there is no need to discard the namespace and other information
associated with the conntrack flow.  In this case the packet will
remain in the tracked state.  If the namespace has changed then it is
discarded and a new connection tracker is created since connection
tracking information is logically separate for different namespaces.
The flow will send the packet to the connection tracker due to the action "ct".
Also "table=0" in the "ct" action forks the pipeline processing in two.  The
original instance of packet will continue processing the current action list
as untracked packet. (Since there are no actions after this, the original
packet gets dropped.)
The forked instance of the packet will be sent to the  connection  tracker,
which will be re-injected into the OpenFlow pipeline to resume processing
in table number, with the ct_state and other ct match fields set.
In this case, the packet with the ct_state and other ct match fields comes back
to table 0.

Next, we add a flow to match on the packet coming back from conntrack::

    (flow #2)
    $ ovs-ofctl add-flow br0 \
        "table=0, priority=50, ct_state=+trk+new, tcp, in_port=veth_l0, actions=ct(commit),veth_r0"

Now that the packet is coming back from conntrack, the ct_state would have
the "trk" set.
Also, if this is the first packet of the TCP connection, the ct_state "new"
would be set. (Which is the condition here as there does not exist any TCP
connection between hosts 192.168.0.2 and 10.0.0.2)
The ct argument "commit" will commit the connection to the connection tracking
module.  The significance of this action is that the information about the
connection will now be stored beyond the lifetime of the packet in the
pipeline.

Let's send the TCP syn segment using scapy (at the "left" scapy session)
(flags=0x02 is syn)::

    $ >>> sendp(Ether()/IP(src="192.168.0.2", dst="10.0.0.2")/TCP(sport=1024, dport=2048, flags=0x02, seq=100), iface="veth_l1")

This packet will match flow #1 and flow #2.

The conntrack module will now have an entry for this connection::

    $ ovs-appctl dpctl/dump-conntrack | grep "192.168.0.2"
    tcp,orig=(src=192.168.0.2,dst=10.0.0.2,sport=1024,dport=2048),reply=(src=10.0.0.2,dst=192.168.0.2,sport=2048,dport=1024),protoinfo=(state=SYN_SENT)


Note: At this stage, if the TCP syn packet is re-transmitted, it will again
match flow #1 (since a new packet is untracked) and it will match flow #2.
The reason it will match flow #2 is that although conntrack has information
about the connection, but it is not in "ESTABLISHED" state, therefore it
matches the "new" state again.

Next for the TCP syn-ack from the opposite/server direction, we need
following flows at OVS::

    (flow #3)
    $ ovs-ofctl add-flow br0 \
        "table=0, priority=50, ct_state=-trk, tcp, in_port=veth_r0, actions=ct(table=0)"
    (flow #4)
    $ ovs-ofctl add-flow br0 \
        "table=0, priority=50, ct_state=+trk+est, tcp, in_port=veth_r0, actions=veth_l0"


flow #3 matches untracked packets coming back from server (10.0.0.2) and sends
this to conntrack. (Alternatively, we could have also combined
flow #1 and flow #3 into one flow by not having the "in_port" match)

The syn-ack packet which has now gone through the conntrack has the ct_state of
"est".

Note: Conntrack puts the ct_state of the connection to "est" state when
it sees bidirectional traffic, but till it does not get the third ack from
client, it puts a short cleanup timer on the conntrack entry.

Sending TCP syn-ack segment using scapy (at the "right" scapy session)
(flags=0x12 is ack and syn)::

    $ >>> sendp(Ether()/IP(src="10.0.0.2", dst="192.168.0.2")/TCP(sport=2048, dport=1024, flags=0x12, seq=200, ack=101), iface="veth_r1")

This packet will match flow #3 and flow #4.

conntrack entry::

     $ ovs-appctl dpctl/dump-conntrack | grep "192.168.0.2"

     tcp,orig=(src=192.168.0.2,dst=10.0.0.2,sport=1024,dport=2048),reply=(src=10.0.0.2,dst=192.168.0.2,sport=2048,dport=1024),protoinfo=(state=ESTABLISHED)

The conntrack state is "ESTABLISHED" on receiving just syn and syn-ack packets,
but at this point if it does not receive the third ack (from client), the
connection gets cleared up from conntrack quickly.

Next, for a TCP ack from client direction, we can add following flows to
match on the packet::

    (flow #5)
    $ ovs-ofctl add-flow br0 \
        "table=0, priority=50, ct_state=+trk+est, tcp, in_port=veth_l0, actions=veth_r0"

Send the third TCP ack segment using scapy (at the "left" scapy session)
(flags=0x10 is ack)::

    $ >>> sendp(Ether()/IP(src="192.168.0.2", dst="10.0.0.2")/TCP(sport=1024, dport=2048, flags=0x10, seq=101, ack=201), iface="veth_l1")

This packet will match on flow #1 and flow #5.


conntrack entry::

    $ ovs-appctl dpctl/dump-conntrack | grep "192.168.0.2"

     tcp,orig=(src=192.168.0.2,dst=10.0.0.2,sport=1024,dport=2048), \
         reply=(src=10.0.0.2,dst=192.168.0.2,sport=2048,dport=1024), \
                                         protoinfo=(state=ESTABLISHED)

The conntrack state stays in "ESTABLISHED" state, but now since it has received
the ack from client, it will stay in this state for a longer time even without
receiving any data on this connection.

TCP Data
~~~~~~~~
When a data segment, carrying one byte of TCP payload, is sent from
192.168.0.2 to 10.0.0.2, the packet carrying the segment would hit flow #1
and then flow #5.

Send a TCP segment with one byte data using scapy
(at the "left" scapy session)
(flags=0x10 is ack)::

    $ >>> sendp(Ether()/IP(src="192.168.0.2", dst="10.0.0.2")/TCP(sport=1024, dport=2048, flags=0x10, seq=101, ack=201)/"X", iface="veth_l1")


Send the TCP ack for the above segment using scapy (at the
"right" scapy session)
(flags=0x10 is ack)::

    $ >>> sendp(Ether()/IP(src="10.0.0.2", dst="192.168.0.2")/TCP(sport=2048, dport=1024, flags=0X10, seq=201, ack=102), iface="veth_r1")

The acknowledgement for the data would hit flow #3 and flow #4.

TCP Connection Teardown
~~~~~~~~~~~~~~~~~~~~~~~
There are different ways to tear down TCP connection. We will tear down the
connection by sending "fin" from client, "fin-ack" from server followed
by the last "ack" by client.

All the packets from client to server would hit flow #1 and flow #5.
All the packets from server to client would hit flow #3 and flow #4.
Interesting point to note is that even when the TCP connection is going
down, all the packets (which are actually tearing down the connection) still
hits "+est" state.  A packet, for which the conntrack
entry *is* or *was* in "ESTABLISHED" state, would continue to match
"+est" ct_state in OVS.

Note: In fact, when the conntrack connection state is in "TIME_WAIT" state
(after all the TCP fins and their acks are exchanged),
a re-transmitted data packet (from 192.168.0.2 -> 10.0.0.2), still hits
flows #1 and #5.

Sending TCP fin segment using scapy (at the "left" scapy session)
(flags=0x11 is ack and fin)::

    $ >>> sendp(Ether()/IP(src="192.168.0.2", dst="10.0.0.2")/TCP(sport=1024, dport=2048, flags=0x11, seq=102, ack=201), iface="veth_l1")

This packet hits flow #1 and flow #5.

conntrack entry::

    $ sudo ovs-appctl dpctl/dump-conntrack | grep "192.168.0.2"

      tcp,orig=(src=192.168.0.2,dst=10.0.0.2,sport=1024,dport=2048),reply=(src=10.0.0.2,dst=192.168.0.2,sport=2048,dport=1024),protoinfo=(state=FIN_WAIT_1)


Sending TCP fin-ack segment using scapy (at the "right" scapy session)
(flags=0x11 is ack and fin)::

    $ >>> sendp(Ether()/IP(src="10.0.0.2", dst="192.168.0.2")/TCP(sport=2048, dport=1024, flags=0X11, seq=201, ack=103), iface="veth_r1")

This packet hits flow #3 and flow #4.

conntrack entry::

    $ sudo ovs-appctl dpctl/dump-conntrack | grep "192.168.0.2"

      tcp,orig=(src=192.168.0.2,dst=10.0.0.2,sport=1024,dport=2048),reply=(src=10.0.0.2,dst=192.168.0.2,sport=2048,dport=1024),protoinfo=(state=LAST_ACK)


Sending TCP ack segment using scapy (at the "left" scapy session)
(flags=0x10 is ack)::

    $ >>> sendp(Ether()/IP(src="192.168.0.2", dst="10.0.0.2")/TCP(sport=1024, dport=2048, flags=0x10, seq=103, ack=202), iface="veth_l1")

This packet hits flow #1 and flow #5.

conntrack entry::

    $ sudo ovs-appctl dpctl/dump-conntrack | grep "192.168.0.2"

      tcp,orig=(src=192.168.0.2,dst=10.0.0.2,sport=1024,dport=2048),reply=(src=10.0.0.2,dst=192.168.0.2,sport=2048,dport=1024),protoinfo=(state=TIME_WAIT)


Summary
-------

Following table summarizes the TCP segments exchanged against the flow
match fields

  +-------------------------------------------------------+-------------------+
  |                     TCP Segment                       |ct_state(flow#)    |
  +=======================================================+===================+
  |                     **Connection Setup**              |                   |
  +-------------------------------------------------------+-------------------+
  |192.168.0.2 → 10.0.0.2 [SYN] Seq=0                     | -trk(#1) then     |
  |                                                       | +trk+new(#2)      |
  +-------------------------------------------------------+-------------------+
  |10.0.0.2 → 192.168.0.2 [SYN, ACK] Seq=0 Ack=1          | -trk(#3) then     |
  |                                                       | +trk+est(#4)      |
  +-------------------------------------------------------+-------------------+
  |192.168.0.2 → 10.0.0.2 [ACK] Seq=1 Ack=1               | -trk(#1) then     |
  |                                                       | +trk+est(#5)      |
  +-------------------------------------------------------+-------------------+
  |                     **Data Transfer**                 |                   |
  +-------------------------------------------------------+-------------------+
  |192.168.0.2 → 10.0.0.2 [ACK] Seq=1 Ack=1               | -trk(#1) then     |
  |                                                       | +trk+est(#5)      |
  +-------------------------------------------------------+-------------------+
  |10.0.0.2 → 192.168.0.2 [ACK] Seq=1 Ack=2               | -trk(#3) then     |
  |                                                       | +trk+est(#4)      |
  +-------------------------------------------------------+-------------------+
  |                     **Connection Teardown**           |                   |
  +-------------------------------------------------------+-------------------+
  |192.168.0.2 → 10.0.0.2 [FIN, ACK] Seq=2 Ack=1          | -trk(#1) then     |
  |                                                       | +trk+est(#5)      |
  +-------------------------------------------------------+-------------------+
  |10.0.0.2 → 192.168.0.2 [FIN, ACK] Seq=1 Ack=3          | -trk(#3) then     |
  |                                                       | +trk+est(#4)      |
  +-------------------------------------------------------+-------------------+
  |192.168.0.2 → 10.0.0.2 [ACK] Seq=3 Ack=2               | -trk(#1) then     |
  |                                                       | +trk+est(#5)      |
  +-------------------------------------------------------+-------------------+

Note: Relative sequence number and acknowledgement numbers are shown as
captured from tshark.

Flows
~~~~~
::

     (flow #1)
     $ ovs-ofctl add-flow br0 \
        "table=0, priority=50, ct_state=-trk, tcp, in_port=veth_l0, actions=ct(table=0)"

    (flow #2)
    $ ovs-ofctl add-flow br0 \
        "table=0, priority=50, ct_state=+trk+new, tcp, in_port=veth_l0, actions=ct(commit),veth_r0"

    (flow #3)
    $ ovs-ofctl add-flow br0 \
        "table=0, priority=50, ct_state=-trk, tcp, in_port=veth_r0, actions=ct(table=0)"

    (flow #4)
    $ ovs-ofctl add-flow br0 \
        "table=0, priority=50, ct_state=+trk+est, tcp, in_port=veth_r0, actions=veth_l0"

    (flow #5)
    $ ovs-ofctl add-flow br0 \
        "table=0, priority=50, ct_state=+trk+est, tcp, in_port=veth_l0, actions=veth_r0"

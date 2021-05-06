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

===================
OVS Faucet Tutorial
===================

This tutorial demonstrates how Open vSwitch works with a general-purpose
OpenFlow controller, using the Faucet controller as a simple way to get
started.  It was tested with the "master" branch of Open vSwitch and version
1.6.15 of Faucet.  It does not use advanced or recently added features in OVS
or Faucet, so other versions of both pieces of software are likely to work
equally well.

The goal of the tutorial is to demonstrate Open vSwitch and Faucet in an
end-to-end way, that is, to show how it works from the Faucet controller
configuration at the top, through the OpenFlow flow table, to the datapath
processing.  Along the way, in addition to helping to understand the
architecture at each level, we discuss performance and troubleshooting issues.
We hope that this demonstration makes it easier for users and potential users
to understand how Open vSwitch works and how to debug and troubleshoot it.

We provide enough details in the tutorial that you should be able to fully
follow along by following the instructions.

Setting Up OVS
--------------

This section explains how to set up Open vSwitch for the purpose of using it
with Faucet for the tutorial.

You might already have Open vSwitch installed on one or more computers or VMs,
perhaps set up to control a set of VMs or a physical network.  This is
admirable, but we will be using Open vSwitch in a different way to set up a
simulation environment called the OVS "sandbox".  The sandbox does not use
virtual machines or containers, which makes it more limited, but on the other
hand it is (in this writer's opinion) easier to set up.

There are two ways to start a sandbox: one that uses the Open vSwitch that is
already installed on a system, and another that uses a copy of Open vSwitch
that has been built but not yet installed.  The latter is more often used and
thus better tested, but both should work.  The instructions below explain both
approaches:

1. Get a copy of the Open vSwitch source repository using Git, then ``cd`` into
   the new directory::

     $ git clone https://github.com/openvswitch/ovs.git
     $ cd ovs

   The default checkout is the master branch.  You will need to use the master
   branch for this tutorial as it includes some functionality required for this
   tutorial.

2. If you do not already have an installed copy of Open vSwitch on your system,
   or if you do not want to use it for the sandbox (the sandbox will not
   disturb the functionality of any existing switches), then proceed to step 3.
   If you do have an installed copy and you want to use it for the sandbox, try
   to start the sandbox by running::

     $ tutorial/ovs-sandbox

   .. note::

     The default behaviour for some of the commands used in this tutorial
     changed in Open vSwitch versions 2.9.x and 2.10.x which breaks the
     tutorial.  We recommend following step 3 and building master from
     source or using a system Open vSwitch that is version 2.8.x or older.

   If it is successful, you will find yourself in a subshell environment, which
   is the sandbox (you can exit with ``exit`` or Control+D).  If so, you're
   finished and do not need to complete the rest of the steps.  If it fails,
   you can proceed to step 3 to build Open vSwitch anyway.

3. Before you build, you might want to check that your system meets the build
   requirements.  Read :doc:`/intro/install/general` to find out.  For this
   tutorial, there is no need to compile the Linux kernel module, or to use any
   of the optional libraries such as OpenSSL, DPDK, or libcap-ng.

   If you are using a Linux system that uses apt and have some ``deb-src``
   repos listed in ``/etc/apt/sources.list``, often an easy way to install
   the build dependencies for a package is to use ``build-dep``::

     $ sudo apt-get build-dep openvswitch

4. Configure and build Open vSwitch::

     $ ./boot.sh
     $ ./configure
     $ make -j4

5. Try out the sandbox by running::

     $ make sandbox

   You can exit the sandbox with ``exit`` or Control+D.

Setting up Faucet
-----------------

This section explains how to get a copy of Faucet and set it up
appropriately for the tutorial.  There are many other ways to install
Faucet, but this simple approach worked well for me.  It has the
advantage that it does not require modifying any system-level files or
directories on your machine.  It does, on the other hand, require
Docker, so make sure you have it installed and working.

It will be a little easier to go through the rest of the tutorial if
you run these instructions in a separate terminal from the one that
you're using for Open vSwitch, because it's often necessary to switch
between one and the other.

1. Get a copy of the Faucet source repository using Git, then ``cd``
   into the new directory::

     $ git clone https://github.com/faucetsdn/faucet.git
     $ cd faucet

   At this point I checked out the latest tag::

     $ latest_tag=$(git describe --tags $(git rev-list --tags --max-count=1))
     $ git checkout $latest_tag

2. Build a docker container image::

     $ sudo docker build -t faucet/faucet -f Dockerfile.faucet .

   This will take a few minutes.

3. Create an installation directory under the ``faucet`` directory for
   the docker image to use::

     $ mkdir inst

   The Faucet configuration will go in ``inst/faucet.yaml`` and its
   main log will appear in ``inst/faucet.log``.  (The official Faucet
   installation instructions call to put these in ``/etc/ryu/faucet``
   and ``/var/log/ryu/faucet``, respectively, but we avoid modifying
   these system directories.)

4. Create a container and start Faucet::

     $ sudo docker run -d --name faucet --restart=always -v $(pwd)/inst/:/etc/faucet/ -v $(pwd)/inst/:/var/log/faucet/ -p 6653:6653 -p 9302:9302 faucet/faucet

5. Look in ``inst/faucet.log`` to verify that Faucet started.  It will
   probably start with an exception and traceback because we have not
   yet created ``inst/faucet.yaml``.

6. Later on, to make a new or updated Faucet configuration take
   effect quickly, you can run::

     $ sudo docker exec faucet pkill -HUP -f faucet.faucet

   Another way is to stop and start the Faucet container::

     $ sudo docker restart faucet

   You can also stop and delete the container; after this, to start it
   again, you need to rerun the ``docker run`` command::

     $ sudo docker stop faucet
     $ sudo docker rm faucet

Overview
--------

Now that Open vSwitch and Faucet are ready, here's an overview of what
we're going to do for the remainder of the tutorial:

1. Switching: Set up an L2 network with Faucet.

2. Routing: Route between multiple L3 networks with Faucet.

3. ACLs: Add and modify access control rules.

At each step, we will take a look at how the features in question work
from Faucet at the top to the data plane layer at the bottom.  From
the highest to lowest level, these layers and the software components
that connect them are:

Faucet.
  As the top level in the system, this is the authoritative source of the
  network configuration.

  Faucet connects to a variety of monitoring and performance tools,
  but we won't use them in this tutorial.  Our main insights into the
  system will be through ``faucet.yaml`` for configuration and
  ``faucet.log`` to observe state, such as MAC learning and ARP
  resolution, and to tell when we've screwed up configuration syntax
  or semantics.

The OpenFlow subsystem in Open vSwitch.
  OpenFlow is the protocol, standardized by the Open Networking Foundation,
  that controllers like Faucet use to control how Open vSwitch and other
  switches treat packets in the network.

  We will use ``ovs-ofctl``, a utility that comes with Open vSwitch,
  to observe and occasionally modify Open vSwitch's OpenFlow behavior.
  We will also use ``ovs-appctl``, a utility for communicating with
  ``ovs-vswitchd`` and other Open vSwitch daemons, to ask "what-if?"
  type questions.

  In addition, the OVS sandbox by default raises the Open vSwitch
  logging level for OpenFlow high enough that we can learn a great
  deal about OpenFlow behavior simply by reading its log file.

Open vSwitch datapath.
  This is essentially a cache designed to accelerate packet processing.  Open
  vSwitch includes a few different datapaths, such as one based on the Linux
  kernel and a userspace-only datapath (sometimes called the "DPDK" datapath).
  The OVS sandbox uses the latter, but the principles behind it apply equally
  well to other datapaths.

At each step, we discuss how the design of each layer influences
performance.  We demonstrate how Open vSwitch features can be used to
debug, troubleshoot, and understand the system as a whole.

Switching
---------

Layer-2 (L2) switching is the basis of modern networking.  It's also
very simple and a good place to start, so let's set up a switch with
some VLANs in Faucet and see how it works at each layer.  Begin by
putting the following into ``inst/faucet.yaml``::

  dps:
      switch-1:
          dp_id: 0x1
          timeout: 3600
          arp_neighbor_timeout: 3600
          interfaces:
              1:
                  native_vlan: 100
              2:
                  native_vlan: 100
              3:
                  native_vlan: 100
              4:
                  native_vlan: 200
              5:
                  native_vlan: 200
  vlans:
      100:
      200:

This configuration file defines a single switch ("datapath" or "dp")
named ``switch-1``.  The switch has five ports, numbered 1 through 5.
Ports 1, 2, and 3 are in VLAN 100, and ports 4 and 5 are in VLAN 2.
Faucet can identify the switch from its datapath ID, which is defined
to be 0x1.

.. note::

  This also sets high MAC learning and ARP timeouts.  The defaults are
  5 minutes and about 8 minutes, which are fine in production but
  sometimes too fast for manual experimentation.

Now restart Faucet so that the configuration takes effect, e.g.::

  $ sudo docker restart faucet

Assuming that the configuration update is successful, you should now
see a new line at the end of ``inst/faucet.log``::

  Sep 10 06:44:10 faucet INFO     Add new datapath DPID 1 (0x1)

Faucet is now waiting for a switch with datapath ID 0x1 to connect to
it over OpenFlow, so our next step is to create a switch with OVS and
make it connect to Faucet.  To do that, switch to the terminal where
you checked out OVS and start a sandbox with ``make sandbox`` or
``tutorial/ovs-sandbox`` (as explained earlier under `Setting Up
OVS`_).  You should see something like this toward the end of the
output::

  ----------------------------------------------------------------------
  You are running in a dummy Open vSwitch environment.  You can use
  ovs-vsctl, ovs-ofctl, ovs-appctl, and other tools to work with the
  dummy switch.

  Log files, pidfiles, and the configuration database are in the
  "sandbox" subdirectory.

  Exit the shell to kill the running daemons.
  blp@sigabrt:~/nicira/ovs/tutorial(0)$

Inside the sandbox, create a switch ("bridge") named ``br0``, set its
datapath ID to 0x1, add simulated ports to it named ``p1`` through
``p5``, and tell it to connect to the Faucet controller.  To make it
easier to understand, we request for port ``p1`` to be assigned
OpenFlow port 1, ``p2`` port 2, and so on.  As a final touch,
configure the controller to be "out-of-band" (this is mainly to avoid
some annoying messages in the ``ovs-vswitchd`` logs; for more
information, run ``man ovs-vswitchd.conf.db`` and search for
``connection_mode``)::

  $ ovs-vsctl add-br br0 \
           -- set bridge br0 other-config:datapath-id=0000000000000001 \
           -- add-port br0 p1 -- set interface p1 ofport_request=1 \
           -- add-port br0 p2 -- set interface p2 ofport_request=2 \
           -- add-port br0 p3 -- set interface p3 ofport_request=3 \
           -- add-port br0 p4 -- set interface p4 ofport_request=4 \
           -- add-port br0 p5 -- set interface p5 ofport_request=5 \
           -- set-controller br0 tcp:127.0.0.1:6653 \
           -- set controller br0 connection-mode=out-of-band

.. note::

  You don't have to run all of these as a single ``ovs-vsctl``
  invocation.  It is a little more efficient, though, and since it
  updates the OVS configuration in a single database transaction it
  means that, for example, there is never a time when the controller
  is set but it has not yet been configured as out-of-band.

Faucet requires ports to be in the up state before it will configure them.  In
Open vSwitch versions earlier than 2.11.0 dummy ports started in the down state.
You will need to force them to come up with the following ``ovs-appctl`` command
(please skip this step if using a newer version of Open vSwitch)::

  $ ovs-appctl netdev-dummy/set-admin-state up

Now, if you look at ``inst/faucet.log`` again, you should see that
Faucet recognized and configured the new switch and its ports::

  Sep 10 06:45:03 faucet.valve INFO     DPID 1 (0x1) switch-1 Cold start configuring DP
  Sep 10 06:45:03 faucet.valve INFO     DPID 1 (0x1) switch-1 Configuring VLAN 100 vid:100 ports:Port 1,Port 2,Port 3
  Sep 10 06:45:03 faucet.valve INFO     DPID 1 (0x1) switch-1 Configuring VLAN 200 vid:200 ports:Port 4,Port 5
  Sep 10 06:45:24 faucet.valve INFO     DPID 1 (0x1) switch-1 Port 1 (1) up
  Sep 10 06:45:24 faucet.valve INFO     DPID 1 (0x1) switch-1 Port 2 (2) up
  Sep 10 06:45:24 faucet.valve INFO     DPID 1 (0x1) switch-1 Port 3 (3) up
  Sep 10 06:45:24 faucet.valve INFO     DPID 1 (0x1) switch-1 Port 4 (4) up
  Sep 10 06:45:24 faucet.valve INFO     DPID 1 (0x1) switch-1 Port 5 (5) up

Over on the Open vSwitch side, you can see a lot of related activity
if you take a look in ``sandbox/ovs-vswitchd.log``.  For example, here
is the basic OpenFlow session setup and Faucet's probe of the switch's
ports and capabilities::

  rconn|INFO|br0<->tcp:127.0.0.1:6653: connecting...
  vconn|DBG|tcp:127.0.0.1:6653: sent (Success): OFPT_HELLO (OF1.4) (xid=0x1):
   version bitmap: 0x01, 0x02, 0x03, 0x04, 0x05
  vconn|DBG|tcp:127.0.0.1:6653: received: OFPT_HELLO (OF1.3) (xid=0xdb9dab08):
   version bitmap: 0x01, 0x02, 0x03, 0x04
  vconn|DBG|tcp:127.0.0.1:6653: negotiated OpenFlow version 0x04 (we support version 0x05 and earlier, peer supports version 0x04 and earlier)
  rconn|INFO|br0<->tcp:127.0.0.1:6653: connected
  vconn|DBG|tcp:127.0.0.1:6653: received: OFPT_FEATURES_REQUEST (OF1.3) (xid=0xdb9dab09):
  00040|vconn|DBG|tcp:127.0.0.1:6653: sent (Success): OFPT_FEATURES_REPLY (OF1.3) (xid=0xdb9dab09): dpid:0000000000000001
  n_tables:254, n_buffers:0
  capabilities: FLOW_STATS TABLE_STATS PORT_STATS GROUP_STATS QUEUE_STATS
  vconn|DBG|tcp:127.0.0.1:6653: received: OFPST_PORT_DESC request (OF1.3) (xid=0xdb9dab0a): port=ANY
  vconn|DBG|tcp:127.0.0.1:6653: sent (Success): OFPST_PORT_DESC reply (OF1.3) (xid=0xdb9dab0a):
   1(p1): addr:aa:55:aa:55:00:14
       config:     0
       state:      LIVE
       speed: 0 Mbps now, 0 Mbps max
   2(p2): addr:aa:55:aa:55:00:15
       config:     0
       state:      LIVE
       speed: 0 Mbps now, 0 Mbps max
   3(p3): addr:aa:55:aa:55:00:16
       config:     0
       state:      LIVE
       speed: 0 Mbps now, 0 Mbps max
   4(p4): addr:aa:55:aa:55:00:17
       config:     0
       state:      LIVE
       speed: 0 Mbps now, 0 Mbps max
   5(p5): addr:aa:55:aa:55:00:18
       config:     0
       state:      LIVE
       speed: 0 Mbps now, 0 Mbps max
   LOCAL(br0): addr:42:51:a1:c4:97:45
       config:     0
       state:      LIVE
       speed: 0 Mbps now, 0 Mbps max

After that, you can see Faucet delete all existing flows and then
start adding new ones::

  vconn|DBG|tcp:127.0.0.1:6653: received: OFPT_FLOW_MOD (OF1.3) (xid=0xdb9dab0f): DEL table:255 priority=0 actions=drop
  vconn|DBG|tcp:127.0.0.1:6653: received: OFPT_FLOW_MOD (OF1.3) (xid=0xdb9dab10): ADD priority=0 cookie:0x5adc15c0 out_port:0 actions=drop
  vconn|DBG|tcp:127.0.0.1:6653: received: OFPT_FLOW_MOD (OF1.3) (xid=0xdb9dab11): ADD table:1 priority=0 cookie:0x5adc15c0 out_port:0 actions=goto_table:2
  vconn|DBG|tcp:127.0.0.1:6653: received: OFPT_FLOW_MOD (OF1.3) (xid=0xdb9dab12): ADD table:2 priority=0 cookie:0x5adc15c0 out_port:0 actions=goto_table:3
  ...

OpenFlow Layer
~~~~~~~~~~~~~~

Let's take a look at the OpenFlow tables that Faucet set up.  Before
we do that, it's helpful to take a look at ``docs/architecture.rst``
in the Faucet documentation to learn how Faucet structures its flow
tables.  In summary, this document says that when all features are enabled
our table layout will be:

Table 0
  Port-based ACLs

Table 1
  Ingress VLAN processing

Table 2
  VLAN-based ACLs

Table 3
  Ingress L2 processing, MAC learning

Table 4
  L3 forwarding for IPv4

Table 5
  L3 forwarding for IPv6

Table 6
  Virtual IP processing, e.g. for router IP addresses implemented by Faucet

Table 7
  Egress L2 processing

Table 8
  Flooding

With that in mind, let's dump the flow tables.  The simplest way is to
just run plain ``ovs-ofctl dump-flows``::

  $ ovs-ofctl dump-flows br0

If you run that bare command, it produces a lot of extra junk that
makes the output harder to read, like statistics and "cookie" values
that are all the same.  In addition, for historical reasons
``ovs-ofctl`` always defaults to using OpenFlow 1.0 even though Faucet
and most modern controllers use OpenFlow 1.3, so it's best to force it
to use OpenFlow 1.3.  We could throw in a lot of options to fix these,
but we'll want to do this more than once, so let's start by defining a
shell function for ourselves::

  $ dump-flows () {
    ovs-ofctl -OOpenFlow13 --names --no-stat dump-flows "$@" \
      | sed 's/cookie=0x5adc15c0, //'
  }

Let's also define ``save-flows`` and ``diff-flows`` functions for
later use::

  $ save-flows () {
    ovs-ofctl -OOpenFlow13 --no-names --sort dump-flows "$@"
  }
  $ diff-flows () {
    ovs-ofctl -OOpenFlow13 diff-flows "$@" | sed 's/cookie=0x5adc15c0 //'
  }

Now let's take a look at the flows we've got and what they mean, like
this::

  $ dump-flows br0

To reduce resource utilisation on hardware switches, Faucet will try to install
the minimal set of OpenFlow tables to match the features enabled in
``faucet.yaml``.  Since we have only enabled switching we will end up
with 4 tables. If we inspect the contents of ``inst/faucet.log`` Faucet will
tell us what each table does::

  Sep 10 06:44:10 faucet.valve INFO     DPID 1 (0x1) switch-1 table ID 0 table config dec_ttl: None exact_match: None match_types: (('eth_dst', True), ('eth_type', False), ('in_port', False), ('vlan_vid', False)) meter: None miss_goto: None name: vlan next_tables: ['eth_src'] output: True set_fields: ('vlan_vid',) size: 32 table_id: 0 vlan_port_scale: 1.5
  Sep 10 06:44:10 faucet.valve INFO     DPID 1 (0x1) switch-1 table ID 1 table config dec_ttl: None exact_match: None match_types: (('eth_dst', True), ('eth_src', False), ('eth_type', False), ('in_port', False), ('vlan_vid', False)) meter: None miss_goto: eth_dst name: eth_src next_tables: ['eth_dst', 'flood'] output: True set_fields: ('vlan_vid', 'eth_dst') size: 32 table_id: 1 vlan_port_scale: 4.1
  Sep 10 06:44:10 faucet.valve INFO     DPID 1 (0x1) switch-1 table ID 2 table config dec_ttl: None exact_match: True match_types: (('eth_dst', False), ('vlan_vid', False)) meter: None miss_goto: flood name: eth_dst next_tables: [] output: True set_fields: None size: 41 table_id: 2 vlan_port_scale: 4.1
  Sep 10 06:44:10 faucet.valve INFO     DPID 1 (0x1) switch-1 table ID 3 table config dec_ttl: None exact_match: None match_types: (('eth_dst', True), ('in_port', False), ('vlan_vid', False)) meter: None miss_goto: None name: flood next_tables: [] output: True set_fields: None size: 32 table_id: 3 vlan_port_scale: 2.1

Currently, we have:

Table 0 (vlan)
  Ingress VLAN processing

Table 1 (eth_src)
  Ingress L2 processing, MAC learning

Table 2 (eth_dst)
  Egress L2 processing

Table 3 (flood)
  Flooding

In Table 0 we see flows that recognize packets without a VLAN header on each of
our ports (``vlan_tci=0x0000/0x1fff``), push on the VLAN configured for the
port, and proceed to table 3.  There is also a fallback flow to drop other
packets, which in practice means that if any received packet already has a
VLAN header then it will be dropped::

  priority=9000,in_port=p1,vlan_tci=0x0000/0x1fff actions=push_vlan:0x8100,set_field:4196->vlan_vid,goto_table:1
  priority=9000,in_port=p2,vlan_tci=0x0000/0x1fff actions=push_vlan:0x8100,set_field:4196->vlan_vid,goto_table:1
  priority=9000,in_port=p3,vlan_tci=0x0000/0x1fff actions=push_vlan:0x8100,set_field:4196->vlan_vid,goto_table:1
  priority=9000,in_port=p4,vlan_tci=0x0000/0x1fff actions=push_vlan:0x8100,set_field:4296->vlan_vid,goto_table:1
  priority=9000,in_port=p5,vlan_tci=0x0000/0x1fff actions=push_vlan:0x8100,set_field:4296->vlan_vid,goto_table:1
  priority=0 actions=drop

.. note::

  The syntax ``set_field:4196->vlan_vid`` is curious and somewhat
  misleading.  OpenFlow 1.3 defines the ``vlan_vid`` field as a 13-bit
  field where bit 12 is set to 1 if the VLAN header is present.  Thus,
  since 4196 is 0x1064, this action sets VLAN value 0x64, which in
  decimal is 100.

Table 1 starts off with a flow that drops some inappropriate packets,
in this case EtherType 0x9000 (Ethernet Configuration Testing Protocol),
which should not be forwarded by a switch::

  table=1, priority=9099,dl_type=0x9000 actions=drop

Table 1 is primarily used for MAC learning but the controller hasn't learned
any MAC addresses yet. It also drops some more inappropriate packets such as
those that claim to be from a broadcast source address (why not from all
multicast source addresses, though?). We'll come back here later::

  table=1, priority=9099,dl_src=ff:ff:ff:ff:ff:ff actions=drop
  table=1, priority=9001,dl_src=0e:00:00:00:00:01 actions=drop
  table=1, priority=9000,dl_vlan=100 actions=CONTROLLER:96,goto_table:2
  table=1, priority=9000,dl_vlan=200 actions=CONTROLLER:96,goto_table:2
  table=1, priority=0 actions=goto_table:2

Table 2 is used to direct packets to learned MACs but Faucet hasn't
learned any MACs yet, so it just sends all the packets along to table 3::

  table=2, priority=0 actions=goto_table:3

Table 3 does some more dropping of packets we don't want to forward,
in this case STP::

  table=3, priority=9099,dl_dst=01:00:0c:cc:cc:cd actions=drop
  table=3, priority=9099,dl_dst=01:80:c2:00:00:00/ff:ff:ff:ff:ff:f0 actions=drop

Table 3 implements flooding, broadcast, and multicast.  The flows for
broadcast and flood are easy to understand: if the packet came in on a
given port and needs to be flooded or broadcast, output it to all the
other ports in the same VLAN::

  table=3, priority=9004,dl_vlan=100,dl_dst=ff:ff:ff:ff:ff:ff actions=pop_vlan,output:p1,output:p2,output:p3
  table=3, priority=9004,dl_vlan=200,dl_dst=ff:ff:ff:ff:ff:ff actions=pop_vlan,output:p4,output:p5
  table=3, priority=9000,dl_vlan=100 actions=pop_vlan,output:p1,output:p2,output:p3
  table=3, priority=9000,dl_vlan=200 actions=pop_vlan,output:p4,output:p5

There are also some flows for handling some standard forms of
multicast, and a fallback drop flow::

  table=3, priority=9003,dl_vlan=100,dl_dst=33:33:00:00:00:00/ff:ff:00:00:00:00 actions=pop_vlan,output:p1,output:p2,output:p3
  table=3, priority=9003,dl_vlan=200,dl_dst=33:33:00:00:00:00/ff:ff:00:00:00:00 actions=pop_vlan,output:p4,output:p5
  table=3, priority=9001,dl_vlan=100,dl_dst=01:80:c2:00:00:00/ff:ff:ff:00:00:00 actions=pop_vlan,output:p1,output:p2,output:p3
  table=3, priority=9002,dl_vlan=100,dl_dst=01:00:5e:00:00:00/ff:ff:ff:00:00:00 actions=pop_vlan,output:p1,output:p2,output:p3
  table=3, priority=9001,dl_vlan=200,dl_dst=01:80:c2:00:00:00/ff:ff:ff:00:00:00 actions=pop_vlan,output:p4,output:p5
  table=3, priority=9002,dl_vlan=200,dl_dst=01:00:5e:00:00:00/ff:ff:ff:00:00:00 actions=pop_vlan,output:p4,output:p5
  table=3, priority=0 actions=drop

Tracing
~~~~~~~

Let's go a level deeper.  So far, everything we've done has been
fairly general.  We can also look at something more specific: the path
that a particular packet would take through Open vSwitch.  We can use
the ``ofproto/trace`` command to play "what-if?" games.  This command
is one that we send directly to ``ovs-vswitchd``, using the
``ovs-appctl`` utility.

.. note::

  ``ovs-appctl`` is actually a very simple-minded JSON-RPC client, so you could
  also use some other utility that speaks JSON-RPC, or access it from a program
  as an API.

The ``ovs-vswitchd``\(8) manpage has a lot of detail on how to use
``ofproto/trace``, but let's just start by building up from a simple
example.  You can start with a command that just specifies the
datapath (e.g. ``br0``), an input port, and nothing else; unspecified
fields default to all-zeros.  Let's look at the full output for this
trivial example::

  $ ovs-appctl ofproto/trace br0 in_port=p1
  Flow: in_port=1,vlan_tci=0x0000,dl_src=00:00:00:00:00:00,dl_dst=00:00:00:00:00:00,dl_type=0x0000

  bridge("br0")
  -------------
   0. in_port=1,vlan_tci=0x0000/0x1fff, priority 9000, cookie 0x5adc15c0
      push_vlan:0x8100
      set_field:4196->vlan_vid
      goto_table:1
   1. dl_vlan=100, priority 9000, cookie 0x5adc15c0
      CONTROLLER:96
      goto_table:2
   2. priority 0, cookie 0x5adc15c0
      goto_table:3
   3. dl_vlan=100, priority 9000, cookie 0x5adc15c0
      pop_vlan
      output:1
       >> skipping output to input port
      output:2
      output:3

  Final flow: unchanged
  Megaflow: recirc_id=0,eth,in_port=1,vlan_tci=0x0000,dl_src=00:00:00:00:00:00,dl_dst=00:00:00:00:00:00,dl_type=0x0000
  Datapath actions: push_vlan(vid=100,pcp=0),userspace(pid=0,controller(reason=1,dont_send=1,continuation=0,recirc_id=1,rule_cookie=0x5adc15c0,controller_id=0,max_len=96)),pop_vlan,2,3

The first line of output, beginning with ``Flow:``, just repeats our
request in a more verbose form, including the L2 fields that were
zeroed.

Each of the numbered items under ``bridge("br0")`` shows what would
happen to our hypothetical packet in the table with the given number.
For example, we see in table 0 that the packet matches a flow that
push on a VLAN header, set the VLAN ID to 100, and goes on to further
processing in table 1.  In table 1, the packet gets sent to the
controller to allow MAC learning to take place, and then table 3
floods the packet to the other ports in the same VLAN.

Summary information follows the numbered tables.  The packet hasn't
been changed (overall, even though a VLAN was pushed and then popped
back off) since ingress, hence ``Final flow: unchanged``.  We'll look
at the ``Megaflow`` information later.  The ``Datapath actions``
summarize what would actually happen to such a packet.

Triggering MAC Learning
~~~~~~~~~~~~~~~~~~~~~~~

We just saw how a packet gets sent to the controller to trigger MAC
learning.  Let's actually send the packet and see what happens.  But
before we do that, let's save a copy of the current flow tables for
later comparison::

  $ save-flows br0 > flows1

Now use ``ofproto/trace``, as before, with a few new twists: we
specify the source and destination Ethernet addresses and append the
``-generate`` option so that side effects like sending a packet to the
controller actually happen::

  $ ovs-appctl ofproto/trace br0 in_port=p1,dl_src=00:11:11:00:00:00,dl_dst=00:22:22:00:00:00 -generate

The output is almost identical to that before, so it is not repeated
here.  But, take a look at ``inst/faucet.log`` now.  It should now
include a line at the end that says that it learned about our MAC
00:11:11:00:00:00, like this::

  Sep 10 08:16:28 faucet.valve INFO     DPID 1 (0x1) switch-1 L2 learned 00:11:11:00:00:00 (L2 type 0x0000, L3 src None, L3 dst None) Port 1 VLAN 100  (1 hosts total)

Now compare the flow tables that we saved to the current ones::

  diff-flows flows1 br0

The result should look like this, showing new flows for the learned
MACs::

  +table=1 priority=9098,in_port=1,dl_vlan=100,dl_src=00:11:11:00:00:00 hard_timeout=3605 actions=goto_table:2
  +table=2 priority=9099,dl_vlan=100,dl_dst=00:11:11:00:00:00 idle_timeout=3605 actions=pop_vlan,output:1

To demonstrate the usefulness of the learned MAC, try tracing (with
side effects) a packet arriving on ``p2`` (or ``p3``) and destined to
the address learned on ``p1``, like this::

  $ ovs-appctl ofproto/trace br0 in_port=p2,dl_src=00:22:22:00:00:00,dl_dst=00:11:11:00:00:00 -generate

The first time you run this command, you will notice that it sends the
packet to the controller, to learn ``p2``'s 00:22:22:00:00:00 source
address::

  bridge("br0")
  -------------
   0. in_port=2,vlan_tci=0x0000/0x1fff, priority 9000, cookie 0x5adc15c0
      push_vlan:0x8100
      set_field:4196->vlan_vid
      goto_table:1
   1. dl_vlan=100, priority 9000, cookie 0x5adc15c0
      CONTROLLER:96
      goto_table:2
   2. dl_vlan=100,dl_dst=00:11:11:00:00:00, priority 9099, cookie 0x5adc15c0
      pop_vlan
      output:1

If you check ``inst/faucet.log``, you can see that ``p2``'s MAC has
been learned too::

  Sep 10 08:17:45 faucet.valve INFO     DPID 1 (0x1) switch-1 L2 learned 00:22:22:00:00:00 (L2 type 0x0000, L3 src None, L3 dst None) Port 2 VLAN 100  (2 hosts total)

Similarly for ``diff-flows``::

  $ diff-flows flows1 br0
  +table=1 priority=9098,in_port=1,dl_vlan=100,dl_src=00:11:11:00:00:00 hard_timeout=3605 actions=goto_table:2
  +table=1 priority=9098,in_port=2,dl_vlan=100,dl_src=00:22:22:00:00:00 hard_timeout=3599 actions=goto_table:2
  +table=2 priority=9099,dl_vlan=100,dl_dst=00:11:11:00:00:00 idle_timeout=3605 actions=pop_vlan,output:1
  +table=2 priority=9099,dl_vlan=100,dl_dst=00:22:22:00:00:00 idle_timeout=3599 actions=pop_vlan,output:2

Then, if you re-run either of the ``ofproto/trace`` commands (with or
without ``-generate``), you can see that the packets go back and forth
without any further MAC learning, e.g.::

  $ ovs-appctl ofproto/trace br0 in_port=p2,dl_src=00:22:22:00:00:00,dl_dst=00:11:11:00:00:00 -generate
  Flow: in_port=2,vlan_tci=0x0000,dl_src=00:22:22:00:00:00,dl_dst=00:11:11:00:00:00,dl_type=0x0000

  bridge("br0")
  -------------
   0. in_port=2,vlan_tci=0x0000/0x1fff, priority 9000, cookie 0x5adc15c0
      push_vlan:0x8100
      set_field:4196->vlan_vid
      goto_table:1
   1. in_port=2,dl_vlan=100,dl_src=00:22:22:00:00:00, priority 9098, cookie 0x5adc15c0
      goto_table:2
   2. dl_vlan=100,dl_dst=00:11:11:00:00:00, priority 9099, cookie 0x5adc15c0
      pop_vlan
      output:1

  Final flow: unchanged
  Megaflow: recirc_id=0,eth,in_port=2,vlan_tci=0x0000/0x1fff,dl_src=00:22:22:00:00:00,dl_dst=00:11:11:00:00:00,dl_type=0x0000
  Datapath actions: 1

Performance
~~~~~~~~~~~

Open vSwitch has a concept of a "fast path" and a "slow path"; ideally
all packets stay in the fast path.  This distinction between slow path
and fast path is the key to making sure that Open vSwitch performs as
fast as possible.

Some factors can force a flow or a packet to take the slow path.  As one
example, all CFM, BFD, LACP, STP, and LLDP processing takes place in the
slow path, in the cases where Open vSwitch processes these protocols
itself instead of delegating to controller-written flows.  As a second
example, any flow that modifies ARP fields is processed in the slow
path.  These are corner cases that are unlikely to cause performance
problems in practice because these protocols send packets at a
relatively slow rate, and users and controller authors do not normally
need to be concerned about them.

To understand what cases users and controller authors should consider,
we need to talk about how Open vSwitch optimizes for performance.  The
Open vSwitch code is divided into two major components which, as
already mentioned, are called the "slow path" and "fast path" (aka
"datapath").  The slow path is embedded in the ``ovs-vswitchd``
userspace program.  It is the part of the Open vSwitch packet
processing logic that understands OpenFlow.  Its job is to take a
packet and run it through the OpenFlow tables to determine what should
happen to it.  It outputs a list of actions in a form similar to
OpenFlow actions but simpler, called "ODP actions" or "datapath
actions".  It then passes the ODP actions to the datapath, which
applies them to the packet.

.. note::

  Open vSwitch contains a single slow path and multiple fast paths.
  The difference between using Open vSwitch with the Linux kernel
  versus with DPDK is the datapath.

If every packet passed through the slow path and the fast path in this
way, performance would be terrible.  The key to getting high
performance from this architecture is caching.  Open vSwitch includes
a multi-level cache.  It works like this:

1. A packet initially arrives at the datapath.  Some datapaths (such
   as DPDK and the in-tree version of the OVS kernel module) have a
   first-level cache called the "microflow cache".  The microflow
   cache is the key to performance for relatively long-lived, high
   packet rate flows.  If the datapath has a microflow cache, then it
   consults it and, if there is a cache hit, the datapath executes the
   associated actions.  Otherwise, it proceeds to step 2.

2. The datapath consults its second-level cache, called the "megaflow
   cache".  The megaflow cache is the key to performance for shorter
   or low packet rate flows.  If there is a megaflow cache hit, the
   datapath executes the associated actions.  Otherwise, it proceeds
   to step 3.

3. The datapath passes the packet to the slow path, which runs it
   through the OpenFlow table to yield ODP actions, a process that is
   often called "flow translation".  It then passes the packet back to
   the datapath to execute the actions and to, if possible, install a
   megaflow cache entry so that subsequent similar packets can be
   handled directly by the fast path.  (We already described above
   most of the cases where a cache entry cannot be installed.)

The megaflow cache is the key cache to consider for performance
tuning.  Open vSwitch provides tools for understanding and optimizing
its behavior.  The ``ofproto/trace`` command that we have already been
using is the most common tool for this use.  Let's take another look
at the most recent ``ofproto/trace`` output::

  $ ovs-appctl ofproto/trace br0 in_port=p2,dl_src=00:22:22:00:00:00,dl_dst=00:11:11:00:00:00 -generate
  Flow: in_port=2,vlan_tci=0x0000,dl_src=00:22:22:00:00:00,dl_dst=00:11:11:00:00:00,dl_type=0x0000

  bridge("br0")
  -------------
   0. in_port=2,vlan_tci=0x0000/0x1fff, priority 9000, cookie 0x5adc15c0
      push_vlan:0x8100
      set_field:4196->vlan_vid
      goto_table:1
   1. in_port=2,dl_vlan=100,dl_src=00:22:22:00:00:00, priority 9098, cookie 0x5adc15c0
      goto_table:2
   2. dl_vlan=100,dl_dst=00:11:11:00:00:00, priority 9099, cookie 0x5adc15c0
      pop_vlan
      output:1

  Final flow: unchanged
  Megaflow: recirc_id=0,eth,in_port=2,vlan_tci=0x0000/0x1fff,dl_src=00:22:22:00:00:00,dl_dst=00:11:11:00:00:00,dl_type=0x0000
  Datapath actions: 1

This time, it's the last line that we're interested in.  This line
shows the entry that Open vSwitch would insert into the megaflow cache
given the particular packet with the current flow tables.  The
megaflow entry includes:

* ``recirc_id``.  This is an implementation detail that users don't
  normally need to understand.

* ``eth``.  This just indicates that the cache entry matches only
  Ethernet packets; Open vSwitch also supports other types of packets,
  such as IP packets not encapsulated in Ethernet.

* All of the fields matched by any of the flows that the packet
  visited:

  ``in_port``
    In tables 0 and 1.

  ``vlan_tci``
    In tables 0, 1, and 2 (``vlan_tci`` includes the VLAN ID and PCP
    fields and``dl_vlan`` is just the VLAN ID).

  ``dl_src``
    In table 1.

  ``dl_dst``
    In table 2.

* All of the fields matched by flows that had to be ruled out to
  ensure that the ones that actually matched were the highest priority
  matching rules.

The last one is important.  Notice how the megaflow matches on
``dl_type=0x0000``, even though none of the tables matched on
``dl_type`` (the Ethernet type).  One reason is because of this flow
in OpenFlow table 1 (which shows up in ``dump-flows`` output)::

  table=1, priority=9099,dl_type=0x9000 actions=drop

This flow has higher priority than the flow in table 1 that actually
matched.  This means that, to put it in the megaflow cache,
``ovs-vswitchd`` has to add a match on ``dl_type`` to ensure that the
cache entry doesn't match ECTP packets (with Ethertype 0x9000).

.. note::

  In fact, in some cases ``ovs-vswitchd`` matches on fields that
  aren't strictly required according to this description.  ``dl_type``
  is actually one of those, so deleting the LLDP flow probably would
  not have any effect on the megaflow.  But the principle here is
  sound.

So why does any of this matter?  It's because, the more specific a
megaflow is, that is, the more fields or bits within fields that a
megaflow matches, the less valuable it is from a caching viewpoint.  A
very specific megaflow might match on L2 and L3 addresses and L4 port
numbers.  When that happens, only packets in one (half-)connection
match the megaflow.  If that connection has only a few packets, as
many connections do, then the high cost of the slow path translation
is amortized over only a few packets, so the average cost of
forwarding those packets is high.  On the other hand, if a megaflow
only matches a relatively small number of L2 and L3 packets, then the
cache entry can potentially be used by many individual connections,
and the average cost is low.

For more information on how Open vSwitch constructs megaflows,
including about ways that it can make megaflow entries less specific
than one would infer from the discussion here, please refer to the
2015 NSDI paper, "The Design and Implementation of Open vSwitch",
which focuses on this algorithm.

Routing
-------

We've looked at how Faucet implements switching in OpenFlow, and how
Open vSwitch implements OpenFlow through its datapath architecture.
Now let's start over, adding L3 routing into the picture.

It's remarkably easy to enable routing.  We just change our ``vlans``
section in ``inst/faucet.yaml`` to specify a router IP address for
each VLAN and define a router between them. The ``dps`` section is unchanged::

  dps:
      switch-1:
          dp_id: 0x1
          timeout: 3600
          arp_neighbor_timeout: 3600
          interfaces:
              1:
                  native_vlan: 100
              2:
                  native_vlan: 100
              3:
                  native_vlan: 100
              4:
                  native_vlan: 200
              5:
                  native_vlan: 200
  vlans:
      100:
          faucet_vips: ["10.100.0.254/24"]
      200:
          faucet_vips: ["10.200.0.254/24"]
  routers:
      router-1:
          vlans: [100, 200]

Then we can tell Faucet to reload its configuration::

  $ sudo docker exec faucet pkill -HUP -f faucet.faucet

OpenFlow Layer
~~~~~~~~~~~~~~

Now that we have an additional feature enabled (routing) we will notice some
additional OpenFlow tables if we check ``inst/faucet.log``::

  Sep 10 08:28:14 faucet.valve INFO     DPID 1 (0x1) switch-1 table ID 0 table config dec_ttl: None exact_match: None match_types: (('eth_dst', True), ('eth_type', False), ('in_port', False), ('vlan_vid', False)) meter: None miss_goto: None name: vlan next_tables: ['eth_src'] output: True set_fields: ('vlan_vid',) size: 32 table_id: 0 vlan_port_scale: 1.5
  Sep 10 08:28:14 faucet.valve INFO     DPID 1 (0x1) switch-1 table ID 1 table config dec_ttl: None exact_match: None match_types: (('eth_dst', True), ('eth_src', False), ('eth_type', False), ('in_port', False), ('vlan_vid', False)) meter: None miss_goto: eth_dst name: eth_src next_tables: ['ipv4_fib', 'vip', 'eth_dst', 'flood'] output: True set_fields: ('vlan_vid', 'eth_dst') size: 32 table_id: 1 vlan_port_scale: 4.1
  Sep 10 08:28:14 faucet.valve INFO     DPID 1 (0x1) switch-1 table ID 2 table config dec_ttl: True exact_match: None match_types: (('eth_type', False), ('ipv4_dst', True), ('vlan_vid', False)) meter: None miss_goto: None name: ipv4_fib next_tables: ['vip', 'eth_dst', 'flood'] output: True set_fields: ('eth_dst', 'eth_src', 'vlan_vid') size: 32 table_id: 2 vlan_port_scale: 3.1
  Sep 10 08:28:14 faucet.valve INFO     DPID 1 (0x1) switch-1 table ID 3 table config dec_ttl: None exact_match: None match_types: (('arp_tpa', False), ('eth_dst', False), ('eth_type', False), ('icmpv6_type', False), ('ip_proto', False)) meter: None miss_goto: None name: vip next_tables: ['eth_dst', 'flood'] output: True set_fields: None size: 32 table_id: 3 vlan_port_scale: None
  Sep 10 08:28:14 faucet.valve INFO     DPID 1 (0x1) switch-1 table ID 4 table config dec_ttl: None exact_match: True match_types: (('eth_dst', False), ('vlan_vid', False)) meter: None miss_goto: flood name: eth_dst next_tables: [] output: True set_fields: None size: 41 table_id: 4 vlan_port_scale: 4.1
  Sep 10 08:28:14 faucet.valve INFO     DPID 1 (0x1) switch-1 table ID 5 table config dec_ttl: None exact_match: None match_types: (('eth_dst', True), ('in_port', False), ('vlan_vid', False)) meter: None miss_goto: None name: flood next_tables: [] output: True set_fields: None size: 32 table_id: 5 vlan_port_scale: 2.1

So now we have an additional FIB and VIP table:

Table 0 (vlan)
  Ingress VLAN processing

Table 1 (eth_src)
  Ingress L2 processing, MAC learning

Table 2 (ipv4_fib)
  L3 forwarding for IPv4

Table 3 (vip)
  Virtual IP processing, e.g. for router IP addresses implemented by Faucet

Table 4 (eth_dst)
  Egress L2 processing

Table 5 (flood)
  Flooding

Back in the OVS sandbox, let's see what new flow rules have been added, with::

  $ diff-flows flows1 br0 | grep +

First, table 1 has new flows to direct ARP packets to table 3 (the
virtual IP processing table), presumably to handle ARP for the router
IPs.  New flows also send IP packets destined to a particular Ethernet
address to table 2 (the L3 forwarding table); we can make the educated
guess that the Ethernet address is the one used by the Faucet router::

  +table=1 priority=9131,arp,dl_vlan=100 actions=goto_table:3
  +table=1 priority=9131,arp,dl_vlan=200 actions=goto_table:3
  +table=1 priority=9099,ip,dl_vlan=100,dl_dst=0e:00:00:00:00:01 actions=goto_table:2
  +table=1 priority=9099,ip,dl_vlan=200,dl_dst=0e:00:00:00:00:01 actions=goto_table:2

In the new ``ipv4_fib`` table (table 2) there appear to be flows for verifying
that the packets are indeed addressed to a network or IP address that Faucet
knows how to route::

  +table=2 priority=9131,ip,dl_vlan=100,nw_dst=10.100.0.254 actions=goto_table:3
  +table=2 priority=9131,ip,dl_vlan=200,nw_dst=10.200.0.254 actions=goto_table:3
  +table=2 priority=9123,ip,dl_vlan=200,nw_dst=10.100.0.0/24 actions=goto_table:3
  +table=2 priority=9123,ip,dl_vlan=100,nw_dst=10.100.0.0/24 actions=goto_table:3
  +table=2 priority=9123,ip,dl_vlan=200,nw_dst=10.200.0.0/24 actions=goto_table:3
  +table=2 priority=9123,ip,dl_vlan=100,nw_dst=10.200.0.0/24 actions=goto_table:3

In our new ``vip`` table (table 3) there are a few different things going on.
It sends ARP requests for the router IPs to the controller; presumably the
controller will generate replies and send them back to the requester.
It switches other ARP packets, either broadcasting them if they have a broadcast
destination or attempting to unicast them otherwise.  It sends all
other IP packets to the controller::

  +table=3 priority=9133,arp,arp_tpa=10.100.0.254 actions=CONTROLLER:128
  +table=3 priority=9133,arp,arp_tpa=10.200.0.254 actions=CONTROLLER:128
  +table=3 priority=9132,arp,dl_dst=ff:ff:ff:ff:ff:ff actions=goto_table:4
  +table=3 priority=9131,arp actions=goto_table:4
  +table=3 priority=9130,ip actions=CONTROLLER:128

Performance is clearly going to be poor if every packet that needs to
be routed has to go to the controller, but it's unlikely that's the
full story.  In the next section, we'll take a closer look.

Tracing
~~~~~~~

As in our switching example, we can play some "what-if?" games to
figure out how this works.  Let's suppose that a machine with IP
10.100.0.1, on port ``p1``, wants to send a IP packet to a machine
with IP 10.200.0.1 on port ``p4``.  Assuming that these hosts have not
been in communication recently, the steps to accomplish this are
normally the following:

1. Host 10.100.0.1 sends an ARP request to router 10.100.0.254.

2. The router sends an ARP reply to the host.

3. Host 10.100.0.1 sends an IP packet to 10.200.0.1, via the router's
   Ethernet address.

4. The router broadcasts an ARP request to ``p4`` and ``p5``, the
   ports that carry the 10.200.0.<x> network.

5. Host 10.200.0.1 sends an ARP reply to the router.

6. Either the router sends the IP packet (which it buffered) to
   10.200.0.1, or eventually 10.100.0.1 times out and resends it.

Let's use ``ofproto/trace`` to see whether Faucet and OVS follow this
procedure.

Before we start, save a new snapshot of the flow tables for later
comparison::

  $ save-flows br0 > flows2

Step 1: Host ARP for Router
+++++++++++++++++++++++++++

Let's simulate the ARP from 10.100.0.1 to its gateway router
10.100.0.254.  This requires more detail than any of the packets we've
simulated previously::

  $ ovs-appctl ofproto/trace br0 in_port=p1,dl_src=00:01:02:03:04:05,dl_dst=ff:ff:ff:ff:ff:ff,dl_type=0x806,arp_spa=10.100.0.1,arp_tpa=10.100.0.254,arp_sha=00:01:02:03:04:05,arp_tha=ff:ff:ff:ff:ff:ff,arp_op=1 -generate

The important part of the output is where it shows that the packet was
recognized as an ARP request destined to the router gateway and
therefore sent to the controller::

  3. arp,arp_tpa=10.100.0.254, priority 9133, cookie 0x5adc15c0
    CONTROLLER:128

The Faucet log shows that Faucet learned the host's MAC address,
its MAC-to-IP mapping, and responded to the ARP request::

  Sep 10 08:52:46 faucet.valve INFO     DPID 1 (0x1) switch-1 Adding new route 10.100.0.1/32 via 10.100.0.1 (00:01:02:03:04:05) on VLAN 100
  Sep 10 08:52:46 faucet.valve INFO     DPID 1 (0x1) switch-1 Resolve response to 10.100.0.254 from 00:01:02:03:04:05 (L2 type 0x0806, L3 src 10.100.0.1, L3 dst 10.100.0.254) Port 1 VLAN 100
  Sep 10 08:52:46 faucet.valve INFO     DPID 1 (0x1) switch-1 L2 learned 00:01:02:03:04:05 (L2 type 0x0806, L3 src 10.100.0.1, L3 dst 10.100.0.254) Port 1 VLAN 100  (1 hosts total)

We can also look at the changes to the flow tables::

  $ diff-flows flows2 br0
  +table=1 priority=9098,in_port=1,dl_vlan=100,dl_src=00:01:02:03:04:05 hard_timeout=3605 actions=goto_table:4
  +table=2 priority=9131,ip,dl_vlan=200,nw_dst=10.100.0.1 actions=set_field:4196->vlan_vid,set_field:0e:00:00:00:00:01->eth_src,set_field:00:01:02:03:04:05->eth_dst,dec_ttl,goto_table:4
  +table=2 priority=9131,ip,dl_vlan=100,nw_dst=10.100.0.1 actions=set_field:4196->vlan_vid,set_field:0e:00:00:00:00:01->eth_src,set_field:00:01:02:03:04:05->eth_dst,dec_ttl,goto_table:4
  +table=4 priority=9099,dl_vlan=100,dl_dst=00:01:02:03:04:05 idle_timeout=3605 actions=pop_vlan,output:1

The new flows include one in table 1 and one in table 4 for the
learned MAC, which have the same forms we saw before.  The new flows
in table 2 are different.  They matches packets directed to 10.100.0.1
(in two VLANs) and forward them to the host by updating the Ethernet
source and destination addresses appropriately, decrementing the TTL,
and skipping ahead to unicast output in table 7.  This means that
packets sent **to** 10.100.0.1 should now get to their destination.

Step 2: Router Sends ARP Reply
++++++++++++++++++++++++++++++

``inst/faucet.log`` said that the router sent an ARP reply.  How can
we see it?  Simulated packets just get dropped by default.  One way is
to configure the dummy ports to write the packets they receive to a
file.  Let's try that.  First configure the port::

  $ ovs-vsctl set interface p1 options:pcap=p1.pcap

Then re-run the "trace" command::

  $ ovs-appctl ofproto/trace br0 in_port=p1,dl_src=00:01:02:03:04:05,dl_dst=ff:ff:ff:ff:ff:ff,dl_type=0x806,arp_spa=10.100.0.1,arp_tpa=10.100.0.254,arp_sha=00:01:02:03:04:05,arp_tha=ff:ff:ff:ff:ff:ff,arp_op=1 -generate

And dump the reply packet::

  $ /usr/sbin/tcpdump -evvvr sandbox/p1.pcap
  reading from file sandbox/p1.pcap, link-type EN10MB (Ethernet)
  20:55:13.186932 0e:00:00:00:00:01 (oui Unknown) > 00:01:02:03:04:05 (oui Unknown), ethertype ARP (0x0806), length 60: Ethernet (len 6), IPv4 (len 4), Reply 10.100.0.254 is-at 0e:00:00:00:00:01 (oui Unknown), length 46

We clearly see the ARP reply, which tells us that the Faucet router's
Ethernet address is 0e:00:00:00:00:01 (as we guessed before from the
flow table.

Let's configure the rest of our ports to log their packets, too::

  $ for i in 2 3 4 5; do ovs-vsctl set interface p$i options:pcap=p$i.pcap; done

Step 3: Host Sends IP Packet
++++++++++++++++++++++++++++

Now that host 10.100.0.1 has the MAC address for its router, it can
send an IP packet to 10.200.0.1 via the router's MAC address, like
this::

  $ ovs-appctl ofproto/trace br0 in_port=p1,dl_src=00:01:02:03:04:05,dl_dst=0e:00:00:00:00:01,udp,nw_src=10.100.0.1,nw_dst=10.200.0.1,nw_ttl=64 -generate
  Flow: udp,in_port=1,vlan_tci=0x0000,dl_src=00:01:02:03:04:05,dl_dst=0e:00:00:00:00:01,nw_src=10.100.0.1,nw_dst=10.200.0.1,nw_tos=0,nw_ecn=0,nw_ttl=64,tp_src=0,tp_dst=0

  bridge("br0")
  -------------
   0. in_port=1,vlan_tci=0x0000/0x1fff, priority 9000, cookie 0x5adc15c0
      push_vlan:0x8100
      set_field:4196->vlan_vid
      goto_table:1
   1. ip,dl_vlan=100,dl_dst=0e:00:00:00:00:01, priority 9099, cookie 0x5adc15c0
      goto_table:2
   2. ip,dl_vlan=100,nw_dst=10.200.0.0/24, priority 9123, cookie 0x5adc15c0
      goto_table:3
   3. ip, priority 9130, cookie 0x5adc15c0
      CONTROLLER:128

  Final flow: udp,in_port=1,dl_vlan=100,dl_vlan_pcp=0,vlan_tci1=0x0000,dl_src=00:01:02:03:04:05,dl_dst=0e:00:00:00:00:01,nw_src=10.100.0.1,nw_dst=10.200.0.1,nw_tos=0,nw_ecn=0,nw_ttl=64,tp_src=0,tp_dst=0
  Megaflow: recirc_id=0,eth,ip,in_port=1,vlan_tci=0x0000/0x1fff,dl_src=00:01:02:03:04:05,dl_dst=0e:00:00:00:00:01,nw_dst=10.200.0.0/25,nw_frag=no
  Datapath actions: push_vlan(vid=100,pcp=0),userspace(pid=0,controller(reason=1,dont_send=0,continuation=0,recirc_id=6,rule_cookie=0x5adc15c0,controller_id=0,max_len=128))

Observe that the packet gets recognized as destined to the router, in
table 1, and then as properly destined to the 10.200.0.0/24 network,
in table 2.  In table 3, however, it gets sent to the controller.
Presumably, this is because Faucet has not yet resolved an Ethernet
address for the destination host 10.200.0.1.  It probably sent out an
ARP request.  Let's take a look in the next step.

Step 4: Router Broadcasts ARP Request
+++++++++++++++++++++++++++++++++++++

The router needs to know the Ethernet address of 10.200.0.1.  It knows
that, if this machine exists, it's on port ``p4`` or ``p5``, since we
configured those ports as VLAN 200.

Let's make sure::

  $ /usr/sbin/tcpdump -evvvr sandbox/p4.pcap
  reading from file sandbox/p4.pcap, link-type EN10MB (Ethernet)
  20:57:31.116097 0e:00:00:00:00:01 (oui Unknown) > Broadcast, ethertype ARP (0x0806), length 60: Ethernet (len 6), IPv4 (len 4), Request who-has 10.200.0.1 tell 10.200.0.254, length 46

and::

  $ /usr/sbin/tcpdump -evvvr sandbox/p5.pcap
  reading from file sandbox/p5.pcap, link-type EN10MB (Ethernet)
  20:58:04.129735 0e:00:00:00:00:01 (oui Unknown) > Broadcast, ethertype ARP (0x0806), length 60: Ethernet (len 6), IPv4 (len 4), Request who-has 10.200.0.1 tell 10.200.0.254, length 46

For good measure, let's make sure that it wasn't sent to ``p3``::

  $ /usr/sbin/tcpdump -evvvr sandbox/p3.pcap
  reading from file sandbox/p3.pcap, link-type EN10MB (Ethernet)

Step 5: Host 2 Sends ARP Reply
++++++++++++++++++++++++++++++

The Faucet controller sent an ARP request, so we can send an ARP
reply::

  $ ovs-appctl ofproto/trace br0 in_port=p4,dl_src=00:10:20:30:40:50,dl_dst=0e:00:00:00:00:01,dl_type=0x806,arp_spa=10.200.0.1,arp_tpa=10.200.0.254,arp_sha=00:10:20:30:40:50,arp_tha=0e:00:00:00:00:01,arp_op=2 -generate
  Flow: arp,in_port=4,vlan_tci=0x0000,dl_src=00:10:20:30:40:50,dl_dst=0e:00:00:00:00:01,arp_spa=10.200.0.1,arp_tpa=10.200.0.254,arp_op=2,arp_sha=00:10:20:30:40:50,arp_tha=0e:00:00:00:00:01

  bridge("br0")
  -------------
   0. in_port=4,vlan_tci=0x0000/0x1fff, priority 9000, cookie 0x5adc15c0
      push_vlan:0x8100
      set_field:4296->vlan_vid
      goto_table:1
   1. arp,dl_vlan=200, priority 9131, cookie 0x5adc15c0
      goto_table:3
   3. arp,arp_tpa=10.200.0.254, priority 9133, cookie 0x5adc15c0
      CONTROLLER:128

  Final flow: arp,in_port=4,dl_vlan=200,dl_vlan_pcp=0,vlan_tci1=0x0000,dl_src=00:10:20:30:40:50,dl_dst=0e:00:00:00:00:01,arp_spa=10.200.0.1,arp_tpa=10.200.0.254,arp_op=2,arp_sha=00:10:20:30:40:50,arp_tha=0e:00:00:00:00:01
  Megaflow: recirc_id=0,eth,arp,in_port=4,vlan_tci=0x0000/0x1fff,arp_tpa=10.200.0.254
  Datapath actions: push_vlan(vid=200,pcp=0),userspace(pid=0,controller(reason=1,dont_send=0,continuation=0,recirc_id=7,rule_cookie=0x5adc15c0,controller_id=0,max_len=128))

It shows up in ``inst/faucet.log``::

  Sep 10 08:59:02 faucet.valve INFO     DPID 1 (0x1) switch-1 Adding new route 10.200.0.1/32 via 10.200.0.1 (00:10:20:30:40:50) on VLAN 200
  Sep 10 08:59:02 faucet.valve INFO     DPID 1 (0x1) switch-1 Received advert for 10.200.0.1 from 00:10:20:30:40:50 (L2 type 0x0806, L3 src 10.200.0.1, L3 dst 10.200.0.254) Port 4 VLAN 200
  Sep 10 08:59:02 faucet.valve INFO     DPID 1 (0x1) switch-1 L2 learned 00:10:20:30:40:50 (L2 type 0x0806, L3 src 10.200.0.1, L3 dst 10.200.0.254) Port 4 VLAN 200  (1 hosts total)

and in the OVS flow tables::

  $ diff-flows flows2 br0
  +table=1 priority=9098,in_port=4,dl_vlan=200,dl_src=00:10:20:30:40:50 hard_timeout=3598 actions=goto_table:4
  ...
  +table=2 priority=9131,ip,dl_vlan=200,nw_dst=10.200.0.1 actions=set_field:4296->vlan_vid,set_field:0e:00:00:00:00:01->eth_src,set_field:00:10:20:30:40:50->eth_dst,dec_ttl,goto_table:4
  +table=2 priority=9131,ip,dl_vlan=100,nw_dst=10.200.0.1 actions=set_field:4296->vlan_vid,set_field:0e:00:00:00:00:01->eth_src,set_field:00:10:20:30:40:50->eth_dst,dec_ttl,goto_table:4
  ...
  +table=4 priority=9099,dl_vlan=200,dl_dst=00:10:20:30:40:50 idle_timeout=3598 actions=pop_vlan,output:4

Step 6: IP Packet Delivery
++++++++++++++++++++++++++

Now both the host and the router have everything they need to deliver
the packet.  There are two ways it might happen.  If Faucet's router
is smart enough to buffer the packet that trigger ARP resolution, then
it might have delivered it already.  If so, then it should show up in
``p4.pcap``.  Let's take a look::

  $ /usr/sbin/tcpdump -evvvr sandbox/p4.pcap ip
  reading from file sandbox/p4.pcap, link-type EN10MB (Ethernet)

Nope.  That leaves the other possibility, which is that Faucet waits
for the original sending host to re-send the packet.  We can do that
by re-running the trace::

  $ ovs-appctl ofproto/trace br0 in_port=p1,dl_src=00:01:02:03:04:05,dl_dst=0e:00:00:00:00:01,udp,nw_src=10.100.0.1,nw_dst=10.200.0.1,nw_ttl=64 -generate

  Flow: udp,in_port=1,vlan_tci=0x0000,dl_src=00:01:02:03:04:05,dl_dst=0e:00:00:00:00:01,nw_src=10.100.0.1,nw_dst=10.200.0.1,nw_tos=0,nw_ecn=0,nw_ttl=64,tp_src=0,tp_dst=0
  bridge("br0")
  -------------
   0. in_port=1,vlan_tci=0x0000/0x1fff, priority 9000, cookie 0x5adc15c0
      push_vlan:0x8100
      set_field:4196->vlan_vid
      goto_table:1
   1. ip,dl_vlan=100,dl_dst=0e:00:00:00:00:01, priority 9099, cookie 0x5adc15c0
      goto_table:2
   2. ip,dl_vlan=100,nw_dst=10.200.0.1, priority 9131, cookie 0x5adc15c0
      set_field:4296->vlan_vid
      set_field:0e:00:00:00:00:01->eth_src
      set_field:00:10:20:30:40:50->eth_dst
      dec_ttl
      goto_table:4
   4. dl_vlan=200,dl_dst=00:10:20:30:40:50, priority 9099, cookie 0x5adc15c0
      pop_vlan
      output:4

  Final flow: udp,in_port=1,vlan_tci=0x0000,dl_src=0e:00:00:00:00:01,dl_dst=00:10:20:30:40:50,nw_src=10.100.0.1,nw_dst=10.200.0.1,nw_tos=0,nw_ecn=0,nw_ttl=63,tp_src=0,tp_dst=0
  Megaflow: recirc_id=0,eth,ip,in_port=1,vlan_tci=0x0000/0x1fff,dl_src=00:01:02:03:04:05,dl_dst=0e:00:00:00:00:01,nw_dst=10.200.0.1,nw_ttl=64,nw_frag=no
  Datapath actions: set(eth(src=0e:00:00:00:00:01,dst=00:10:20:30:40:50)),set(ipv4(dst=10.200.0.1,ttl=63)),4

Finally, we have working IP packet forwarding!

Performance
~~~~~~~~~~~

Take another look at the megaflow line above::

  Megaflow: recirc_id=0,eth,ip,in_port=1,vlan_tci=0x0000/0x1fff,dl_src=00:01:02:03:04:05,dl_dst=0e:00:00:00:00:01,nw_dst=10.200.0.1,nw_ttl=64,nw_frag=no

This means that (almost) any packet between these Ethernet source and
destination hosts, destined to the given IP host, will be handled by
this single megaflow cache entry.  So regardless of the number of UDP
packets or TCP connections that these hosts exchange, Open vSwitch
packet processing won't need to fall back to the slow path.  It is
quite efficient.

.. note::

  The exceptions are packets with a TTL other than 64, and fragmented
  packets.  Most hosts use a constant TTL for outgoing packets, and
  fragments are rare.  If either of those did change, then that would
  simply result in a new megaflow cache entry.

The datapath actions might also be worth a look::

  Datapath actions: set(eth(src=0e:00:00:00:00:01,dst=00:10:20:30:40:50)),set(ipv4(dst=10.200.0.1,ttl=63)),4

This just means that, to process these packets, the datapath changes
the Ethernet source and destination addresses and the IP TTL, and then
transmits the packet to port ``p4`` (also numbered 4).  Notice in
particular that, despite the OpenFlow actions that pushed, modified,
and popped back off a VLAN, there is nothing in the datapath actions
about VLANs.  This is because the OVS flow translation code "optimizes
out" redundant or unneeded actions, which saves time when the cache
entry is executed later.

.. note::

  It's not clear why the actions also re-set the IP destination
  address to its original value.  Perhaps this is a minor performance
  bug.

ACLs
----

Let's try out some ACLs, since they do a good job illustrating some of
the ways that OVS tries to optimize megaflows.  Update
``inst/faucet.yaml`` to the following::

  dps:
      switch-1:
          dp_id: 0x1
          timeout: 3600
          arp_neighbor_timeout: 3600
          interfaces:
              1:
                  native_vlan: 100
                  acl_in: 1
              2:
                  native_vlan: 100
              3:
                  native_vlan: 100
              4:
                  native_vlan: 200
              5:
                  native_vlan: 200
  vlans:
      100:
          faucet_vips: ["10.100.0.254/24"]
      200:
          faucet_vips: ["10.200.0.254/24"]
  routers:
      router-1:
          vlans: [100, 200]
  acls:
      1:
          - rule:
              dl_type: 0x800
              nw_proto: 6
              tcp_dst: 8080
              actions:
                  allow: 0
          - rule:
              actions:
                  allow: 1

Then reload Faucet::

  $ sudo docker exec faucet pkill -HUP -f faucet.faucet

We will now find Faucet has added a new table to the start of the pipeline
for processing port ACLs.  Let's take a look at our new table 0 with
``dump-flows br0``::

  priority=9099,tcp,in_port=p1,tp_dst=8080 actions=drop
  priority=9098,in_port=p1 actions=goto_table:1
  priority=9099,in_port=p2 actions=goto_table:1
  priority=9099,in_port=p3 actions=goto_table:1
  priority=9099,in_port=p4 actions=goto_table:1
  priority=9099,in_port=p5 actions=goto_table:1
  priority=0 actions=drop

We now have a flow that just jumps to table 1 (vlan) for each configured port,
and a low priority rule to drop other unrecognized packets.  We also see a flow
rule for dropping TCP port 8080 traffic on port 1.  If we compare this rule to
the ACL we configured, we can clearly see how Faucet has converted this ACL to
fit into the OpenFlow pipeline.

The most interesting question here is performance.  If you recall the
earlier discussion, when a packet through the flow table encounters a
match on a given field, the resulting megaflow has to match on that
field, even if the flow didn't actually match.  This is expensive.

In particular, here you can see that any TCP packet is going to
encounter the ACL flow, even if it is directed to a port other than
8080.  If that means that every megaflow for a TCP packet is going to
have to match on the TCP destination, that's going to be bad for
caching performance because there will be a need for a separate
megaflow for every TCP destination port that actually appears in
traffic, which means a lot more megaflows than otherwise.  (Really, in
practice, if such a simple ACL blew up performance, OVS wouldn't be a
very good switch!)

Let's see what happens, by sending a packet to port 80 (instead of
8080)::

  $ ovs-appctl ofproto/trace br0 in_port=p1,dl_src=00:01:02:03:04:05,dl_dst=0e:00:00:00:00:01,tcp,nw_src=10.100.0.1,nw_dst=10.200.0.1,nw_ttl=64,tp_dst=80 -generate
  src=10.100.0.1,nw_dst=10.200.0.1,nw_ttl=64,tp_dst=80 -generate
  Flow: tcp,in_port=1,vlan_tci=0x0000,dl_src=00:01:02:03:04:05,dl_dst=0e:00:00:00:00:01,nw_src=10.100.0.1,nw_dst=10.200.0.1,nw_tos=0,nw_ecn=0,nw_ttl=64,tp_src=0,tp_dst=80,tcp_flags=0

  bridge("br0")
  -------------
   0. in_port=1, priority 9098, cookie 0x5adc15c0
      goto_table:1
   1. in_port=1,vlan_tci=0x0000/0x1fff, priority 9000, cookie 0x5adc15c0
      push_vlan:0x8100
      set_field:4196->vlan_vid
      goto_table:2
   2. ip,dl_vlan=100,dl_dst=0e:00:00:00:00:01, priority 9099, cookie 0x5adc15c0
      goto_table:3
   3. ip,dl_vlan=100,nw_dst=10.200.0.0/24, priority 9123, cookie 0x5adc15c0
      goto_table:4
   4. ip, priority 9130, cookie 0x5adc15c0
      CONTROLLER:128

  Final flow: tcp,in_port=1,dl_vlan=100,dl_vlan_pcp=0,vlan_tci1=0x0000,dl_src=00:01:02:03:04:05,dl_dst=0e:00:00:00:00:01,nw_src=10.100.0.1,nw_dst=10.200.0.1,nw_tos=0,nw_ecn=0,nw_ttl=64,tp_src=0,tp_dst=80,tcp_flags=0
  Megaflow: recirc_id=0,eth,tcp,in_port=1,vlan_tci=0x0000/0x1fff,dl_src=00:01:02:03:04:05,dl_dst=0e:00:00:00:00:01,nw_dst=10.200.0.0/25,nw_frag=no,tp_dst=0x0/0xf000
  Datapath actions: push_vlan(vid=100,pcp=0),userspace(pid=0,controller(reason=1,dont_send=0,continuation=0,recirc_id=8,rule_cookie=0x5adc15c0,controller_id=0,max_len=128))

Take a look at the Megaflow line and in particular the match on
``tp_dst``, which says ``tp_dst=0x0/0xf000``.  What this means is that
the megaflow matches on only the top 4 bits of the TCP destination
port.  That works because::

    80 (base 10) == 0000,0000,0101,0000 (base 2)
  8080 (base 10) == 0001,1111,1001,0000 (base 2)

and so by matching on only the top 4 bits, rather than all 16, the OVS
fast path can distinguish port 80 from port 8080.  This allows this
megaflow to match one-sixteenth of the TCP destination port address
space, rather than just 1/65536th of it.

.. note::

  The algorithm OVS uses for this purpose isn't perfect.  In this
  case, a single-bit match would work (e.g. tp_dst=0x0/0x1000), and
  would be superior since it would only match half the port address
  space instead of one-sixteenth.

For details of this algorithm, please refer to ``lib/classifier.c`` in
the Open vSwitch source tree, or our 2015 NSDI paper "The Design and
Implementation of Open vSwitch".

Finishing Up
------------

When you're done, you probably want to exit the sandbox session, with
Control+D or ``exit``, and stop the Faucet controller with ``sudo docker
stop faucet; sudo docker rm faucet``.

Further Directions
------------------

We've looked a fair bit at how Faucet interacts with Open vSwitch.  If
you still have some interest, you might want to explore some of these
directions:

* Adding more than one switch.  Faucet can control multiple switches
  but we've only been simulating one of them.  It's easy enough to
  make a single OVS instance act as multiple switches (just
  ``ovs-vsctl add-br`` another bridge), or you could use genuinely
  separate OVS instances.

* Additional features.  Faucet has more features than we've
  demonstrated, such as IPv6 routing and port mirroring.  These should
  also interact gracefully with Open vSwitch.

* Real performance testing.  We've looked at how flows and traces
  **should** demonstrate good performance, but of course there's no
  proof until it actually works in practice.  We've also only tested
  with trivial configurations.  Open vSwitch can scale to millions of
  OpenFlow flows, but the scaling in practice depends on the
  particular flow tables and traffic patterns, so it's valuable to
  test with large configurations, either in the way we've done it or
  with real traffic.

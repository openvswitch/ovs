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

========================
Quality of Service (QoS)
========================

Q: Does OVS support Quality of Service (QoS)?

    A: Yes.  For traffic that egresses from a switch, OVS supports traffic
    shaping; for traffic that ingresses into a switch, OVS support policing.
    Policing is a simple form of quality-of-service that simply drops packets
    received in excess of the configured rate.  Due to its simplicity, policing
    is usually less accurate and less effective than egress traffic shaping,
    which queues packets.

    Keep in mind that ingress and egress are from the perspective of the
    switch.  That means that egress shaping limits the rate at which traffic is
    allowed to transmit from a physical interface, but not the rate at which
    traffic will be received on a virtual machine's VIF.  For ingress policing,
    the behavior is the opposite.

Q: How do I configure egress traffic shaping?

    A: Suppose that you want to set up bridge br0 connected to physical
    Ethernet port eth0 (a 1 Gbps device) and virtual machine interfaces vif1.0
    and vif2.0, and that you want to limit traffic from vif1.0 to eth0 to 10
    Mbps and from vif2.0 to eth0 to 20 Mbps.  Then, you could configure the
    bridge this way::

        $ ovs-vsctl -- \
          add-br br0 -- \
          add-port br0 eth0 -- \
          add-port br0 vif1.0 -- set interface vif1.0 ofport_request=5 -- \
          add-port br0 vif2.0 -- set interface vif2.0 ofport_request=6 -- \
          set port eth0 qos=@newqos -- \
          --id=@newqos create qos type=linux-htb \
              other-config:max-rate=1000000000 \
              queues:123=@vif10queue \
              queues:234=@vif20queue -- \
          --id=@vif10queue create queue other-config:max-rate=10000000 -- \
          --id=@vif20queue create queue other-config:max-rate=20000000

    At this point, bridge br0 is configured with the ports and eth0 is
    configured with the queues that you need for QoS, but nothing is actually
    directing packets from vif1.0 or vif2.0 to the queues that we have set up
    for them.  That means that all of the packets to eth0 are going to the
    "default queue", which is not what we want.

    We use OpenFlow to direct packets from vif1.0 and vif2.0 to the queues
    reserved for them::

        $ ovs-ofctl add-flow br0 in_port=5,actions=set_queue:123,normal
        $ ovs-ofctl add-flow br0 in_port=6,actions=set_queue:234,normal

    Each of the above flows matches on the input port, sets up the appropriate
    queue (123 for vif1.0, 234 for vif2.0), and then executes the "normal"
    action, which performs the same switching that Open vSwitch would have done
    without any OpenFlow flows being present.  (We know that vif1.0 and vif2.0
    have OpenFlow port numbers 5 and 6, respectively, because we set their
    ofport_request columns above.  If we had not done that, then we would have
    needed to find out their port numbers before setting up these flows.)

    Now traffic going from vif1.0 or vif2.0 to eth0 should be rate-limited.

    By the way, if you delete the bridge created by the above commands, with::

        $ ovs-vsctl del-br br0

    then that will leave one unreferenced QoS record and two unreferenced Queue
    records in the Open vSwich database.  One way to clear them out, assuming
    you don't have other QoS or Queue records that you want to keep, is::

        $ ovs-vsctl -- --all destroy QoS -- --all destroy Queue

    If you do want to keep some QoS or Queue records, or the Open vSwitch you
    are using is older than version 1.8 (which added the ``--all`` option),
    then you will have to destroy QoS and Queue records individually.

Q: How do I configure ingress policing?

    A: A policing policy can be configured on an interface to drop packets that
    arrive at a higher rate than the configured value.  For example, the
    following commands will rate-limit traffic that vif1.0 may generate to
    10Mbps:

        $ ovs-vsctl set interface vif1.0 ingress_policing_rate=10000
        $ ovs-vsctl set interface vif1.0 ingress_policing_burst=8000

    Traffic policing can interact poorly with some network protocols and can
    have surprising results.  The "Ingress Policing" section of
    ovs-vswitchd.conf.db(5) discusses the issues in greater detail.

Q: I configured Quality of Service (QoS) in my OpenFlow network by adding
records to the QoS and Queue table, but the results aren't what I expect.

    A: Did you install OpenFlow flows that use your queues?  This is the
    primary way to tell Open vSwitch which queues you want to use.  If you
    don't do this, then the default queue will be used, which will probably not
    have the effect you want.

    Refer to the previous question for an example.

Q: I'd like to take advantage of some QoS feature that Open vSwitch doesn't yet
support.  How do I do that?

    A: Open vSwitch does not implement QoS itself.  Instead, it can configure
    some, but not all, of the QoS features built into the Linux kernel.  If you
    need some QoS feature that OVS cannot configure itself, then the first step
    is to figure out whether Linux QoS supports that feature.  If it does, then
    you can submit a patch to support Open vSwitch configuration for that
    feature, or you can use "tc" directly to configure the feature in Linux.
    (If Linux QoS doesn't support the feature you want, then first you have to
    add that support to Linux.)

Q: I configured QoS, correctly, but my measurements show that it isn't working
as well as I expect.

    A: With the Linux kernel, the Open vSwitch implementation of QoS has two
    aspects:

    - Open vSwitch configures a subset of Linux kernel QoS features, according
      to what is in OVSDB.  It is possible that this code has bugs.  If you
      believe that this is so, then you can configure the Linux traffic control
      (QoS) stack directly with the "tc" program.  If you get better results
      that way, you can send a detailed bug report to bugs@openvswitch.org.

      It is certain that Open vSwitch cannot configure every Linux kernel QoS
      feature.  If you need some feature that OVS cannot configure, then you
      can also use "tc" directly (or add that feature to OVS).

    - The Open vSwitch implementation of OpenFlow allows flows to be directed
      to particular queues.  This is pretty simple and unlikely to have serious
      bugs at this point.

    However, most problems with QoS on Linux are not bugs in Open vSwitch at
    all.  They tend to be either configuration errors (please see the earlier
    questions in this section) or issues with the traffic control (QoS) stack
    in Linux.  The Open vSwitch developers are not experts on Linux traffic
    control.  We suggest that, if you believe you are encountering a problem
    with Linux traffic control, that you consult the tc manpages (e.g. tc(8),
    tc-htb(8), tc-hfsc(8)), web resources (e.g. http://lartc.org/), or mailing
    lists (e.g. http://vger.kernel.org/vger-lists.html#netdev).

Q: Does Open vSwitch support OpenFlow meters?

    A: Since version 2.0, Open vSwitch has OpenFlow protocol support for
    OpenFlow meters.  There is no implementation of meters in the Open vSwitch
    software switch (neither the kernel-based nor userspace switches)
    prior to version 2.8. Userspace switch meter implementation has been
    added to the master branch and is planned to be part of 2.8 release.

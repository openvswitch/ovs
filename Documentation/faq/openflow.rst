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

==============
Using OpenFlow
==============

Q: What versions of OpenFlow does Open vSwitch support?

    A: The following table lists the versions of OpenFlow supported by each
    version of Open vSwitch:

    ===================== ===== ===== ===== ===== ===== =====
    Open vSwitch          OF1.0 OF1.1 OF1.2 OF1.3 OF1.4 OF1.5
    ===================== ===== ===== ===== ===== ===== =====
    1.9 and earlier        yes   ---   ---   ---   ---   ---
    1.10, 1.11             yes   ---   (*)   (*)   ---   ---
    2.0, 2.1               yes   (*)   (*)   (*)   ---   ---
    2.2                    yes   (*)   (*)   (*)   (%)   (*)
    2.3, 2.4               yes   yes   yes   yes   (*)   (*)
    2.5, 2.6, 2.7          yes   yes   yes   yes   (*)   (*)
    2.8, 2.9, 2.10, 2.11   yes   yes   yes   yes   yes   (*)
    2.12                   yes   yes   yes   yes   yes   yes
    ===================== ===== ===== ===== ===== ===== =====

    --- Not supported.
    yes Supported and enabled by default
    (*) Supported, but missing features, and must be enabled by user.
    (%) Experimental, unsafe implementation.

    In any case, the user may override the default:

    - To enable OpenFlow 1.0, 1.1, 1.2, and 1.3 on bridge br0::

          $ ovs-vsctl set bridge br0 \
              protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13

    - To enable OpenFlow 1.0, 1.1, 1.2, 1.3, 1.4, and 1.5 on bridge br0::

          $ ovs-vsctl set bridge br0 \
              protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13,OpenFlow14,OpenFlow15

    - To enable only OpenFlow 1.0 on bridge br0::

          $ ovs-vsctl set bridge br0 protocols=OpenFlow10

    All current versions of ovs-ofctl enable only OpenFlow 1.0 by default.  Use
    the -O option to enable support for later versions of OpenFlow in
    ovs-ofctl.  For example::

        $ ovs-ofctl -O OpenFlow13 dump-flows br0

    (Open vSwitch 2.2 had an experimental implementation of OpenFlow 1.4 that
    could cause crashes.  We don't recommend enabling it.)

    :doc:`/topics/openflow` tracks support for OpenFlow 1.1 and later features.

Q: Does Open vSwitch support MPLS?

    A: Before version 1.11, Open vSwitch did not support MPLS.  That is, these
    versions can match on MPLS Ethernet types, but they cannot match, push, or
    pop MPLS labels, nor can they look past MPLS labels into the encapsulated
    packet.

    Open vSwitch versions 1.11, 2.0, and 2.1 have very minimal support for
    MPLS.  With the userspace datapath only, these versions can match, push, or
    pop a single MPLS label, but they still cannot look past MPLS labels (even
    after popping them) into the encapsulated packet.  Kernel datapath support
    is unchanged from earlier versions.

    Open vSwitch version 2.3 can match, push, or pop a single MPLS label and
    look past the MPLS label into the encapsulated packet.  Both userspace and
    kernel datapaths will be supported, but MPLS processing always happens in
    userspace either way, so kernel datapath performance will be disappointing.

    Open vSwitch version 2.4 can match, push, or pop up to 3 MPLS labels and
    look past the MPLS label into the encapsulated packet.  It will have kernel
    support for MPLS, yielding improved performance.

Q: I'm getting "error type 45250 code 0".  What's that?

    A: This is a Open vSwitch extension to OpenFlow error codes.  Open vSwitch
    uses this extension when it must report an error to an OpenFlow controller
    but no standard OpenFlow error code is suitable.

    Open vSwitch logs the errors that it sends to controllers, so the easiest
    thing to do is probably to look at the ovs-vswitchd log to find out what
    the error was.

    If you want to dissect the extended error message yourself, the format is
    documented in include/openflow/nicira-ext.h in the Open vSwitch source
    distribution.  The extended error codes are documented in
    include/openvswitch/ofp-errors.h.

Q: Some of the traffic that I'd expect my OpenFlow controller to see doesn't
actually appear through the OpenFlow connection, even though I know that it's
going through.

    A: By default, Open vSwitch assumes that OpenFlow controllers are connected
    "in-band", that is, that the controllers are actually part of the network
    that is being controlled.  In in-band mode, Open vSwitch sets up special
    "hidden" flows to make sure that traffic can make it back and forth between
    OVS and the controllers.  These hidden flows are higher priority than any
    flows that can be set up through OpenFlow, and they are not visible through
    normal OpenFlow flow table dumps.

    Usually, the hidden flows are desirable and helpful, but occasionally they
    can cause unexpected behavior.  You can view the full OpenFlow flow table,
    including hidden flows, on bridge br0 with the command::

        $ ovs-appctl bridge/dump-flows br0

    to help you debug.  The hidden flows are those with priorities
    greater than 65535 (the maximum priority that can be set with
    OpenFlow).

    The ``Documentation/topics/design`` doc describes the in-band model in
    detail.

    If your controllers are not actually in-band (e.g. they are on
    localhost via 127.0.0.1, or on a separate network), then you should
    configure your controllers in "out-of-band" mode.  If you have one
    controller on bridge br0, then you can configure out-of-band mode
    on it with::

        $ ovs-vsctl set controller br0 connection-mode=out-of-band

Q: Some of the OpenFlow flows that my controller sets up don't seem to apply to
certain traffic, especially traffic between OVS and the controller itself.

    A: See above.

Q: I configured all my controllers for out-of-band control mode but "ovs-appctl
bridge/dump-flows" still shows some hidden flows.

    A: You probably have a remote manager configured (e.g. with "ovs-vsctl
    set-manager").  By default, Open vSwitch assumes that managers need in-band
    rules set up on every bridge.  You can disable these rules on bridge br0
    with::

        $ ovs-vsctl set bridge br0 other-config:disable-in-band=true

    This actually disables in-band control entirely for the bridge, as if all
    the bridge's controllers were configured for out-of-band control.

Q: My OpenFlow controller doesn't see the VLANs that I expect.

    A: See answer under "VLANs", above.

Q: I ran ``ovs-ofctl add-flow br0 nw_dst=192.168.0.1,actions=drop`` but I got a
funny message like this::

    ofp_util|INFO|normalization changed ofp_match, details:
    ofp_util|INFO| pre: nw_dst=192.168.0.1
    ofp_util|INFO|post:

and when I ran ``ovs-ofctl dump-flows br0`` I saw that my nw_dst match had
disappeared, so that the flow ends up matching every packet.

    A: The term "normalization" in the log message means that a flow cannot
    match on an L3 field without saying what L3 protocol is in use.  The
    "ovs-ofctl" command above didn't specify an L3 protocol, so the L3 field
    match was dropped.

    In this case, the L3 protocol could be IP or ARP.  A correct command for
    each possibility is, respectively::

        $ ovs-ofctl add-flow br0 ip,nw_dst=192.168.0.1,actions=drop

    and::

        $ ovs-ofctl add-flow br0 arp,nw_dst=192.168.0.1,actions=drop

    Similarly, a flow cannot match on an L4 field without saying what L4
    protocol is in use.  For example, the flow match ``tp_src=1234`` is, by
    itself, meaningless and will be ignored.  Instead, to match TCP source port
    1234, write ``tcp,tp_src=1234``, or to match UDP source port 1234, write
    ``udp,tp_src=1234``.

Q: How can I figure out the OpenFlow port number for a given port?

    A: The ``OFPT_FEATURES_REQUEST`` message requests an OpenFlow switch to
    respond with an ``OFPT_FEATURES_REPLY`` that, among other information,
    includes a mapping between OpenFlow port names and numbers.  From a command
    prompt, ``ovs-ofctl show br0`` makes such a request and prints the response
    for switch br0.

    The Interface table in the Open vSwitch database also maps OpenFlow port
    names to numbers.  To print the OpenFlow port number associated with
    interface eth0, run::

        $ ovs-vsctl get Interface eth0 ofport

    You can print the entire mapping with::

        $ ovs-vsctl -- --columns=name,ofport list Interface

    but the output mixes together interfaces from all bridges in the database,
    so it may be confusing if more than one bridge exists.

    In the Open vSwitch database, ofport value ``-1`` means that the interface
    could not be created due to an error.  (The Open vSwitch log should
    indicate the reason.)  ofport value ``[]`` (the empty set) means that the
    interface hasn't been created yet.  The latter is normally an intermittent
    condition (unless ovs-vswitchd is not running).

Q: I added some flows with my controller or with ovs-ofctl, but when I run
"ovs-dpctl dump-flows" I don't see them.

    A: ovs-dpctl queries a kernel datapath, not an OpenFlow switch.  It won't
    display the information that you want.  You want to use ``ovs-ofctl
    dump-flows`` instead.

Q: It looks like each of the interfaces in my bonded port shows up as an
individual OpenFlow port.  Is that right?

    A: Yes, Open vSwitch makes individual bond interfaces visible as OpenFlow
    ports, rather than the bond as a whole.  The interfaces are treated
    together as a bond for only a few purposes:

    - Sending a packet to the OFPP_NORMAL port.  (When an OpenFlow controller
      is not configured, this happens implicitly to every packet.)

    - Mirrors configured for output to a bonded port.

    It would make a lot of sense for Open vSwitch to present a bond as a single
    OpenFlow port.  If you want to contribute an implementation of such a
    feature, please bring it up on the Open vSwitch development mailing list at
    dev@openvswitch.org.

Q: I have a sophisticated network setup involving Open vSwitch, VMs or multiple
hosts, and other components.  The behavior isn't what I expect.  Help!

    A: To debug network behavior problems, trace the path of a packet,
    hop-by-hop, from its origin in one host to a remote host.  If that's
    correct, then trace the path of the response packet back to the origin.

    The open source tool called ``plotnetcfg`` can help to understand the
    relationship between the networking devices on a single host.

    Usually a simple ICMP echo request and reply (``ping``) packet is good
    enough.  Start by initiating an ongoing ``ping`` from the origin host to a
    remote host.  If you are tracking down a connectivity problem, the "ping"
    will not display any successful output, but packets are still being sent.
    (In this case the packets being sent are likely ARP rather than ICMP.)

    Tools available for tracing include the following:

    - ``tcpdump`` and ``wireshark`` for observing hops across network devices,
      such as Open vSwitch internal devices and physical wires.

    - ``ovs-appctl dpif/dump-flows <br>`` in Open vSwitch 1.10 and later or
      ``ovs-dpctl dump-flows <br>`` in earlier versions.  These tools allow one
      to observe the actions being taken on packets in ongoing flows.

      See ovs-vswitchd(8) for ``ovs-appctl dpif/dump-flows`` documentation,
      ovs-dpctl(8) for ``ovs-dpctl dump-flows`` documentation, and "Why are
      there so many different ways to dump flows?" above for some background.

    - ``ovs-appctl ofproto/trace`` to observe the logic behind how ovs-vswitchd
      treats packets.  See ovs-vswitchd(8) for documentation.  You can out more
      details about a given flow that ``ovs-dpctl dump-flows`` displays, by
      cutting and pasting a flow from the output into an ``ovs-appctl
      ofproto/trace`` command.

    - SPAN, RSPAN, and ERSPAN features of physical switches, to observe what
      goes on at these physical hops.

    Starting at the origin of a given packet, observe the packet at each hop in
    turn.  For example, in one plausible scenario, you might:

    1. ``tcpdump`` the ``eth`` interface through which an ARP egresses a VM,
       from inside the VM.

    2. ``tcpdump`` the ``vif`` or ``tap`` interface through which the ARP
       ingresses the host machine.

    3. Use ``ovs-dpctl dump-flows`` to spot the ARP flow and observe the host
       interface through which the ARP egresses the physical machine.  You may
       need to use ``ovs-dpctl show`` to interpret the port numbers.  If the
       output seems surprising, you can use ``ovs-appctl ofproto/trace`` to
       observe details of how ovs-vswitchd determined the actions in the
       ``ovs-dpctl dump-flows`` output.

    4. ``tcpdump`` the ``eth`` interface through which the ARP egresses the
       physical machine.

    5. ``tcpdump`` the ``eth`` interface through which the ARP ingresses the
       physical machine, at the remote host that receives the ARP.

    6. Use ``ovs-dpctl dump-flows`` to spot the ARP flow on the remote host
       remote host that receives the ARP and observe the VM ``vif`` or ``tap``
       interface to which the flow is directed.  Again, ``ovs-dpctl show`` and
       ``ovs-appctl ofproto/trace`` might help.

    7. ``tcpdump`` the ``vif`` or ``tap`` interface to which the ARP is
       directed.

    8. ``tcpdump`` the ``eth`` interface through which the ARP ingresses a VM,
       from inside the VM.

    It is likely that during one of these steps you will figure out the
    problem.  If not, then follow the ARP reply back to the origin, in reverse.

Q: How do I make a flow drop packets?

    A: To drop a packet is to receive it without forwarding it.  OpenFlow
    explicitly specifies forwarding actions.  Thus, a flow with an empty set of
    actions does not forward packets anywhere, causing them to be dropped.  You
    can specify an empty set of actions with ``actions=`` on the ovs-ofctl
    command line.  For example::

        $ ovs-ofctl add-flow br0 priority=65535,actions=

    would cause every packet entering switch br0 to be dropped.

    You can write "drop" explicitly if you like.  The effect is the same.
    Thus, the following command also causes every packet entering switch br0 to
    be dropped::

        $ ovs-ofctl add-flow br0 priority=65535,actions=drop

    ``drop`` is not an action, either in OpenFlow or Open vSwitch.  Rather, it
    is only a way to say that there are no actions.

Q: I added a flow to send packets out the ingress port, like this::

    $ ovs-ofctl add-flow br0 in_port=2,actions=2

but OVS drops the packets instead.

    A: Yes, OpenFlow requires a switch to ignore attempts to send a packet out
    its ingress port.  The rationale is that dropping these packets makes it
    harder to loop the network.  Sometimes this behavior can even be
    convenient, e.g. it is often the desired behavior in a flow that forwards a
    packet to several ports ("floods" the packet).

    Sometimes one really needs to send a packet out its ingress port
    ("hairpin"). In this case, output to ``OFPP_IN_PORT``, which in ovs-ofctl
    syntax is expressed as just ``in_port``, e.g.::

        $ ovs-ofctl add-flow br0 in_port=2,actions=in_port

    This also works in some circumstances where the flow doesn't match on the
    input port.  For example, if you know that your switch has five ports
    numbered 2 through 6, then the following will send every received packet
    out every port, even its ingress port::

        $ ovs-ofctl add-flow br0 actions=2,3,4,5,6,in_port

    or, equivalently::

        $ ovs-ofctl add-flow br0 actions=all,in_port

    Sometimes, in complicated flow tables with multiple levels of ``resubmit``
    actions, a flow needs to output to a particular port that may or may not be
    the ingress port.  It's difficult to take advantage of ``OFPP_IN_PORT`` in
    this situation.  To help, Open vSwitch provides, as an OpenFlow extension,
    the ability to modify the in_port field.  Whatever value is currently in
    the in_port field is the port to which outputs will be dropped, as well as
    the destination for ``OFPP_IN_PORT``.  This means that the following will
    reliably output to port 2 or to ports 2 through 6, respectively::

        $ ovs-ofctl add-flow br0 in_port=2,actions=load:0->NXM_OF_IN_PORT[],2
        $ ovs-ofctl add-flow br0 actions=load:0->NXM_OF_IN_PORT[],2,3,4,5,6

    If the input port is important, then one may save and restore it on the
    stack::

         $ ovs-ofctl add-flow br0 actions=push:NXM_OF_IN_PORT[],\
             load:0->NXM_OF_IN_PORT[],\
             2,3,4,5,6,\
             pop:NXM_OF_IN_PORT[]

Q: My bridge br0 has host 192.168.0.1 on port 1 and host 192.168.0.2 on port 2.
I set up flows to forward only traffic destined to the other host and drop
other traffic, like this::

    priority=5,in_port=1,ip,nw_dst=192.168.0.2,actions=2
    priority=5,in_port=2,ip,nw_dst=192.168.0.1,actions=1
    priority=0,actions=drop

But it doesn't work--I don't get any connectivity when I do this.  Why?

    A: These flows drop the ARP packets that IP hosts use to establish IP
    connectivity over Ethernet.  To solve the problem, add flows to allow ARP
    to pass between the hosts::

        priority=5,in_port=1,arp,actions=2
        priority=5,in_port=2,arp,actions=1

    This issue can manifest other ways, too.  The following flows that match on
    Ethernet addresses instead of IP addresses will also drop ARP packets,
    because ARP requests are broadcast instead of being directed to a specific
    host::

        priority=5,in_port=1,dl_dst=54:00:00:00:00:02,actions=2
        priority=5,in_port=2,dl_dst=54:00:00:00:00:01,actions=1
        priority=0,actions=drop

    The solution already described above will also work in this case.  It may
    be better to add flows to allow all multicast and broadcast traffic::

        priority=5,in_port=1,dl_dst=01:00:00:00:00:00/01:00:00:00:00:00,actions=2
        priority=5,in_port=2,dl_dst=01:00:00:00:00:00/01:00:00:00:00:00,actions=1

Q: My bridge disconnects from my controller on add-port/del-port.

    A: Reconfiguring your bridge can change your bridge's datapath-id because
    Open vSwitch generates datapath-id from the MAC address of one of its
    ports.  In that case, Open vSwitch disconnects from controllers because
    there's no graceful way to notify controllers about the change of
    datapath-id.

    To avoid the behaviour, you can configure datapath-id manually.::

        $ ovs-vsctl set bridge br0 other-config:datapath-id=0123456789abcdef

Q: My controller complains that OVS is not buffering packets.
What's going on?

    A: "Packet buffering" is an optional OpenFlow feature, and controllers
    should detect how many "buffers" an OpenFlow switch implements.  It was
    recently noticed that OVS implementation of the buffering feature was not
    compliant to OpenFlow specifications.  Rather than fix it and risk
    controller incompatibility, the buffering feature is removed as of OVS 2.7.
    Controllers are already expected to work properly in cases where the switch
    can not buffer packets, but sends full packets in "packet-in" messages
    instead, so this change should not affect existing users.  After the change
    OVS always sends the ``buffer_id`` as ``0xffffffff`` in "packet-in"
    messages and will send an error response if any other value of this field
    is included in a "packet-out" or a "flow mod" sent by a controller.

    Packet buffers have limited usefulness in any case.  Table-miss packet-in
    messages most commonly pass the first packet in a microflow to the OpenFlow
    controller, which then sets up an OpenFlow flow that handles remaining
    traffic in the microflow without further controller intervention.  In such
    a case, the packet that initiates the microflow is in practice usually
    small (certainly for TCP), which means that the switch sends the entire
    packet to the controller and the buffer only saves a small number of bytes
    in the reverse direction.

Q: How does OVS divide flows among buckets in an OpenFlow "select" group?

    A: In Open vSwitch 2.3 and earlier, Open vSwitch used the destination
    Ethernet address to choose a bucket in a select group.

    Open vSwitch 2.4 and later by default hashes the source and destination
    Ethernet address, VLAN ID, Ethernet type, IPv4/v6 source and destination
    address and protocol, and for TCP and SCTP only, the source and destination
    ports.  The hash is "symmetric", meaning that exchanging source and
    destination addresses does not change the bucket selection.

    Select groups in Open vSwitch 2.4 and later can be configured to use a
    different hash function, using a Netronome extension to the OpenFlow 1.5+
    group_mod message.  For more information, see
    Documentation/group-selection-method-property.txt in the Open vSwitch
    source tree.

Q: An OpenFlow "select" group isn't dividing packets evenly among the buckets.

    A: When a packet passes through a "select" group, Open vSwitch hashes a
    subset of the fields in the packet, then it maps the hash value to a
    bucket.  This means that packets whose hashed fields are the same will
    always go to the same bucket[*].  More specifically, if you test with a
    single traffic flow, only one bucket will receive any traffic[**].
    Furthermore, statistics and probability mean that testing with a small
    number of flows may still yield an uneven distribution.

    [*] Unless its bucket has a watch port or group whose liveness changes
    during the test.

    [**] Unless the hash includes fields that vary within a traffic flow, such
    as tcp_flags.

Q: I added a flow to accept packets on VLAN 123 and output them on VLAN 456,
like so::

    $ ovs-ofctl add-flow br0 dl_vlan=123,actions=output:1,mod_vlan_vid:456

but the packets are actually being output in VLAN 123.  Why?

    A: OpenFlow actions are executed in the order specified.  Thus, the actions
    above first output the packet, then change its VLAN.  Since the output
    occurs before changing the VLAN, the change in VLAN will have no visible
    effect.

    To solve this and similar problems, order actions so that changes to
    headers happen before output, e.g.::

        $ ovs-ofctl add-flow br0 dl_vlan=123,actions=mod_vlan_vid:456,output:1

    See also the following question.

Q: I added a flow to a redirect packets for TCP port 80 to port 443,
like so::

    $ ovs-ofctl add-flow br0 tcp,tcp_dst=123,actions=mod_tp_dst:443

but the packets are getting dropped instead.  Why?

    A: This set of actions does change the TCP destination port to 443, but
    then it does nothing more.  It doesn't, for example, say to continue to
    another flow table or to output the packet.  Therefore, the packet is
    dropped.

    To solve the problem, add an action that does something with the modified
    packet.  For example::

        $ ovs-ofctl add-flow br0 tcp,tcp_dst=123,actions=mod_tp_dst:443,normal

    See also the preceding question.

Q: When using the "ct" action with FTP connections, it doesn't seem to matter
if I set the "alg=ftp" parameter in the action. Is this required?

    A: It is advisable to use this option. Some platforms may automatically
    detect and apply ALGs in the "ct" action regardless of the parameters you
    provide, however this is not consistent across all implementations. The
    `ovs-ofctl(8) <http://openvswitch.org/support/dist-docs/ovs-ofctl.8.html>`_
    man pages contain further details in the description of the ALG parameter.


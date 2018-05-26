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

===========================
Common Configuration Issues
===========================

Q: I created a bridge and added my Ethernet port to it, using commands like
these::

    $ ovs-vsctl add-br br0
    $ ovs-vsctl add-port br0 eth0

and as soon as I ran the "add-port" command I lost all connectivity through
eth0.  Help!

    A: A physical Ethernet device that is part of an Open vSwitch bridge should
    not have an IP address.  If one does, then that IP address will not be
    fully functional.

    You can restore functionality by moving the IP address to an Open vSwitch
    "internal" device, such as the network device named after the bridge
    itself.  For example, assuming that eth0's IP address is 192.168.128.5, you
    could run the commands below to fix up the situation::

        $ ip addr flush dev eth0
        $ ip addr add 192.168.128.5/24 dev br0
        $ ip link set br0 up

    (If your only connection to the machine running OVS is through the IP
    address in question, then you would want to run all of these commands on a
    single command line, or put them into a script.)  If there were any
    additional routes assigned to eth0, then you would also want to use
    commands to adjust these routes to go through br0.

    If you use DHCP to obtain an IP address, then you should kill the DHCP
    client that was listening on the physical Ethernet interface (e.g. eth0)
    and start one listening on the internal interface (e.g. br0).  You might
    still need to manually clear the IP address from the physical interface
    (e.g. with "ip addr flush dev eth0").

    There is no compelling reason why Open vSwitch must work this way.
    However, this is the way that the Linux kernel bridge module has always
    worked, so it's a model that those accustomed to Linux bridging are already
    used to.  Also, the model that most people expect is not implementable
    without kernel changes on all the versions of Linux that Open vSwitch
    supports.

    By the way, this issue is not specific to physical Ethernet devices.  It
    applies to all network devices except Open vSwitch "internal" devices.

Q: I created a bridge and added a couple of Ethernet ports to it, using
commands like these::

    $ ovs-vsctl add-br br0
    $ ovs-vsctl add-port br0 eth0
    $ ovs-vsctl add-port br0 eth1

and now my network seems to have melted: connectivity is unreliable (even
connectivity that doesn't go through Open vSwitch), all the LEDs on my physical
switches are blinking, wireshark shows duplicated packets, and CPU usage is
very high.

    A: More than likely, you've looped your network.  Probably, eth0 and eth1
    are connected to the same physical Ethernet switch.  This yields a scenario
    where OVS receives a broadcast packet on eth0 and sends it out on eth1,
    then the physical switch connected to eth1 sends the packet back on eth0,
    and so on forever.  More complicated scenarios, involving a loop through
    multiple switches, are possible too.

    The solution depends on what you are trying to do:

    - If you added eth0 and eth1 to get higher bandwidth or higher reliability
      between OVS and your physical Ethernet switch, use a bond.  The following
      commands create br0 and then add eth0 and eth1 as a bond::

          $ ovs-vsctl add-br br0
          $ ovs-vsctl add-bond br0 bond0 eth0 eth1

      Bonds have tons of configuration options.  Please read the documentation
      on the Port table in ovs-vswitchd.conf.db(5) for all the details.

      Configuration for DPDK-enabled interfaces is slightly less
      straightforward. Refer to :doc:`/intro/install/dpdk` for more
      information.

    - Perhaps you don't actually need eth0 and eth1 to be on the same bridge.
      For example, if you simply want to be able to connect each of them to
      virtual machines, then you can put each of them on a bridge of its own::

          $ ovs-vsctl add-br br0
          $ ovs-vsctl add-port br0 eth0

          $ ovs-vsctl add-br br1
          $ ovs-vsctl add-port br1 eth1

      and then connect VMs to br0 and br1.  (A potential disadvantage is that
      traffic cannot directly pass between br0 and br1.  Instead, it will go
      out eth0 and come back in eth1, or vice versa.)

    - If you have a redundant or complex network topology and you want to
      prevent loops, turn on spanning tree protocol (STP).  The following
      commands create br0, enable STP, and add eth0 and eth1 to the bridge.
      The order is important because you don't want have to have a loop in your
      network even transiently::

          $ ovs-vsctl add-br br0
          $ ovs-vsctl set bridge br0 stp_enable=true
          $ ovs-vsctl add-port br0 eth0
          $ ovs-vsctl add-port br0 eth1

      The Open vSwitch implementation of STP is not well tested.  Report any
      bugs you observe, but if you'd rather avoid acting as a beta tester then
      another option might be your best shot.

Q: I can't seem to use Open vSwitch in a wireless network.

    A: Wireless base stations generally only allow packets with the source MAC
    address of NIC that completed the initial handshake.  Therefore, without
    MAC rewriting, only a single device can communicate over a single wireless
    link.

    This isn't specific to Open vSwitch, it's enforced by the access point, so
    the same problems will show up with the Linux bridge or any other way to do
    bridging.

Q: I can't seem to add my PPP interface to an Open vSwitch bridge.

    A: PPP most commonly carries IP packets, but Open vSwitch works only with
    Ethernet frames.  The correct way to interface PPP to an Ethernet network
    is usually to use routing instead of switching.

Q: Is there any documentation on the database tables and fields?

    A: Yes.  ovs-vswitchd.conf.db(5) is a comprehensive reference.

Q: When I run ovs-dpctl I no longer see the bridges I created.  Instead, I only
see a datapath called "ovs-system".  How can I see datapath information about a
particular bridge?

    A: In version 1.9.0, OVS switched to using a single datapath that is shared
    by all bridges of that type.  The ``ovs-appctl dpif/*`` commands provide
    similar functionality that is scoped by the bridge.

Q: I created a GRE port using ovs-vsctl so why can't I send traffic or see the
port in the datapath?

    A: On Linux kernels before 3.11, the OVS GRE module and Linux GRE module
    cannot be loaded at the same time. It is likely that on your system the
    Linux GRE module is already loaded and blocking OVS (to confirm, check
    dmesg for errors regarding GRE registration). To fix this, unload all GRE
    modules that appear in lsmod as well as the OVS kernel module. You can then
    reload the OVS module following the directions in
    :doc:`/intro/install/general` , which will ensure that dependencies are
    satisfied.

Q: Open vSwitch does not seem to obey my packet filter rules.

    A: It depends on mechanisms and configurations you want to use.

    You cannot usefully use typical packet filters, like iptables, on physical
    Ethernet ports that you add to an Open vSwitch bridge.  This is because
    Open vSwitch captures packets from the interface at a layer lower below
    where typical packet-filter implementations install their hooks.  (This
    actually applies to any interface of type "system" that you might add to an
    Open vSwitch bridge.)

    You can usefully use typical packet filters on Open vSwitch internal ports
    as they are mostly ordinary interfaces from the point of view of packet
    filters.

    For example, suppose you create a bridge br0 and add Ethernet port eth0 to
    it.  Then you can usefully add iptables rules to affect the internal
    interface br0, but not the physical interface eth0.  (br0 is also where you
    would add an IP address, as discussed elsewhere in the FAQ.)

    For simple filtering rules, it might be possible to achieve similar results
    by installing appropriate OpenFlow flows instead.  The OVS conntrack
    feature (see the "ct" action in ovs-ofctl(8)) can implement a stateful
    firewall.

    If the use of a particular packet filter setup is essential, Open vSwitch
    might not be the best choice for you.  On Linux, you might want to consider
    using the Linux Bridge.  (This is the only choice if you want to use
    ebtables rules.)  On NetBSD, you might want to consider using the bridge(4)
    with BRIDGE_IPF option.

Q: It seems that Open vSwitch does nothing when I removed a port and then
immediately put it back.  For example, consider that p1 is a port of
``type=internal``::

     $ ovs-vsctl del-port br0 p1 -- \
         add-port br0 p1 -- \
         set interface p1 type=internal

Any other type of port gets the same effect.

    A: It's an expected behaviour.

    If del-port and add-port happen in a single OVSDB transaction as your
    example, Open vSwitch always "skips" the intermediate steps.  Even if they
    are done in multiple transactions, it's still allowed for Open vSwitch to
    skip the intermediate steps and just implement the overall effect.  In both
    cases, your example would be turned into a no-op.

    If you want to make Open vSwitch actually destroy and then re-create the
    port for some side effects like resetting kernel setting for the
    corresponding interface, you need to separate operations into multiple
    OVSDB transactions and ensure that at least the first one does not have
    ``--no-wait``.  In the following example, the first ovs-vsctl will block
    until Open vSwitch reloads the new configuration and removes the port::

        $ ovs-vsctl del-port br0 p1
        $ ovs-vsctl add-port br0 p1 -- \
            set interface p1 type=internal

Q: I want to add thousands of ports to an Open vSwitch bridge, but it takes too
long (minutes or hours) to do it with ovs-vsctl.  How can I do it faster?

    A: If you add them one at a time with ovs-vsctl, it can take a long time to
    add thousands of ports to an Open vSwitch bridge.  This is because every
    invocation of ovs-vsctl first reads the current configuration from OVSDB.
    As the number of ports grows, this starts to take an appreciable amount of
    time, and when it is repeated thousands of times the total time becomes
    significant.

    The solution is to add the ports in one invocation of ovs-vsctl (or a small
    number of them).  For example, using bash::

        $ ovs-vsctl add-br br0
        $ cmds=; for i in {1..5000}; do cmds+=" -- add-port br0 p$i"; done
        $ ovs-vsctl $cmds

    takes seconds, not minutes or hours, in the OVS sandbox environment.

Q: I created a bridge named br0.  My bridge shows up in "ovs-vsctl show", but
"ovs-ofctl show br0" just prints "br0 is not a bridge or a socket".

    A: Open vSwitch wasn't able to create the bridge.  Check the ovs-vswitchd
    log for details (Debian and Red Hat packaging for Open vSwitch put it in
    /var/log/openvswitch/ovs-vswitchd.log).

    In general, the Open vSwitch database reflects the desired configuration
    state.  ovs-vswitchd monitors the database and, when it changes,
    reconfigures the system to reflect the new desired state.  This normally
    happens very quickly.  Thus, a discrepancy between the database and the
    actual state indicates that ovs-vswitchd could not implement the
    configuration, and so one should check the log to find out why.  (Another
    possible cause is that ovs-vswitchd is not running.  This will make
    ovs-vsctl commands hang, if they change the configuration, unless one
    specifies ``--no-wait``.)

Q: I have a bridge br0.  I added a new port vif1.0, and it shows up in
"ovs-vsctl show", but "ovs-vsctl list port" says that it has OpenFlow port
("ofport") -1, and "ovs-ofctl show br0" doesn't show vif1.0 at all.

    A: Open vSwitch wasn't able to create the port.  Check the ovs-vswitchd log
    for details (Debian and Red Hat packaging for Open vSwitch put it in
    /var/log/openvswitch/ovs-vswitchd.log).  Please see the previous question
    for more information.

    You may want to upgrade to Open vSwitch 2.3 (or later), in which ovs-vsctl
    will immediately report when there is an issue creating a port.

Q: I created a tap device tap0, configured an IP address on it, and added it to
a bridge, like this::

    $ tunctl -t tap0
    $ ip addr add 192.168.0.123/24 dev tap0
    $ ip link set tap0 up
    $ ovs-vsctl add-br br0
    $ ovs-vsctl add-port br0 tap0

I expected that I could then use this IP address to contact other hosts on the
network, but it doesn't work.  Why not?

    A: The short answer is that this is a misuse of a "tap" device.  Use an
    "internal" device implemented by Open vSwitch, which works differently and
    is designed for this use.  To solve this problem with an internal device,
    instead run::

        $ ovs-vsctl add-br br0
        $ ovs-vsctl add-port br0 int0 -- set Interface int0 type=internal
        $ ip addr add 192.168.0.123/24 dev int0
        $ ip link set int0 up

    Even more simply, you can take advantage of the internal port that every
    bridge has under the name of the bridge::

        $ ovs-vsctl add-br br0
        $ ip addr add 192.168.0.123/24 dev br0
        $ ip link set br0 up

    In more detail, a "tap" device is an interface between the Linux (or BSD)
    network stack and a user program that opens it as a socket.  When the "tap"
    device transmits a packet, it appears in the socket opened by the userspace
    program.  Conversely, when the userspace program writes to the "tap"
    socket, the kernel TCP/IP stack processes the packet as if it had been
    received by the "tap" device.

    Consider the configuration above.  Given this configuration, if you "ping"
    an IP address in the 192.168.0.x subnet, the Linux kernel routing stack
    will transmit an ARP on the tap0 device.  Open vSwitch userspace treats
    "tap" devices just like any other network device; that is, it doesn't open
    them as "tap" sockets.  That means that the ARP packet will simply get
    dropped.

    You might wonder why the Open vSwitch kernel module doesn't intercept the
    ARP packet and bridge it.  After all, Open vSwitch intercepts packets on
    other devices.  The answer is that Open vSwitch only intercepts *received*
    packets, but this is a packet being transmitted.  The same thing happens
    for all other types of network devices, except for Open vSwitch "internal"
    ports.  If you, for example, add a physical Ethernet port to an OVS bridge,
    configure an IP address on a physical Ethernet port, and then issue a
    "ping" to an address in that subnet, the same thing happens: an ARP gets
    transmitted on the physical Ethernet port and Open vSwitch never sees it.
    (You should not do that, as documented at the beginning of this section.)

    It can make sense to add a "tap" device to an Open vSwitch bridge, if some
    userspace program (other than Open vSwitch) has opened the tap socket.
    This is the case, for example, if the "tap" device was created by KVM (or
    QEMU) to simulate a virtual NIC.  In such a case, when OVS bridges a packet
    to the "tap" device, the kernel forwards that packet to KVM in userspace,
    which passes it along to the VM, and in the other direction, when the VM
    sends a packet, KVM writes it to the "tap" socket, which causes OVS to
    receive it and bridge it to the other OVS ports.  Please note that in such
    a case no IP address is configured on the "tap" device (there is normally
    an IP address configured in the virtual NIC inside the VM, but this is not
    visible to the host Linux kernel or to Open vSwitch).

    There is one special case in which Open vSwitch does directly read and
    write "tap" sockets.  This is an implementation detail of the Open vSwitch
    userspace switch, which implements its "internal" ports as Linux (or BSD)
    "tap" sockets.  In such a userspace switch, OVS receives packets sent on
    the "tap" device used to implement an "internal" port by reading the
    associated "tap" socket, and bridges them to the rest of the switch.  In
    the other direction, OVS transmits packets bridged to the "internal" port
    by writing them to the "tap" socket, causing them to be processed by the
    kernel TCP/IP stack as if they had been received on the "tap" device.
    Users should not need to be concerned with this implementation detail.

    Open vSwitch has a network device type called "tap".  This is intended only
    for implementing "internal" ports in the OVS userspace switch and should
    not be used otherwise.  In particular, users should not configure KVM "tap"
    devices as type "tap" (use type "system", the default, instead).

Q: I observe packet loss at the beginning of RFC2544 tests on a server running
few hundred container apps bridged to OVS with traffic generated by HW traffic
generator.  How can I fix this?

    A: This is expected behavior on virtual switches.  RFC2544 tests were
    designed for hardware switches, which don't have caches on the fastpath
    that need to be heated.  Traffic generators in order to prime the switch
    use learning phase to heat the caches before sending the actual traffic in
    test phase.  In case of OVS the cache is flushed quickly and to accommodate
    the traffic generator's delay between learning and test phase, the max-idle
    timeout settings should be changed to 50000 ms.::

        $ ovs-vsctl --no-wait set Open_vSwitch . other_config:max-idle=50000

Q: How can I configure the bridge internal interface MTU? Why does Open vSwitch
keep changing internal ports MTU?

    A: By default Open vSwitch overrides the internal interfaces (e.g. br0)
    MTU.  If you have just an internal interface (e.g. br0) and a physical
    interface (e.g. eth0), then every change in MTU to eth0 will be reflected
    to br0.  Any manual MTU configuration using `ip` on internal interfaces is
    going to be overridden by Open vSwitch to match the current bridge minimum.

    Sometimes this behavior is not desirable, for example with tunnels.  The
    MTU of an internal interface can be explicitly set using the following
    command::

        $ ovs-vsctl set int br0 mtu_request=1450

    After this, Open vSwitch will configure br0 MTU to 1450.  Since this
    setting is in the database it will be persistent (compared to what happens
    with `ip`).

    The MTU configuration can be removed to restore the default behavior
    with::

        $ ovs-vsctl set int br0 mtu_request=[]

    The ``mtu_request`` column can be used to configure MTU even for physical
    interfaces (e.g. eth0).

Q: I just upgraded and I see a performance drop.  Why?

    A: The OVS kernel datapath may have been updated to a newer version than
    the OVS userspace components.  Sometimes new versions of OVS kernel module
    add functionality that is backwards compatible with older userspace
    components but may cause a drop in performance with them.  Especially, if a
    kernel module from OVS 2.1 or newer is paired with OVS userspace 1.10 or
    older, there will be a performance drop for TCP traffic.

    Updating the OVS userspace components to the latest released version should
    fix the performance degradation.

    To get the best possible performance and functionality, it is recommended
    to pair the same versions of the kernel module and OVS userspace.

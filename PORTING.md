How to Port Open vSwitch to New Software or Hardware
====================================================

Open vSwitch (OVS) is intended to be easily ported to new software and
hardware platforms.  This document describes the types of changes that
are most likely to be necessary in porting OVS to Unix-like platforms.
(Porting OVS to other kinds of platforms is likely to be more
difficult.)


Vocabulary
----------

For historical reasons, different words are used for essentially the
same concept in different areas of the Open vSwitch source tree.  Here
is a concordance, indexed by the area of the source tree:

        datapath/       vport           ---
        vswitchd/       iface           port
        ofproto/        port            bundle
        ofproto/bond.c  slave           bond
        lib/lacp.c      slave           lacp
        lib/netdev.c    netdev          ---
        database        Interface       Port


Open vSwitch Architectural Overview
-----------------------------------

The following diagram shows the very high-level architecture of Open
vSwitch from a porter's perspective.

                   +-------------------+
                   |    ovs-vswitchd   |<-->ovsdb-server
                   +-------------------+
                   |      ofproto      |<-->OpenFlow controllers
                   +--------+-+--------+
                   | netdev | | ofproto|
                   +--------+ |provider|
                   | netdev | +--------+
                   |provider|
                   +--------+

Some of the components are generic.  Modulo bugs or inadequacies,
these components should not need to be modified as part of a port:

  - "ovs-vswitchd" is the main Open vSwitch userspace program, in
    vswitchd/.  It reads the desired Open vSwitch configuration from
    the ovsdb-server program over an IPC channel and passes this
    configuration down to the "ofproto" library.  It also passes
    certain status and statistical information from ofproto back
    into the database.

  - "ofproto" is the Open vSwitch library, in ofproto/, that
    implements an OpenFlow switch.  It talks to OpenFlow controllers
    over the network and to switch hardware or software through an
    "ofproto provider", explained further below.

  - "netdev" is the Open vSwitch library, in lib/netdev.c, that
    abstracts interacting with network devices, that is, Ethernet
    interfaces.  The netdev library is a thin layer over "netdev
    provider" code, explained further below.

The other components may need attention during a port.  You will
almost certainly have to implement a "netdev provider".  Depending on
the type of port you are doing and the desired performance, you may
also have to implement an "ofproto provider" or a lower-level
component called a "dpif" provider.

The following sections talk about these components in more detail.


Writing a netdev Provider
-------------------------

A "netdev provider" implements an operating system and hardware
specific interface to "network devices", e.g. eth0 on Linux.  Open
vSwitch must be able to open each port on a switch as a netdev, so you
will need to implement a "netdev provider" that works with your switch
hardware and software.

struct netdev_class, in lib/netdev-provider.h, defines the interfaces
required to implement a netdev.  That structure contains many function
pointers, each of which has a comment that is meant to describe its
behavior in detail.  If the requirements are unclear, please report
this as a bug.

The netdev interface can be divided into a few rough categories:

  * Functions required to properly implement OpenFlow features.  For
    example, OpenFlow requires the ability to report the Ethernet
    hardware address of a port.  These functions must be implemented
    for minimally correct operation.

  * Functions required to implement optional Open vSwitch features.
    For example, the Open vSwitch support for in-band control
    requires netdev support for inspecting the TCP/IP stack's ARP
    table.  These functions must be implemented if the corresponding
    OVS features are to work, but may be omitted initially.

  * Functions needed in some implementations but not in others.  For
    example, most kinds of ports (see below) do not need
    functionality to receive packets from a network device.

The existing netdev implementations may serve as useful examples
during a port:

  * lib/netdev-linux.c implements netdev functionality for Linux
    network devices, using Linux kernel calls.  It may be a good
    place to start for full-featured netdev implementations.

  * lib/netdev-vport.c provides support for "virtual ports"
    implemented by the Open vSwitch datapath module for the Linux
    kernel.  This may serve as a model for minimal netdev
    implementations.

  * lib/netdev-dummy.c is a fake netdev implementation useful only
    for testing.


Porting Strategies
------------------

After a netdev provider has been implemented for a system's network
devices, you may choose among three basic porting strategies.

The lowest-effort strategy is to use the "userspace switch"
implementation built into Open vSwitch.  This ought to work, without
writing any more code, as long as the netdev provider that you
implemented supports receiving packets.  It yields poor performance,
however, because every packet passes through the ovs-vswitchd process.
See [INSTALL.userspace.md] for instructions on how to configure a
userspace switch.

If the userspace switch is not the right choice for your port, then
you will have to write more code.  You may implement either an
"ofproto provider" or a "dpif provider".  Which you should choose
depends on a few different factors:

  * Only an ofproto provider can take full advantage of hardware
    with built-in support for wildcards (e.g. an ACL table or a
    TCAM).

  * A dpif provider can take advantage of the Open vSwitch built-in
    implementations of bonding, LACP, 802.1ag, 802.1Q VLANs, and
    other features.  An ofproto provider has to provide its own
    implementations, if the hardware can support them at all.

  * A dpif provider is usually easier to implement, but most
    appropriate for software switching.  It "explodes" wildcard
    rules into exact-match entries (with an optional wildcard mask).
    This allows fast hash lookups in software, but makes
    inefficient use of TCAMs in hardware that support wildcarding.

The following sections describe how to implement each kind of port.


ofproto Providers
-----------------

An "ofproto provider" is what ofproto uses to directly monitor and
control an OpenFlow-capable switch.  struct ofproto_class, in
ofproto/ofproto-provider.h, defines the interfaces to implement an
ofproto provider for new hardware or software.  That structure contains
many function pointers, each of which has a comment that is meant to
describe its behavior in detail.  If the requirements are unclear,
please report this as a bug.

The ofproto provider interface is preliminary.  Please let us know if
it seems unsuitable for your purpose.  We will try to improve it.


Writing a dpif Provider
-----------------------

Open vSwitch has a built-in ofproto provider named "ofproto-dpif",
which is built on top of a library for manipulating datapaths, called
"dpif".  A "datapath" is a simple flow table, one that is only required
to support exact-match flows, that is, flows without wildcards.  When a
packet arrives on a network device, the datapath looks for it in this
table.  If there is a match, then it performs the associated actions.
If there is no match, the datapath passes the packet up to ofproto-dpif,
which maintains the full OpenFlow flow table.  If the packet matches in
this flow table, then ofproto-dpif executes its actions and inserts a
new entry into the dpif flow table.  (Otherwise, ofproto-dpif passes the
packet up to ofproto to send the packet to the OpenFlow controller, if
one is configured.)

When calculating the dpif flow, ofproto-dpif generates an exact-match
flow that describes the missed packet.  It makes an effort to figure out
what fields can be wildcarded based on the switch's configuration and
OpenFlow flow table.  The dpif is free to ignore the suggested wildcards
and only support the exact-match entry.  However, if the dpif supports
wildcarding, then it can use the masks to match multiple flows with
fewer entries and potentially significantly reduce the number of flow
misses handled by ofproto-dpif.

The "dpif" library in turn delegates much of its functionality to a
"dpif provider".  The following diagram shows how dpif providers fit
into the Open vSwitch architecture:

                _
               |   +-------------------+
               |   |    ovs-vswitchd   |<-->ovsdb-server
               |   +-------------------+
               |   |      ofproto      |<-->OpenFlow controllers
               |   +--------+-+--------+  _
               |   | netdev | |ofproto-|   |
     userspace |   +--------+ |  dpif  |   |
               |   | netdev | +--------+   |
               |   |provider| |  dpif  |   |
               |   +---||---+ +--------+   |
               |       ||     |  dpif  |   | implementation of
               |       ||     |provider|   | ofproto provider
               |_      ||     +---||---+   |
                       ||         ||       |
                _  +---||-----+---||---+   |
               |   |          |datapath|   |
        kernel |   |          +--------+  _|
               |   |                   |
               |_  +--------||---------+
                            ||
                         physical
                           NIC

struct dpif_class, in lib/dpif-provider.h, defines the interfaces
required to implement a dpif provider for new hardware or software.
That structure contains many function pointers, each of which has a
comment that is meant to describe its behavior in detail.  If the
requirements are unclear, please report this as a bug.

There are two existing dpif implementations that may serve as
useful examples during a port:

  * lib/dpif-netlink.c is a Linux-specific dpif implementation that
    talks to an Open vSwitch-specific kernel module (whose sources
    are in the "datapath" directory).  The kernel module performs
    all of the switching work, passing packets that do not match any
    flow table entry up to userspace.  This dpif implementation is
    essentially a wrapper around calls into the kernel module.

  * lib/dpif-netdev.c is a generic dpif implementation that performs
    all switching internally.  This is how the Open vSwitch
    userspace switch is implemented.


Miscellaneous Notes
-------------------

Open vSwitch source code uses uint16_t, uint32_t, and uint64_t as
fixed-width types in host byte order, and ovs_be16, ovs_be32, and
ovs_be64 as fixed-width types in network byte order.  Each of the
latter is equivalent to the one of the former, but the difference in
name makes the intended use obvious.

The default "fail-mode" for Open vSwitch bridges is "standalone",
meaning that, when the OpenFlow controllers cannot be contacted, Open
vSwitch acts as a regular MAC-learning switch.  This works well in
virtualization environments where there is normally just one uplink
(either a single physical interface or a bond).  In a more general
environment, it can create loops.  So, if you are porting to a
general-purpose switch platform, you should consider changing the
default "fail-mode" to "secure", which does not behave this way.  See
documentation for the "fail-mode" column in the Bridge table in
ovs-vswitchd.conf.db(5) for more information.

lib/entropy.c assumes that it can obtain high-quality random number
seeds at startup by reading from /dev/urandom.  You will need to
modify it if this is not true on your platform.

vswitchd/system-stats.c only knows how to obtain some statistics on
Linux.  Optionally you may implement them for your platform as well.


Why OVS Does Not Support Hybrid Providers
-----------------------------------------

The "Porting Strategies" section above describes the "ofproto
provider" and "dpif provider" porting strategies.  Only an ofproto
provider can take advantage of hardware TCAM support, and only a dpif
provider can take advantage of the OVS built-in implementations of
various features.  It is therefore tempting to suggest a hybrid
approach that shares the advantages of both strategies.

However, Open vSwitch does not support a hybrid approach.  Doing so
may be possible, with a significant amount of extra development work,
but it does not yet seem worthwhile, for the reasons explained below.

First, user surprise is likely when a switch supports a feature only
with a high performance penalty.  For example, one user questioned why
adding a particular OpenFlow action to a flow caused a 1,058x slowdown
on a hardware OpenFlow implementation [1].  The action required the
flow to be implemented in software.

Given that implementing a flow in software on the slow management CPU
of a hardware switch causes a major slowdown, software-implemented
flows would only make sense for very low-volume traffic.  But many of
the features built into the OVS software switch implementation would
need to apply to every flow to be useful.  There is no value, for
example, in applying bonding or 802.1Q VLAN support only to low-volume
traffic.

Besides supporting features of OpenFlow actions, a hybrid approach
could also support forms of matching not supported by particular
switching hardware, by sending all packets that might match a rule to
software.  But again this can cause an unacceptable slowdown by
forcing bulk traffic through software in the hardware switch's slow
management CPU.  Consider, for example, a hardware switch that can
match on the IPv6 Ethernet type but not on fields in IPv6 headers.  An
OpenFlow table that matched on the IPv6 Ethernet type would perform
well, but adding a rule that matched only UDPv6 would force every IPv6
packet to software, slowing down not just UDPv6 but all IPv6
processing.

[1] Aaron Rosen, "Modify packet fields extremely slow",
    openflow-discuss mailing list, June 26, 2011, archived at
    https://mailman.stanford.edu/pipermail/openflow-discuss/2011-June/002386.html.


Questions
---------

Please direct porting questions to dev@openvswitch.org.  We will try
to use questions to improve this porting guide.

[INSTALL.userspace.md]:INSTALL.userspace.md

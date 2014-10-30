Open vSwitch Project Ideas
==========================

This file lists a number of project ideas for Open vSwitch.  The ideas
here overlap somewhat with those in the [OPENFLOW-1.1+.md] file.


Programming Project Ideas
=========================

Each of these projects would ideally result in a patch or a short
series of them posted to ovs-dev.

Please read [CONTRIBUTING.md] and [CodingStyle.md] in the top of the
source tree before you begin work. The [OPENFLOW-1.1+.md] file also has
an introduction to how OpenFlow is implemented in Open vSwitch. It is
also a good idea to look around the source tree for related code, and
back through the Git history for commits on related subjects, to allow
you to follow existing patterns and conventions.

Meters
------

Open vSwitch has OpenFlow protocol support for meters, but it does not
have an implementation in the kernel or userspace datapaths.  An
implementation was proposed some time ago (I recommend looking for the
discussion in the ovs-dev mailing list archives), but for a few
different reasons it was not accepted.  Some of those reasons apply
only to a kernel implementation of meters.  At the time, a userspace
implementation wasn't as interesting, because the userspace switch
did not perform at a production speed, but with the advent of
multithreaded forwarding and, now, DPDK support, userspace-only meters
would be a great way to get started.

Improve SSL/TLS Security
------------------------

Open vSwitch allows some weak ciphers to be used for its secure
connections.  Security audits often suggest that the project remove
those ciphers, but there's not a clean way to modify the acceptable
ciphers.  At the very least, the cipher list should be audited, but it
would be nice to make it configurable.

Open vSwitch does not insist on perfect forward security via ephemeral
Diffie-Hellman key exchange when it establishes an SSL/TLS connection.
Given the wiretapping revelations over the last year, it seems wise to
turn this on.  (This would probably amount to finding the right
OpenSSL function to call or just reducing the acceptable ciphers
further.)

These changes might have backward-compatibility implications; one
would have to test the behavior of the reduced cipher list OVS against
older versions.

Bash Command Completion
-----------------------

ovs-vsctl and other programs would be easier to use if bash command
completion (with ``tab'', etc.) were supported.  Alex Wang
<alexw@nicira.com> is leading a team for this project.

Auxiliary Connections
---------------------

Auxiliary connections are a feature of OpenFlow 1.3 and later that
allow OpenFlow messages to be carried over datagram channels such as
UDP or DTLS.  One place to start would be to implement a datagram
abstraction library for OVS analogous to the ``stream'' library
that already abstracts TCP, SSL, and other stream protocols.

Controller connection logging to pcap file
------------------------------------------

http://patchwork.openvswitch.org/patch/2249/ is an RFC patch that
allows the switch to record the traffic on OpenFlow controller
connections to a pcap file for later analysis. The patch lacks a good
way to enable and disable the feature. The task here would be to add
that and repost the patch.

Basic OpenFlow 1.4 support
--------------------------

Some basic support for OpenFlow 1.4 is missing and needs to be
implemented.  These can be found by looking through lib/ofp-util.c for
mentions of OFP14_VERSION followed by a call to OVS_NOT_REACHED (which
aborts the program).

OpenFlow 1.4: Flow monitoring
-----------------------------

OpenFlow 1.4 introduces OFPMP_FLOW_MONITOR for notifying a controller
of changes to selected flow tables.  This feature is based on
NXST_FLOW_MONITOR that is already part of Open vSwitch, so to
implement this feature would be to extend that code to handle the
OpenFlow 1.4 wire protocol.

OpenFlow 1.3 also includes this feature as a ONF-defined extension, so
ideally OVS would support that too.

OpenFlow 1.4 Role Status Message
--------------------------------

OpenFlow 1.4 section 7.4.4 ``Controller Role Status Message''
defines a new message sent by a switch to notify the controller that
its role (whether it is a master or a slave) has changed. OVS should
implement this.

OpenFlow 1.3 also includes this feature as a ONF-defined extension, so
ideally OVS would support that too.

OpenFlow 1.4 Vacancy Events
---------------------------

OpenFlow 1.4 section 7.4.5 ``Table Status Message'' defines a new
message sent by a switch to notify the controller that a flow table is
close to filling up (or that it is no longer close to filling up).
OVS should implement this.

OpenFlow 1.3 also includes this feature as a ONF-defined extension, so
ideally OVS would support that too.

OpenFlow 1.4 Group and Meter Change Notification
------------------------------------------------

OpenFlow 1.4 adds a feature whereby a controller can ask the switch to
send it copies of messages that change groups and meters. (This is
only useful in the presence of multiple controllers.) OVS should
implement this.

OpenFlow 1.3 also includes this feature as a ONF-defined extension, so
ideally OVS would support that too.
   

Testing Project Ideas
=====================

Each of these projects would ideally result in confirmation that
features work or bug reports explaining how they do not.  Please sent
bug reports to dev at openvswitch.org, with as many details as you have.

ONF Plugfest Results Analysis
-----------------------------

Ben Pfaff has a collection of files reporting Open vSwitch conformance
to OpenFlow 1.3 provided by one of the vendors at the ONF plugfest
last year.  Some of the reported failures have been fixed, some of the
other failures probably result from differing interpretations of
OpenFlow 1.3, and others are probably genuine bugs in Open vSwitch.
Open vSwitch has also improved in the meantime.  Ben can provide the
results, privately, to some person or team who wishes to check them
out and try to pick out the genuine bugs.

OpenFlow Fuzzer
---------------

Build a ``fuzzer'' for the OpenFlow protocol (or use an existing
one, if there is one) and run it against the Open vSwitch
implementation.  One could also build a fuzzer for the OSVDB protocol.

Ryu Certification Tests Analysis
--------------------------------

The Ryu controller comes with a suite of ``certification tests''
that check the correctness of a switch's implementation of various
OpenFlow 1.3 features.  The INSTALL file in the OVS source tree has a
section that explains how to easily run these tests against an OVS
source tree.  Run the tests and figure out whether any tests fail but
should pass.  (Some tests fail and should fail because OVS does not
implement the particular feature; for example, OVS does not implement
PBB encapsulation, so related tests fail.)

OFTest Results Analysis
-----------------------

OFTest is a test suite for OpenFlow 1.0 compliance.  The INSTALL file
in the OVS source tree has a section that explains how to easily run
these tests against an OVS source tree.  Run the tests and figure out
whether any tests fail but should pass, and ideally why.  OFTest is
not particularly well vetted--in the past, at least, some tests have
failed against OVS due to bugs in OFTest, not in OVS--so some care is
warranted.


Documentation Project Ideas
===========================

Each of these projects would ideally result in creating some new
documentation for users.  Some documentation might be suitable to
accompany Open vSwitch as part of its source tree most likely either
in plain text or ``nroff'' (manpage) format.

OpenFlow Basics Tutorial
------------------------

Open vSwitch has a tutorial that covers its advanced features, but it
does not have a basic tutorial.  There are several tutorials on the
Internet already, so a new tutorial would have to distinguish itself
in some way. One way would be to use the Open vSwitch ``sandbox''
environment already used in the advanced tutorial.  The sandbox does
not require any real network or even supervisor privilege on the
machine where it runs, and thus it is easy to use with hardly any
up-front setup, so it is a gentle way to get started.

FlowVisor via patch ports
-------------------------

FlowVisor is a proxy that sits between OpenFlow controllers and a
switch. It divides up switch resources, allowing each controller to
control a ``slice'' of the network. For example, it can break up a
network based on VLAN, allowing different controllers to handle
packets with different VLANs.

It seems that Open vSwitch has features that allow it to implement at
least simple forms of FlowVisor control without any need for
FlowVisor.  Consider an Open vSwitch instance with three bridges.
Bridge br0 has physical ports eth0 and eth1.  Bridge v9 has no
physical ports, but it has two ``patch ports'' that connect it to
br0.  Bridge v11 has the same setup.  Flows in br0 match packets
received on vlan 9, strip the vlan header, and direct them to the
appropriate patch port leading to v9.  Additional flows in br0 match
packets received from v9, attach a VLAN 9 tag to them, and direct them
out eth0 or eth1 as appropriate.  Other flows in br0 treat packets on
VLAN 11 similarly.  Controllers attached to bridge v9 or v11 may thus
work as if they had full control of a network.

It seems to me that this is a good example of the power of OpenFlow
and Open vSwitch. The point of this project is to explain how to do
this, with detailed examples, in case someone finds it handy and to
open eyes toward the generality of Open vSwitch usefulness.

``Cookbooks''
-------------

The Open vSwitch website has a few ``cookbook'' entries that
describe how to use Open vSwitch in a few scenarios. There are only a
few of these and all of them are dated. It would be a good idea to
come up with ideas for some more and write them. These could be added
to the Open vSwitch website or the source tree or somewhere else.

Demos
-----

Record a demo of Open vSwitch functionality in use (or something else
relevant) and post it to youtube or another video site so that we can
link to it from openvswitch.org.


How to contribute
=================

If you plan to contribute code for a feature, please let everyone know
on ovs-dev before you start work.  This will help avoid duplicating
work.

Please consider the following:

  * Testing.  Please test your code.

  * Unit tests.  Please consider writing some.  The tests directory
    has many examples that you can use as a starting point.

  * ovs-ofctl.  If you add a feature that is useful for some
    ovs-ofctl command then you should add support for it there.

  * Documentation.  If you add a user-visible feature, then you
    should document it in the appropriate manpage and mention it in
    NEWS as well.

  * Coding style (see the [CodingStyle.md] file at the top of the
    source tree).

  * The patch submission guidelines (see [CONTRIBUTING.md]).  I
    recommend using "git send-email", which automatically follows a
    lot of those guidelines.


Bug Reporting
=============

Please report problems to bugs@openvswitch.org.


Local Variables:
mode: text
End:

[OPENFLOW-1.1+.md]:OPENFLOW-1.1+.md
[CONTRIBUTING.md]:CONTRIBUTING.md
[CodingStyle.md]:CodingStyle.md

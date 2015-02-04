OpenFlow 1.1+ support in Open vSwitch
=====================================

Open vSwitch support for OpenFlow 1.1 and beyond is a work in
progress.  This file describes the work still to be done.

The Plan
--------

OpenFlow version support is not a build-time option.  A single build
of Open vSwitch must be able to handle all supported versions of
OpenFlow.  Ideally, even at runtime it should be able to support all
protocol versions at the same time on different OpenFlow bridges (and
perhaps even on the same bridge).

At the same time, it would be a shame to litter the core of the OVS
code with lots of ugly code concerned with the details of various
OpenFlow protocol versions.

The primary approach to compatibility is to abstract most of the
details of the differences from the core code, by adding a protocol
layer that translates between OF1.x and a slightly higher-level
abstract representation.  The core of this approach is the many struct
ofputil_* structures in lib/ofp-util.h.

As a consequence of this approach, OVS cannot use OpenFlow protocol
definitions that closely resemble those in the OpenFlow specification,
because openflow.h in different versions of the OpenFlow specification
defines the same identifier with different values.  Instead,
openflow-common.h contains definitions that are common to all the
specifications and separate protocol version-specific headers contain
protocol-specific definitions renamed so as not to conflict,
e.g. OFPAT10_ENQUEUE and OFPAT11_ENQUEUE for the OpenFlow 1.0 and 1.1
values for OFPAT_ENQUEUE.  Generally, in cases of conflict, the
protocol layer will define a more abstract OFPUTIL_* or struct
ofputil_*.

Here are the current approaches in a few tricky areas:

  * Port numbering.  OpenFlow 1.0 has 16-bit port numbers and later
    OpenFlow versions have 32-bit port numbers.  For now, OVS
    support for later protocol versions requires all port numbers to
    fall into the 16-bit range, translating the reserved OFPP_* port
    numbers.

  * Actions.  OpenFlow 1.0 and later versions have very different
    ideas of actions.  OVS reconciles by translating all the
    versions' actions (and instructions) to and from a common
    internal representation.

OpenFlow 1.1
------------

The list of remaining work items for OpenFlow 1.1 is below.  It is
probably incomplete.

  * Match and set double-tagged VLANs (QinQ).  This requires kernel
    work for reasonable performance.
    [optional for OF1.1+]

  * VLANs tagged with 88a8 Ethertype.  This requires kernel work for
    reasonable performance.
    [required for OF1.1+]

OpenFlow 1.2
------------

OpenFlow 1.2 support requires OpenFlow 1.1 as a prerequisite. All the
additional work specific to Openflow 1.2 are complete.  (This is based
on the change log at the end of the OF1.2 spec.  I didn't compare the
specs carefully yet.)

OpenFlow 1.3
------------

OpenFlow 1.3 support requires OpenFlow 1.2 as a prerequisite, plus the
following additional work.  (This is based on the change log at the
end of the OF1.3 spec, reusing most of the section titles directly.  I
didn't compare the specs carefully yet.)

  * Add support for multipart requests.
    Currently we always report OFPBRC_MULTIPART_BUFFER_OVERFLOW.
    [optional for OF1.3+]

  * IPv6 extension header handling support.  Fully implementing this
    requires kernel support.  This likely will take some careful and
    probably time-consuming design work.  The actual coding, once
    that is all done, is probably 2 or 3 days work.
    [optional for OF1.3+]

  * Per-flow meters.  OpenFlow protocol support is now implemented.
    Support for the special OFPM_SLOWPATH and OFPM_CONTROLLER meters
    is missing.  Support for the software switch is under review.
    [optional for OF1.3+]

  * Auxiliary connections.  An implementation in generic code might
    be a week's worth of work.  The value of an implementation in
    generic code is questionable, though, since much of the benefit
    of axuiliary connections is supposed to be to take advantage of
    hardware support.  (We could make the kernel module somehow
    send packets across the auxiliary connections directly, for
    some kind of "hardware" support, if we judged it useful enough.)
    [optional for OF1.3+]

  * Provider Backbone Bridge tagging.  I don't plan to implement
    this (but we'd accept an implementation).
    [optional for OF1.3+]

  * On-demand flow counters.  I think this might be a real
    optimization in some cases for the software switch.
    [optional for OF1.3+]

OpenFlow 1.4 & ONF Extensions for 1.3.X Pack1
---------------------------------------------

The following features are both defined as a set of ONF Extensions
for 1.3 and integrated in 1.4.
When defined as an ONF Extension for 1.3, the feature is using the
Experimenter mechanism with the ONF Experimenter ID.
When defined integrated in 1.4, the feature use the standard OpenFlow
structures (for example defined in openflow-1.4.h).
The two definitions for each feature are independant and can exist in
parallel in OVS.

  * Flow entry notifications
    This seems to be modelled after OVS's NXST_FLOW_MONITOR.
    (Simon Horman is working on this.)
    [EXT-187]
    [optional for OF1.4+]

  * Role Status
    Already implemented as a 1.4 feature.
    [EXT-191]
    [required for OF1.4+]

  * Flow entry eviction
    OVS has flow eviction functionality.
    table_mod OFPTC_EVICTION, flow_mod 'importance', and
    table_desc ofp_table_mod_prop_eviction need to be implemented.
    [EXT-192-e]
    [optional for OF1.4+]

  * Vacancy events
    [EXT-192-v]
    [optional for OF1.4+]

  * Bundle
    Transactional modification.  OpenFlow 1.4 requires to support
    flow_mods and port_mods in a bundle if bundle is supported.
    (Not related to OVS's 'ofbundle' stuff.)
    [EXT-230]
    [optional for OF1.4+]

  * Table synchronisation
    Probably not so useful to the software switch.
    [EXT-232]
    [optional for OF1.4+]

  * Group and Meter change notifications
    [EXT-235]
    [optional for OF1.4+]

  * Bad flow entry priority error
    Probably not so useful to the software switch.
    [EXT-236]
    [optional for OF1.4+]

  * Set async config error
    [EXT-237]
    [optional for OF1.4+]

  * PBB UCA header field
    See comment on Provider Backbone Bridge in section about OpenFlow 1.3.
    [EXT-256]
    [optional for OF1.4+]

  * Multipart timeout error
    [EXT-264]
    [required for OF1.4+]

OpenFlow 1.4 only
-----------------

Those features are those only available in OpenFlow 1.4, other
OpenFlow 1.4 features are listed in the previous section.

  * More extensible wire protocol
    Many on-wire structures got TLVs.
    Already implemented: port desc properties, port mod properties,
                         port stats properties, table mod properties,
                         queue stats, unified property errors.
    Remaining required: set-async, queue desc
    Remaining optional: table desc, table-status
    [EXT-262]
    [required for OF1.4+]

  * More descriptive reasons for packet-in
    Distinguish OFPR_APPLY_ACTION, OFPR_ACTION_SET, OFPR_GROUP,
    OFPR_PACKET_OUT.  NO_MATCH was renamed to OFPR_TABLE_MISS.
    (OFPR_ACTION_SET and OFPR_GROUP are now supported)
    [EXT-136]
    [required for OF1.4+]

  * Optical port properties
    [EXT-154]
    [optional for OF1.4+]

OpenFlow 1.5 & ONF Extensions for 1.3.X Pack2
---------------------------------------------

The following features are both defined as a set of ONF Extensions for
1.3 and integrated in 1.5. Note that this list is not definitive as
those are not yet published.
When defined as an ONF Extension for 1.3, the feature is using the
Experimenter mechanism with the ONF Experimenter ID.
When defined integrated in 1.5, the feature use the standard OpenFlow
structures (for example defined in openflow-1.5.h).
The two definitions for each feature are independant and can exist in
parallel in OVS.

  * Time scheduled bundles
    [EXT-340]
    [optional for OF1.5+]

OpenFlow 1.5 only
-----------------

Those features are those only available in OpenFlow 1.5, other
OpenFlow 1.5 features are listed in the previous section.
Note that this list is not definitive as OpenFlow 1.5 is not yet
published.

  * Egress Tables
    [EXT-306]
    [optional for OF1.5+]

  * Packet Type aware pipeline
    Prototype for OVS was done during specification.
    [EXT-112]
    [optional for OF1.5+]

  * Extensible Flow Entry Statistics
    [EXT-334]
    [required for OF1.5+]

  * Flow Entry Statistics Trigger
    [EXT-335]
    [optional for OF1.5+]

  * Controller connection status
    Prototype for OVS was done during specification.
    [EXT-454]
    [optional for OF1.5+]

  * Meter action
    [EXT-379]
    [required for OF1.5+ if metering is supported]

  * Enable setting all pipeline fields in packet-out
    Prototype for OVS was done during specification.
    [EXT-427]
    [required for OF1.5+]

  * Port properties for pipeline fields
    Prototype for OVS was done during specification.
    [EXT-388]
    [optional for OF1.5+]

  * Port property for recirculation
    Prototype for OVS was done during specification.
    [EXT-399]
    [optional for OF1.5+]

General
-----

  * ovs-ofctl(8) often lists as Nicira extensions features that
    later OpenFlow versions support in standard ways.

How to contribute
-----------------

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
-------------

Please report problems to bugs@openvswitch.org.

[CONTRIBUTING.md]:CONTRIBUTING.md
[CodingStyle.md]:CodingStyle.md

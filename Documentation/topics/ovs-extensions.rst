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

=======================
Open vSwitch Extensions
=======================

Introduction
------------

OpenFlow allows vendor extensions to the protocol.  OVS implements
many of its own extensions.  These days, we typically refer to these
as "Open vSwitch extensions" to OpenFlow.  You might also see them
called "Nicira extensions" after the company that initiated the Open
vSwitch project.  These extensions have been used to add additional
functionality for the desired features not present in the standard
OpenFlow protocol.

OpenFlow 1.0 refers to extensions as "vendor extensions", whereas
OpenFlow 1.1 and later call them "experimenter extensions".  These are
different names for the same concept and we use them interchangeably.

OVS vendor extension messages in OpenFlow and OVS
-------------------------------------------------

Vendor/experimenter request and replies
+++++++++++++++++++++++++++++++++++++++

OpenFlow supports vendor extensions for basic requests and replies.
In OpenFlow 1.0, such messages carry ``OFPT_VENDOR`` in the ``struct
ofp_header`` message type field, and in later versions
``OFPT_EXPERIMENTER``.  After the header of this message, there is a
vendor id field which identifies the vendor.  Everything after the
vendor ID is vendor specific, but it would typically include a subtype
field to identify a particular kind of vendor-specific message.
Vendor ids are defined in ``ovs/include/openflow/openflow-common.h``.

To see a list of all the vendor message subtypes that OVS understands,
we can refer to ``ovs/lib/ofp-msgs.h``.  We can see the instances of
``enum ofpraw`` which has a comment containing the keyword ``NXT``,
e.g.  ``OFPRAW_NXT_FLOW_MOD`` below:

::

   /* NXT 1.0+ (13): struct nx_flow_mod, uint8_t[8][]. */
   OFPRAW_NXT_FLOW_MOD,

which may be interpreted as follows:

``NXT``
    stands for Nicira extension message.
``nx_flow_mod``
    data that follow the OpenFlow header.
``uint8_t[8][]``
    multiple of 8 data.
``13``
    the subtype for the Flow Mod message when it is sent as a Open
    vSwitch extension message
``OFPRAW_NXT_FLOW_MOD``
    the Open vSwitch Flow Mod extension message.

For reference, the vendor message header is defined as
``struct ofp_vendor_header`` in ``ovs/lib/ofp-msgs.c``.

The general structure of a message with a vendor message type is:

ofp_header(msg_type=VENDOR/EXPERIMENTER) / vendor id / vendor subtype /
vendor defined additional data
(e.g. nx_flow_mod structure for OFPRAW_NXT_FLOW_MOD message)

Multipart vendor requests and replies
+++++++++++++++++++++++++++++++++++++

OpenFlow supports "statistics" or "multipart" messages that consist of
a sequence of shorter messages with associated content.  In OpenFlow
1.0 through 1.2, these are ``OFPT_STATS_REQUEST`` requests and
``OFPT_STATS_REPLY`` replies, and in OpenFlow 1.3 and later, they are
``OFPT_MULTIPART_REQUEST``and ``OFPT_MULTIPART_REPLY``.

A multipart message carries its own embedded type that denotes the
kind of multipart data.  Multipart vendor requests and replies use
type ``OFPT_VENDOR`` in OpenFlow 1.0, ``OFPST_EXPERIMENTER`` in
OpenFlow 1.1 and 1.2, and ``OFPMP_EXPERIMENTER`` in OpenFlow 1.3 and
later.

Again if we refer to ``ovs/lib/ofp-msgs.h``, we see the following lines:

::

    /* NXST 1.0 (2): uint8_t[8][]. */
    OFPRAW_NXST_FLOW_MONITOR_REQUEST,

``NXST``
    stands for Nicira extension statistics or multipart message.
``uint8_t[8][]``
    multiple of 8 data.
``2``
    the subtype for the Flow Monitor Request message when it is sent
    as a Flow Monitor Request message with extension vendor id.
``OFPRAW_NXST_FLOW_MONITOR_REQUEST``
    the OpenFlow Flow Monitor extension message.

For reference, the vendor extension stats message header is defined as
``struct ofp11_vendor_stats_msg`` in ``ovs/lib/ofp-msgs.c``.

The general structure of a multipart/stats message with vendor type is:

ofp_header(msg_type=STATS/MULTIPART) / stats_msg(type=VENDOR/EXPERIMENTER) /
 vendor-id / subtype / vendor defined additional data

Extended Match
--------------

OpenFlow 1.0 uses a fixed size flow match structure (struct
ofp_match) to define the fields to match in a packet.  This is
limiting and not extensible.  To make the match structure extensible,
OVS added as an extension ``nx_match`` structure, called NXM, as a
series of TLV (type-length-value) entries or ``nxm_entry``.  OpenFlow
1.2 standardized NXM as OXM, with extensions of its own.  OVS supports
standard and extension OXM and NXM TLVs.

For a detailed description of NXM and OXM, please see the OVS fields
documentation at
https://www.openvswitch.org/support/dist-docs/ovs-fields.7.pdf.

Error Message Extension
-----------------------

In OpenFlow version 1.0 and 1.1, there is no provision to generate
vendor specific error codes and does not even provide ``generic``
error codes that can apply to problems not anticipated by the OpenFlow
specification authors.  OVS added a generic "error vendor extension"
which uses ``NXET_VENDOR`` as type and ``NXVC_VENDOR_ERROR`` as code,
followed by ``struct nx_vendor_error`` with vendor-specific details,
followed by at least 64 bytes of the failed request.

OpenFlow version 1.2+ added a ``OFPET_EXPERIMENTER`` error type to
support vendor specific error codes.

Source files related to Open vSwitch extensions
-----------------------------------------------

::

   ovs/include/openflow/nicira-ext.h
   ovs/lib/ofp-msgs.inc
   ovs/include/openvswitch/ofp-msgs.h
   ovs/lib/ofp-msgs.c

/*
 * Copyright (c) 2011, 2012, 2013, 2014 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef META_FLOW_H
#define META_FLOW_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include "bitmap.h"
#include "flow.h"
#include "ofp-errors.h"
#include "packets.h"
#include "util.h"

struct ds;
struct match;

/* Open vSwitch fields
 * ===================
 *
 * A "field" is a property of a packet.  Most familiarly, "data fields" are
 * fields that can be extracted from a packet.
 *
 * Some data fields are always present as a consequence of the basic networking
 * technology in use.  Ethernet is the assumed base technology for current
 * versions of OpenFlow and Open vSwitch, so Ethernet header fields are always
 * available.
 *
 * Other data fields are not always present.  A packet contains ARP fields, for
 * example, only when its Ethernet header indicates the Ethertype for ARP,
 * 0x0806.  We say that a field is "applicable" when it is it present in a
 * packet, and "inapplicable" when it is not, and refer to the conditions that
 * determine whether a field is applicable as "prerequisites".  Some
 * VLAN-related fields are a special case: these fields are always applicable,
 * but have a designated value or bit that indicates whether a VLAN header is
 * present, with the remaining values or bits indicating the VLAN header's
 * content (if it is present).  See MFF_VLAN_TCI for an example.
 *
 * Conceptually, an inapplicable field does not have a value, not even a
 * nominal ``value'' such as all-zero-bits.  In many circumstances, OpenFlow
 * and Open vSwitch allow references only to applicable fields.  For example,
 * one may match a given field only if the match includes the field's
 * prerequisite, e.g. matching an ARP field is only allowed if one also matches
 * on Ethertype 0x0806.
 *
 * (Practically, however, OVS represents a field's value as some fixed member
 * in its "struct flow", so accessing that member will obtain some value.  Some
 * members are used for more than one purpose, e.g. the "tp_src" member
 * represents the TCP, UDP, and SCTP source port, so the value read may not
 * even make sense.  For this reason, it is important to know whether a field's
 * prerequisites are satisfied before attempting to read it.)
 *
 * Sometimes a packet may contain multiple instances of a header.  For example,
 * a packet may contain multiple VLAN or MPLS headers, and tunnels can cause
 * any data field to recur.  OpenFlow and Open vSwitch do not address these
 * cases uniformly.  For VLAN and MPLS headers, only the outermost header is
 * accessible, so that inner headers may be accessed only by ``popping''
 * (removing) the outer header.  (Open vSwitch supports only a single VLAN
 * header in any case.)  For tunnels, e.g. GRE or VXLAN, the outer header and
 * inner headers are treated as different data fields.
 *
 * OpenFlow and Open vSwitch support some fields other than data fields.
 * "Metadata fields" relate to the origin or treatment of a packet, but they
 * are not extracted from the packet data itself.  One example is the physical
 * port on which a packet arrived at the switch.  "Register fields" act like
 * variables: they give an OpenFlow switch space for temporary storage while
 * processing a packet.  Existing metadata and register fields have no
 * prerequisites.
 *
 * A field's value consists of an integral number of bytes.  Most data fields
 * are copied directly from protocol headers, e.g. at layer 2, MFF_ETH_SRC is
 * copied from the Ethernet source address and MFF_ETH_DST from the destination
 * address.  Other data fields are copied from a packet with padding, usually
 * with zeros and in the most significant positions (see e.g. MFF_MPLS_LABEL)
 * but not always (see e.g. MFF_IP_DSCP).  A final category of data fields is
 * transformed in other ways as they are copied from the packets, to make them
 * more useful for matching, e.g. MFF_IP_FRAG describes whether a packet is a
 * fragment but it is not copied directly from the IP header.
 *
 *
 * Field specifications
 * ====================
 *
 * Each of the enumeration values below represents a field.  The comments
 * preceding each enum must be in a stylized form that is parsed at compile
 * time by the extract-ofp-fields program.  The comment itself consists of a
 * series of paragraphs separate by blank lines.  The paragraphs consist of:
 *
 *     - The first paragraph gives the user-visible name of the field as a
 *       quoted string.  This is the name used for parsing and formatting the
 *       field.
 *
 *       For historical reasons, some fields have an additional name that is
 *       accepted as an alternative in parsing.  This name, when there is one,
 *       is given as a quoted string in parentheses along with "aka".  For
 *       example:
 *
 *           "tun_id" (aka "tunnel_id").
 *
 *       New fields should have only one name.
 *
 *     - Any number of paragraphs of free text that describe the field.  This
 *       is meant for human readers, so extract-ofp-fields ignores it.
 *
 *     - A final paragraph that consists of a series of key-value pairs, one
 *       per line, in the form "key: value." where the period at the end of the
 *       line is a mandatory part of the syntax.
 *
 * Every field must specify the following key-value pairs:
 *
 *   Type:
 *
 *     The format and size of the field's value.  Some possible values are
 *     generic:
 *
 *         u8: A one-byte field.
 *         be16: A two-byte field.
 *         be32: A four-byte field.
 *         be64: An eight-byte field.
 *
 *     The remaining values imply more about the value's semantics, though OVS
 *     does not currently take advantage of this additional information:
 *
 *         MAC: A six-byte field whose value is an Ethernet address.
 *         IPv6: A 16-byte field whose value is an IPv6 address.
 *
 *   Maskable:
 *
 *     Either "bitwise", if OVS supports matching any subset of bits in the
 *     field, or "no", if OVS only supports matching or wildcarding the entire
 *     field.
 *
 *   Formatting:
 *
 *     Explains how a field's value is formatted and parsed for human
 *     consumption.  Some of the options are fairly generally useful:
 *
 *       decimal: Formats the value as a decimal number.  On parsing, accepts
 *         decimal (with no prefix), hexadecimal with 0x prefix, or octal
 *         with 0 prefix.
 *
 *       hexadecimal: Same as decimal except nonzero values are formatted in
 *         hex with 0x prefix.  The default for parsing is *not* hexadecimal:
 *         only with a 0x prefix is the input in hexadecimal.
 *
 *       Ethernet: Formats and accepts the common format xx:xx:xx:xx:xx:xx.
 *         6-byte fields only.
 *
 *       IPv4: Formats and accepts the common format w.x.y.z.  4-byte fields
 *         only.
 *
 *       IPv6: Formats and accepts the common IPv6 formats.  16-byte fields
 *         only.
 *
 *       OpenFlow 1.0 port: Accepts an OpenFlow well-known port name
 *         (e.g. "IN_PORT") in uppercase or lowercase, or a 16-bit port
 *         number in decimal.  Formats ports using their well-known names in
 *         uppercase, or in decimal otherwise.  2-byte fields only.
 *
 *       OpenFlow 1.1+ port: Same syntax as for OpenFlow 1.0 ports but for
 *         4-byte OpenFlow 1.1+ port number fields.
 *
 *     Others are very specific to particular fields:
 *
 *       frag: One of the strings "no", "first", "later", "yes", "not_later"
 *         describing which IPv4/v6 fragments are matched.
 *
 *       tunnel flags: Any number of the strings "df", "csum", "key", or
 *         "oam" separated by "|".
 *
 *       TCP flags: See the description of tcp_flags in ovs-ofctl(8).
 *
 *   Prerequisites:
 *
 *     The field's prerequisites.  The values should be straightfoward.
 *
 *   Access:
 *
 *     Either "read-only", for a field that cannot be changed via OpenFlow, or
 *     "read/write" for a modifiable field.
 *
 *   NXM:
 *
 *     If the field has an NXM field assignment, then this specifies the NXM
 *     name of the field (e.g. "NXM_OF_ETH_SRC"), followed by its nxm_type in
 *     parentheses, followed by "since v<x>.<y>" specifying the version of Open
 *     vSwitch that first supported this field in NXM (e.g. "since v1.1" if it
 *     was introduced in Open vSwitch 1.1).
 *
 *     The NXM name must begin with NXM_OF_ or NXM_NX_.  This allows OVS to
 *     determine the correct NXM class.
 *
 *     If the field does not have an NXM field assignment, specify "none".
 *
 *   OXM:
 *
 *     If the field has an OXM field assignment, then this specifies the OXM
 *     name of the field (e.g. "OXM_OF_ETH_SRC"), followed by its nxm_type in
 *     parentheses, followed by "since OF<a>.<b> v<x>.<y>" specifying the
 *     versions of OpenFlow and Open vSwitch that first supported this field in
 *     OXM (e.g. "since OF1.3 and v1.10" if it was introduced in OpenFlow 1.3
 *     and first supported by Open vSwitch in version 1.10).
 *
 *     Some fields have more than one OXM field assignment.  For example,
 *     actset_output has an experimenter OXM assignment in OpenFlow 1.3 and a
 *     standard OXM assignment in OpenFlow 1.5.  In such a case, specify both,
 *     separated by commas.
 *
 *     OVS uses the start of the OXM field name to determine the correct OXM
 *     class.  To support a new OXM class, edit the mapping table in
 *     build-aux/extract-ofp-fields.
 *
 *     If the field does not have an OXM field assignment, specify "none".
 *
 * The following key-value pairs are optional.  Open vSwitch already supports
 * all the fields to which they apply, so new fields should probably not
 * include these pairs:
 *
 *   OF1.0:
 *
 *     Specify this as "exact match" if OpenFlow 1.0 can match or wildcard the
 *     entire field, or as "CIDR mask" if OpenFlow 1.0 can match any CIDR
 *     prefix of the field.  (OpenFlow 1.0 did not support bitwise matching.)
 *     Omit, if OpenFlow 1.0 did not support this field.
 *
 *   OF1.1:
 *
 *     Specify this as "exact match" if OpenFlow 1.1 can match or wildcard the
 *     entire field, or as "bitwise" if OpenFlow 1.1 can match any subset of
 *     bits in the field.  Omit, if OpenFlow 1.1 did not support this field.
 *
 * The following key-value pair is optional:
 *
 *   Prefix lookup member:
 *
 *     If this field makes sense for use with classifier_set_prefix_fields(),
 *     specify the name of the "struct flow" member that corresponds to the
 *     field.
 *
 * Finally, a few "register" fields have very similar names and purposes,
 * e.g. MFF_REG0 through MFF_REG7.  For these, the comments may be merged
 * together using <N> as a metasyntactic variable for the numeric suffix.
 * Lines in the comment that are specific to one of the particular fields by
 * writing, e.g. <1>, to consider that line only for e.g. MFF_REG1.
 */

enum OVS_PACKED_ENUM mf_field_id {
/* ## -------- ## */
/* ## Metadata ## */
/* ## -------- ## */

    /* "dp_hash".
     *
     * Flow hash computed in the datapath.  Internal use only, not programmable
     * from controller.
     *
     * The OXM code point for this is an attempt to test OXM experimenter
     * support, which is otherwise difficult to test due to the dearth of use
     * out in the wild.  Because controllers can't add flows that match on
     * dp_hash, this doesn't commit OVS to supporting this OXM experimenter
     * code point in the future.
     *
     * Type: be32.
     * Maskable: bitwise.
     * Formatting: hexadecimal.
     * Prerequisites: none.
     * Access: read-only.
     * NXM: NXM_NX_DP_HASH(35) since v2.2.
     * OXM: NXOXM_ET_DP_HASH(0) since OF1.5 and v2.4.
     */
    MFF_DP_HASH,

    /* "recirc_id".
     *
     * ID for recirculation.  The value 0 is reserved for initially received
     * packets.  Internal use only, not programmable from controller.
     *
     * Type: be32.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: none.
     * Access: read-only.
     * NXM: NXM_NX_RECIRC_ID(36) since v2.2.
     * OXM: none.
     */
    MFF_RECIRC_ID,

    /* "conj_id".
     *
     * ID for "conjunction" actions.  Please refer to ovs-ofctl(8)
     * documentation of "conjunction" for details.
     *
     * Type: be32.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: none.
     * Access: read-only.
     * NXM: NXM_NX_CONJ_ID(37) since v2.4.
     * OXM: none. */
    MFF_CONJ_ID,

    /* "tun_id" (aka "tunnel_id").
     *
     * The "key" or "tunnel ID" or "VNI" in a packet received via a keyed
     * tunnel.  For protocols in which the key is shorter than 64 bits, the key
     * is stored in the low bits and the high bits are zeroed.  For non-keyed
     * tunnels and packets not received via a tunnel, the value is 0.
     *
     * Type: be64.
     * Maskable: bitwise.
     * Formatting: hexadecimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: NXM_NX_TUN_ID(16) since v1.1.
     * OXM: OXM_OF_TUNNEL_ID(38) since OF1.3 and v1.10.
     * Prefix lookup member: tunnel.tun_id.
     */
    MFF_TUN_ID,

    /* "tun_src".
     *
     * The IPv4 source address in the outer IP header of a tunneled packet.
     *
     * For non-tunneled packets, the value is 0.
     *
     * Type: be32.
     * Maskable: bitwise.
     * Formatting: IPv4.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: NXM_NX_TUN_IPV4_SRC(31) since v2.0.
     * OXM: none.
     * Prefix lookup member: tunnel.ip_src.
     */
    MFF_TUN_SRC,

    /* "tun_dst".
     *
     * The IPv4 destination address in the outer IP header of a tunneled
     * packet.
     *
     * For non-tunneled packets, the value is 0.
     *
     * Type: be32.
     * Maskable: bitwise.
     * Formatting: IPv4.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: NXM_NX_TUN_IPV4_DST(32) since v2.0.
     * OXM: none.
     * Prefix lookup member: tunnel.ip_dst.
     */
    MFF_TUN_DST,

    /* "tun_flags".
     *
     * Combination of FLOW_TNL_F_* bitmapped flags that indicate properties of
     * a tunneled packet.  Internal use only, not programmable from controller.
     *
     * For non-tunneled packets, the value is 0.
     *
     * Type: be16.
     * Maskable: no.
     * Formatting: tunnel flags.
     * Prerequisites: none.
     * Access: read-only.
     * NXM: none.
     * OXM: none.
     */
    MFF_TUN_FLAGS,

    /* "tun_ttl".
     *
     * The TTL in the outer IP header of a tunneled packet.  Internal use only,
     * not programmable from controller.
     *
     * For non-tunneled packets, the value is 0.
     *
     * Type: u8.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: none.
     * Access: read-only.
     * NXM: none.
     * OXM: none.
     */
    MFF_TUN_TTL,

    /* "tun_tos".
     *
     * The ToS value in the outer IP header of a tunneled packet.  Internal use
     * only, not programmable from controller.
     *
     * Type: u8.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: none.
     * Access: read-only.
     * NXM: none.
     * OXM: none.
     */
    MFF_TUN_TOS,

    /* "metadata".
     *
     * A scratch pad value standardized in OpenFlow 1.1+.  Initially zero, at
     * the beginning of the pipeline.
     *
     * Type: be64.
     * Maskable: bitwise.
     * Formatting: hexadecimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: none.
     * OXM: OXM_OF_METADATA(2) since OF1.2 and v1.8.
     * OF1.1: bitwise mask.
     */
    MFF_METADATA,

    /* "in_port".
     *
     * 16-bit (OpenFlow 1.0) view of the physical or virtual port on which the
     * packet was received.
     *
     * Type: be16.
     * Maskable: no.
     * Formatting: OpenFlow 1.0 port.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: NXM_OF_IN_PORT(0) since v1.1.
     * OXM: none.
     * OF1.0: exact match.
     * OF1.1: exact match.
     */
    MFF_IN_PORT,

    /* "in_port_oxm".
     *
     * 32-bit (OpenFlow 1.1+) view of the physical or virtual port on which the
     * packet was received.
     *
     * Type: be32.
     * Maskable: no.
     * Formatting: OpenFlow 1.1+ port.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: none.
     * OXM: OXM_OF_IN_PORT(0) since OF1.2 and v1.7.
     * OF1.1: exact match.
     */
    MFF_IN_PORT_OXM,

    /* "actset_output".
     *
     * Type: be32.
     * Maskable: no.
     * Formatting: OpenFlow 1.1+ port.
     * Prerequisites: none.
     * Access: read-only.
     * NXM: none.
     * OXM: ONFOXM_ET_ACTSET_OUTPUT(43) since OF1.3 and v2.4,
     *      OXM_OF_ACTSET_OUTPUT(43) since OF1.5 and v2.4.
     */
    MFF_ACTSET_OUTPUT,

    /* "skb_priority".
     *
     * Designates the queue to which output will be directed.  The value in
     * this field is not necessarily the OpenFlow queue number; with the Linux
     * kernel switch, it instead has a pair of subfields designating the
     * "major" and "minor" numbers of a Linux kernel qdisc handle.
     *
     * This field is "semi-internal" in that it can be set with the "set_queue"
     * action but not matched or read or written other ways.
     *
     * Type: be32.
     * Maskable: no.
     * Formatting: hexadecimal.
     * Prerequisites: none.
     * Access: read-only.
     * NXM: none.
     * OXM: none.
     */
    MFF_SKB_PRIORITY,

    /* "pkt_mark".
     *
     * Packet metadata mark.  The mark may be passed into other system
     * components in order to facilitate interaction between subsystems.  On
     * Linux this corresponds to struct sk_buff's "skb_mark" member but the
     * exact implementation is platform-dependent.
     *
     * Type: be32.
     * Maskable: bitwise.
     * Formatting: hexadecimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: NXM_NX_PKT_MARK(33) since v2.0.
     * OXM: none.
     */
    MFF_PKT_MARK,

#if FLOW_N_REGS == 8
    /* "reg<N>".
     *
     * Nicira extension scratch pad register with initial value 0.
     *
     * Type: be32.
     * Maskable: bitwise.
     * Formatting: hexadecimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: NXM_NX_REG0(0) since v1.1.        <0>
     * NXM: NXM_NX_REG1(1) since v1.1.        <1>
     * NXM: NXM_NX_REG2(2) since v1.1.        <2>
     * NXM: NXM_NX_REG3(3) since v1.1.        <3>
     * NXM: NXM_NX_REG4(4) since v1.3.        <4>
     * NXM: NXM_NX_REG5(5) since v1.7.        <5>
     * NXM: NXM_NX_REG6(6) since v1.7.        <6>
     * NXM: NXM_NX_REG7(7) since v1.7.        <7>
     * OXM: none.
     */
    MFF_REG0,
    MFF_REG1,
    MFF_REG2,
    MFF_REG3,
    MFF_REG4,
    MFF_REG5,
    MFF_REG6,
    MFF_REG7,
#else
#error "Need to update MFF_REG* to match FLOW_N_REGS"
#endif

#if FLOW_N_XREGS == 4
    /* "xreg<N>".
     *
     * OpenFlow 1.5 (draft) ``extended register".  Each extended register
     * overlays two of the Nicira extension 32-bit registers: xreg0 overlays
     * reg0 and reg1, with reg0 supplying the most-significant bits of xreg0
     * and reg1 the least-significant.  xreg1 similarly overlays reg2 and reg3,
     * and so on.
     *
     * These registers were introduced in OpenFlow 1.5, but EXT-244 in the ONF
     * JIRA also publishes them as a (draft) OpenFlow extension to OpenFlow
     * 1.3.
     *
     * Type: be64.
     * Maskable: bitwise.
     * Formatting: hexadecimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: none.
     * OXM: OXM_OF_PKT_REG<N>(<N>) since OF1.3 and v2.4.
     */
    MFF_XREG0,
    MFF_XREG1,
    MFF_XREG2,
    MFF_XREG3,
#else
#error "Need to update MFF_REG* to match FLOW_N_XREGS"
#endif

/* ## -------- ## */
/* ## Ethernet ## */
/* ## -------- ## */

    /* "eth_src" (aka "dl_src").
     *
     * Source address in Ethernet header.
     *
     * This field was not maskable before Open vSwitch 1.8.
     *
     * Type: MAC.
     * Maskable: bitwise.
     * Formatting: Ethernet.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: NXM_OF_ETH_SRC(2) since v1.1.
     * OXM: OXM_OF_ETH_SRC(4) since OF1.2 and v1.7.
     * OF1.0: exact match.
     * OF1.1: bitwise mask.
     */
    MFF_ETH_SRC,

    /* "eth_dst" (aka "dl_dst").
     *
     * Destination address in Ethernet header.
     *
     * Before Open vSwitch 1.8, the allowed masks were restricted to
     * 00:00:00:00:00:00, fe:ff:ff:ff:ff:ff, 01:00:00:00:00:00,
     * ff:ff:ff:ff:ff:ff.
     *
     * Type: MAC.
     * Maskable: bitwise.
     * Formatting: Ethernet.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: NXM_OF_ETH_DST(1) since v1.1.
     * OXM: OXM_OF_ETH_DST(3) since OF1.2 and v1.7.
     * OF1.0: exact match.
     * OF1.1: bitwise mask.
     */
    MFF_ETH_DST,

    /* "eth_type" (aka "dl_type").
     *
     * Packet's Ethernet type.
     *
     * For an Ethernet II packet this is taken from the Ethernet header.  For
     * an 802.2 LLC+SNAP header with OUI 00-00-00 this is taken from the SNAP
     * header.  A packet that has neither format has value 0x05ff
     * (OFP_DL_TYPE_NOT_ETH_TYPE).
     *
     * For a packet with an 802.1Q header, this is the type of the encapsulated
     * frame.
     *
     * Type: be16.
     * Maskable: no.
     * Formatting: hexadecimal.
     * Prerequisites: none.
     * Access: read-only.
     * NXM: NXM_OF_ETH_TYPE(3) since v1.1.
     * OXM: OXM_OF_ETH_TYPE(5) since OF1.2 and v1.7.
     * OF1.0: exact match.
     * OF1.1: exact match.
     */
    MFF_ETH_TYPE,

/* ## ---- ## */
/* ## VLAN ## */
/* ## ---- ## */

/* It looks odd for vlan_tci, vlan_vid, and vlan_pcp to say that they are
 * supported in OF1.0 and OF1.1, since the detailed semantics of these fields
 * only apply to NXM or OXM.  They are marked as supported for exact matches in
 * OF1.0 and OF1.1 because exact matches on those fields can be successfully
 * translated into the OF1.0 and OF1.1 flow formats. */

    /* "vlan_tci".
     *
     * 802.1Q TCI.
     *
     * For a packet with an 802.1Q header, this is the Tag Control Information
     * (TCI) field, with the CFI bit forced to 1.  For a packet with no 802.1Q
     * header, this has value 0.
     *
     * This field can be used in various ways:
     *
     *   - If it is not constrained at all, the nx_match matches packets
     *     without an 802.1Q header or with an 802.1Q header that has any TCI
     *     value.
     *
     *   - Testing for an exact match with 0 matches only packets without an
     *     802.1Q header.
     *
     *   - Testing for an exact match with a TCI value with CFI=1 matches
     *     packets that have an 802.1Q header with a specified VID and PCP.
     *
     *   - Testing for an exact match with a nonzero TCI value with CFI=0 does
     *     not make sense.  The switch may reject this combination.
     *
     *   - Testing with a specific VID and CFI=1, with nxm_mask=0x1fff, matches
     *     packets that have an 802.1Q header with that VID (and any PCP).
     *
     *   - Testing with a specific PCP and CFI=1, with nxm_mask=0xf000, matches
     *     packets that have an 802.1Q header with that PCP (and any VID).
     *
     *   - Testing with nxm_value=0, nxm_mask=0x0fff matches packets with no
     *     802.1Q header or with an 802.1Q header with a VID of 0.
     *
     *   - Testing with nxm_value=0, nxm_mask=0xe000 matches packets with no
     *     802.1Q header or with an 802.1Q header with a PCP of 0.
     *
     *   - Testing with nxm_value=0, nxm_mask=0xefff matches packets with no
     *     802.1Q header or with an 802.1Q header with both VID and PCP of 0.
     *
     * Type: be16.
     * Maskable: bitwise.
     * Formatting: hexadecimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: NXM_OF_VLAN_TCI(4) since v1.1.
     * OXM: none.
     * OF1.0: exact match.
     * OF1.1: exact match.
     */
    MFF_VLAN_TCI,

    /* "dl_vlan" (OpenFlow 1.0).
     *
     * VLAN ID field.  Zero if no 802.1Q header is present.
     *
     * Type: be16 (low 12 bits).
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: none.
     * OXM: none.
     * OF1.0: exact match.
     * OF1.1: exact match.
     */
    MFF_DL_VLAN,

    /* "vlan_vid" (OpenFlow 1.2+).
     *
     * If an 802.1Q header is present, this field's value is 0x1000
     * bitwise-or'd with the VLAN ID.  If no 802.1Q is present, this field's
     * value is 0.
     *
     * Type: be16 (low 12 bits).
     * Maskable: bitwise.
     * Formatting: decimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: none.
     * OXM: OXM_OF_VLAN_VID(6) since OF1.2 and v1.7.
     * OF1.0: exact match.
     * OF1.1: exact match.
     */
    MFF_VLAN_VID,

    /* "dl_vlan_pcp" (OpenFlow 1.0).
     *
     * VLAN priority (PCP) field.  Zero if no 802.1Q header is present.
     *
     * Type: u8 (low 3 bits).
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: none.
     * OXM: none.
     * OF1.0: exact match.
     * OF1.1: exact match.
     */
    MFF_DL_VLAN_PCP,

    /* "vlan_pcp" (OpenFlow 1.2+).
     *
     * VLAN priority (PCP) field.  Zero if no 802.1Q header is present.
     *
     * Type: u8 (low 3 bits).
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: VLAN VID.
     * Access: read/write.
     * NXM: none.
     * OXM: OXM_OF_VLAN_PCP(7) since OF1.2 and v1.7.
     * OF1.0: exact match.
     * OF1.1: exact match.
     */
    MFF_VLAN_PCP,

/* ## ---- ## */
/* ## MPLS ## */
/* ## ---- ## */

    /* "mpls_label".
     *
     * The outermost MPLS label, or 0 if no MPLS labels are present.
     *
     * Type: be32 (low 20 bits).
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: MPLS.
     * Access: read/write.
     * NXM: none.
     * OXM: OXM_OF_MPLS_LABEL(34) since OF1.2 and v1.11.
     * OF1.1: exact match.
     */
    MFF_MPLS_LABEL,

    /* "mpls_tc".
     *
     * The outermost MPLS label's traffic control (TC) field, or 0 if no MPLS
     * labels are present.
     *
     * Type: u8 (low 3 bits).
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: MPLS.
     * Access: read/write.
     * NXM: none.
     * OXM: OXM_OF_MPLS_TC(35) since OF1.2 and v1.11.
     * OF1.1: exact match.
     */
    MFF_MPLS_TC,

    /* "mpls_bos".
     *
     * The outermost MPLS label's bottom of stack (BoS) field, or 0 if no MPLS
     * labels are present.
     *
     * Type: u8 (low 1 bits).
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: MPLS.
     * Access: read-only.
     * NXM: none.
     * OXM: OXM_OF_MPLS_BOS(36) since OF1.3 and v1.11.
     */
    MFF_MPLS_BOS,

/* ## ---- ## */
/* ## IPv4 ## */
/* ## ---- ## */

/* Update mf_is_l3_or_higher() if MFF_IPV4_SRC is no longer the first element
 * for a field of layer 3 or higher */

    /* "ip_src" (aka "nw_src").
     *
     * The source address in the IPv4 header.
     *
     * Before Open vSwitch 1.8, only CIDR masks were supported.
     *
     * Type: be32.
     * Maskable: bitwise.
     * Formatting: IPv4.
     * Prerequisites: IPv4.
     * Access: read/write.
     * NXM: NXM_OF_IP_SRC(7) since v1.1.
     * OXM: OXM_OF_IPV4_SRC(11) since OF1.2 and v1.7.
     * OF1.0: CIDR mask.
     * OF1.1: bitwise mask.
     * Prefix lookup member: nw_src.
     */
    MFF_IPV4_SRC,

    /* "ip_dst" (aka "nw_dst").
     *
     * The destination address in the IPv4 header.
     *
     * Before Open vSwitch 1.8, only CIDR masks were supported.
     *
     * Type: be32.
     * Maskable: bitwise.
     * Formatting: IPv4.
     * Prerequisites: IPv4.
     * Access: read/write.
     * NXM: NXM_OF_IP_DST(8) since v1.1.
     * OXM: OXM_OF_IPV4_DST(12) since OF1.2 and v1.7.
     * OF1.0: CIDR mask.
     * OF1.1: bitwise mask.
     * Prefix lookup member: nw_dst.
     */
    MFF_IPV4_DST,

/* ## ---- ## */
/* ## IPv6 ## */
/* ## ---- ## */

    /* "ipv6_src".
     *
     * The source address in the IPv6 header.
     *
     * Type: IPv6.
     * Maskable: bitwise.
     * Formatting: IPv6.
     * Prerequisites: IPv6.
     * Access: read/write.
     * NXM: NXM_NX_IPV6_SRC(19) since v1.1.
     * OXM: OXM_OF_IPV6_SRC(26) since OF1.2 and v1.1.
     * Prefix lookup member: ipv6_src.
     */
    MFF_IPV6_SRC,

    /* "ipv6_dst".
     *
     * The destination address in the IPv6 header.
     *
     * Type: IPv6.
     * Maskable: bitwise.
     * Formatting: IPv6.
     * Prerequisites: IPv6.
     * Access: read/write.
     * NXM: NXM_NX_IPV6_DST(20) since v1.1.
     * OXM: OXM_OF_IPV6_DST(27) since OF1.2 and v1.1.
     * Prefix lookup member: ipv6_dst.
     */
    MFF_IPV6_DST,

    /* "ipv6_label".
     *
     * The flow label in the IPv6 header.
     *
     * Type: be32 (low 20 bits).
     * Maskable: bitwise.
     * Formatting: hexadecimal.
     * Prerequisites: IPv6.
     * Access: read/write.
     * NXM: NXM_NX_IPV6_LABEL(27) since v1.4.
     * OXM: OXM_OF_IPV6_FLABEL(28) since OF1.2 and v1.7.
     */
    MFF_IPV6_LABEL,

/* ## ----------------------- ## */
/* ## IPv4/IPv6 common fields ## */
/* ## ----------------------- ## */

    /* "nw_proto" (aka "ip_proto").
     *
     * The "protocol" byte in the IPv4 or IPv6 header.
     *
     * Type: u8.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: IPv4/IPv6.
     * Access: read-only.
     * NXM: NXM_OF_IP_PROTO(6) since v1.1.
     * OXM: OXM_OF_IP_PROTO(10) since OF1.2 and v1.7.
     * OF1.0: exact match.
     * OF1.1: exact match.
     */
    MFF_IP_PROTO,

/* Both views of the DSCP below are marked as supported in all of the versions
 * of OpenFlow because a match on either view can be successfully translated
 * into every OpenFlow flow format. */

    /* "nw_tos" (OpenFlow 1.0/1.1).
     *
     * The DSCP byte in the IPv4 header or the traffic class byte from the IPv6
     * header, with the ECN bits forced to 0.  (That is, bits 2-7 contain the
     * type of service and bits 0-1 are zero.)
     *
     * Type: u8.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: IPv4/IPv6.
     * Access: read/write.
     * NXM: NXM_OF_IP_TOS(5) since v1.1.
     * OXM: none.
     * OF1.0: exact match.
     * OF1.1: exact match.
     */
    MFF_IP_DSCP,

    /* "ip_dscp" (OpenFlow 1.2+).
     *
     * The DSCP byte in the IPv4 header or the traffic class byte from the IPv6
     * header, shifted right 2 bits.  (That is, bits 0-5 contain the type of
     * service and bits 6-7 are zero.)
     *
     * Type: u8 (low 6 bits).
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: IPv4/IPv6.
     * Access: read/write.
     * NXM: none.
     * OXM: OXM_OF_IP_DSCP(8) since OF1.2 and v1.7.
     * OF1.0: exact match.
     * OF1.1: exact match.
     */
    MFF_IP_DSCP_SHIFTED,

    /* "nw_ecn" (aka "ip_ecn").
     *
     * The ECN bits in the IPv4 or IPv6 header.
     *
     * Type: u8 (low 2 bits).
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: IPv4/IPv6.
     * Access: read/write.
     * NXM: NXM_NX_IP_ECN(28) since v1.4.
     * OXM: OXM_OF_IP_ECN(9) since OF1.2 and v1.7.
     */
    MFF_IP_ECN,

    /* "nw_ttl".
     *
     * The time-to-live (TTL) in the IPv4 header or hop limit in the IPv6
     * header.
     *
     * Type: u8.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: IPv4/IPv6.
     * Access: read/write.
     * NXM: NXM_NX_IP_TTL(29) since v1.4.
     * OXM: none.
     */
    MFF_IP_TTL,

    /* "ip_frag".
     *
     * IP fragment information.
     *
     * This field has three possible values:
     *
     *   - A packet that is not an IP fragment has value 0.
     *
     *   - A packet that is an IP fragment with offset 0 (the first fragment)
     *     has bit 0 set and thus value 1.
     *
     *   - A packet that is an IP fragment with nonzero offset has bits 0 and 1
     *     set and thus value 3.
     *
     * NX_IP_FRAG_ANY and NX_IP_FRAG_LATER are declared to symbolically
     * represent the meanings of bits 0 and 1.
     *
     * The switch may reject matches against values that can never appear.
     *
     * It is important to understand how this field interacts with the OpenFlow
     * IP fragment handling mode:
     *
     *   - In OFPC_FRAG_DROP mode, the OpenFlow switch drops all IP fragments
     *     before they reach the flow table, so every packet that is available
     *     for matching will have value 0 in this field.
     *
     *   - Open vSwitch does not implement OFPC_FRAG_REASM mode, but if it did
     *     then IP fragments would be reassembled before they reached the flow
     *     table and again every packet available for matching would always
     *     have value 0.
     *
     *   - In OFPC_FRAG_NORMAL mode, all three values are possible, but
     *     OpenFlow 1.0 says that fragments' transport ports are always 0, even
     *     for the first fragment, so this does not provide much extra
     *     information.
     *
     *   - In OFPC_FRAG_NX_MATCH mode, all three values are possible.  For
     *     fragments with offset 0, Open vSwitch makes L4 header information
     *     available.
     *
     * Type: u8 (low 2 bits).
     * Maskable: bitwise.
     * Formatting: frag.
     * Prerequisites: IPv4/IPv6.
     * Access: read-only.
     * NXM: NXM_NX_IP_FRAG(26) since v1.3.
     * OXM: none.
     */
    MFF_IP_FRAG,

/* ## --- ## */
/* ## ARP ## */
/* ## --- ## */

    /* "arp_op".
     *
     * ARP opcode.
     *
     * For an Ethernet+IP ARP packet, the opcode in the ARP header.  Always 0
     * otherwise.  Only ARP opcodes between 1 and 255 should be specified for
     * matching.
     *
     * Type: be16.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: ARP.
     * Access: read/write.
     * NXM: NXM_OF_ARP_OP(15) since v1.1.
     * OXM: OXM_OF_ARP_OP(21) since OF1.2 and v1.7.
     * OF1.0: exact match.
     * OF1.1: exact match.
     */
    MFF_ARP_OP,

    /* "arp_spa".
     *
     * For an Ethernet+IP ARP packet, the source protocol (IPv4) address in the
     * ARP header.  Always 0 otherwise.
     *
     * Before Open vSwitch 1.8, only CIDR masks were supported.
     *
     * Type: be32.
     * Maskable: bitwise.
     * Formatting: IPv4.
     * Prerequisites: ARP.
     * Access: read/write.
     * NXM: NXM_OF_ARP_SPA(16) since v1.1.
     * OXM: OXM_OF_ARP_SPA(22) since OF1.2 and v1.7.
     * OF1.0: CIDR mask.
     * OF1.1: bitwise mask.
     */
    MFF_ARP_SPA,

    /* "arp_tpa".
     *
     * For an Ethernet+IP ARP packet, the target protocol (IPv4) address in the
     * ARP header.  Always 0 otherwise.
     *
     * Before Open vSwitch 1.8, only CIDR masks were supported.
     *
     * Type: be32.
     * Maskable: bitwise.
     * Formatting: IPv4.
     * Prerequisites: ARP.
     * Access: read/write.
     * NXM: NXM_OF_ARP_TPA(17) since v1.1.
     * OXM: OXM_OF_ARP_TPA(23) since OF1.2 and v1.7.
     * OF1.0: CIDR mask.
     * OF1.1: bitwise mask.
     */
    MFF_ARP_TPA,

    /* "arp_sha".
     *
     * For an Ethernet+IP ARP packet, the source hardware (Ethernet) address in
     * the ARP header.  Always 0 otherwise.
     *
     * Type: MAC.
     * Maskable: bitwise.
     * Formatting: Ethernet.
     * Prerequisites: ARP.
     * Access: read/write.
     * NXM: NXM_NX_ARP_SHA(17) since v1.1.
     * OXM: OXM_OF_ARP_SHA(24) since OF1.2 and v1.7.
     */
    MFF_ARP_SHA,

    /* "arp_tha".
     *
     * For an Ethernet+IP ARP packet, the target hardware (Ethernet) address in
     * the ARP header.  Always 0 otherwise.
     *
     * Type: MAC.
     * Maskable: bitwise.
     * Formatting: Ethernet.
     * Prerequisites: ARP.
     * Access: read/write.
     * NXM: NXM_NX_ARP_THA(18) since v1.1.
     * OXM: OXM_OF_ARP_THA(25) since OF1.2 and v1.7.
     */
    MFF_ARP_THA,

/* ## --- ## */
/* ## TCP ## */
/* ## --- ## */

    /* "tcp_src" (aka "tp_src").
     *
     * TCP source port.
     *
     * Type: be16.
     * Maskable: bitwise.
     * Formatting: decimal.
     * Prerequisites: TCP.
     * Access: read/write.
     * NXM: NXM_OF_TCP_SRC(9) since v1.1.
     * OXM: OXM_OF_TCP_SRC(13) since OF1.2 and v1.7.
     * OF1.0: exact match.
     * OF1.1: exact match.
     */
    MFF_TCP_SRC,

    /* "tcp_dst" (aka "tp_dst").
     *
     * TCP destination port.
     *
     * Type: be16.
     * Maskable: bitwise.
     * Formatting: decimal.
     * Prerequisites: TCP.
     * Access: read/write.
     * NXM: NXM_OF_TCP_DST(10) since v1.1.
     * OXM: OXM_OF_TCP_DST(14) since OF1.2 and v1.7.
     * OF1.0: exact match.
     * OF1.1: exact match.
     */
    MFF_TCP_DST,

    /* "tcp_flags".
     *
     * Flags in the TCP header.
     *
     * TCP currently defines 9 flag bits, and additional 3 bits are reserved
     * (must be transmitted as zero).  See RFCs 793, 3168, and 3540.
     *
     * Type: be16 (low 12 bits).
     * Maskable: bitwise.
     * Formatting: TCP flags.
     * Prerequisites: TCP.
     * Access: read-only.
     * NXM: NXM_NX_TCP_FLAGS(34) since v2.1.
     * OXM: ONFOXM_ET_TCP_FLAGS(42) since OF1.3 and v2.4,
     *      OXM_OF_TCP_FLAGS(42) since OF1.5 and v2.3.
     */
    MFF_TCP_FLAGS,

/* ## --- ## */
/* ## UDP ## */
/* ## --- ## */

    /* "udp_src".
     *
     * UDP source port.
     *
     * Type: be16.
     * Maskable: bitwise.
     * Formatting: decimal.
     * Prerequisites: UDP.
     * Access: read/write.
     * NXM: NXM_OF_UDP_SRC(11) since v1.1.
     * OXM: OXM_OF_UDP_SRC(15) since OF1.2 and v1.7.
     * OF1.0: exact match.
     * OF1.1: exact match.
     */
    MFF_UDP_SRC,

    /* "udp_dst".
     *
     * UDP destination port
     *
     * Type: be16.
     * Maskable: bitwise.
     * Formatting: decimal.
     * Prerequisites: UDP.
     * Access: read/write.
     * NXM: NXM_OF_UDP_DST(12) since v1.1.
     * OXM: OXM_OF_UDP_DST(16) since OF1.2 and v1.7.
     * OF1.0: exact match.
     * OF1.1: exact match.
     */
    MFF_UDP_DST,

/* ## ---- ## */
/* ## SCTP ## */
/* ## ---- ## */

    /* "sctp_src".
     *
     * SCTP source port.
     *
     * Type: be16.
     * Maskable: bitwise.
     * Formatting: decimal.
     * Prerequisites: SCTP.
     * Access: read/write.
     * NXM: none.
     * OXM: OXM_OF_SCTP_SRC(17) since OF1.2 and v2.0.
     * OF1.1: exact match.
     */
    MFF_SCTP_SRC,

    /* "sctp_dst".
     *
     * SCTP destination port.
     *
     * Type: be16.
     * Maskable: bitwise.
     * Formatting: decimal.
     * Prerequisites: SCTP.
     * Access: read/write.
     * NXM: none.
     * OXM: OXM_OF_SCTP_DST(18) since OF1.2 and v2.0.
     * OF1.1: exact match.
     */
    MFF_SCTP_DST,

/* ## ---- ## */
/* ## ICMP ## */
/* ## ---- ## */

    /* "icmp_type".
     *
     * ICMPv4 type.
     *
     * Type: u8.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: ICMPv4.
     * Access: read-only.
     * NXM: NXM_OF_ICMP_TYPE(13) since v1.1.
     * OXM: OXM_OF_ICMPV4_TYPE(19) since OF1.2 and v1.7.
     * OF1.0: exact match.
     * OF1.1: exact match.
     */
    MFF_ICMPV4_TYPE,

    /* "icmp_code".
     *
     * ICMPv4 code.
     *
     * Type: u8.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: ICMPv4.
     * Access: read-only.
     * NXM: NXM_OF_ICMP_CODE(14) since v1.1.
     * OXM: OXM_OF_ICMPV4_CODE(20) since OF1.2 and v1.7.
     * OF1.0: exact match.
     * OF1.1: exact match.
     */
    MFF_ICMPV4_CODE,

    /* "icmpv6_type".
     *
     * ICMPv6 type.
     *
     * Type: u8.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: ICMPv6.
     * Access: read-only.
     * NXM: NXM_NX_ICMPV6_TYPE(21) since v1.1.
     * OXM: OXM_OF_ICMPV6_TYPE(29) since OF1.2 and v1.7.
     */
    MFF_ICMPV6_TYPE,

    /* "icmpv6_code".
     *
     * ICMPv6 code.
     *
     * Type: u8.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: ICMPv6.
     * Access: read-only.
     * NXM: NXM_NX_ICMPV6_CODE(22) since v1.1.
     * OXM: OXM_OF_ICMPV6_CODE(30) since OF1.2 and v1.7.
     */
    MFF_ICMPV6_CODE,

/* ## ------------------------- ## */
/* ## ICMPv6 Neighbor Discovery ## */
/* ## ------------------------- ## */

    /* "nd_target".
     *
     * The target address in an IPv6 Neighbor Discovery message.
     *
     * Before Open vSwitch 1.8, only CIDR masks were supported.
     *
     * Type: IPv6.
     * Maskable: bitwise.
     * Formatting: IPv6.
     * Prerequisites: ND.
     * Access: read/write.
     * NXM: NXM_NX_ND_TARGET(23) since v1.1.
     * OXM: OXM_OF_IPV6_ND_TARGET(31) since OF1.2 and v1.7.
     */
    MFF_ND_TARGET,

    /* "nd_sll".
     *
     * The source link layer address in an IPv6 Neighbor Discovery message.
     *
     * Type: MAC.
     * Maskable: bitwise.
     * Formatting: Ethernet.
     * Prerequisites: ND solicit.
     * Access: read/write.
     * NXM: NXM_NX_ND_SLL(24) since v1.1.
     * OXM: OXM_OF_IPV6_ND_SLL(32) since OF1.2 and v1.7.
     */
    MFF_ND_SLL,

    /* "nd_tll".
     *
     * The target link layer address in an IPv6 Neighbor Discovery message.
     *
     * Type: MAC.
     * Maskable: bitwise.
     * Formatting: Ethernet.
     * Prerequisites: ND advert.
     * Access: read/write.
     * NXM: NXM_NX_ND_TLL(25) since v1.1.
     * OXM: OXM_OF_IPV6_ND_TLL(33) since OF1.2 and v1.7.
     */
    MFF_ND_TLL,

    MFF_N_IDS
};

/* A set of mf_field_ids. */
struct mf_bitmap {
    unsigned long bm[BITMAP_N_LONGS(MFF_N_IDS)];
};
#define MF_BITMAP_INITIALIZER { { [0] = 0 } }

/* Use this macro as CASE_MFF_REGS: in a switch statement to choose all of the
 * MFF_REGn cases. */
#if FLOW_N_REGS == 8
#define CASE_MFF_REGS                                           \
    case MFF_REG0: case MFF_REG1: case MFF_REG2: case MFF_REG3: \
    case MFF_REG4: case MFF_REG5: case MFF_REG6: case MFF_REG7
#else
#error "Need to update CASE_MFF_REGS to match FLOW_N_REGS"
#endif

/* Use this macro as CASE_MFF_XREGS: in a switch statement to choose all of the
 * MFF_REGn cases. */
#if FLOW_N_XREGS == 4
#define CASE_MFF_XREGS                                              \
    case MFF_XREG0: case MFF_XREG1: case MFF_XREG2: case MFF_XREG3
#else
#error "Need to update CASE_MFF_XREGS to match FLOW_N_XREGS"
#endif

/* Prerequisites for matching a field.
 *
 * A field may only be matched if the correct lower-level protocols are also
 * matched.  For example, the TCP port may be matched only if the Ethernet type
 * matches ETH_TYPE_IP and the IP protocol matches IPPROTO_TCP. */
enum OVS_PACKED_ENUM mf_prereqs {
    MFP_NONE,

    /* L2 requirements. */
    MFP_ARP,
    MFP_VLAN_VID,
    MFP_IPV4,
    MFP_IPV6,
    MFP_IP_ANY,

    /* L2.5 requirements. */
    MFP_MPLS,

    /* L2+L3 requirements. */
    MFP_TCP,                    /* On IPv4 or IPv6. */
    MFP_UDP,                    /* On IPv4 or IPv6. */
    MFP_SCTP,                   /* On IPv4 or IPv6. */
    MFP_ICMPV4,
    MFP_ICMPV6,

    /* L2+L3+L4 requirements. */
    MFP_ND,
    MFP_ND_SOLICIT,
    MFP_ND_ADVERT
};

/* Forms of partial-field masking allowed for a field.
 *
 * Every field may be masked as a whole. */
enum OVS_PACKED_ENUM mf_maskable {
    MFM_NONE,                   /* No sub-field masking. */
    MFM_FULLY,                  /* Every bit is individually maskable. */
};

/* How to format or parse a field's value. */
enum OVS_PACKED_ENUM mf_string {
    /* Integer formats.
     *
     * The particular MFS_* constant sets the output format.  On input, either
     * decimal or hexadecimal (prefixed with 0x) is accepted. */
    MFS_DECIMAL,
    MFS_HEXADECIMAL,

    /* Other formats. */
    MFS_ETHERNET,
    MFS_IPV4,
    MFS_IPV6,
    MFS_OFP_PORT,               /* 16-bit OpenFlow 1.0 port number or name. */
    MFS_OFP_PORT_OXM,           /* 32-bit OpenFlow 1.1+ port number or name. */
    MFS_FRAG,                   /* no, yes, first, later, not_later */
    MFS_TNL_FLAGS,              /* FLOW_TNL_F_* flags */
    MFS_TCP_FLAGS,              /* TCP_* flags */
};

struct mf_field {
    /* Identification. */
    enum mf_field_id id;        /* MFF_*. */
    const char *name;           /* Name of this field, e.g. "eth_type". */
    const char *extra_name;     /* Alternate name, e.g. "dl_type", or NULL. */

    /* Size.
     *
     * Most fields have n_bytes * 8 == n_bits.  There are a few exceptions:
     *
     *     - "dl_vlan" is 2 bytes but only 12 bits.
     *     - "dl_vlan_pcp" is 1 byte but only 3 bits.
     *     - "is_frag" is 1 byte but only 2 bits.
     *     - "ipv6_label" is 4 bytes but only 20 bits.
     *     - "mpls_label" is 4 bytes but only 20 bits.
     *     - "mpls_tc"    is 1 byte but only 3 bits.
     *     - "mpls_bos"   is 1 byte but only 1 bit.
     */
    unsigned int n_bytes;       /* Width of the field in bytes. */
    unsigned int n_bits;        /* Number of significant bits in field. */

    /* Properties. */
    enum mf_maskable maskable;
    enum mf_string string;
    enum mf_prereqs prereqs;
    bool writable;              /* May be written by actions? */

    /* Usable protocols.
     *
     * NXM and OXM are extensible, allowing later extensions to be sent in
     * earlier protocol versions, so this does not necessarily correspond to
     * the OpenFlow protocol version the field was introduced in.
     * Also, some field types are tranparently mapped to each other via the
     * struct flow (like vlan and dscp/tos fields), so each variant supports
     * all protocols.
     *
     * These are combinations of OFPUTIL_P_*.  (They are not declared as type
     * enum ofputil_protocol because that would give meta-flow.h and ofp-util.h
     * a circular dependency.) */
    uint32_t usable_protocols_exact;   /* Matching or setting whole field. */
    uint32_t usable_protocols_cidr;    /* Matching a CIDR mask in field. */
    uint32_t usable_protocols_bitwise; /* Matching arbitrary bits in field. */

    int flow_be32ofs;  /* Field's be32 offset in "struct flow", if prefix tree
                        * lookup is supported for the field, or -1. */
};

/* The representation of a field's value. */
union mf_value {
    struct in6_addr ipv6;
    uint8_t mac[ETH_ADDR_LEN];
    ovs_be64 be64;
    ovs_be32 be32;
    ovs_be16 be16;
    uint8_t u8;
};
BUILD_ASSERT_DECL(sizeof(union mf_value) == 16);

/* An all-1-bits mf_value.  Needs to be updated if struct mf_value grows.*/
#define MF_EXACT_MASK_INITIALIZER { IN6ADDR_EXACT_INIT }
BUILD_ASSERT_DECL(sizeof(union mf_value) == sizeof(struct in6_addr));

/* Part of a field. */
struct mf_subfield {
    const struct mf_field *field;
    unsigned int ofs;           /* Bit offset. */
    unsigned int n_bits;        /* Number of bits. */
};

/* Data for some part of an mf_field.
 *
 * The data is stored "right-justified".  For example, if "union mf_subvalue
 * value" contains NXM_OF_VLAN_TCI[0..11], then one could access the
 * corresponding data in value.be16[7] as the bits in the mask htons(0xfff). */
union mf_subvalue {
    uint8_t u8[16];
    ovs_be16 be16[8];
    ovs_be32 be32[4];
    ovs_be64 be64[2];
};
BUILD_ASSERT_DECL(sizeof(union mf_value) == sizeof (union mf_subvalue));

/* Finding mf_fields. */
const struct mf_field *mf_from_name(const char *name);

static inline const struct mf_field *
mf_from_id(enum mf_field_id id)
{
    extern const struct mf_field mf_fields[MFF_N_IDS];
    ovs_assert((unsigned int) id < MFF_N_IDS);
    return &mf_fields[id];
}

/* Inspecting wildcarded bits. */
bool mf_is_all_wild(const struct mf_field *, const struct flow_wildcards *);

bool mf_is_mask_valid(const struct mf_field *, const union mf_value *mask);
void mf_get_mask(const struct mf_field *, const struct flow_wildcards *,
                 union mf_value *mask);

/* Prerequisites. */
bool mf_are_prereqs_ok(const struct mf_field *, const struct flow *);
void mf_mask_field_and_prereqs(const struct mf_field *, struct flow *mask);

static inline bool
mf_is_l3_or_higher(const struct mf_field *mf)
{
    return mf->id >= MFF_IPV4_SRC;
}

/* Field values. */
bool mf_is_value_valid(const struct mf_field *, const union mf_value *value);

void mf_get_value(const struct mf_field *, const struct flow *,
                  union mf_value *value);
void mf_set_value(const struct mf_field *, const union mf_value *value,
                  struct match *);
void mf_set_flow_value(const struct mf_field *, const union mf_value *value,
                       struct flow *);
void mf_set_flow_value_masked(const struct mf_field *,
                              const union mf_value *value,
                              const union mf_value *mask,
                              struct flow *);
bool mf_is_zero(const struct mf_field *, const struct flow *);
void mf_mask_field(const struct mf_field *, struct flow *);

void mf_get(const struct mf_field *, const struct match *,
            union mf_value *value, union mf_value *mask);

/* Returns the set of usable protocols. */
enum ofputil_protocol mf_set(const struct mf_field *,
                             const union mf_value *value,
                             const union mf_value *mask,
                             struct match *);

void mf_set_wild(const struct mf_field *, struct match *);

/* Subfields. */
void mf_write_subfield_flow(const struct mf_subfield *,
                            const union mf_subvalue *, struct flow *);
void mf_write_subfield(const struct mf_subfield *, const union mf_subvalue *,
                       struct match *);

void mf_read_subfield(const struct mf_subfield *, const struct flow *,
                      union mf_subvalue *);
uint64_t mf_get_subfield(const struct mf_subfield *, const struct flow *);


enum ofperr mf_check_src(const struct mf_subfield *, const struct flow *);
enum ofperr mf_check_dst(const struct mf_subfield *, const struct flow *);

/* Parsing and formatting. */
char *mf_parse(const struct mf_field *, const char *,
               union mf_value *value, union mf_value *mask);
char *mf_parse_value(const struct mf_field *, const char *, union mf_value *);
void mf_format(const struct mf_field *,
               const union mf_value *value, const union mf_value *mask,
               struct ds *);
void mf_format_subvalue(const union mf_subvalue *subvalue, struct ds *s);

#endif /* meta-flow.h */

/*
 * Copyright (c) 2011-2017 Nicira, Inc.
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

#ifndef OPENVSWITCH_META_FLOW_H
#define OPENVSWITCH_META_FLOW_H 1

#include <limits.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include "openvswitch/flow.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-protocol.h"
#include "openvswitch/packets.h"
#include "openvswitch/util.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ds;
struct match;
struct ofputil_port_map;
struct ofputil_tlv_table_mod;

/* Open vSwitch fields
 * ===================
 *
 * Refer to ovs-fields(7) for a detailed introduction to Open vSwitch fields.
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
 *     - Any number of paragraphs of free text that describe the field.  These
 *       are kept brief because the main description is in meta-flow.xml.
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
 *         tunnelMD: A variable length field, up to 124 bytes, that carries
 *                   tunnel metadata.
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
 *       TCP flags: See the description of tcp_flags in ovs-fields(7).
 *
 *       packet type: A pair of packet type namespace NS and NS_TYPE within
 *       that namespace "(NS,NS_TYPE)". NS and NS_TYPE are formatted in
 *       decimal or hexadecimal as and accept decimal and hexadecimal (with
 *       0x prefix) at parsing.
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
 * e.g. MFF_REG0 through MFF_REG15.  For these, the comments may be merged
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
     * OXM: NXOXM_ET_DP_HASH(0) since v2.4.
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

    /* "packet_type".
     *
     * Define the packet type in OpenFlow 1.5+.
     *
     * Type: be32.
     * Maskable: no.
     * Formatting: packet type.
     * Prerequisites: none.
     * Access: read-only.
     * NXM: none.
     * OXM: OXM_OF_PACKET_TYPE(44) since OF1.5 and v2.8.
     */
    MFF_PACKET_TYPE,

    /* "conj_id".
     *
     * ID for "conjunction" actions.  Please refer to ovs-fields(7)
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

    /* "tun_ipv6_src".
     *
     * The IPv6 source address in the outer IP header of a tunneled packet.
     *
     * For non-tunneled packets, the value is 0.
     *
     * Type: be128.
     * Maskable: bitwise.
     * Formatting: IPv6.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: NXM_NX_TUN_IPV6_SRC(109) since v2.5.
     * OXM: none.
     * Prefix lookup member: tunnel.ipv6_src.
     */
    MFF_TUN_IPV6_SRC,

    /* "tun_ipv6_dst".
     *
     * The IPv6 destination address in the outer IP header of a tunneled
     * packet.
     *
     * For non-tunneled packets, the value is 0.
     *
     * Type: be128.
     * Maskable: bitwise.
     * Formatting: IPv6.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: NXM_NX_TUN_IPV6_DST(110) since v2.5.
     * OXM: none.
     * Prefix lookup member: tunnel.ipv6_dst.
     */
    MFF_TUN_IPV6_DST,

    /* "tun_flags".
     *
     * Flags representing aspects of tunnel behavior.
     *
     * For non-tunneled packets, the value is 0.
     *
     * Type: be16 (low 1 bits).
     * Maskable: bitwise.
     * Formatting: tunnel flags.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: NXM_NX_TUN_FLAGS(104) since v2.5.
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

    /* "tun_gbp_id".
     *
     * VXLAN Group Policy ID
     *
     * Type: be16.
     * Maskable: bitwise.
     * Formatting: decimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: NXM_NX_TUN_GBP_ID(38) since v2.4.
     * OXM: none.
     */
    MFF_TUN_GBP_ID,

    /* "tun_gbp_flags".
     *
     * VXLAN Group Policy flags
     *
     * Type: u8.
     * Maskable: bitwise.
     * Formatting: hexadecimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: NXM_NX_TUN_GBP_FLAGS(39) since v2.4.
     * OXM: none.
     */
    MFF_TUN_GBP_FLAGS,

    /* "tun_erspan_idx".
     *
     * ERSPAN index (direction/port number)
     *
     * Type: be32 (low 20 bits).
     * Maskable: bitwise.
     * Formatting: hexadecimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: none.
     * OXM: NXOXM_ET_ERSPAN_IDX(11) since v2.10.
     */
    MFF_TUN_ERSPAN_IDX,

    /* "tun_erspan_ver".
     *
     * ERSPAN version (v1 / v2)
     *
     * Type: u8 (low 4 bits).
     * Maskable: bitwise.
     * Formatting: decimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: none.
     * OXM: NXOXM_ET_ERSPAN_VER(12) since v2.10.
     */
    MFF_TUN_ERSPAN_VER,

    /* "tun_erspan_dir".
     *
     * ERSPAN mirrored traffic's direction
     *
     * Type: u8 (low 1 bits).
     * Maskable: bitwise.
     * Formatting: decimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: none.
     * OXM: NXOXM_ET_ERSPAN_DIR(13) since v2.10.
     */
    MFF_TUN_ERSPAN_DIR,

    /* "tun_erspan_hwid".
     *
     * ERSPAN Hardware ID
     *
     * Type: u8 (low 6 bits).
     * Maskable: bitwise.
     * Formatting: hexadecimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: none.
     * OXM: NXOXM_ET_ERSPAN_HWID(14) since v2.10.
     */
    MFF_TUN_ERSPAN_HWID,

    /* "tun_gtpu_flags".
     *
     * GTP-U tunnel flags.
     *
     * Type: u8.
     * Maskable: bitwise.
     * Formatting: hexadecimal.
     * Prerequisites: none.
     * Access: read-only.
     * NXM: none.
     * OXM: NXOXM_ET_GTPU_FLAGS(15) since v2.13.
     */
    MFF_TUN_GTPU_FLAGS,

    /* "tun_gtpu_msgtype".
     *
     * GTP-U tunnel message type.
     *
     * Type: u8.
     * Maskable: bitwise.
     * Formatting: decimal.
     * Prerequisites: none.
     * Access: read-only.
     * NXM: none.
     * OXM: NXOXM_ET_GTPU_MSGTYPE(16) since v2.13.
     */
    MFF_TUN_GTPU_MSGTYPE,

#if TUN_METADATA_NUM_OPTS == 64
    /* "tun_metadata<N>".
     *
     * Encapsulation metadata for tunnels.
     *
     * Each NXM can be dynamically mapped onto a particular tunnel field using
     * OpenFlow commands. The individual NXMs can each carry up to 124 bytes
     * of data and a combined total of 256 across all allocated fields.
     *
     * Type: tunnelMD.
     * Maskable: bitwise.
     * Formatting: hexadecimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: NXM_NX_TUN_METADATA0(40) since v2.5.        <0>
     * NXM: NXM_NX_TUN_METADATA1(41) since v2.5.        <1>
     * NXM: NXM_NX_TUN_METADATA2(42) since v2.5.        <2>
     * NXM: NXM_NX_TUN_METADATA3(43) since v2.5.        <3>
     * NXM: NXM_NX_TUN_METADATA4(44) since v2.5.        <4>
     * NXM: NXM_NX_TUN_METADATA5(45) since v2.5.        <5>
     * NXM: NXM_NX_TUN_METADATA6(46) since v2.5.        <6>
     * NXM: NXM_NX_TUN_METADATA7(47) since v2.5.        <7>
     * NXM: NXM_NX_TUN_METADATA8(48) since v2.5.        <8>
     * NXM: NXM_NX_TUN_METADATA9(49) since v2.5.        <9>
     * NXM: NXM_NX_TUN_METADATA10(50) since v2.5.       <10>
     * NXM: NXM_NX_TUN_METADATA11(51) since v2.5.       <11>
     * NXM: NXM_NX_TUN_METADATA12(52) since v2.5.       <12>
     * NXM: NXM_NX_TUN_METADATA13(53) since v2.5.       <13>
     * NXM: NXM_NX_TUN_METADATA14(54) since v2.5.       <14>
     * NXM: NXM_NX_TUN_METADATA15(55) since v2.5.       <15>
     * NXM: NXM_NX_TUN_METADATA16(56) since v2.5.       <16>
     * NXM: NXM_NX_TUN_METADATA17(57) since v2.5.       <17>
     * NXM: NXM_NX_TUN_METADATA18(58) since v2.5.       <18>
     * NXM: NXM_NX_TUN_METADATA19(59) since v2.5.       <19>
     * NXM: NXM_NX_TUN_METADATA20(60) since v2.5.       <20>
     * NXM: NXM_NX_TUN_METADATA21(61) since v2.5.       <21>
     * NXM: NXM_NX_TUN_METADATA22(62) since v2.5.       <22>
     * NXM: NXM_NX_TUN_METADATA23(63) since v2.5.       <23>
     * NXM: NXM_NX_TUN_METADATA24(64) since v2.5.       <24>
     * NXM: NXM_NX_TUN_METADATA25(65) since v2.5.       <25>
     * NXM: NXM_NX_TUN_METADATA26(66) since v2.5.       <26>
     * NXM: NXM_NX_TUN_METADATA27(67) since v2.5.       <27>
     * NXM: NXM_NX_TUN_METADATA28(68) since v2.5.       <28>
     * NXM: NXM_NX_TUN_METADATA29(69) since v2.5.       <29>
     * NXM: NXM_NX_TUN_METADATA30(70) since v2.5.       <30>
     * NXM: NXM_NX_TUN_METADATA31(71) since v2.5.       <31>
     * NXM: NXM_NX_TUN_METADATA32(72) since v2.5.       <32>
     * NXM: NXM_NX_TUN_METADATA33(73) since v2.5.       <33>
     * NXM: NXM_NX_TUN_METADATA34(74) since v2.5.       <34>
     * NXM: NXM_NX_TUN_METADATA35(75) since v2.5.       <35>
     * NXM: NXM_NX_TUN_METADATA36(76) since v2.5.       <36>
     * NXM: NXM_NX_TUN_METADATA37(77) since v2.5.       <37>
     * NXM: NXM_NX_TUN_METADATA38(78) since v2.5.       <38>
     * NXM: NXM_NX_TUN_METADATA39(79) since v2.5.       <39>
     * NXM: NXM_NX_TUN_METADATA40(80) since v2.5.       <40>
     * NXM: NXM_NX_TUN_METADATA41(81) since v2.5.       <41>
     * NXM: NXM_NX_TUN_METADATA42(82) since v2.5.       <42>
     * NXM: NXM_NX_TUN_METADATA43(83) since v2.5.       <43>
     * NXM: NXM_NX_TUN_METADATA44(84) since v2.5.       <44>
     * NXM: NXM_NX_TUN_METADATA45(85) since v2.5.       <45>
     * NXM: NXM_NX_TUN_METADATA46(86) since v2.5.       <46>
     * NXM: NXM_NX_TUN_METADATA47(87) since v2.5.       <47>
     * NXM: NXM_NX_TUN_METADATA48(88) since v2.5.       <48>
     * NXM: NXM_NX_TUN_METADATA49(89) since v2.5.       <49>
     * NXM: NXM_NX_TUN_METADATA50(90) since v2.5.       <50>
     * NXM: NXM_NX_TUN_METADATA51(91) since v2.5.       <51>
     * NXM: NXM_NX_TUN_METADATA52(92) since v2.5.       <52>
     * NXM: NXM_NX_TUN_METADATA53(93) since v2.5.       <53>
     * NXM: NXM_NX_TUN_METADATA54(94) since v2.5.       <54>
     * NXM: NXM_NX_TUN_METADATA55(95) since v2.5.       <55>
     * NXM: NXM_NX_TUN_METADATA56(96) since v2.5.       <56>
     * NXM: NXM_NX_TUN_METADATA57(97) since v2.5.       <57>
     * NXM: NXM_NX_TUN_METADATA58(98) since v2.5.       <58>
     * NXM: NXM_NX_TUN_METADATA59(99) since v2.5.       <59>
     * NXM: NXM_NX_TUN_METADATA60(100) since v2.5.      <60>
     * NXM: NXM_NX_TUN_METADATA61(101) since v2.5.      <61>
     * NXM: NXM_NX_TUN_METADATA62(102) since v2.5.      <62>
     * NXM: NXM_NX_TUN_METADATA63(103) since v2.5.      <63>
     * OXM: none.
     */
    MFF_TUN_METADATA0,
    MFF_TUN_METADATA1,
    MFF_TUN_METADATA2,
    MFF_TUN_METADATA3,
    MFF_TUN_METADATA4,
    MFF_TUN_METADATA5,
    MFF_TUN_METADATA6,
    MFF_TUN_METADATA7,
    MFF_TUN_METADATA8,
    MFF_TUN_METADATA9,
    MFF_TUN_METADATA10,
    MFF_TUN_METADATA11,
    MFF_TUN_METADATA12,
    MFF_TUN_METADATA13,
    MFF_TUN_METADATA14,
    MFF_TUN_METADATA15,
    MFF_TUN_METADATA16,
    MFF_TUN_METADATA17,
    MFF_TUN_METADATA18,
    MFF_TUN_METADATA19,
    MFF_TUN_METADATA20,
    MFF_TUN_METADATA21,
    MFF_TUN_METADATA22,
    MFF_TUN_METADATA23,
    MFF_TUN_METADATA24,
    MFF_TUN_METADATA25,
    MFF_TUN_METADATA26,
    MFF_TUN_METADATA27,
    MFF_TUN_METADATA28,
    MFF_TUN_METADATA29,
    MFF_TUN_METADATA30,
    MFF_TUN_METADATA31,
    MFF_TUN_METADATA32,
    MFF_TUN_METADATA33,
    MFF_TUN_METADATA34,
    MFF_TUN_METADATA35,
    MFF_TUN_METADATA36,
    MFF_TUN_METADATA37,
    MFF_TUN_METADATA38,
    MFF_TUN_METADATA39,
    MFF_TUN_METADATA40,
    MFF_TUN_METADATA41,
    MFF_TUN_METADATA42,
    MFF_TUN_METADATA43,
    MFF_TUN_METADATA44,
    MFF_TUN_METADATA45,
    MFF_TUN_METADATA46,
    MFF_TUN_METADATA47,
    MFF_TUN_METADATA48,
    MFF_TUN_METADATA49,
    MFF_TUN_METADATA50,
    MFF_TUN_METADATA51,
    MFF_TUN_METADATA52,
    MFF_TUN_METADATA53,
    MFF_TUN_METADATA54,
    MFF_TUN_METADATA55,
    MFF_TUN_METADATA56,
    MFF_TUN_METADATA57,
    MFF_TUN_METADATA58,
    MFF_TUN_METADATA59,
    MFF_TUN_METADATA60,
    MFF_TUN_METADATA61,
    MFF_TUN_METADATA62,
    MFF_TUN_METADATA63,
#else
#error "Need to update MFF_TUN_METADATA* to match TUN_METADATA_NUM_OPTS"
#endif

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

    /* "ct_state".
     *
     * Connection tracking state.  The field is populated by the NXAST_CT
     * action.
     *
     * Type: be32.
     * Maskable: bitwise.
     * Formatting: ct state.
     * Prerequisites: none.
     * Access: read-only.
     * NXM: NXM_NX_CT_STATE(105) since v2.5.
     * OXM: none.
     */
    MFF_CT_STATE,

    /* "ct_zone".
     *
     * Connection tracking zone.  The field is populated by the
     * NXAST_CT action.
     *
     * Type: be16.
     * Maskable: no.
     * Formatting: hexadecimal.
     * Prerequisites: none.
     * Access: read-only.
     * NXM: NXM_NX_CT_ZONE(106) since v2.5.
     * OXM: none.
     */
    MFF_CT_ZONE,

    /* "ct_mark".
     *
     * Connection tracking mark.  The mark is carried with the
     * connection tracking state.  On Linux this corresponds to the
     * nf_conn's "mark" member but the exact implementation is
     * platform-dependent.
     *
     * Writable only from nested actions within the NXAST_CT action.
     *
     * Type: be32.
     * Maskable: bitwise.
     * Formatting: hexadecimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: NXM_NX_CT_MARK(107) since v2.5.
     * OXM: none.
     */
    MFF_CT_MARK,

    /* "ct_label".
     *
     * Connection tracking label.  The label is carried with the
     * connection tracking state.  On Linux this is held in the
     * conntrack label extension but the exact implementation is
     * platform-dependent.
     *
     * Writable only from nested actions within the NXAST_CT action.
     *
     * Type: be128.
     * Maskable: bitwise.
     * Formatting: hexadecimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: NXM_NX_CT_LABEL(108) since v2.5.
     * OXM: none.
     */
    MFF_CT_LABEL,

    /* "ct_nw_proto".
     *
     * The "protocol" byte in the IPv4 or IPv6 header for the original
     * direction conntrack tuple, or of the parent conntrack entry, if the
     * current connection is a related connection.
     *
     * The value is initially zero and populated by the CT action.  The value
     * remains zero after the CT action only if the packet can not be
     * associated with a valid connection, in which case the prerequisites
     * for matching this field ("CT") are not met.
     *
     * Type: u8.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: CT.
     * Access: read-only.
     * NXM: NXM_NX_CT_NW_PROTO(119) since v2.8.
     * OXM: none.
     */
    MFF_CT_NW_PROTO,

    /* "ct_nw_src".
     *
     * IPv4 source address of the original direction tuple of the conntrack
     * entry, or of the parent conntrack entry, if the current connection is a
     * related connection.
     *
     * The value is populated by the CT action.
     *
     * Type: be32.
     * Maskable: bitwise.
     * Formatting: IPv4.
     * Prerequisites: CT.
     * Access: read-only.
     * NXM: NXM_NX_CT_NW_SRC(120) since v2.8.
     * OXM: none.
     * Prefix lookup member: ct_nw_src.
     */
    MFF_CT_NW_SRC,

    /* "ct_nw_dst".
     *
     * IPv4 destination address of the original direction tuple of the
     * conntrack entry, or of the parent conntrack entry, if the current
     * connection is a related connection.
     *
     * The value is populated by the CT action.
     *
     * Type: be32.
     * Maskable: bitwise.
     * Formatting: IPv4.
     * Prerequisites: CT.
     * Access: read-only.
     * NXM: NXM_NX_CT_NW_DST(121) since v2.8.
     * OXM: none.
     * Prefix lookup member: ct_nw_dst.
     */
    MFF_CT_NW_DST,

    /* "ct_ipv6_src".
     *
     * IPv6 source address of the original direction tuple of the conntrack
     * entry, or of the parent conntrack entry, if the current connection is a
     * related connection.
     *
     * The value is populated by the CT action.
     *
     * Type: be128.
     * Maskable: bitwise.
     * Formatting: IPv6.
     * Prerequisites: CT.
     * Access: read-only.
     * NXM: NXM_NX_CT_IPV6_SRC(122) since v2.8.
     * OXM: none.
     * Prefix lookup member: ct_ipv6_src.
     */
    MFF_CT_IPV6_SRC,

    /* "ct_ipv6_dst".
     *
     * IPv6 destination address of the original direction tuple of the
     * conntrack entry, or of the parent conntrack entry, if the current
     * connection is a related connection.
     *
     * The value is populated by the CT action.
     *
     * Type: be128.
     * Maskable: bitwise.
     * Formatting: IPv6.
     * Prerequisites: CT.
     * Access: read-only.
     * NXM: NXM_NX_CT_IPV6_DST(123) since v2.8.
     * OXM: none.
     * Prefix lookup member: ct_ipv6_dst.
     */
    MFF_CT_IPV6_DST,

    /* "ct_tp_src".
     *
     * Transport layer source port of the original direction tuple of the
     * conntrack entry, or of the parent conntrack entry, if the current
     * connection is a related connection.
     *
     * The value is populated by the CT action.
     *
     * Type: be16.
     * Maskable: bitwise.
     * Formatting: decimal.
     * Prerequisites: CT.
     * Access: read-only.
     * NXM: NXM_NX_CT_TP_SRC(124) since v2.8.
     * OXM: none.
     */
    MFF_CT_TP_SRC,

    /* "ct_tp_dst".
     *
     * Transport layer destination port of the original direction tuple of the
     * conntrack entry, or of the parent conntrack entry, if the current
     * connection is a related connection.
     *
     * The value is populated by the CT action.
     *
     * Type: be16.
     * Maskable: bitwise.
     * Formatting: decimal.
     * Prerequisites: CT.
     * Access: read-only.
     * NXM: NXM_NX_CT_TP_DST(125) since v2.8.
     * OXM: none.
     */
    MFF_CT_TP_DST,

#if FLOW_N_REGS == 16
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
     * NXM: NXM_NX_REG8(8) since v2.6.        <8>
     * NXM: NXM_NX_REG9(9) since v2.6.        <9>
     * NXM: NXM_NX_REG10(10) since v2.6.      <10>
     * NXM: NXM_NX_REG11(11) since v2.6.      <11>
     * NXM: NXM_NX_REG12(12) since v2.6.      <12>
     * NXM: NXM_NX_REG13(13) since v2.6.      <13>
     * NXM: NXM_NX_REG14(14) since v2.6.      <14>
     * NXM: NXM_NX_REG15(15) since v2.6.      <15>
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
    MFF_REG8,
    MFF_REG9,
    MFF_REG10,
    MFF_REG11,
    MFF_REG12,
    MFF_REG13,
    MFF_REG14,
    MFF_REG15,
#else
#error "Need to update MFF_REG* to match FLOW_N_REGS"
#endif

#if FLOW_N_XREGS == 8
    /* "xreg<N>".
     *
     * OpenFlow 1.5 ``extended register".
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
    MFF_XREG4,
    MFF_XREG5,
    MFF_XREG6,
    MFF_XREG7,
#else
#error "Need to update MFF_REG* to match FLOW_N_XREGS"
#endif

#if FLOW_N_XXREGS == 4
    /* "xxreg<N>".
     *
     * ``extended-extended register".
     *
     * Type: be128.
     * Maskable: bitwise.
     * Formatting: hexadecimal.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: NXM_NX_XXREG0(111) since v2.6.              <0>
     * NXM: NXM_NX_XXREG1(112) since v2.6.              <1>
     * NXM: NXM_NX_XXREG2(113) since v2.6.              <2>
     * NXM: NXM_NX_XXREG3(114) since v2.6.              <3>
     * NXM: NXM_NX_XXREG4(115) since vX.Y.              <4>
     * NXM: NXM_NX_XXREG5(116) since vX.Y.              <5>
     * NXM: NXM_NX_XXREG6(117) since vX.Y.              <6>
     * NXM: NXM_NX_XXREG7(118) since vX.Y.              <7>
     * OXM: none.
     */
    MFF_XXREG0,
    MFF_XXREG1,
    MFF_XXREG2,
    MFF_XXREG3,
#else
#error "Need to update MFF_REG* to match FLOW_N_XXREGS"
#endif

/* ## -------- ## */
/* ## Ethernet ## */
/* ## -------- ## */

    /* "eth_src" (aka "dl_src").
     *
     * Source address in Ethernet header.
     *
     * Type: MAC.
     * Maskable: bitwise.
     * Formatting: Ethernet.
     * Prerequisites: Ethernet.
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
     * Type: MAC.
     * Maskable: bitwise.
     * Formatting: Ethernet.
     * Prerequisites: Ethernet.
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
     * For a packet with an 802.1Q header, this is the type of the encapsulated
     * frame.
     *
     * Type: be16.
     * Maskable: no.
     * Formatting: hexadecimal.
     * Prerequisites: Ethernet.
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
     * Type: be16.
     * Maskable: bitwise.
     * Formatting: hexadecimal.
     * Prerequisites: Ethernet.
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
     * Prerequisites: Ethernet.
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
     * Prerequisites: Ethernet.
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
     * Prerequisites: Ethernet.
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

    /* "mpls_ttl".
     *
     * The outermost MPLS label's time-to-live (TTL) field, or 0 if no MPLS
     * labels are present.
     *
     * Type: u8.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: MPLS.
     * Access: read/write.
     * NXM: NXM_NX_MPLS_TTL(30) since v2.6.
     * OXM: none.
     */
    MFF_MPLS_TTL,

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
     * Type: be128.
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
     * Type: be128.
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
     * OF1.1: exact match.
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

    /* "ip_frag" (aka "nw_frag").
     *
     * IP fragment information.
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
     * Access: read/write.
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
     * Access: read/write.
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
     * Access: read/write.
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
     * Access: read/write.
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
     * Type: be128.
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

    /* "nd_reserved".
     *
     * The reserved field in IPv6 Neighbor Discovery message.
     *
     * Type: be32.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: ND.
     * Access: read/write.
     * NXM: none.
     * OXM: ERICOXM_OF_ICMPV6_ND_RESERVED(1) since v2.11.
     */
    MFF_ND_RESERVED,

    /* "nd_options_type".
     *
     * The type of the option in IPv6 Neighbor Discovery message.
     *
     * Type: u8.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: ND.
     * Access: read/write.
     * NXM: none.
     * OXM: ERICOXM_OF_ICMPV6_ND_OPTIONS_TYPE(2) since v2.11.
     */
    MFF_ND_OPTIONS_TYPE,

/* ## ---- ## */
/* ## NSH  ## */
/* ## ---- ## */

    /* "nsh_flags".
     *
     * flags field in NSH base header.
     *
     * Type: u8.
     * Maskable: bitwise.
     * Formatting: decimal.
     * Prerequisites: NSH.
     * Access: read/write.
     * NXM: none.
     * OXM: NXOXM_NSH_FLAGS(1) since v2.8.
     */
    MFF_NSH_FLAGS,

    /* "nsh_mdtype".
     *
     * mdtype field in NSH base header.
     *
     * Type: u8.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: NSH.
     * Access: read-only.
     * NXM: none.
     * OXM: NXOXM_NSH_MDTYPE(2) since v2.8.
     */
    MFF_NSH_MDTYPE,

    /* "nsh_np".
     *
     * np (next protocol) field in NSH base header.
     *
     * Type: u8.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: NSH.
     * Access: read-only.
     * NXM: none.
     * OXM: NXOXM_NSH_NP(3) since v2.8.
     */
    MFF_NSH_NP,

    /* "nsh_spi" (aka "nsp").
     *
     * spi (service path identifier) field in NSH base header.
     *
     * Type: be32 (low 24 bits).
     * Maskable: no.
     * Formatting: hexadecimal.
     * Prerequisites: NSH.
     * Access: read/write.
     * NXM: none.
     * OXM: NXOXM_NSH_SPI(4) since v2.8.
     */
    MFF_NSH_SPI,

    /* "nsh_si" (aka "nsi").
     *
     * si (service index) field in NSH base header.
     *
     * Type: u8.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: NSH.
     * Access: read/write.
     * NXM: none.
     * OXM: NXOXM_NSH_SI(5) since v2.8.
     */
    MFF_NSH_SI,

    /* "nsh_c<N>" (aka "nshc<N>").
     *
     * context fields in NSH context header.
     *
     * Type: be32.
     * Maskable: bitwise.
     * Formatting: hexadecimal.
     * Prerequisites: NSH.
     * Access: read/write.
     * NXM: none.
     * OXM: NXOXM_NSH_C1(6) since v2.8.        <1>
     * OXM: NXOXM_NSH_C2(7) since v2.8.        <2>
     * OXM: NXOXM_NSH_C3(8) since v2.8.        <3>
     * OXM: NXOXM_NSH_C4(9) since v2.8.        <4>
     */
    MFF_NSH_C1,
    MFF_NSH_C2,
    MFF_NSH_C3,
    MFF_NSH_C4,

    /* "nsh_ttl".
     *
     * TTL field in NSH base header.
     *
     * Type: u8.
     * Maskable: no.
     * Formatting: decimal.
     * Prerequisites: NSH.
     * Access: read/write.
     * NXM: none.
     * OXM: NXOXM_NSH_TTL(10) since v2.9.
     */
    MFF_NSH_TTL,

    MFF_N_IDS
};

/* A set of mf_field_ids. */
struct mf_bitmap {
    unsigned long bm[BITMAP_N_LONGS(MFF_N_IDS)];
};
#define MF_BITMAP_INITIALIZER { { [0] = 0 } }

bool mf_bitmap_is_superset(const struct mf_bitmap *super,
                           const struct mf_bitmap *sub);
struct mf_bitmap mf_bitmap_and(struct mf_bitmap, struct mf_bitmap);
struct mf_bitmap mf_bitmap_or(struct mf_bitmap, struct mf_bitmap);
struct mf_bitmap mf_bitmap_not(struct mf_bitmap);

/* Use this macro as CASE_MFF_REGS: in a switch statement to choose all of the
 * MFF_REGn cases. */
#if FLOW_N_REGS ==16
#define CASE_MFF_REGS                                             \
    case MFF_REG0: case MFF_REG1: case MFF_REG2: case MFF_REG3:   \
    case MFF_REG4: case MFF_REG5: case MFF_REG6: case MFF_REG7:   \
    case MFF_REG8: case MFF_REG9: case MFF_REG10: case MFF_REG11: \
    case MFF_REG12: case MFF_REG13: case MFF_REG14: case MFF_REG15
#else
#error "Need to update CASE_MFF_REGS to match FLOW_N_REGS"
#endif

/* Use this macro as CASE_MFF_XREGS: in a switch statement to choose all of the
 * MFF_REGn cases. */
#if FLOW_N_XREGS == 8
#define CASE_MFF_XREGS                                              \
    case MFF_XREG0: case MFF_XREG1: case MFF_XREG2: case MFF_XREG3: \
    case MFF_XREG4: case MFF_XREG5: case MFF_XREG6: case MFF_XREG7
#else
#error "Need to update CASE_MFF_XREGS to match FLOW_N_XREGS"
#endif

/* Use this macro as CASE_MFF_XXREGS: in a switch statement to choose
 * all of the MFF_REGn cases. */
#if FLOW_N_XXREGS == 4
#define CASE_MFF_XXREGS                                              \
    case MFF_XXREG0: case MFF_XXREG1: case MFF_XXREG2: case MFF_XXREG3
#else
#error "Need to update CASE_MFF_XXREGS to match FLOW_N_XXREGS"
#endif

static inline bool
mf_is_register(enum mf_field_id id)
{
    return ((id >= MFF_REG0   && id < MFF_REG0   + FLOW_N_REGS) ||
            (id >= MFF_XREG0  && id < MFF_XREG0  + FLOW_N_XREGS) ||
            (id >= MFF_XXREG0 && id < MFF_XXREG0 + FLOW_N_XXREGS));
}

/* Use this macro as CASE_MFF_TUN_METADATA: in a switch statement to choose
 * all of the MFF_TUN_METADATAn cases. */
#define CASE_MFF_TUN_METADATA                         \
    case MFF_TUN_METADATA0: case MFF_TUN_METADATA1:   \
    case MFF_TUN_METADATA2: case MFF_TUN_METADATA3:   \
    case MFF_TUN_METADATA4: case MFF_TUN_METADATA5:   \
    case MFF_TUN_METADATA6: case MFF_TUN_METADATA7:   \
    case MFF_TUN_METADATA8: case MFF_TUN_METADATA9:   \
    case MFF_TUN_METADATA10: case MFF_TUN_METADATA11: \
    case MFF_TUN_METADATA12: case MFF_TUN_METADATA13: \
    case MFF_TUN_METADATA14: case MFF_TUN_METADATA15: \
    case MFF_TUN_METADATA16: case MFF_TUN_METADATA17: \
    case MFF_TUN_METADATA18: case MFF_TUN_METADATA19: \
    case MFF_TUN_METADATA20: case MFF_TUN_METADATA21: \
    case MFF_TUN_METADATA22: case MFF_TUN_METADATA23: \
    case MFF_TUN_METADATA24: case MFF_TUN_METADATA25: \
    case MFF_TUN_METADATA26: case MFF_TUN_METADATA27: \
    case MFF_TUN_METADATA28: case MFF_TUN_METADATA29: \
    case MFF_TUN_METADATA30: case MFF_TUN_METADATA31: \
    case MFF_TUN_METADATA32: case MFF_TUN_METADATA33: \
    case MFF_TUN_METADATA34: case MFF_TUN_METADATA35: \
    case MFF_TUN_METADATA36: case MFF_TUN_METADATA37: \
    case MFF_TUN_METADATA38: case MFF_TUN_METADATA39: \
    case MFF_TUN_METADATA40: case MFF_TUN_METADATA41: \
    case MFF_TUN_METADATA42: case MFF_TUN_METADATA43: \
    case MFF_TUN_METADATA44: case MFF_TUN_METADATA45: \
    case MFF_TUN_METADATA46: case MFF_TUN_METADATA47: \
    case MFF_TUN_METADATA48: case MFF_TUN_METADATA49: \
    case MFF_TUN_METADATA50: case MFF_TUN_METADATA51: \
    case MFF_TUN_METADATA52: case MFF_TUN_METADATA53: \
    case MFF_TUN_METADATA54: case MFF_TUN_METADATA55: \
    case MFF_TUN_METADATA56: case MFF_TUN_METADATA57: \
    case MFF_TUN_METADATA58: case MFF_TUN_METADATA59: \
    case MFF_TUN_METADATA60: case MFF_TUN_METADATA61: \
    case MFF_TUN_METADATA62: case MFF_TUN_METADATA63

/* Prerequisites for matching a field.
 *
 * A field may only be matched if the correct lower-level protocols are also
 * matched.  For example, the TCP port may be matched only if the Ethernet type
 * matches ETH_TYPE_IP and the IP protocol matches IPPROTO_TCP. */
enum OVS_PACKED_ENUM mf_prereqs {
    MFP_NONE,

    /* L2 requirements. */
    MFP_ETHERNET,
    MFP_ARP,
    MFP_VLAN_VID,
    MFP_IPV4,
    MFP_IPV6,
    MFP_IP_ANY,
    MFP_NSH,

    /* L2.5 requirements. */
    MFP_MPLS,

    /* L2+L3 requirements. */
    MFP_TCP,                    /* On IPv4 or IPv6. */
    MFP_UDP,                    /* On IPv4 or IPv6. */
    MFP_SCTP,                   /* On IPv4 or IPv6. */
    MFP_ICMPV4,
    MFP_ICMPV6,
    MFP_CT_VALID,               /* Implies IPv4 or IPv6. */

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
    MFS_CT_STATE,               /* Connection tracking state */
    MFS_ETHERNET,
    MFS_IPV4,
    MFS_IPV6,
    MFS_OFP_PORT,               /* 16-bit OpenFlow 1.0 port number or name. */
    MFS_OFP_PORT_OXM,           /* 32-bit OpenFlow 1.1+ port number or name. */
    MFS_FRAG,                   /* no, yes, first, later, not_later */
    MFS_TNL_FLAGS,              /* FLOW_TNL_F_* flags */
    MFS_TCP_FLAGS,              /* TCP_* flags */
    MFS_PACKET_TYPE,            /* "(NS,NS_TYPE)" */
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
    bool variable_len;          /* Length is variable, if so width is max. */

    /* Properties. */
    enum mf_maskable maskable;
    enum mf_string string;
    enum mf_prereqs prereqs;
    bool writable;              /* May be written by actions? */
    bool mapped;                /* Variable length mf_field is mapped. */

    /* Usable protocols.
     *
     * NXM and OXM are extensible, allowing later extensions to be sent in
     * earlier protocol versions, so this does not necessarily correspond to
     * the OpenFlow protocol version the field was introduced in.
     * Also, some field types are tranparently mapped to each other via the
     * struct flow (like vlan and dscp/tos fields), so each variant supports
     * all protocols. */
    enum ofputil_protocol usable_protocols_exact; /* Match/set whole field. */
    enum ofputil_protocol usable_protocols_cidr;    /* Match CIDR mask. */
    enum ofputil_protocol usable_protocols_bitwise; /* Match arbitrary bits. */

    int flow_be32ofs;  /* Field's be32 offset in "struct flow", if prefix tree
                        * lookup is supported for the field, or -1. */
};

/* The representation of a field's value. */
union mf_value {
    uint8_t b[128];
    uint8_t tun_metadata[128];
    struct in6_addr ipv6;
    struct eth_addr mac;
    ovs_be128 be128;
    ovs_be64 be64;
    ovs_be32 be32;
    ovs_be16 be16;
    uint8_t u8;
};
BUILD_ASSERT_DECL(sizeof(union mf_value) == 128);
BUILD_ASSERT_DECL(sizeof(union mf_value) >= TLV_MAX_OPT_SIZE);

/* A const mf_value with all bits initialized to ones. */
extern const union mf_value exact_match_mask;

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
    /* Access to full data. */
    uint8_t u8[128];
    ovs_be16 be16[64];
    ovs_be32 be32[32];
    ovs_be64 be64[16];
    ovs_be128 be128[8];

    /* Convenient access to just least-significant bits in various forms. */
    struct {
        uint8_t dummy_u8[127];
        uint8_t u8_val;
    };
    struct {
        ovs_be16 dummy_be16[63];
        ovs_be16 be16_int;
    };
    struct {
        ovs_be32 dummy_be32[31];
        ovs_be32 be32_int;
    };
    struct {
        ovs_be64 dummy_integer[15];
        ovs_be64 integer;
    };
    struct {
        ovs_be128 dummy_be128[7];
        ovs_be128 be128_int;
    };
    struct {
        uint8_t dummy_mac[122];
        struct eth_addr mac;
    };
    struct {
        ovs_be32 dummy_ipv4[31];
        ovs_be32 ipv4;
    };
    struct {
        struct in6_addr dummy_ipv6[7];
        struct in6_addr ipv6;
    };
};
BUILD_ASSERT_DECL(sizeof(union mf_value) == sizeof (union mf_subvalue));

bool mf_subvalue_intersect(const union mf_subvalue *a_value,
                           const union mf_subvalue *a_mask,
                           const union mf_subvalue *b_value,
                           const union mf_subvalue *b_mask,
                           union mf_subvalue *dst_value,
                           union mf_subvalue *dst_mask);
int mf_subvalue_width(const union mf_subvalue *);
void mf_subvalue_shift(union mf_subvalue *, int n);
void mf_subvalue_format(const union mf_subvalue *, struct ds *);

static inline void mf_subvalue_from_value(const struct mf_subfield *sf,
                                          union mf_subvalue *sv,
                                          const void *value)
{
    unsigned int n_bytes = DIV_ROUND_UP(sf->n_bits, 8);
    memset(sv, 0, sizeof *sv - n_bytes);
    memcpy(&sv->u8[sizeof sv->u8 - n_bytes], value, n_bytes);
}


/* Set of field values. 'values' only includes the actual data bytes for each
 * field for which is used, as marked by 1-bits in 'used'. */
struct field_array {
    struct mf_bitmap used;
    size_t values_size;      /* Number of bytes currently in 'values'. */
    uint8_t *values;     /* Dynamically allocated to the correct size. */
};

/* Finding mf_fields. */
const struct mf_field *mf_from_name(const char *name);
const struct mf_field *mf_from_name_len(const char *name, size_t len);

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
bool mf_are_prereqs_ok(const struct mf_field *mf, const struct flow *flow,
                       struct flow_wildcards *wc);
bool mf_are_match_prereqs_ok(const struct mf_field *, const struct match *);

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
                  struct match *, char **err_str);
void mf_set_flow_value(const struct mf_field *, const union mf_value *value,
                       struct flow *);
void mf_set_flow_value_masked(const struct mf_field *,
                              const union mf_value *value,
                              const union mf_value *mask,
                              struct flow *);
bool mf_is_tun_metadata(const struct mf_field *);
bool mf_is_pipeline_field(const struct mf_field *);
bool mf_is_set(const struct mf_field *, const struct flow *);
void mf_mask_field(const struct mf_field *, struct flow_wildcards *);
void mf_mask_field_masked(const struct mf_field *, const union mf_value *mask,
                          struct flow_wildcards *);
int mf_field_len(const struct mf_field *, const union mf_value *value,
                 const union mf_value *mask, bool *is_masked);

void mf_get(const struct mf_field *, const struct match *,
            union mf_value *value, union mf_value *mask);

/* Returns the set of usable protocols. */
uint32_t mf_set(const struct mf_field *, const union mf_value *value,
                const union mf_value *mask, struct match *, char **err_str);

void mf_set_wild(const struct mf_field *, struct match *, char **err_str);

/* Subfields. */
void mf_write_subfield_flow(const struct mf_subfield *,
                            const union mf_subvalue *, struct flow *);
void mf_write_subfield(const struct mf_subfield *, const union mf_subvalue *,
                       struct match *);
void mf_write_subfield_value(const struct mf_subfield *, const void *src,
                             struct match *);

void mf_mask_subfield(const struct mf_field *,
                      const union mf_subvalue *value,
                      const union mf_subvalue *mask,
                      struct match *);

void mf_read_subfield(const struct mf_subfield *, const struct flow *,
                      union mf_subvalue *);
uint64_t mf_get_subfield(const struct mf_subfield *, const struct flow *);

void mf_subfield_copy(const struct mf_subfield *src,
                      const struct mf_subfield *dst,
                      struct flow *, struct flow_wildcards *);
void mf_subfield_swap(const struct mf_subfield *,
                      const struct mf_subfield *,
                      struct flow *flow, struct flow_wildcards *);

enum ofperr mf_check_src(const struct mf_subfield *, const struct match *);
enum ofperr mf_check_dst(const struct mf_subfield *, const struct match *);

/* Parsing and formatting. */
char *mf_parse(const struct mf_field *, const char *,
               const struct ofputil_port_map *,
               union mf_value *value, union mf_value *mask);
char *mf_parse_value(const struct mf_field *, const char *,
                     const struct ofputil_port_map *, union mf_value *);
void mf_format(const struct mf_field *,
               const union mf_value *value, const union mf_value *mask,
               const struct ofputil_port_map *,
               struct ds *);
void mf_format_subvalue(const union mf_subvalue *subvalue, struct ds *s);

/* Field Arrays. */
void field_array_set(enum mf_field_id id, const union mf_value *,
                     struct field_array *);

#ifdef __cplusplus
}
#endif

#endif /* meta-flow.h */

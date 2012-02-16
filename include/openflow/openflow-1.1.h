/* Copyright (c) 2008, 2011, 2012 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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

/* OpenFlow: protocol between controller and datapath. */

#ifndef OPENFLOW_11_H
#define OPENFLOW_11_H 1

#include "openflow/openflow-common.h"

/* OpenFlow 1.1 uses 32-bit port numbers.  Open vSwitch, for now, uses OpenFlow
 * 1.0 port numbers internally.  We map them to OpenFlow 1.0 as follows:
 *
 * OF1.1                    <=>  OF1.0
 * -----------------------       ---------------
 * 0x00000000...0x0000feff  <=>  0x0000...0xfeff  "physical" ports
 * 0x0000ff00...0xfffffeff  <=>  not supported
 * 0xffffff00...0xffffffff  <=>  0xff00...0xffff  "reserved" OFPP_* ports
 *
 * OFPP11_OFFSET is the value that must be added or subtracted to convert
 * an OpenFlow 1.0 reserved port number to or from, respectively, the
 * corresponding OpenFlow 1.1 reserved port number.
 */
#define OFPP11_MAX    0xffffff00
#define OFPP11_OFFSET (OFPP11_MAX - OFPP_MAX)

/* OpenFlow 1.1 specific message types, in addition to the common message
 * types. */
enum ofp11_type {
    /* Controller command messages. */
    OFPT11_PACKET_OUT = 13,     /* Controller/switch message */
    OFPT11_FLOW_MOD,            /* Controller/switch message */
    OFPT11_GROUP_MOD,           /* Controller/switch message */
    OFPT11_PORT_MOD,            /* Controller/switch message */
    OFPT11_TABLE_MOD,           /* Controller/switch message */

    /* Statistics messages. */
    OFPT11_STATS_REQUEST,       /* Controller/switch message */
    OFPT11_STATS_REPLY,         /* Controller/switch message */

    /* Barrier messages. */
    OFPT11_BARRIER_REQUEST,     /* Controller/switch message */
    OFPT11_BARRIER_REPLY,       /* Controller/switch message */

    /* Queue Configuration messages. */
    OFPT11_QUEUE_GET_CONFIG_REQUEST,  /* Controller/switch message */
    OFPT11_QUEUE_GET_CONFIG_REPLY,    /* Controller/switch message */
};

/* OpenFlow 1.1 port config flags are just the common flags. */
#define OFPPC11_ALL \
    (OFPPC_PORT_DOWN | OFPPC_NO_RECV | OFPPC_NO_FWD | OFPPC_NO_PACKET_IN)

/* OpenFlow 1.1 specific current state of the physical port.  These are not
 * configurable from the controller.
 */
enum ofp11_port_state {
    OFPPS11_BLOCKED      = 1 << 1,  /* Port is blocked */
    OFPPS11_LIVE         = 1 << 2,  /* Live for Fast Failover Group. */
#define OFPPS11_ALL (OFPPS_LINK_DOWN | OFPPS11_BLOCKED | OFPPS11_LIVE)
};

/* OpenFlow 1.1 specific features of ports available in a datapath. */
enum ofp11_port_features {
    OFPPF11_40GB_FD    = 1 << 7,  /* 40 Gb full-duplex rate support. */
    OFPPF11_100GB_FD   = 1 << 8,  /* 100 Gb full-duplex rate support. */
    OFPPF11_1TB_FD     = 1 << 9,  /* 1 Tb full-duplex rate support. */
    OFPPF11_OTHER      = 1 << 10, /* Other rate, not in the list. */

    OFPPF11_COPPER     = 1 << 11, /* Copper medium. */
    OFPPF11_FIBER      = 1 << 12, /* Fiber medium. */
    OFPPF11_AUTONEG    = 1 << 13, /* Auto-negotiation. */
    OFPPF11_PAUSE      = 1 << 14, /* Pause. */
    OFPPF11_PAUSE_ASYM = 1 << 15  /* Asymmetric pause. */
#define OFPPF11_ALL ((1 << 16) - 1)
};

/* Description of a port */
struct ofp11_port {
    ovs_be32 port_no;
    uint8_t pad[4];
    uint8_t hw_addr[OFP_ETH_ALEN];
    uint8_t pad2[2];                  /* Align to 64 bits. */
    char name[OFP_MAX_PORT_NAME_LEN]; /* Null-terminated */

    ovs_be32 config;        /* Bitmap of OFPPC_* flags. */
    ovs_be32 state;         /* Bitmap of OFPPS_* and OFPPS11_* flags. */

    /* Bitmaps of OFPPF_* and OFPPF11_* that describe features.  All bits
     * zeroed if unsupported or unavailable. */
    ovs_be32 curr;          /* Current features. */
    ovs_be32 advertised;    /* Features being advertised by the port. */
    ovs_be32 supported;     /* Features supported by the port. */
    ovs_be32 peer;          /* Features advertised by peer. */

    ovs_be32 curr_speed;    /* Current port bitrate in kbps. */
    ovs_be32 max_speed;     /* Max port bitrate in kbps */
};

/* Modify behavior of the physical port */
struct ofp11_port_mod {
    struct ofp_header header;
    ovs_be32 port_no;
    uint8_t pad[4];
    uint8_t hw_addr[OFP_ETH_ALEN]; /* The hardware address is not
                                      configurable.  This is used to
                                      sanity-check the request, so it must
                                      be the same as returned in an
                                      ofp11_port struct. */
    uint8_t pad2[2];        /* Pad to 64 bits. */
    ovs_be32 config;        /* Bitmap of OFPPC_* flags. */
    ovs_be32 mask;          /* Bitmap of OFPPC_* flags to be changed. */

    ovs_be32 advertise;     /* Bitmap of OFPPF_* and OFPPF11_*.  Zero all bits
                               to prevent any action taking place. */
    uint8_t pad3[4];        /* Pad to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp11_port_mod) == 40);

/* OpenFlow 1.1 specific capabilities supported by the datapath (struct
 * ofp_switch_features, member capabilities). */
enum ofp11_capabilities {
    OFPC11_GROUP_STATS    = 1 << 3,  /* Group statistics. */
};

enum ofp11_action_type {
    OFPAT11_OUTPUT,           /* Output to switch port. */
    OFPAT11_SET_VLAN_VID,     /* Set the 802.1q VLAN id. */
    OFPAT11_SET_VLAN_PCP,     /* Set the 802.1q priority. */
    OFPAT11_SET_DL_SRC,       /* Ethernet source address. */
    OFPAT11_SET_DL_DST,       /* Ethernet destination address. */
    OFPAT11_SET_NW_SRC,       /* IP source address. */
    OFPAT11_SET_NW_DST,       /* IP destination address. */
    OFPAT11_SET_NW_TOS,       /* IP ToS (DSCP field, 6 bits). */
    OFPAT11_SET_NW_ECN,       /* IP ECN (2 bits). */
    OFPAT11_SET_TP_SRC,       /* TCP/UDP/SCTP source port. */
    OFPAT11_SET_TP_DST,       /* TCP/UDP/SCTP destination port. */
    OFPAT11_COPY_TTL_OUT,     /* Copy TTL "outwards" -- from next-to-outermost
                                 to outermost */
    OFPAT11_COPY_TTL_IN,      /* Copy TTL "inwards" -- from outermost to
                               next-to-outermost */
    OFPAT11_SET_MPLS_LABEL,   /* MPLS label */
    OFPAT11_SET_MPLS_TC,      /* MPLS TC */
    OFPAT11_SET_MPLS_TTL,     /* MPLS TTL */
    OFPAT11_DEC_MPLS_TTL,     /* Decrement MPLS TTL */

    OFPAT11_PUSH_VLAN,        /* Push a new VLAN tag */
    OFPAT11_POP_VLAN,         /* Pop the outer VLAN tag */
    OFPAT11_PUSH_MPLS,        /* Push a new MPLS tag */
    OFPAT11_POP_MPLS,         /* Pop the outer MPLS tag */
    OFPAT11_SET_QUEUE,        /* Set queue id when outputting to a port */
    OFPAT11_GROUP,            /* Apply group. */
    OFPAT11_SET_NW_TTL,       /* IP TTL. */
    OFPAT11_DEC_NW_TTL,       /* Decrement IP TTL. */
    OFPAT11_EXPERIMENTER = 0xffff
};

#endif /* openflow/openflow-1.1.h */

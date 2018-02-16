/*
 * Copyright (c) 2008-2017 Nicira, Inc.
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

#include <config.h>
#include "openvswitch/ofp-util.h"
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <stdlib.h>
#include "bitmap.h"
#include "bundle.h"
#include "byte-order.h"
#include "classifier.h"
#include "learn.h"
#include "multipath.h"
#include "netdev.h"
#include "nx-match.h"
#include "id-pool.h"
#include "openflow/netronome-ext.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-prop.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/type-props.h"
#include "openvswitch/vlog.h"
#include "openflow/intel-ext.h"
#include "packets.h"
#include "random.h"
#include "tun-metadata.h"
#include "unaligned.h"
#include "util.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(ofp_util);

/* Rate limit for OpenFlow message parse errors.  These always indicate a bug
 * in the peer and so there's not much point in showing a lot of them. */
static struct vlog_rate_limit bad_ofmsg_rl = VLOG_RATE_LIMIT_INIT(1, 5);

static bool
ofputil_decode_hello_bitmap(const struct ofp_hello_elem_header *oheh,
                            uint32_t *allowed_versionsp)
{
    uint16_t bitmap_len = ntohs(oheh->length) - sizeof *oheh;
    const ovs_be32 *bitmap = ALIGNED_CAST(const ovs_be32 *, oheh + 1);
    uint32_t allowed_versions;

    if (!bitmap_len || bitmap_len % sizeof *bitmap) {
        return false;
    }

    /* Only use the first 32-bit element of the bitmap as that is all the
     * current implementation supports.  Subsequent elements are ignored which
     * should have no effect on session negotiation until Open vSwitch supports
     * wire-protocol versions greater than 31.
     */
    allowed_versions = ntohl(bitmap[0]);

    if (allowed_versions & 1) {
        /* There's no OpenFlow version 0. */
        VLOG_WARN_RL(&bad_ofmsg_rl, "peer claims to support invalid OpenFlow "
                     "version 0x00");
        allowed_versions &= ~1u;
    }

    if (!allowed_versions) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "peer does not support any OpenFlow "
                     "version (between 0x01 and 0x1f)");
        return false;
    }

    *allowed_versionsp = allowed_versions;
    return true;
}

static uint32_t
version_bitmap_from_version(uint8_t ofp_version)
{
    return ((ofp_version < 32 ? 1u << ofp_version : 0) - 1) << 1;
}

/* Decodes OpenFlow OFPT_HELLO message 'oh', storing into '*allowed_versions'
 * the set of OpenFlow versions for which 'oh' announces support.
 *
 * Because of how OpenFlow defines OFPT_HELLO messages, this function is always
 * successful, and thus '*allowed_versions' is always initialized.  However, it
 * returns false if 'oh' contains some data that could not be fully understood,
 * true if 'oh' was completely parsed. */
bool
ofputil_decode_hello(const struct ofp_header *oh, uint32_t *allowed_versions)
{
    struct ofpbuf msg = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpbuf_pull(&msg, sizeof *oh);

    *allowed_versions = version_bitmap_from_version(oh->version);

    bool ok = true;
    while (msg.size) {
        const struct ofp_hello_elem_header *oheh;
        unsigned int len;

        if (msg.size < sizeof *oheh) {
            return false;
        }

        oheh = msg.data;
        len = ntohs(oheh->length);
        if (len < sizeof *oheh || !ofpbuf_try_pull(&msg, ROUND_UP(len, 8))) {
            return false;
        }

        if (oheh->type != htons(OFPHET_VERSIONBITMAP)
            || !ofputil_decode_hello_bitmap(oheh, allowed_versions)) {
            ok = false;
        }
    }

    return ok;
}

/* Returns true if 'allowed_versions' needs to be accompanied by a version
 * bitmap to be correctly expressed in an OFPT_HELLO message. */
static bool
should_send_version_bitmap(uint32_t allowed_versions)
{
    return !is_pow2((allowed_versions >> 1) + 1);
}

/* Create an OFPT_HELLO message that expresses support for the OpenFlow
 * versions in the 'allowed_versions' bitmaps and returns the message. */
struct ofpbuf *
ofputil_encode_hello(uint32_t allowed_versions)
{
    enum ofp_version ofp_version;
    struct ofpbuf *msg;

    ofp_version = leftmost_1bit_idx(allowed_versions);
    msg = ofpraw_alloc(OFPRAW_OFPT_HELLO, ofp_version, 0);

    if (should_send_version_bitmap(allowed_versions)) {
        struct ofp_hello_elem_header *oheh;
        uint16_t map_len;

        map_len = sizeof allowed_versions;
        oheh = ofpbuf_put_zeros(msg, ROUND_UP(map_len + sizeof *oheh, 8));
        oheh->type = htons(OFPHET_VERSIONBITMAP);
        oheh->length = htons(map_len + sizeof *oheh);
        *ALIGNED_CAST(ovs_be32 *, oheh + 1) = htonl(allowed_versions);

        ofpmsg_update_length(msg);
    }

    return msg;
}

void
ofputil_hello_format(struct ds *string, const struct ofp_header *oh)
{
    uint32_t allowed_versions;
    bool ok;

    ok = ofputil_decode_hello(oh, &allowed_versions);

    ds_put_cstr(string, "\n version bitmap: ");
    ofputil_format_version_bitmap(string, allowed_versions);

    if (!ok) {
        ds_put_cstr(string, "\n unknown data in hello:\n");
        ds_put_hex_dump(string, oh, ntohs(oh->length), 0, true);
    }
}

/* Creates and returns an OFPT_ECHO_REQUEST message with an empty payload. */
struct ofpbuf *
ofputil_encode_echo_request(enum ofp_version ofp_version)
{
    return ofpraw_alloc_xid(OFPRAW_OFPT_ECHO_REQUEST, ofp_version,
                            htonl(0), 0);
}

/* Creates and returns an OFPT_ECHO_REPLY message matching the
 * OFPT_ECHO_REQUEST message in 'rq'. */
struct ofpbuf *
ofputil_encode_echo_reply(const struct ofp_header *rq)
{
    struct ofpbuf rq_buf = ofpbuf_const_initializer(rq, ntohs(rq->length));
    ofpraw_pull_assert(&rq_buf);

    struct ofpbuf *reply = ofpraw_alloc_reply(OFPRAW_OFPT_ECHO_REPLY,
                                              rq, rq_buf.size);
    ofpbuf_put(reply, rq_buf.data, rq_buf.size);
    return reply;
}

struct ofpbuf *
ofputil_encode_barrier_request(enum ofp_version ofp_version)
{
    enum ofpraw type;

    switch (ofp_version) {
    case OFP16_VERSION:
    case OFP15_VERSION:
    case OFP14_VERSION:
    case OFP13_VERSION:
    case OFP12_VERSION:
    case OFP11_VERSION:
        type = OFPRAW_OFPT11_BARRIER_REQUEST;
        break;

    case OFP10_VERSION:
        type = OFPRAW_OFPT10_BARRIER_REQUEST;
        break;

    default:
        OVS_NOT_REACHED();
    }

    return ofpraw_alloc(type, ofp_version, 0);
}

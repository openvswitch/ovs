/*
 * Copyright (c) 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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
#include "byte-order.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "ovs-thread.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ofp_msgs);

#define OFPT_VENDOR 4
#define OFPT10_STATS_REQUEST 16
#define OFPT10_STATS_REPLY 17
#define OFPT11_STATS_REQUEST 18
#define OFPT11_STATS_REPLY 19
#define OFPST_VENDOR 0xffff

/* Vendor extension message. */
struct ofp_vendor_header {
    struct ofp_header header;   /* OFPT_VENDOR. */
    ovs_be32 vendor;            /* Vendor ID:
                                 * - MSB 0: low-order bytes are IEEE OUI.
                                 * - MSB != 0: defined by OpenFlow
                                 *   consortium. */

    /* In theory everything after 'vendor' is vendor specific.  In practice,
     * the vendors we support put a 32-bit subtype here.  We'll change this
     * structure if we start adding support for other vendor formats. */
    ovs_be32 subtype;           /* Vendor-specific subtype. */

    /* Followed by vendor-defined additional data. */
};
OFP_ASSERT(sizeof(struct ofp_vendor_header) == 16);

/* Statistics request or reply message. */
struct ofp10_stats_msg {
    struct ofp_header header;
    ovs_be16 type;              /* One of the OFPST_* constants. */
    ovs_be16 flags;             /* Requests: always 0.
                                 * Replies: 0 or OFPSF_REPLY_MORE. */
};
OFP_ASSERT(sizeof(struct ofp10_stats_msg) == 12);

/* Vendor extension stats message. */
struct ofp10_vendor_stats_msg {
    struct ofp10_stats_msg osm; /* Type OFPST_VENDOR. */
    ovs_be32 vendor;            /* Vendor ID:
                                 * - MSB 0: low-order bytes are IEEE OUI.
                                 * - MSB != 0: defined by OpenFlow
                                 *   consortium. */
    /* Followed by vendor-defined arbitrary additional data. */
};
OFP_ASSERT(sizeof(struct ofp10_vendor_stats_msg) == 16);

struct ofp11_stats_msg {
    struct ofp_header header;
    ovs_be16 type;              /* One of the OFPST_* constants. */
    ovs_be16 flags;             /* OFPSF_REQ_* flags (none yet defined). */
    uint8_t pad[4];
    /* Followed by the body of the request. */
};
OFP_ASSERT(sizeof(struct ofp11_stats_msg) == 16);

/* Vendor extension stats message. */
struct ofp11_vendor_stats_msg {
    struct ofp11_stats_msg osm; /* Type OFPST_VENDOR. */
    ovs_be32 vendor;            /* Vendor ID:
                                 * - MSB 0: low-order bytes are IEEE OUI.
                                 * - MSB != 0: defined by OpenFlow
                                 *   consortium. */

    /* In theory everything after 'vendor' is vendor specific.  In practice,
     * the vendors we support put a 32-bit subtype here.  We'll change this
     * structure if we start adding support for other vendor formats. */
    ovs_be32 subtype;           /* Vendor-specific subtype. */

    /* Followed by vendor-defined additional data. */
};
OFP_ASSERT(sizeof(struct ofp11_vendor_stats_msg) == 24);

/* Header for Nicira vendor stats request and reply messages in OpenFlow
 * 1.0. */
struct nicira10_stats_msg {
    struct ofp10_vendor_stats_msg vsm; /* Vendor NX_VENDOR_ID. */
    ovs_be32 subtype;           /* One of NXST_* below. */
    uint8_t pad[4];             /* Align to 64-bits. */
};
OFP_ASSERT(sizeof(struct nicira10_stats_msg) == 24);

/* A thin abstraction of OpenFlow headers:
 *
 *   - 'version' and 'type' come straight from struct ofp_header, so these are
 *     always present and meaningful.
 *
 *   - 'stat' comes from the 'type' member in statistics messages only.  It is
 *     meaningful, therefore, only if 'version' and 'type' taken together
 *     specify a statistics request or reply.  Otherwise it is 0.
 *
 *   - 'vendor' is meaningful only for vendor messages, that is, if 'version'
 *     and 'type' specify a vendor message or if 'version' and 'type' specify
 *     a statistics message and 'stat' specifies a vendor statistic type.
 *     Otherwise it is 0.
 *
 *   - 'subtype' is meaningful only for vendor messages and otherwise 0.  It
 *     specifies a vendor-defined subtype.  There is no standard format for
 *     these but 32 bits seems like it should be enough. */
struct ofphdrs {
    uint8_t version;            /* From ofp_header. */
    uint8_t type;               /* From ofp_header. */
    uint16_t stat;              /* From ofp10_stats_msg or ofp11_stats_msg. */
    uint32_t vendor;            /* From ofp_vendor_header,
                                 * ofp10_vendor_stats_msg, or
                                 * ofp11_vendor_stats_msg. */
    uint32_t subtype;           /* From nicira_header, nicira10_stats_msg, or
                                 * nicira11_stats_msg. */
};
BUILD_ASSERT_DECL(sizeof(struct ofphdrs) == 12);

/* A mapping from OpenFlow headers to OFPRAW_*.  */
struct raw_instance {
    struct hmap_node hmap_node; /* In 'raw_instance_map'. */
    struct ofphdrs hdrs;        /* Key. */
    enum ofpraw raw;            /* Value. */
    unsigned int hdrs_len;      /* ofphdrs_len(hdrs). */
};

/* Information about a particular 'enum ofpraw'. */
struct raw_info {
    /* All possible instantiations of this OFPRAW_* into OpenFlow headers. */
    struct raw_instance *instances; /* min_version - max_version + 1 elems. */
    uint8_t min_version;
    uint8_t max_version;

    unsigned int min_body;
    unsigned int extra_multiple;
    enum ofptype type;
    const char *name;
};

/* All understood OpenFlow message types, indexed by their 'struct ofphdrs'. */
static struct hmap raw_instance_map;
#include "ofp-msgs.inc"

static ovs_be32 alloc_xid(void);

/* ofphdrs functions. */
static uint32_t ofphdrs_hash(const struct ofphdrs *);
static bool ofphdrs_equal(const struct ofphdrs *a, const struct ofphdrs *b);
static enum ofperr ofphdrs_decode(struct ofphdrs *,
                                  const struct ofp_header *oh, size_t length);
static void ofphdrs_decode_assert(struct ofphdrs *,
                                  const struct ofp_header *oh, size_t length);
size_t ofphdrs_len(const struct ofphdrs *);

static const struct raw_info *raw_info_get(enum ofpraw);
static struct raw_instance *raw_instance_get(const struct raw_info *,
                                             uint8_t version);

static enum ofperr ofpraw_from_ofphdrs(enum ofpraw *, const struct ofphdrs *);

/* Returns a transaction ID to use for an outgoing OpenFlow message. */
static ovs_be32
alloc_xid(void)
{
    static atomic_count next_xid = ATOMIC_COUNT_INIT(1);

    return htonl(atomic_count_inc(&next_xid));
}

static uint32_t
ofphdrs_hash(const struct ofphdrs *hdrs)
{
    BUILD_ASSERT_DECL(sizeof *hdrs % 4 == 0);
    return hash_bytes32((const uint32_t *) hdrs, sizeof *hdrs, 0);
}

static bool
ofphdrs_equal(const struct ofphdrs *a, const struct ofphdrs *b)
{
    return !memcmp(a, b, sizeof *a);
}

static void
log_bad_vendor(uint32_t vendor)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

    VLOG_WARN_RL(&rl, "OpenFlow message has unknown vendor %#"PRIx32, vendor);
}

static enum ofperr
ofphdrs_decode(struct ofphdrs *hdrs,
               const struct ofp_header *oh, size_t length)
{
    memset(hdrs, 0, sizeof *hdrs);
    if (length < sizeof *oh) {
        return OFPERR_OFPBRC_BAD_LEN;
    }

    /* Get base message version and type (OFPT_*). */
    hdrs->version = oh->version;
    hdrs->type = oh->type;

    if (hdrs->type == OFPT_VENDOR) {
        /* Get vendor. */
        const struct ofp_vendor_header *ovh;

        if (length < sizeof *ovh) {
            return OFPERR_OFPBRC_BAD_LEN;
        }

        ovh = (const struct ofp_vendor_header *) oh;
        hdrs->vendor = ntohl(ovh->vendor);
        if (hdrs->vendor == NX_VENDOR_ID || hdrs->vendor == ONF_VENDOR_ID) {
            hdrs->subtype = ntohl(ovh->subtype);
        } else {
            log_bad_vendor(hdrs->vendor);
            return OFPERR_OFPBRC_BAD_VENDOR;
        }
    } else if (hdrs->version == OFP10_VERSION
               && (hdrs->type == OFPT10_STATS_REQUEST ||
                   hdrs->type == OFPT10_STATS_REPLY)) {
        const struct ofp10_stats_msg *osm;

        /* Get statistic type (OFPST_*). */
        if (length < sizeof *osm) {
            return OFPERR_OFPBRC_BAD_LEN;
        }
        osm = (const struct ofp10_stats_msg *) oh;
        hdrs->stat = ntohs(osm->type);

        if (hdrs->stat == OFPST_VENDOR) {
            /* Get vendor. */
            const struct ofp10_vendor_stats_msg *ovsm;

            if (length < sizeof *ovsm) {
                return OFPERR_OFPBRC_BAD_LEN;
            }

            ovsm = (const struct ofp10_vendor_stats_msg *) oh;
            hdrs->vendor = ntohl(ovsm->vendor);
            if (hdrs->vendor == NX_VENDOR_ID) {
                /* Get Nicira statistic type (NXST_*). */
                const struct nicira10_stats_msg *nsm;

                if (length < sizeof *nsm) {
                    return OFPERR_OFPBRC_BAD_LEN;
                }
                nsm = (const struct nicira10_stats_msg *) oh;
                hdrs->subtype = ntohl(nsm->subtype);
            } else {
                log_bad_vendor(hdrs->vendor);
                return OFPERR_OFPBRC_BAD_VENDOR;
            }
        }
    } else if (hdrs->version != OFP10_VERSION
               && (hdrs->type == OFPT11_STATS_REQUEST ||
                   hdrs->type == OFPT11_STATS_REPLY)) {
        const struct ofp11_stats_msg *osm;

        /* Get statistic type (OFPST_*). */
        if (length < sizeof *osm) {
            return OFPERR_OFPBRC_BAD_LEN;
        }
        osm = (const struct ofp11_stats_msg *) oh;
        hdrs->stat = ntohs(osm->type);

        if (hdrs->stat == OFPST_VENDOR) {
            /* Get vendor. */
            const struct ofp11_vendor_stats_msg *ovsm;

            if (length < sizeof *ovsm) {
                return OFPERR_OFPBRC_BAD_LEN;
            }

            ovsm = (const struct ofp11_vendor_stats_msg *) oh;
            hdrs->vendor = ntohl(ovsm->vendor);
            if (hdrs->vendor == NX_VENDOR_ID ||
                hdrs->vendor == ONF_VENDOR_ID) {
                hdrs->subtype = ntohl(ovsm->subtype);
            } else {
                log_bad_vendor(hdrs->vendor);
                return OFPERR_OFPBRC_BAD_VENDOR;
            }
        }
    }

    return 0;
}

static void
ofphdrs_decode_assert(struct ofphdrs *hdrs,
                      const struct ofp_header *oh, size_t length)
{
    ovs_assert(!ofphdrs_decode(hdrs, oh, length));
}

static bool
ofp_is_stat_request(enum ofp_version version, uint8_t type)
{
    switch (version) {
    case OFP10_VERSION:
        return type == OFPT10_STATS_REQUEST;
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
        return type == OFPT11_STATS_REQUEST;
    }

    return false;
}

static bool
ofp_is_stat_reply(enum ofp_version version, uint8_t type)
{
    switch (version) {
    case OFP10_VERSION:
        return type == OFPT10_STATS_REPLY;
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
        return type == OFPT11_STATS_REPLY;
    }

    return false;
}

static bool
ofp_is_stat(enum ofp_version version, uint8_t type)
{
    return (ofp_is_stat_request(version, type) ||
            ofp_is_stat_reply(version, type));
}

static bool
ofphdrs_is_stat(const struct ofphdrs *hdrs)
{
    return ofp_is_stat(hdrs->version, hdrs->type);
}

size_t
ofphdrs_len(const struct ofphdrs *hdrs)
{
    if (hdrs->type == OFPT_VENDOR) {
        return sizeof(struct ofp_vendor_header);
    }

    switch ((enum ofp_version) hdrs->version) {
    case OFP10_VERSION:
        if (hdrs->type == OFPT10_STATS_REQUEST ||
            hdrs->type == OFPT10_STATS_REPLY) {
            return (hdrs->stat == OFPST_VENDOR
                    ? sizeof(struct nicira10_stats_msg)
                    : sizeof(struct ofp10_stats_msg));
        }
        break;

    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
        if (hdrs->type == OFPT11_STATS_REQUEST ||
            hdrs->type == OFPT11_STATS_REPLY) {
            return (hdrs->stat == OFPST_VENDOR
                    ? sizeof(struct ofp11_vendor_stats_msg)
                    : sizeof(struct ofp11_stats_msg));
        }
        break;
    }

    return sizeof(struct ofp_header);
}

/* Determines the OFPRAW_* type of the OpenFlow message at 'oh', which has
 * length 'oh->length'.  (The caller must ensure that 'oh->length' bytes of
 * data are readable at 'oh'.)  On success, returns 0 and stores the type into
 * '*raw'.  On failure, returns an OFPERR_* error code and zeros '*raw'.
 *
 * This function checks that 'oh' is a valid length for its particular type of
 * message, and returns an error if not. */
enum ofperr
ofpraw_decode(enum ofpraw *raw, const struct ofp_header *oh)
{
    struct ofpbuf msg = ofpbuf_const_initializer(oh, ntohs(oh->length));
    return ofpraw_pull(raw, &msg);
}

/* Does the same job as ofpraw_decode(), except that it assert-fails if
 * ofpraw_decode() would have reported an error.  Thus, it's able to use the
 * return value for the OFPRAW_* message type instead of an error code.
 *
 * (It only makes sense to use this function if you previously called
 * ofpraw_decode() on the message and thus know that it's OK.) */
enum ofpraw
ofpraw_decode_assert(const struct ofp_header *oh)
{
    enum ofpraw raw;
    ovs_assert(!ofpraw_decode(&raw, oh));
    return raw;
}

/* Checks that 'len' is a valid length for an OpenFlow message that corresponds
 * to 'info' and 'instance'.  Returns 0 if so, otherwise an OpenFlow error. */
static enum ofperr
ofpraw_check_length(const struct raw_info *info,
                    const struct raw_instance *instance,
                    unsigned int len)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    unsigned int min_len = instance->hdrs_len + info->min_body;
    switch (info->extra_multiple) {
    case 0:
        if (len != min_len) {
            VLOG_WARN_RL(&rl, "received %s with incorrect length %u (expected "
                         "length %u)", info->name, len, min_len);
            return OFPERR_OFPBRC_BAD_LEN;
        }
        break;

    case 1:
        if (len < min_len) {
            VLOG_WARN_RL(&rl, "received %s with incorrect length %u (expected "
                         "length at least %u bytes)",
                         info->name, len, min_len);
            return OFPERR_OFPBRC_BAD_LEN;
        }
        break;

    default:
        if (len < min_len || (len - min_len) % info->extra_multiple) {
            VLOG_WARN_RL(&rl, "received %s with incorrect length %u (must be "
                         "exactly %u bytes or longer by an integer multiple "
                         "of %u bytes)",
                         info->name, len, min_len, info->extra_multiple);
            return OFPERR_OFPBRC_BAD_LEN;
        }
        break;
    }

    return 0;
}

/* Determines the OFPRAW_* type of the OpenFlow message in 'msg', which starts
 * at 'msg->data' and has length 'msg->size' bytes.  On success,
 * returns 0 and stores the type into '*rawp'.  On failure, returns an OFPERR_*
 * error code and zeros '*rawp'.
 *
 * This function checks that the message has a valid length for its particular
 * type of message, and returns an error if not.
 *
 * In addition to setting '*rawp', this function pulls off the OpenFlow header
 * (including the stats headers, vendor header, and any subtype header) with
 * ofpbuf_pull().  It also sets 'msg->header' to the start of the OpenFlow
 * header and 'msg->msg' just beyond the headers (that is, to the final value
 * of msg->data). */
enum ofperr
ofpraw_pull(enum ofpraw *rawp, struct ofpbuf *msg)
{
    /* Set default outputs. */
    msg->header = msg->data;
    msg->msg = msg->header;
    *rawp = 0;

    struct ofphdrs hdrs;
    enum ofperr error = ofphdrs_decode(&hdrs, msg->data, msg->size);
    if (error) {
        return error;
    }

    enum ofpraw raw;
    error = ofpraw_from_ofphdrs(&raw, &hdrs);
    if (error) {
        return error;
    }

    const struct raw_info *info = raw_info_get(raw);
    const struct raw_instance *instance = raw_instance_get(info, hdrs.version);
    error = ofpraw_check_length(info, instance, msg->size);
    if (error) {
        return error;
    }

    msg->header = ofpbuf_pull(msg, instance->hdrs_len);
    msg->msg = msg->data;
    *rawp = raw;
    return 0;
}

/* Does the same job as ofpraw_pull(), except that it assert-fails if
 * ofpraw_pull() would have reported an error.  Thus, it's able to use the
 * return value for the OFPRAW_* message type instead of an error code.
 *
 * (It only makes sense to use this function if you previously called
 * ofpraw_decode() on the message and thus know that it's OK.) */
enum ofpraw
ofpraw_pull_assert(struct ofpbuf *msg)
{
    enum ofpraw raw;
    ovs_assert(!ofpraw_pull(&raw, msg));
    return raw;
}

/* Determines the OFPRAW_* type of the OpenFlow message that starts at 'oh' and
 * has length 'length' bytes.  On success, returns 0 and stores the type into
 * '*rawp'.  On failure, returns an OFPERR_* error code and zeros '*rawp'.
 *
 * Unlike other functions for decoding message types, this one is not picky
 * about message length.  For example, it will successfully decode a message
 * whose body is shorter than the minimum length for a message of its type.
 * Thus, this is the correct function to use for decoding the type of a message
 * that might have been truncated, such as the payload of an OpenFlow error
 * message (which is allowed to be truncated to 64 bytes). */
enum ofperr
ofpraw_decode_partial(enum ofpraw *raw,
                      const struct ofp_header *oh, size_t length)
{
    struct ofphdrs hdrs;
    enum ofperr error;

    error = ofphdrs_decode(&hdrs, oh, length);
    if (!error) {
        error = ofpraw_from_ofphdrs(raw, &hdrs);
    }

    if (error) {
        *raw = 0;
    }
    return error;
}

/* Encoding messages using OFPRAW_* values. */

static void ofpraw_put__(enum ofpraw, uint8_t version, ovs_be32 xid,
                         size_t extra_tailroom, struct ofpbuf *);

/* Allocates and returns a new ofpbuf that contains an OpenFlow header for
 * 'raw' with OpenFlow version 'version' and a fresh OpenFlow transaction ID.
 * The ofpbuf has enough tailroom for the minimum body length of 'raw', plus
 * 'extra_tailroom' additional bytes.
 *
 * Each 'raw' value is valid only for certain OpenFlow versions.  The caller
 * must specify a valid (raw, version) pair.
 *
 * In the returned ofpbuf, 'header' points to the beginning of the
 * OpenFlow header and 'msg' points just after it, to where the
 * message's body will start.  The caller must actually allocate the
 * body into the space reserved for it, e.g. with ofpbuf_put_uninit().
 *
 * The caller owns the returned ofpbuf and must free it when it is no longer
 * needed, e.g. with ofpbuf_delete(). */
struct ofpbuf *
ofpraw_alloc(enum ofpraw raw, uint8_t version, size_t extra_tailroom)
{
    return ofpraw_alloc_xid(raw, version, alloc_xid(), extra_tailroom);
}

/* Same as ofpraw_alloc() but the caller provides the transaction ID. */
struct ofpbuf *
ofpraw_alloc_xid(enum ofpraw raw, uint8_t version, ovs_be32 xid,
                 size_t extra_tailroom)
{
    struct ofpbuf *buf = ofpbuf_new(0);
    ofpraw_put__(raw, version, xid, extra_tailroom, buf);
    return buf;
}

/* Same as ofpraw_alloc(), but obtains the OpenFlow version and transaction ID
 * from 'request->version' and 'request->xid', respectively.
 *
 * Even though the version comes from 'request->version', the caller must still
 * know what it is doing, by specifying a valid pairing of 'raw' and
 * 'request->version', just like ofpraw_alloc(). */
struct ofpbuf *
ofpraw_alloc_reply(enum ofpraw raw, const struct ofp_header *request,
                   size_t extra_tailroom)
{
    return ofpraw_alloc_xid(raw, request->version, request->xid,
                            extra_tailroom);
}

/* Allocates and returns a new ofpbuf that contains an OpenFlow header that is
 * a stats reply to the stats request in 'request', using the same OpenFlow
 * version and transaction ID as 'request'.  The ofpbuf has enough tailroom for
 * the stats reply's minimum body length, plus 'extra_tailroom' additional
 * bytes.
 *
 * 'request' must be a stats request, that is, an OFPRAW_OFPST* or OFPRAW_NXST*
 * value.  Every stats request has a corresponding reply, so the (raw, version)
 * pairing pitfalls of the other ofpraw_alloc_*() functions don't apply here.
 *
 * In the returned ofpbuf, 'header' points to the beginning of the
 * OpenFlow header and 'msg' points just after it, to where the
 * message's body will start.  The caller must actually allocate the
 * body into the space reserved for it, e.g. with ofpbuf_put_uninit().
 *
 * The caller owns the returned ofpbuf and must free it when it is no longer
 * needed, e.g. with ofpbuf_delete(). */
struct ofpbuf *
ofpraw_alloc_stats_reply(const struct ofp_header *request,
                         size_t extra_tailroom)
{
    enum ofpraw request_raw;
    enum ofpraw reply_raw;

    ovs_assert(!ofpraw_decode_partial(&request_raw, request,
                                      ntohs(request->length)));

    reply_raw = ofpraw_stats_request_to_reply(request_raw, request->version);
    ovs_assert(reply_raw);

    return ofpraw_alloc_reply(reply_raw, request, extra_tailroom);
}

/* Appends to 'buf' an OpenFlow header for 'raw' with OpenFlow version
 * 'version' and a fresh OpenFlow transaction ID.  Preallocates enough tailroom
 * in 'buf' for the minimum body length of 'raw', plus 'extra_tailroom'
 * additional bytes.
 *
 * Each 'raw' value is valid only for certain OpenFlow versions.  The caller
 * must specify a valid (raw, version) pair.
 *
 * Upon return, 'buf->header' points to the beginning of the OpenFlow header
 * and 'buf->msg' points just after it, to where the message's body will start.
 * The caller must actually allocating the body into the space reserved for it,
 * e.g. with ofpbuf_put_uninit(). */
void
ofpraw_put(enum ofpraw raw, uint8_t version, struct ofpbuf *buf)
{
    ofpraw_put__(raw, version, alloc_xid(), 0, buf);
}

/* Same as ofpraw_put() but the caller provides the transaction ID. */
void
ofpraw_put_xid(enum ofpraw raw, uint8_t version, ovs_be32 xid,
               struct ofpbuf *buf)
{
    ofpraw_put__(raw, version, xid, 0, buf);
}

/* Same as ofpraw_put(), but obtains the OpenFlow version and transaction ID
 * from 'request->version' and 'request->xid', respectively.
 *
 * Even though the version comes from 'request->version', the caller must still
 * know what it is doing, by specifying a valid pairing of 'raw' and
 * 'request->version', just like ofpraw_put(). */
void
ofpraw_put_reply(enum ofpraw raw, const struct ofp_header *request,
                 struct ofpbuf *buf)
{
    ofpraw_put__(raw, request->version, request->xid, 0, buf);
}

/* Appends to 'buf' an OpenFlow header that is a stats reply to the stats
 * request in 'request', using the same OpenFlow version and transaction ID as
 * 'request'.  Preallocate enough tailroom in 'buf for the stats reply's
 * minimum body length, plus 'extra_tailroom' additional bytes.
 *
 * 'request' must be a stats request, that is, an OFPRAW_OFPST* or OFPRAW_NXST*
 * value.  Every stats request has a corresponding reply, so the (raw, version)
 * pairing pitfalls of the other ofpraw_alloc_*() functions don't apply here.
 *
 * In the returned ofpbuf, 'header' points to the beginning of the
 * OpenFlow header and 'msg' points just after it, to where the
 * message's body will start.  The caller must actually allocate the
 * body into the space reserved for it, e.g. with ofpbuf_put_uninit().
 *
 * The caller owns the returned ofpbuf and must free it when it is no longer
 * needed, e.g. with ofpbuf_delete(). */
void
ofpraw_put_stats_reply(const struct ofp_header *request, struct ofpbuf *buf)
{
    enum ofpraw raw;

    ovs_assert(!ofpraw_decode_partial(&raw, request, ntohs(request->length)));

    raw = ofpraw_stats_request_to_reply(raw, request->version);
    ovs_assert(raw);

    ofpraw_put__(raw, request->version, request->xid, 0, buf);
}

static void
ofpraw_put__(enum ofpraw raw, uint8_t version, ovs_be32 xid,
             size_t extra_tailroom, struct ofpbuf *buf)
{
    const struct raw_info *info = raw_info_get(raw);
    const struct raw_instance *instance = raw_instance_get(info, version);
    const struct ofphdrs *hdrs = &instance->hdrs;
    struct ofp_header *oh;

    ofpbuf_prealloc_tailroom(buf, (instance->hdrs_len + info->min_body
                                   + extra_tailroom));
    buf->header = ofpbuf_put_uninit(buf, instance->hdrs_len);
    buf->msg = ofpbuf_tail(buf);

    oh = buf->header;
    oh->version = version;
    oh->type = hdrs->type;
    oh->length = htons(buf->size);
    oh->xid = xid;

    if (hdrs->type == OFPT_VENDOR) {
        struct ofp_vendor_header *ovh = buf->header;

        ovh->vendor = htonl(hdrs->vendor);
        ovh->subtype = htonl(hdrs->subtype);
    } else if (version == OFP10_VERSION
               && (hdrs->type == OFPT10_STATS_REQUEST ||
                   hdrs->type == OFPT10_STATS_REPLY)) {
        struct ofp10_stats_msg *osm = buf->header;

        osm->type = htons(hdrs->stat);
        osm->flags = htons(0);

        if (hdrs->stat == OFPST_VENDOR) {
            struct ofp10_vendor_stats_msg *ovsm = buf->header;

            ovsm->vendor = htonl(hdrs->vendor);
            if (hdrs->vendor == NX_VENDOR_ID) {
                struct nicira10_stats_msg *nsm = buf->header;

                nsm->subtype = htonl(hdrs->subtype);
                memset(nsm->pad, 0, sizeof nsm->pad);
            } else {
                OVS_NOT_REACHED();
            }
        }
    } else if (version != OFP10_VERSION
               && (hdrs->type == OFPT11_STATS_REQUEST ||
                   hdrs->type == OFPT11_STATS_REPLY)) {
        struct ofp11_stats_msg *osm = buf->header;

        osm->type = htons(hdrs->stat);
        osm->flags = htons(0);
        memset(osm->pad, 0, sizeof osm->pad);

        if (hdrs->stat == OFPST_VENDOR) {
            struct ofp11_vendor_stats_msg *ovsm = buf->header;

            ovsm->vendor = htonl(hdrs->vendor);
            ovsm->subtype = htonl(hdrs->subtype);
        }
    }
}

/* Returns 'raw''s name.
 *
 * The name is the name used for 'raw' in the OpenFlow specification.  For
 * example, ofpraw_get_name(OFPRAW_OFPT10_FEATURES_REPLY) is
 * "OFPT_FEATURES_REPLY".
 *
 * The caller must not modify or free the returned string. */
const char *
ofpraw_get_name(enum ofpraw raw)
{
    return raw_info_get(raw)->name;
}

/* Returns the stats reply that corresponds to 'raw' in the given OpenFlow
 * 'version'. */
enum ofpraw
ofpraw_stats_request_to_reply(enum ofpraw raw, uint8_t version)
{
    const struct raw_info *info = raw_info_get(raw);
    const struct raw_instance *instance = raw_instance_get(info, version);
    enum ofpraw reply_raw;
    struct ofphdrs hdrs;

    hdrs = instance->hdrs;
    switch ((enum ofp_version)hdrs.version) {
    case OFP10_VERSION:
        ovs_assert(hdrs.type == OFPT10_STATS_REQUEST);
        hdrs.type = OFPT10_STATS_REPLY;
        break;
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
        ovs_assert(hdrs.type == OFPT11_STATS_REQUEST);
        hdrs.type = OFPT11_STATS_REPLY;
        break;
    default:
        OVS_NOT_REACHED();
    }

    ovs_assert(!ofpraw_from_ofphdrs(&reply_raw, &hdrs));

    return reply_raw;
}

/* Determines the OFPTYPE_* type of the OpenFlow message at 'oh', which has
 * length 'oh->length'.  (The caller must ensure that 'oh->length' bytes of
 * data are readable at 'oh'.)  On success, returns 0 and stores the type into
 * '*typep'.  On failure, returns an OFPERR_* error code and zeros '*typep'.
 *
 * This function checks that 'oh' is a valid length for its particular type of
 * message, and returns an error if not. */
enum ofperr
ofptype_decode(enum ofptype *typep, const struct ofp_header *oh)
{
    enum ofperr error;
    enum ofpraw raw;

    error = ofpraw_decode(&raw, oh);
    *typep = error ? 0 : ofptype_from_ofpraw(raw);
    return error;
}

/* Determines the OFPTYPE_* type of the OpenFlow message in 'msg', which starts
 * at 'msg->data' and has length 'msg->size' bytes.  On success,
 * returns 0 and stores the type into '*typep'.  On failure, returns an
 * OFPERR_* error code and zeros '*typep'.
 *
 * This function checks that the message has a valid length for its particular
 * type of message, and returns an error if not.
 *
 * In addition to setting '*typep', this function pulls off the OpenFlow header
 * (including the stats headers, vendor header, and any subtype header) with
 * ofpbuf_pull().  It also sets 'msg->header' to the start of the OpenFlow
 * header and 'msg->msg' just beyond the headers (that is, to the final value
 * of msg->data). */
enum ofperr
ofptype_pull(enum ofptype *typep, struct ofpbuf *buf)
{
    enum ofperr error;
    enum ofpraw raw;

    error = ofpraw_pull(&raw, buf);
    *typep = error ? 0 : ofptype_from_ofpraw(raw);
    return error;
}

/* Returns the OFPTYPE_* type that corresponds to 'raw'.
 *
 * (This is a one-way trip, because the mapping from ofpraw to ofptype is
 * many-to-one.)  */
enum ofptype
ofptype_from_ofpraw(enum ofpraw raw)
{
    return raw_info_get(raw)->type;
}

const char *
ofptype_get_name(enum ofptype type)
{
    ovs_assert(type < ARRAY_SIZE(type_names));
    return type_names[type];
}

/* Updates the 'length' field of the OpenFlow message in 'buf' to
 * 'buf->size'. */
void
ofpmsg_update_length(struct ofpbuf *buf)
{
    struct ofp_header *oh = ofpbuf_at_assert(buf, 0, sizeof *oh);
    oh->length = htons(buf->size);
}

/* Returns just past the OpenFlow header (including the stats headers, vendor
 * header, and any subtype header) in 'oh'. */
const void *
ofpmsg_body(const struct ofp_header *oh)
{
    struct ofphdrs hdrs;

    ofphdrs_decode_assert(&hdrs, oh, ntohs(oh->length));
    return (const uint8_t *) oh + ofphdrs_len(&hdrs);
}

/* Return if 'oh' is a stat/multipart (OFPST) request message. */
bool
ofpmsg_is_stat_request(const struct ofp_header *oh)
{
    return ofp_is_stat_request(oh->version, oh->type);
}

/* Return if 'oh' is a stat/multipart (OFPST) reply message. */
bool
ofpmsg_is_stat_reply(const struct ofp_header *oh)
{
    return ofp_is_stat_reply(oh->version, oh->type);
}

/* Return if 'oh' is a stat/multipart (OFPST) request or reply message. */
bool
ofpmsg_is_stat(const struct ofp_header *oh)
{
    return ofp_is_stat(oh->version, oh->type);
}

static ovs_be16 *ofpmp_flags__(const struct ofp_header *);

/* Initializes 'replies' as a new list of stats messages that reply to
 * 'request', which must be a stats request message.  Initially the list will
 * consist of only a single reply part without any body.  The caller should
 * use calls to the other ofpmp_*() functions to add to the body and split the
 * message into multiple parts, if necessary. */
void
ofpmp_init(struct ovs_list *replies, const struct ofp_header *request)
{
    struct ofpbuf *msg;

    ovs_list_init(replies);

    msg = ofpraw_alloc_stats_reply(request, 1000);
    ovs_list_push_back(replies, &msg->list_node);
}

/* Prepares to append up to 'len' bytes to the series of statistics replies in
 * 'replies', which should have been initialized with ofpmp_init(), if
 * necessary adding a new reply to the list.
 *
 * Returns an ofpbuf with at least 'len' bytes of tailroom.  The 'len' bytes
 * have not actually been allocated, so the caller must do so with
 * e.g. ofpbuf_put_uninit(). */
struct ofpbuf *
ofpmp_reserve(struct ovs_list *replies, size_t len)
{
    struct ofpbuf *msg = ofpbuf_from_list(ovs_list_back(replies));

    if (msg->size + len <= UINT16_MAX) {
        ofpbuf_prealloc_tailroom(msg, len);
        return msg;
    } else {
        unsigned int hdrs_len;
        struct ofpbuf *next;
        struct ofphdrs hdrs;

        ofphdrs_decode_assert(&hdrs, msg->data, msg->size);
        hdrs_len = ofphdrs_len(&hdrs);

        next = ofpbuf_new(MAX(1024, hdrs_len + len));
        ofpbuf_put(next, msg->data, hdrs_len);
        next->header = next->data;
        next->msg = ofpbuf_tail(next);
        ovs_list_push_back(replies, &next->list_node);

        *ofpmp_flags__(msg->data) |= htons(OFPSF_REPLY_MORE);

        return next;
    }
}

/* Appends 'len' bytes to the series of statistics replies in 'replies', and
 * returns the first byte. */
void *
ofpmp_append(struct ovs_list *replies, size_t len)
{
    return ofpbuf_put_uninit(ofpmp_reserve(replies, len), len);
}

/* Sometimes, when composing stats replies, it's difficult to predict how long
 * an individual reply chunk will be before actually encoding it into the reply
 * buffer.  This function allows easy handling of this case: just encode the
 * reply, then use this function to break the message into two pieces if it
 * exceeds the OpenFlow message limit.
 *
 * In detail, if the final stats message in 'replies' is too long for OpenFlow,
 * this function breaks it into two separate stats replies, the first one with
 * the first 'start_ofs' bytes, the second one containing the bytes from that
 * offset onward. */
void
ofpmp_postappend(struct ovs_list *replies, size_t start_ofs)
{
    struct ofpbuf *msg = ofpbuf_from_list(ovs_list_back(replies));

    ovs_assert(start_ofs <= UINT16_MAX);
    if (msg->size > UINT16_MAX) {
        size_t len = msg->size - start_ofs;
        memcpy(ofpmp_append(replies, len),
               (const uint8_t *) msg->data + start_ofs, len);
        msg->size = start_ofs;
    }
}

/* Returns the OpenFlow version of the replies being constructed in 'replies',
 * which should have been initialized by ofpmp_init(). */
enum ofp_version
ofpmp_version(struct ovs_list *replies)
{
    struct ofpbuf *msg = ofpbuf_from_list(ovs_list_back(replies));
    const struct ofp_header *oh = msg->data;

    return oh->version;
}

/* Determines the OFPRAW_* type of the OpenFlow messages in 'replies', which
 * should have been initialized by ofpmp_init(). */
enum ofpraw
ofpmp_decode_raw(struct ovs_list *replies)
{
    struct ofpbuf *msg = ofpbuf_from_list(ovs_list_back(replies));
    enum ofpraw raw;
    ovs_assert(!ofpraw_decode_partial(&raw, msg->data, msg->size));
    return raw;
}

static ovs_be16 *
ofpmp_flags__(const struct ofp_header *oh)
{
    switch ((enum ofp_version)oh->version) {
    case OFP10_VERSION:
        return &((struct ofp10_stats_msg *) oh)->flags;
    case OFP11_VERSION:
    case OFP12_VERSION:
    case OFP13_VERSION:
    case OFP14_VERSION:
    case OFP15_VERSION:
        return &((struct ofp11_stats_msg *) oh)->flags;
    default:
        OVS_NOT_REACHED();
    }
}

/* Returns the OFPSF_* flags found in the OpenFlow stats header of 'oh', which
 * must be an OpenFlow stats request or reply.
 *
 * (OFPSF_REPLY_MORE is the only defined flag.) */
uint16_t
ofpmp_flags(const struct ofp_header *oh)
{
    return ntohs(*ofpmp_flags__(oh));
}

/* Returns true if the OFPSF_REPLY_MORE flag is set in the OpenFlow stats
 * header of 'oh', which must be an OpenFlow stats request or reply, false if
 * it is not set. */
bool
ofpmp_more(const struct ofp_header *oh)
{
    return (ofpmp_flags(oh) & OFPSF_REPLY_MORE) != 0;
}

/* Multipart request assembler. */

struct ofpmp_partial {
    struct hmap_node hmap_node; /* In struct ofpmp_assembler's 'msgs'. */
    ovs_be32 xid;
    enum ofpraw raw;
    long long int timeout;
    struct ovs_list msgs;
    size_t size;
    bool has_body;
};

static uint32_t
hash_xid(ovs_be32 xid)
{
    return hash_int((OVS_FORCE uint32_t) xid, 0);
}

static struct ofpmp_partial *
ofpmp_assembler_find(struct hmap *assembler, ovs_be32 xid)
{
    if (hmap_is_empty(assembler)) {
        /* Common case. */
        return NULL;
    }

    struct ofpmp_partial *p;
    HMAP_FOR_EACH_IN_BUCKET (p, hmap_node, hash_xid(xid), assembler) {
        if (p->xid == xid) {
            return p;
        }
    }
    return NULL;
}

static void
ofpmp_partial_destroy(struct hmap *assembler, struct ofpmp_partial *p)
{
    if (p) {
        hmap_remove(assembler, &p->hmap_node);
        ofpbuf_list_delete(&p->msgs);
        free(p);
    }
}

static struct ofpbuf *
ofpmp_partial_error(struct hmap *assembler, struct ofpmp_partial *p,
                    enum ofperr error)
{
    const struct ofpbuf *head = ofpbuf_from_list(ovs_list_back(&p->msgs));
    const struct ofp_header *oh = head->data;
    struct ofpbuf *reply = ofperr_encode_reply(error, oh);

    ofpmp_partial_destroy(assembler, p);

    return reply;
}

/* Clears out and frees any messages currently being reassembled.  Afterward,
 * the caller may destroy the hmap, with hmap_destroy(), without risk of
 * leaks. */
void
ofpmp_assembler_clear(struct hmap *assembler)
{
    struct ofpmp_partial *p, *next;
    HMAP_FOR_EACH_SAFE (p, next, hmap_node, assembler) {
        ofpmp_partial_destroy(assembler, p);
    }
}

/* Does periodic maintenance on 'assembler'.  If any partially assembled
 * requests have timed out, returns an appropriate error message for the caller
 * to send to the controller.
 *
 * 'now' should be the current time as returned by time_msec(). */
struct ofpbuf * OVS_WARN_UNUSED_RESULT
ofpmp_assembler_run(struct hmap *assembler, long long int now)
{
    struct ofpmp_partial *p;
    HMAP_FOR_EACH (p, hmap_node, assembler) {
        if (now >= p->timeout) {
            return ofpmp_partial_error(
                assembler, p, OFPERR_OFPBRC_MULTIPART_REQUEST_TIMEOUT);
        }
    }
    return NULL;
}

/* Returns the time at which the next partially assembled request times out.
 * The caller should pass this time to poll_timer_wait_until(). */
long long int
ofpmp_assembler_wait(struct hmap *assembler)
{
    long long int timeout = LLONG_MAX;

    struct ofpmp_partial *p;
    HMAP_FOR_EACH (p, hmap_node, assembler) {
        timeout = MIN(timeout, p->timeout);
    }

    return timeout;
}

/* Submits 'msg' to 'assembler' for reassembly.
 *
 * If 'msg' was accepted, returns 0 and initializes 'out' either to an empty
 * list (if 'msg' is being held for reassembly) or to a list of one or more
 * reassembled messages.  The reassembler takes ownership of 'msg'; the caller
 * takes ownership of the messages in 'out'.
 *
 * If 'msg' was rejected, returns an OpenFlow error that the caller should
 * reply to the caller and initializes 'out' as empty.  The caller retains
 * ownership of 'msg'.
 *
 * 'now' should be the current time as returned by time_msec(). */
enum ofperr
ofpmp_assembler_execute(struct hmap *assembler, struct ofpbuf *msg,
                        struct ovs_list *out, long long int now)
{
    ovs_list_init(out);

    /* If the message is not a multipart request, pass it along without further
     * inspection.
     *
     * We could also do this kind of early-out for multipart requests that have
     * only a single piece, or for pre-OF1.3 multipart requests (since only
     * OF1.3 introduced multipart requests with more than one piece), but we
     * don't because this allows us to assure code that runs after us that
     * invariants checked below on correct message lengths are always
     * satisfied, even if there's only a single piece. */
    struct ofp_header *oh = msg->data;
    if (!ofpmsg_is_stat_request(oh)) {
        ovs_list_push_back(out, &msg->list_node);
        return 0;
    }

    /* Decode the multipart request. */
    struct ofphdrs hdrs;
    enum ofperr error = ofphdrs_decode(&hdrs, msg->data, msg->size);
    if (error) {
        return error;
    }

    enum ofpraw raw;
    error = ofpraw_from_ofphdrs(&raw, &hdrs);
    if (error) {
        return error;
    }

    /* If the message has a nonempty body, check that it is a valid length.
     *
     * The OpenFlow spec says that pieces with empty bodies are allowed
     * anywhere in a multipart sequence, so for now we allow such messages even
     * if the overall multipart request requires a body. */
    const struct raw_info *info = raw_info_get(raw);
    const struct raw_instance *instance = raw_instance_get(info, hdrs.version);
    unsigned int min_len = ofphdrs_len(&hdrs);
    bool has_body = msg->size > min_len;
    if (has_body) {
        error = ofpraw_check_length(info, instance, msg->size);
        if (error) {
            return error;
        }
    }

    /* Find or create an ofpmp_partial record. */
    struct ofpmp_partial *p = ofpmp_assembler_find(assembler, oh->xid);
    if (!p) {
        p = xzalloc(sizeof *p);
        hmap_insert(assembler, &p->hmap_node, hash_xid(oh->xid));
        p->xid = oh->xid;
        ovs_list_init(&p->msgs);
        p->raw = raw;
    }
    p->timeout = now + 1000;

    /* Check that the type is the same as any previous messages in this
     * sequence. */
    if (p->raw != raw) {
        ofpmp_partial_destroy(assembler, p);
        return OFPERR_OFPBRC_BAD_STAT;
    }

    /* Limit the size of a multipart sequence.
     *
     * (Table features requests can actually be over 1 MB.) */
    p->size += msg->size;
    if (p->size > 4 * 1024 * 1024) {
        ofpmp_partial_destroy(assembler, p);
        return OFPERR_OFPBRC_MULTIPART_BUFFER_OVERFLOW;
    }

    /* If a multipart request type requires a body, ensure that at least one of
     * the pieces in a multipart request has one. */
    bool more = oh->version >= OFP13_VERSION && ofpmp_more(oh);
    if (has_body) {
        p->has_body = true;
    }
    if (!more && !p->has_body && info->min_body) {
        ofpmp_partial_destroy(assembler, p);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    /* Append the part to the list.
     *
     * If there are more pieces to come, we're done for now. */
    ovs_list_push_back(&p->msgs, &msg->list_node);
    if (more) {
        return 0;
    }

    /* This multipart request is complete.  Move the messages from 'p' to 'out'
     * and discard 'p'. */
    ovs_list_move(out, &p->msgs);
    ovs_list_init(&p->msgs);
    ofpmp_partial_destroy(assembler, p);

    /* Delete pieces with empty bodies from 'out' (but leave at least one
     * piece).
     *
     * Most types of multipart requests have fixed-size bodies.  For example,
     * OFPMP_PORT_DESCRIPTION has an 8-byte body.  Thus, it doesn't really make
     * sense for a controller to use multiple pieces for these messages, and
     * it's simpler to implement OVS as if they weren't really multipart.
     *
     * However, the OpenFlow spec says that messages with empty bodies are
     * allowed anywhere in a multipart sequence, so in theory a controller
     * could send an OFPMP_PORT_DESCRIPTION with an 8-byte body bracketed
     * on either side by parts with 0-byte bodies.  We remove the 0-byte
     * ones here to simplify processing later.
     */
    struct ofpbuf *b, *next;
    LIST_FOR_EACH_SAFE (b, next, list_node, out) {
        if (b->size <= min_len && !ovs_list_is_short(out)) {
            ovs_list_remove(&b->list_node);
            ofpbuf_delete(b);
        }
    }
    return 0;
}

static void ofpmsgs_init(void);

static const struct raw_info *
raw_info_get(enum ofpraw raw)
{
    ofpmsgs_init();

    ovs_assert(raw < ARRAY_SIZE(raw_infos));
    return &raw_infos[raw];
}

static struct raw_instance *
raw_instance_get(const struct raw_info *info, uint8_t version)
{
    ovs_assert(version >= info->min_version && version <= info->max_version);
    return &info->instances[version - info->min_version];
}

static enum ofperr
ofpraw_from_ofphdrs(enum ofpraw *raw, const struct ofphdrs *hdrs)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

    struct raw_instance *raw_hdrs;
    uint32_t hash;

    ofpmsgs_init();

    hash = ofphdrs_hash(hdrs);
    HMAP_FOR_EACH_WITH_HASH (raw_hdrs, hmap_node, hash, &raw_instance_map) {
        if (ofphdrs_equal(hdrs, &raw_hdrs->hdrs)) {
            *raw = raw_hdrs->raw;
            return 0;
        }
    }

    if (!VLOG_DROP_WARN(&rl)) {
        struct ds s;

        ds_init(&s);
        ds_put_format(&s, "version %"PRIu8", type %"PRIu8,
                      hdrs->version, hdrs->type);
        if (ofphdrs_is_stat(hdrs)) {
            ds_put_format(&s, ", stat %"PRIu16, hdrs->stat);
        }
        if (hdrs->vendor) {
            ds_put_format(&s, ", vendor 0x%"PRIx32", subtype %"PRIu32,
                          hdrs->vendor, hdrs->subtype);
        }
        VLOG_WARN("unknown OpenFlow message (%s)", ds_cstr(&s));
        ds_destroy(&s);
    }

    return (hdrs->vendor ? OFPERR_OFPBRC_BAD_SUBTYPE
            : ofphdrs_is_stat(hdrs) ? OFPERR_OFPBRC_BAD_STAT
            : OFPERR_OFPBRC_BAD_TYPE);
}

static void
ofpmsgs_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    const struct raw_info *info;

    if (!ovsthread_once_start(&once)) {
        return;
    }

    hmap_init(&raw_instance_map);
    for (info = raw_infos; info < &raw_infos[ARRAY_SIZE(raw_infos)]; info++)
    {
        int n_instances = info->max_version - info->min_version + 1;
        struct raw_instance *inst;

        for (inst = info->instances;
             inst < &info->instances[n_instances];
             inst++) {
            inst->hdrs_len = ofphdrs_len(&inst->hdrs);
            hmap_insert(&raw_instance_map, &inst->hmap_node,
                        ofphdrs_hash(&inst->hdrs));
        }
    }

    ovsthread_once_done(&once);
}

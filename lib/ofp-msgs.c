/*
 * Copyright (c) 2012, 2013, 2014 Nicira, Inc.
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
#include "ofp-msgs.h"
#include "byte-order.h"
#include "dynamic-string.h"
#include "hash.h"
#include "hmap.h"
#include "ofpbuf.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "ovs-thread.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ofp_msgs);

#define OFPT_VENDOR 4
#define OFPT10_STATS_REQUEST 16
#define OFPT10_STATS_REPLY 17
#define OFPT11_STATS_REQUEST 18
#define OFPT11_STATS_REPLY 19
#define OFPST_VENDOR 0xffff

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
    static atomic_uint32_t next_xid = ATOMIC_VAR_INIT(1);
    uint32_t xid;

    atomic_add(&next_xid, 1, &xid);
    return htonl(xid);
}

static uint32_t
ofphdrs_hash(const struct ofphdrs *hdrs)
{
    BUILD_ASSERT_DECL(sizeof *hdrs == 12);
    return hash_words((const uint32_t *) hdrs, 3, 0);
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
        if (hdrs->vendor == NX_VENDOR_ID) {
            /* Get Nicira message subtype (NXT_*). */
            const struct nicira_header *nh;

            if (length < sizeof *nh) {
                return OFPERR_OFPBRC_BAD_LEN;
            }
            nh = (const struct nicira_header *) oh;
            hdrs->subtype = ntohl(nh->subtype);
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
            if (hdrs->vendor == NX_VENDOR_ID) {
                /* Get Nicira statistic type (NXST_*). */
                const struct nicira11_stats_msg *nsm;

                if (length < sizeof *nsm) {
                    return OFPERR_OFPBRC_BAD_LEN;
                }
                nsm = (const struct nicira11_stats_msg *) oh;
                hdrs->subtype = ntohl(nsm->subtype);
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
    enum ofperr error = ofphdrs_decode(hdrs, oh, length);
    ovs_assert(!error);
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
        return sizeof(struct nicira_header);
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
                    ? sizeof(struct nicira11_stats_msg)
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
    struct ofpbuf msg;

    ofpbuf_use_const(&msg, oh, ntohs(oh->length));
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
    enum ofperr error;
    enum ofpraw raw;

    error = ofpraw_decode(&raw, oh);
    ovs_assert(!error);
    return raw;
}

/* Determines the OFPRAW_* type of the OpenFlow message in 'msg', which starts
 * at 'ofpbuf_data(msg)' and has length 'ofpbuf_size(msg)' bytes.  On success,
 * returns 0 and stores the type into '*rawp'.  On failure, returns an OFPERR_*
 * error code and zeros '*rawp'.
 *
 * This function checks that the message has a valid length for its particular
 * type of message, and returns an error if not.
 *
 * In addition to setting '*rawp', this function pulls off the OpenFlow header
 * (including the stats headers, vendor header, and any subtype header) with
 * ofpbuf_pull().  It also sets 'msg->frame' to the start of the OpenFlow
 * header and 'msg->l3' just beyond the headers (that is, to the final value of
 * ofpbuf_data(msg)). */
enum ofperr
ofpraw_pull(enum ofpraw *rawp, struct ofpbuf *msg)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    const struct raw_instance *instance;
    const struct raw_info *info;
    struct ofphdrs hdrs;

    unsigned int min_len;
    unsigned int len;

    enum ofperr error;
    enum ofpraw raw;

    /* Set default outputs. */
    msg->frame = ofpbuf_data(msg);
    ofpbuf_set_l3(msg, msg->frame);
    *rawp = 0;

    len = ofpbuf_size(msg);
    error = ofphdrs_decode(&hdrs, ofpbuf_data(msg), len);
    if (error) {
        return error;
    }

    error = ofpraw_from_ofphdrs(&raw, &hdrs);
    if (error) {
        return error;
    }

    info = raw_info_get(raw);
    instance = raw_instance_get(info, hdrs.version);
    msg->frame = ofpbuf_pull(msg, instance->hdrs_len);
    ofpbuf_set_l3(msg, ofpbuf_data(msg));

    min_len = instance->hdrs_len + info->min_body;
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
    enum ofperr error;
    enum ofpraw raw;

    error = ofpraw_pull(&raw, msg);
    ovs_assert(!error);
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
 * In the returned ofpbuf, 'frame' points to the beginning of the
 * OpenFlow header and 'l3' points just after it, to where the
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
 * In the returned ofpbuf, 'frame' points to the beginning of the
 * OpenFlow header and 'l3' points just after it, to where the
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
    enum ofperr error;

    error = ofpraw_decode_partial(&request_raw, request,
                                  ntohs(request->length));
    ovs_assert(!error);

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
 * Upon return, 'buf->frame' points to the beginning of the OpenFlow header and
 * 'buf->l3' points just after it, to where the message's body will start.  The
 * caller must actually allocating the body into the space reserved for it,
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
 * In the returned ofpbuf, 'frame' points to the beginning of the
 * OpenFlow header and 'l3' points just after it, to where the
 * message's body will start.  The caller must actually allocate the
 * body into the space reserved for it, e.g. with ofpbuf_put_uninit().
 *
 * The caller owns the returned ofpbuf and must free it when it is no longer
 * needed, e.g. with ofpbuf_delete(). */
void
ofpraw_put_stats_reply(const struct ofp_header *request, struct ofpbuf *buf)
{
    enum ofperr error;
    enum ofpraw raw;

    error = ofpraw_decode_partial(&raw, request, ntohs(request->length));
    ovs_assert(!error);

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
    buf->frame = ofpbuf_put_uninit(buf, instance->hdrs_len);
    ofpbuf_set_l3(buf, ofpbuf_tail(buf));

    oh = buf->frame;
    oh->version = version;
    oh->type = hdrs->type;
    oh->length = htons(ofpbuf_size(buf));
    oh->xid = xid;

    if (hdrs->type == OFPT_VENDOR) {
        struct nicira_header *nh = buf->frame;

        ovs_assert(hdrs->vendor == NX_VENDOR_ID);
        nh->vendor = htonl(hdrs->vendor);
        nh->subtype = htonl(hdrs->subtype);
    } else if (version == OFP10_VERSION
               && (hdrs->type == OFPT10_STATS_REQUEST ||
                   hdrs->type == OFPT10_STATS_REPLY)) {
        struct ofp10_stats_msg *osm = buf->frame;

        osm->type = htons(hdrs->stat);
        osm->flags = htons(0);

        if (hdrs->stat == OFPST_VENDOR) {
            struct ofp10_vendor_stats_msg *ovsm = buf->frame;

            ovsm->vendor = htonl(hdrs->vendor);
            if (hdrs->vendor == NX_VENDOR_ID) {
                struct nicira10_stats_msg *nsm = buf->frame;

                nsm->subtype = htonl(hdrs->subtype);
                memset(nsm->pad, 0, sizeof nsm->pad);
            } else {
                OVS_NOT_REACHED();
            }
        }
    } else if (version != OFP10_VERSION
               && (hdrs->type == OFPT11_STATS_REQUEST ||
                   hdrs->type == OFPT11_STATS_REPLY)) {
        struct ofp11_stats_msg *osm = buf->frame;

        osm->type = htons(hdrs->stat);
        osm->flags = htons(0);
        memset(osm->pad, 0, sizeof osm->pad);

        if (hdrs->stat == OFPST_VENDOR) {
            struct ofp11_vendor_stats_msg *ovsm = buf->frame;

            ovsm->vendor = htonl(hdrs->vendor);
            if (hdrs->vendor == NX_VENDOR_ID) {
                struct nicira11_stats_msg *nsm = buf->frame;

                nsm->subtype = htonl(hdrs->subtype);
            } else {
                OVS_NOT_REACHED();
            }
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
    enum ofperr error;

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

    error = ofpraw_from_ofphdrs(&reply_raw, &hdrs);
    ovs_assert(!error);

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
 * at 'ofpbuf_data(msg)' and has length 'ofpbuf_size(msg)' bytes.  On success,
 * returns 0 and stores the type into '*typep'.  On failure, returns an
 * OFPERR_* error code and zeros '*typep'.
 *
 * This function checks that the message has a valid length for its particular
 * type of message, and returns an error if not.
 *
 * In addition to setting '*typep', this function pulls off the OpenFlow header
 * (including the stats headers, vendor header, and any subtype header) with
 * ofpbuf_pull().  It also sets 'msg->frame' to the start of the OpenFlow
 * header and 'msg->l3' just beyond the headers (that is, to the final value of
 * ofpbuf_data(msg)). */
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

/* Updates the 'length' field of the OpenFlow message in 'buf' to
 * 'ofpbuf_size(buf)'. */
void
ofpmsg_update_length(struct ofpbuf *buf)
{
    struct ofp_header *oh = ofpbuf_at_assert(buf, 0, sizeof *oh);
    oh->length = htons(ofpbuf_size(buf));
}

/* Returns just past the Openflow header (including the stats headers, vendor
 * header, and any subtype header) in 'oh'. */
const void *
ofpmsg_body(const struct ofp_header *oh)
{
    struct ofphdrs hdrs;

    ofphdrs_decode_assert(&hdrs, oh, ntohs(oh->length));
    return (const uint8_t *) oh + ofphdrs_len(&hdrs);
}

/* Return if it's a stat/multipart (OFPST) request message. */
bool
ofpmsg_is_stat_request(const struct ofp_header *oh)
{
    return ofp_is_stat_request(oh->version, oh->type);
}

static ovs_be16 *ofpmp_flags__(const struct ofp_header *);

/* Initializes 'replies' as a new list of stats messages that reply to
 * 'request', which must be a stats request message.  Initially the list will
 * consist of only a single reply part without any body.  The caller should
 * use calls to the other ofpmp_*() functions to add to the body and split the
 * message into multiple parts, if necessary. */
void
ofpmp_init(struct list *replies, const struct ofp_header *request)
{
    struct ofpbuf *msg;

    list_init(replies);

    msg = ofpraw_alloc_stats_reply(request, 1000);
    list_push_back(replies, &msg->list_node);
}

/* Prepares to append up to 'len' bytes to the series of statistics replies in
 * 'replies', which should have been initialized with ofpmp_init(), if
 * necessary adding a new reply to the list.
 *
 * Returns an ofpbuf with at least 'len' bytes of tailroom.  The 'len' bytes
 * have not actually been allocated, so the caller must do so with
 * e.g. ofpbuf_put_uninit(). */
struct ofpbuf *
ofpmp_reserve(struct list *replies, size_t len)
{
    struct ofpbuf *msg = ofpbuf_from_list(list_back(replies));

    if (ofpbuf_size(msg) + len <= UINT16_MAX) {
        ofpbuf_prealloc_tailroom(msg, len);
        return msg;
    } else {
        unsigned int hdrs_len;
        struct ofpbuf *next;
        struct ofphdrs hdrs;

        ofphdrs_decode_assert(&hdrs, ofpbuf_data(msg), ofpbuf_size(msg));
        hdrs_len = ofphdrs_len(&hdrs);

        next = ofpbuf_new(MAX(1024, hdrs_len + len));
        ofpbuf_put(next, ofpbuf_data(msg), hdrs_len);
        next->frame = ofpbuf_data(next);
        ofpbuf_set_l3(next, ofpbuf_tail(next));
        list_push_back(replies, &next->list_node);

        *ofpmp_flags__(ofpbuf_data(msg)) |= htons(OFPSF_REPLY_MORE);

        return next;
    }
}

/* Appends 'len' bytes to the series of statistics replies in 'replies', and
 * returns the first byte. */
void *
ofpmp_append(struct list *replies, size_t len)
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
ofpmp_postappend(struct list *replies, size_t start_ofs)
{
    struct ofpbuf *msg = ofpbuf_from_list(list_back(replies));

    ovs_assert(start_ofs <= UINT16_MAX);
    if (ofpbuf_size(msg) > UINT16_MAX) {
        size_t len = ofpbuf_size(msg) - start_ofs;
        memcpy(ofpmp_append(replies, len),
               (const uint8_t *) ofpbuf_data(msg) + start_ofs, len);
        ofpbuf_set_size(msg, start_ofs);
    }
}

/* Returns the OpenFlow version of the replies being constructed in 'replies',
 * which should have been initialized by ofpmp_init(). */
enum ofp_version
ofpmp_version(struct list *replies)
{
    struct ofpbuf *msg = ofpbuf_from_list(list_back(replies));
    const struct ofp_header *oh = ofpbuf_data(msg);

    return oh->version;
}

/* Determines the OFPRAW_* type of the OpenFlow messages in 'replies', which
 * should have been initialized by ofpmp_init(). */
enum ofpraw
ofpmp_decode_raw(struct list *replies)
{
    struct ofpbuf *msg = ofpbuf_from_list(list_back(replies));
    enum ofperr error;
    enum ofpraw raw;

    error = ofpraw_decode_partial(&raw, ofpbuf_data(msg), ofpbuf_size(msg));
    ovs_assert(!error);
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

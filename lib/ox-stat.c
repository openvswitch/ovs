/*
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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
#include "ox-stat.h"
#include "byte-order.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/compiler.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "unaligned.h"

VLOG_DEFINE_THIS_MODULE(ox_stat);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* OXS header
 * ==========
 *
 * The header is 32 bits long.  It looks like this:
 *
 * |31                              16 15            9 8 7                0
 * +----------------------------------+---------------+-+------------------+
 * |            oxs_class             |   oxs_field   |r|    oxs_length    |
 * +----------------------------------+---------------+-+------------------+
 *
 * where r stands for oxs_reserved.  It is followed by oxs_length bytes of
 * payload (the statistic's value).
 *
 * Internally, we represent a standard OXS header as a 64-bit integer with the
 * above information in the most-significant bits.
 *
 *
 * Experimenter OXS
 * ================
 *
 * The header is 64 bits long.  It looks like the diagram above except that a
 * 32-bit experimenter ID, which we call oxs_experimenter and which identifies
 * a vendor, is inserted just before the payload.  Experimenter OXSs are
 * identified by an all-1-bits oxs_class (OFPXSC_EXPERIMENTER).  The oxs_length
 * value *includes* the experimenter ID, so that the real payload is only
 * oxs_length - 4 bytes long.
 *
 * Internally, we represent an experimenter OXS header as a 64-bit integer with
 * the standard header in the upper 32 bits and the experimenter ID in the
 * lower 32 bits.  (It would be more convenient to swap the positions of the
 * two 32-bit words, but this would be more error-prone because experimenter
 * OXSs are very rarely used, so accidentally passing one through a 32-bit type
 * somewhere in the OVS code would be hard to find.)
 */

/* OXS Class IDs.
 * The high order bit differentiate reserved classes from member classes.
 * Classes 0x0000 to 0x7FFF are member classes, allocated by ONF.
 * Classes 0x8000 to 0xFFFE are reserved classes, reserved for standardisation.
 */
enum ofp_oxs_class {
    OFPXSC_OPENFLOW_BASIC = 0x8002,     /* Basic stats class for OpenFlow */
    OFPXSC_EXPERIMENTER = 0xFFFF,       /* Experimenter class */
};

/* Functions for extracting raw field values from OXS headers. */
static uint32_t oxs_experimenter(uint64_t header) { return header; }
static int oxs_class(uint64_t header) { return header >> 48; }
static int oxs_field(uint64_t header) { return (header >> 41) & 0x7f; }
static int oxs_length(uint64_t header) { return (header >> 32) & 0xff; }

static bool
is_experimenter_oxs(uint64_t header)
{
    return oxs_class(header) == OFPXSC_EXPERIMENTER;
}

/* The OXS header "length" field is somewhat tricky:
 *
 *     - For a standard OXS header, the length is the number of bytes of the
 *       payload, and the payload consists of just the value.
 *
 *     - For an experimenter OXS header, the length is the number of bytes in
 *       the payload plus 4 (the length of the experimenter ID).  That is, the
 *       experimenter ID is included in oxs_length.
 *
 * This function returns the length of the experimenter ID field in 'header'.
 * That is, for an experimenter OXS (when an experimenter ID is present), it
 * returns 4, and for a standard OXS (when no experimenter ID is present), it
 * returns 0. */
static int
oxs_experimenter_len(uint64_t header)
{
    return is_experimenter_oxs(header) ? 4 : 0;
}

/* Returns the number of bytes that follow the header for an OXS entry with the
 * given 'header'. */
static int
oxs_payload_len(uint64_t header)
{
    return oxs_length(header) - oxs_experimenter_len(header);
}

/* Returns the number of bytes in the header for an OXS entry with the given
 * 'header'. */
static int
oxs_header_len(uint64_t header)
{
    return 4 + oxs_experimenter_len(header);
}

/* Assembles an OXS header from its components. */
#define OXS_HEADER(EXPERIMENTER, CLASS, FIELD, LENGTH) \
    (((uint64_t) (CLASS) << 48) | \
     ((uint64_t) (FIELD) << 41) | \
     ((uint64_t) (LENGTH) << 32) | \
     (EXPERIMENTER))

#define OXS_HEADER_FMT "%#"PRIx32":%d:%d:%d"
#define OXS_HEADER_ARGS(HEADER)                                     \
    oxs_experimenter(HEADER), oxs_class(HEADER), oxs_field(HEADER), \
    oxs_length(HEADER)

/* Currently defined OXS. */
#define OXS_OF_DURATION     OXS_HEADER (0, 0x8002, OFPXST_OFB_DURATION, 8)
#define OXS_OF_IDLE_TIME    OXS_HEADER (0, 0x8002, OFPXST_OFB_IDLE_TIME, 8)
#define OXS_OF_FLOW_COUNT   OXS_HEADER (0, 0x8002, OFPXST_OFB_FLOW_COUNT, 4)
#define OXS_OF_PACKET_COUNT OXS_HEADER (0, 0x8002, OFPXST_OFB_PACKET_COUNT, 8)
#define OXS_OF_BYTE_COUNT   OXS_HEADER (0, 0x8002, OFPXST_OFB_BYTE_COUNT, 8)

/* Header for a group of OXS statistics. */
struct ofp_oxs_stat {
    ovs_be16 reserved;          /* Must be zero. */
    ovs_be16 length;            /* Stats Length */
};
BUILD_ASSERT_DECL(sizeof(struct ofp_oxs_stat) == 4);

static int oxs_pull_header__(struct ofpbuf *b, uint64_t *header);
static enum ofperr oxs_pull_raw(const uint8_t *, unsigned int stat_len,
                                struct oxs_stats *, uint8_t *oxs_field_set);

static int
oxs_pull_header__(struct ofpbuf *b, uint64_t *header)
{
    if (b->size < 4) {
        goto bad_len;
    }

    *header = ((uint64_t) ntohl(get_unaligned_be32(b->data))) << 32;
    if (is_experimenter_oxs(*header)) {
        if (b->size < 8) {
            goto bad_len;
        }
        *header = ntohll(get_unaligned_be64(b->data));
    }
    if (oxs_length(*header) < oxs_experimenter_len(*header)) {
        VLOG_WARN_RL(&rl, "OXS header "OXS_HEADER_FMT" has invalid length %d "
                     "(minimum is %d)",
                     OXS_HEADER_ARGS(*header), oxs_length(*header),
                     oxs_header_len(*header));
        goto error;
    }
    ofpbuf_pull(b, oxs_header_len(*header));

    return 0;

bad_len:
    VLOG_DBG_RL(&rl, "encountered partial (%"PRIu32"-byte) OXS entry",
                b->size);
error:
    *header = 0;
    return OFPERR_OFPBMC_BAD_LEN;
}

static enum ofperr
oxs_pull_entry__(struct ofpbuf *b, struct oxs_stats *stats,
                 uint8_t *oxs_field_set)
{
    uint64_t header;
    enum ofperr error = oxs_pull_header__(b, &header);
    if (error) {
        return error;
    }

    unsigned int payload_len = oxs_payload_len(header);
    const void *payload = ofpbuf_try_pull(b, payload_len);
    if (!payload) {
        return OFPERR_OFPBMC_BAD_LEN;
    }

    switch (header) {
    case OXS_OF_DURATION: {
        uint64_t duration = ntohll(get_unaligned_be64(payload));
        stats->duration_sec = duration >> 32;
        stats->duration_nsec = duration;
    }
        break;
    case OXS_OF_IDLE_TIME:
        stats->idle_age = ntohll(get_unaligned_be64(payload)) >> 32;
        break;
    case OXS_OF_PACKET_COUNT:
        stats->packet_count = ntohll(get_unaligned_be64(payload));
        break;
    case OXS_OF_BYTE_COUNT:
        stats->byte_count = ntohll(get_unaligned_be64(payload));
        break;
    case OXS_OF_FLOW_COUNT:
        stats->flow_count = ntohl(get_unaligned_be32(payload));
        break;

    default:
        /* Unknown header. */
        return 0;
    }
    if (oxs_field_set
        && oxs_class(header) == OFPXSC_OPENFLOW_BASIC
        && oxs_field(header) < CHAR_BIT * sizeof *oxs_field_set) {
        *oxs_field_set |= 1 << oxs_field(header);
    }
    return error;
}

static enum ofperr
oxs_pull_raw(const uint8_t * p, unsigned int stat_len,
             struct oxs_stats *stats, uint8_t *oxs_field_set)
{
    struct ofpbuf b = ofpbuf_const_initializer(p, stat_len);
    while (b.size) {
        const uint8_t *pos = b.data;
        enum ofperr error = oxs_pull_entry__(&b, stats, oxs_field_set);
        if (error && error != OFPERR_OFPBMC_BAD_FIELD) {
            VLOG_DBG_RL(&rl, "error parsing OXS at offset %"PRIdPTR" "
                        "within match (%s)",
                        pos - p, ofperr_to_string(error));
            return error;
        }
    }
    return 0;
}

/* Retrieve  struct ofp_oxs_stat from 'b', followed by the flow entry
 * statistics in OXS format.
 *
 * Returns error if message parsing fails, otherwise returns zero . */
enum ofperr
oxs_pull_stat(struct ofpbuf *b, struct oxs_stats *stats,
              uint16_t *statlen, uint8_t *oxs_field_set)
{
    memset(stats, 0xff, sizeof *stats);

    struct ofp_oxs_stat *oxs = b->data;
    if (b->size < sizeof *oxs) {
        return OFPERR_OFPBMC_BAD_LEN;
    }

    uint16_t stat_len = ntohs(oxs->length);
    if (stat_len < sizeof *oxs) {
        return OFPERR_OFPBMC_BAD_LEN;
    }

    uint8_t *p = ofpbuf_try_pull(b, ROUND_UP(stat_len, 8));
    if (!p) {
        VLOG_DBG_RL(&rl, "oxs length %u, rounded up to a "
                    "multiple of 8, is longer than space in message (max "
                    "length %" PRIu32 ")", stat_len, b->size);
        return OFPERR_OFPBMC_BAD_LEN;
    }
    *statlen = ROUND_UP(stat_len, 8);
    return oxs_pull_raw(p + sizeof *oxs, stat_len - sizeof *oxs, stats,
                        oxs_field_set);
}

static void
oxs_put__(struct ofpbuf *b, uint64_t header,
          const void *value, size_t value_size)
{
    if (is_experimenter_oxs(header)) {
        ovs_be64 be64 = htonll(header);
        ofpbuf_put(b, &be64, sizeof be64);
    } else {
        ovs_be32 be32 = htonl(header >> 32);
        ofpbuf_put(b, &be32, sizeof be32);
    }

    ovs_assert(oxs_payload_len(header) == value_size);
    ofpbuf_put(b, value, value_size);
}

static void
oxs_put32(struct ofpbuf *b, uint64_t header, uint32_t value_)
{
    ovs_be32 value = htonl(value_);
    oxs_put__(b, header, &value, sizeof value);
}

static void
oxs_put64(struct ofpbuf *b, uint64_t header, uint64_t value_)
{
    ovs_be64 value = htonll(value_);
    oxs_put__(b, header, &value, sizeof value);
}

/* Appends to 'b' an struct ofp_oxs_stat followed by the flow entry statistics
 * in OXS format , plus enough zero bytes to pad the data appended out to a
 * multiple of 8.
 *
 * Specify the OpenFlow version in use as 'version'.
 *
 * This function can cause 'b''s data to be reallocated.
 *
 * Returns the number of bytes appended to 'b', excluding the padding.Never
 * returns zero. */
void
oxs_put_stats(struct ofpbuf *b, const struct oxs_stats *stats)
{
    size_t start = b->size;

    /* Put empty header. */
    struct ofp_oxs_stat *oxs;
    ofpbuf_put_zeros(b, sizeof *oxs);

    /* Put stats. */
    if (stats->duration_sec != UINT32_MAX) {
        oxs_put64(b, OXS_OF_DURATION,
                  (((uint64_t) stats->duration_sec << 32)
                   | stats->duration_nsec));
    }
    if (stats->idle_age != UINT32_MAX) {
        oxs_put64(b, OXS_OF_IDLE_TIME, (uint64_t) stats->idle_age << 32);
    }
    if (stats->packet_count != UINT64_MAX) {
        oxs_put64(b, OXS_OF_PACKET_COUNT, stats->packet_count);
    }
    if (stats->byte_count != UINT64_MAX) {
        oxs_put64(b, OXS_OF_BYTE_COUNT, stats->byte_count);
    }
    if (stats->flow_count != UINT32_MAX) {
        oxs_put32(b, OXS_OF_FLOW_COUNT, stats->flow_count);
    }

    /* Fill in size in header, then pad to multiple of 8 bytes. */
    oxs = ofpbuf_at(b, start, sizeof *oxs);
    oxs->length = htons(b->size - start);
    ofpbuf_put_zeros(b, PAD_SIZE(b->size - start, 8));
}

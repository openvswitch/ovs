/*
 * Copyright (c) 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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

#include "nx-match.h"

#include <netinet/icmp6.h>

#include "classifier.h"
#include "dynamic-string.h"
#include "hmap.h"
#include "meta-flow.h"
#include "ofp-actions.h"
#include "ofp-errors.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "openflow/nicira-ext.h"
#include "packets.h"
#include "shash.h"
#include "unaligned.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(nx_match);

/*
 * OXM Class IDs.
 * The high order bit differentiate reserved classes from member classes.
 * Classes 0x0000 to 0x7FFF are member classes, allocated by ONF.
 * Classes 0x8000 to 0xFFFE are reserved classes, reserved for standardisation.
 */
enum ofp12_oxm_class {
    OFPXMC12_NXM_0          = 0x0000, /* Backward compatibility with NXM */
    OFPXMC12_NXM_1          = 0x0001, /* Backward compatibility with NXM */
    OFPXMC12_OPENFLOW_BASIC = 0x8000, /* Basic class for OpenFlow */
    OFPXMC15_PACKET_REGS    = 0x8001, /* Packet registers (pipeline fields). */
    OFPXMC12_EXPERIMENTER   = 0xffff, /* Experimenter class */
};

/* Functions for extracting fields from OXM/NXM headers. */
static int nxm_vendor(uint32_t header) { return header >> 16; }
static int nxm_field(uint32_t header) { return (header >> 9) & 0x7f; }
static bool nxm_hasmask(uint32_t header) { return (header & 0x100) != 0; }
static int nxm_length(uint32_t header) { return header & 0xff; }

/* Returns true if 'header' is a legacy NXM header, false if it is an OXM
 * header.*/
static bool
is_nxm_header(uint32_t header)
{
    return nxm_vendor(header) <= 1;
}

#define NXM_HEADER(VENDOR, FIELD, HASMASK, LENGTH)                      \
    (((VENDOR) << 16) | ((FIELD) << 9) | ((HASMASK) << 8) | (LENGTH))

#define NXM_HEADER_FMT "%d:%d:%d:%d"
#define NXM_HEADER_ARGS(HEADER)                 \
    nxm_vendor(HEADER), nxm_field(HEADER),      \
    nxm_hasmask(HEADER), nxm_length(HEADER)

/* Functions for turning the "hasmask" bit on or off.  (This also requires
 * adjusting the length.) */
static uint32_t
nxm_make_exact_header(uint32_t header)
{
    return NXM_HEADER(nxm_vendor(header), nxm_field(header), 0,
                      nxm_length(header) / 2);
}
static uint32_t
nxm_make_wild_header(uint32_t header)
{
    return NXM_HEADER(nxm_vendor(header), nxm_field(header), 1,
                      nxm_length(header) * 2);
}

/* Flow cookie.
 *
 * This may be used to gain the OpenFlow 1.1-like ability to restrict
 * certain NXM-based Flow Mod and Flow Stats Request messages to flows
 * with specific cookies.  See the "nx_flow_mod" and "nx_flow_stats_request"
 * structure definitions for more details.  This match is otherwise not
 * allowed. */
#define NXM_NX_COOKIE     NXM_HEADER  (0x0001, 30, 0, 8)
#define NXM_NX_COOKIE_W   nxm_make_wild_header(NXM_NX_COOKIE)

struct nxm_field {
    uint32_t header;
    enum ofp_version version;
    const char *name;           /* e.g. "NXM_OF_IN_PORT". */

    enum mf_field_id id;
};

static const struct nxm_field *nxm_field_by_header(uint32_t header);
static const struct nxm_field *nxm_field_by_name(const char *name, size_t len);
static const struct nxm_field *nxm_field_by_mf_id(enum mf_field_id);
static const struct nxm_field *oxm_field_by_mf_id(enum mf_field_id);

/* Rate limit for nx_match parse errors.  These always indicate a bug in the
 * peer and so there's not much point in showing a lot of them. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

static const struct nxm_field *
mf_parse_subfield_name(const char *name, int name_len, bool *wild);

static const struct nxm_field *
nxm_field_from_mf_field(enum mf_field_id id, enum ofp_version version)
{
    const struct nxm_field *oxm = oxm_field_by_mf_id(id);
    const struct nxm_field *nxm = nxm_field_by_mf_id(id);
    return oxm && (version >= oxm->version || !nxm) ? oxm : nxm;
}

/* Returns the preferred OXM header to use for field 'id' in OpenFlow version
 * 'version'.  Specify 0 for 'version' if an NXM legacy header should be
 * preferred over any standardized OXM header.  Returns 0 if field 'id' cannot
 * be expressed in NXM or OXM. */
uint32_t
mf_oxm_header(enum mf_field_id id, enum ofp_version version)
{
    const struct nxm_field *f = nxm_field_from_mf_field(id, version);
    return f ? f->header : 0;
}

/* Returns the "struct mf_field" that corresponds to NXM or OXM header
 * 'header', or NULL if 'header' doesn't correspond to any known field.  */
const struct mf_field *
mf_from_nxm_header(uint32_t header)
{
    const struct nxm_field *f = nxm_field_by_header(header);
    return f ? mf_from_id(f->id) : NULL;
}

/* Returns the width of the data for a field with the given 'header', in
 * bytes. */
static int
nxm_field_bytes(uint32_t header)
{
    unsigned int length = nxm_length(header);
    return nxm_hasmask(header) ? length / 2 : length;
}

/* Returns the earliest version of OpenFlow that standardized an OXM header for
 * field 'id', or UINT8_MAX if no version of OpenFlow does. */
static enum ofp_version
mf_oxm_version(enum mf_field_id id)
{
    const struct nxm_field *oxm = oxm_field_by_mf_id(id);
    return oxm ? oxm->version : UINT8_MAX;
}
 
/* nx_pull_match() and helpers. */

/* Given NXM/OXM value 'value' and mask 'mask' associated with 'header', checks
 * for any 1-bit in the value where there is a 0-bit in the mask.  Returns 0 if
 * none, otherwise an error code. */
static bool
is_mask_consistent(uint32_t header, const uint8_t *value, const uint8_t *mask)
{
    unsigned int width = nxm_field_bytes(header);
    unsigned int i;

    for (i = 0; i < width; i++) {
        if (value[i] & ~mask[i]) {
            if (!VLOG_DROP_WARN(&rl)) {
                VLOG_WARN_RL(&rl, "Rejecting NXM/OXM entry "NXM_HEADER_FMT " "
                             "with 1-bits in value for bits wildcarded by the "
                             "mask.", NXM_HEADER_ARGS(header));
            }
            return false;
        }
    }
    return true;
}

static bool
is_cookie_pseudoheader(uint32_t header)
{
    return header == NXM_NX_COOKIE || header == NXM_NX_COOKIE_W;
}

static enum ofperr
nx_pull_header__(struct ofpbuf *b, bool allow_cookie, uint32_t *header,
                 const struct mf_field **field)
{
    if (ofpbuf_size(b) < 4) {
        VLOG_DBG_RL(&rl, "encountered partial (%"PRIu32"-byte) OXM entry",
                    ofpbuf_size(b));
        goto error;
    }
    *header = ntohl(get_unaligned_be32(ofpbuf_pull(b, 4)));
    if (nxm_length(*header) == 0) {
        VLOG_WARN_RL(&rl, "OXM header "NXM_HEADER_FMT" has zero length",
                     NXM_HEADER_ARGS(*header));
        goto error;
    }
    if (field) {
        *field = mf_from_nxm_header(*header);
        if (!*field && !(allow_cookie && is_cookie_pseudoheader(*header))) {
            VLOG_DBG_RL(&rl, "OXM header "NXM_HEADER_FMT" is unknown",
                        NXM_HEADER_ARGS(*header));
            return OFPERR_OFPBMC_BAD_FIELD;
        }
    }

    return 0;

error:
    *header = 0;
    *field = NULL;
    return OFPERR_OFPBMC_BAD_LEN;
}

static enum ofperr
nx_pull_entry__(struct ofpbuf *b, bool allow_cookie, uint32_t *header,
                const struct mf_field **field,
                union mf_value *value, union mf_value *mask)
{
    enum ofperr header_error;
    unsigned int payload_len;
    const uint8_t *payload;
    int width;

    header_error = nx_pull_header__(b, allow_cookie, header, field);
    if (header_error && header_error != OFPERR_OFPBMC_BAD_FIELD) {
        return header_error;
    }

    payload_len = nxm_length(*header);
    payload = ofpbuf_try_pull(b, payload_len);
    if (!payload) {
        VLOG_DBG_RL(&rl, "OXM header "NXM_HEADER_FMT" calls for %u-byte "
                    "payload but only %"PRIu32" bytes follow OXM header",
                    NXM_HEADER_ARGS(*header), payload_len, ofpbuf_size(b));
        return OFPERR_OFPBMC_BAD_LEN;
    }

    width = nxm_field_bytes(*header);
    if (nxm_hasmask(*header)
        && !is_mask_consistent(*header, payload, payload + width)) {
        return OFPERR_OFPBMC_BAD_WILDCARDS;
    }

    memcpy(value, payload, MIN(width, sizeof *value));
    if (mask) {
        if (nxm_hasmask(*header)) {
            memcpy(mask, payload + width, MIN(width, sizeof *mask));
        } else {
            memset(mask, 0xff, MIN(width, sizeof *mask));
        }
    } else if (nxm_hasmask(*header)) {
        VLOG_DBG_RL(&rl, "OXM header "NXM_HEADER_FMT" includes mask but "
                    "masked OXMs are not allowed here",
                    NXM_HEADER_ARGS(*header));
        return OFPERR_OFPBMC_BAD_MASK;
    }

    return header_error;
}

/* Attempts to pull an NXM or OXM header, value, and mask (if present) from the
 * beginning of 'b'.  If successful, stores a pointer to the "struct mf_field"
 * corresponding to the pulled header in '*field', the value into '*value',
 * and the mask into '*mask', and returns 0.  On error, returns an OpenFlow
 * error; in this case, some bytes might have been pulled off 'b' anyhow, and
 * the output parameters might have been modified.
 *
 * If a NULL 'mask' is supplied, masked OXM or NXM entries are treated as
 * errors (with OFPERR_OFPBMC_BAD_MASK).
 */
enum ofperr
nx_pull_entry(struct ofpbuf *b, const struct mf_field **field,
              union mf_value *value, union mf_value *mask)
{
    uint32_t header;

    return nx_pull_entry__(b, false, &header, field, value, mask);
}

/* Attempts to pull an NXM or OXM header from the beginning of 'b'.  If
 * successful, stores a pointer to the "struct mf_field" corresponding to the
 * pulled header in '*field', stores the header's hasmask bit in '*masked'
 * (true if hasmask=1, false if hasmask=0), and returns 0.  On error, returns
 * an OpenFlow error; in this case, some bytes might have been pulled off 'b'
 * anyhow, and the output parameters might have been modified.
 *
 * If NULL 'masked' is supplied, masked OXM or NXM headers are treated as
 * errors (with OFPERR_OFPBMC_BAD_MASK).
 */
enum ofperr
nx_pull_header(struct ofpbuf *b, const struct mf_field **field, bool *masked)
{
    enum ofperr error;
    uint32_t header;

    error = nx_pull_header__(b, false, &header, field);
    if (masked) {
        *masked = !error && nxm_hasmask(header);
    } else if (!error && nxm_hasmask(header)) {
        error = OFPERR_OFPBMC_BAD_MASK;
    }
    return error;
}

static enum ofperr
nx_pull_match_entry(struct ofpbuf *b, bool allow_cookie,
                    const struct mf_field **field,
                    union mf_value *value, union mf_value *mask)
{
    enum ofperr error;
    uint32_t header;

    error = nx_pull_entry__(b, allow_cookie, &header, field, value, mask);
    if (error) {
        return error;
    }
    if (field && *field) {
        if (!mf_is_mask_valid(*field, mask)) {
            VLOG_DBG_RL(&rl, "bad mask for field %s", (*field)->name);
            return OFPERR_OFPBMC_BAD_MASK;
        }
        if (!mf_is_value_valid(*field, value)) {
            VLOG_DBG_RL(&rl, "bad value for field %s", (*field)->name);
            return OFPERR_OFPBMC_BAD_VALUE;
        }
    }
    return 0;
}

static enum ofperr
nx_pull_raw(const uint8_t *p, unsigned int match_len, bool strict,
            struct match *match, ovs_be64 *cookie, ovs_be64 *cookie_mask)
{
    struct ofpbuf b;

    ovs_assert((cookie != NULL) == (cookie_mask != NULL));

    match_init_catchall(match);
    if (cookie) {
        *cookie = *cookie_mask = htonll(0);
    }

    ofpbuf_use_const(&b, p, match_len);
    while (ofpbuf_size(&b)) {
        const uint8_t *pos = ofpbuf_data(&b);
        const struct mf_field *field;
        union mf_value value;
        union mf_value mask;
        enum ofperr error;

        error = nx_pull_match_entry(&b, cookie != NULL, &field, &value, &mask);
        if (error) {
            if (error == OFPERR_OFPBMC_BAD_FIELD && !strict) {
                continue;
            }
        } else if (!field) {
            if (!cookie) {
                error = OFPERR_OFPBMC_BAD_FIELD;
            } else if (*cookie_mask) {
                error = OFPERR_OFPBMC_DUP_FIELD;
            } else {
                *cookie = value.be64;
                *cookie_mask = mask.be64;
            }
        } else if (!mf_are_prereqs_ok(field, &match->flow)) {
            error = OFPERR_OFPBMC_BAD_PREREQ;
        } else if (!mf_is_all_wild(field, &match->wc)) {
            error = OFPERR_OFPBMC_DUP_FIELD;
        } else {
            mf_set(field, &value, &mask, match);
        }

        if (error) {
            VLOG_DBG_RL(&rl, "error parsing OXM at offset %"PRIdPTR" "
                        "within match (%s)", pos -
                        p, ofperr_to_string(error));
            return error;
        }
    }

    return 0;
}

static enum ofperr
nx_pull_match__(struct ofpbuf *b, unsigned int match_len, bool strict,
                struct match *match,
                ovs_be64 *cookie, ovs_be64 *cookie_mask)
{
    uint8_t *p = NULL;

    if (match_len) {
        p = ofpbuf_try_pull(b, ROUND_UP(match_len, 8));
        if (!p) {
            VLOG_DBG_RL(&rl, "nx_match length %u, rounded up to a "
                        "multiple of 8, is longer than space in message (max "
                        "length %"PRIu32")", match_len, ofpbuf_size(b));
            return OFPERR_OFPBMC_BAD_LEN;
        }
    }

    return nx_pull_raw(p, match_len, strict, match, cookie, cookie_mask);
}

/* Parses the nx_match formatted match description in 'b' with length
 * 'match_len'.  Stores the results in 'match'.  If 'cookie' and 'cookie_mask'
 * are valid pointers, then stores the cookie and mask in them if 'b' contains
 * a "NXM_NX_COOKIE*" match.  Otherwise, stores 0 in both.
 *
 * Fails with an error upon encountering an unknown NXM header.
 *
 * Returns 0 if successful, otherwise an OpenFlow error code. */
enum ofperr
nx_pull_match(struct ofpbuf *b, unsigned int match_len, struct match *match,
              ovs_be64 *cookie, ovs_be64 *cookie_mask)
{
    return nx_pull_match__(b, match_len, true, match, cookie, cookie_mask);
}

/* Behaves the same as nx_pull_match(), but skips over unknown NXM headers,
 * instead of failing with an error. */
enum ofperr
nx_pull_match_loose(struct ofpbuf *b, unsigned int match_len,
                    struct match *match,
                    ovs_be64 *cookie, ovs_be64 *cookie_mask)
{
    return nx_pull_match__(b, match_len, false, match, cookie, cookie_mask);
}

static enum ofperr
oxm_pull_match__(struct ofpbuf *b, bool strict, struct match *match)
{
    struct ofp11_match_header *omh = ofpbuf_data(b);
    uint8_t *p;
    uint16_t match_len;

    if (ofpbuf_size(b) < sizeof *omh) {
        return OFPERR_OFPBMC_BAD_LEN;
    }

    match_len = ntohs(omh->length);
    if (match_len < sizeof *omh) {
        return OFPERR_OFPBMC_BAD_LEN;
    }

    if (omh->type != htons(OFPMT_OXM)) {
        return OFPERR_OFPBMC_BAD_TYPE;
    }

    p = ofpbuf_try_pull(b, ROUND_UP(match_len, 8));
    if (!p) {
        VLOG_DBG_RL(&rl, "oxm length %u, rounded up to a "
                    "multiple of 8, is longer than space in message (max "
                    "length %"PRIu32")", match_len, ofpbuf_size(b));
        return OFPERR_OFPBMC_BAD_LEN;
    }

    return nx_pull_raw(p + sizeof *omh, match_len - sizeof *omh,
                       strict, match, NULL, NULL);
}

/* Parses the oxm formatted match description preceded by a struct
 * ofp11_match_header in 'b'.  Stores the result in 'match'.
 *
 * Fails with an error when encountering unknown OXM headers.
 *
 * Returns 0 if successful, otherwise an OpenFlow error code. */
enum ofperr
oxm_pull_match(struct ofpbuf *b, struct match *match)
{
    return oxm_pull_match__(b, true, match);
}

/* Behaves the same as oxm_pull_match() with one exception.  Skips over unknown
 * OXM headers instead of failing with an error when they are encountered. */
enum ofperr
oxm_pull_match_loose(struct ofpbuf *b, struct match *match)
{
    return oxm_pull_match__(b, false, match);
}

/* nx_put_match() and helpers.
 *
 * 'put' functions whose names end in 'w' add a wildcarded field.
 * 'put' functions whose names end in 'm' add a field that might be wildcarded.
 * Other 'put' functions add exact-match fields.
 */

static void
nxm_put_header(struct ofpbuf *b, uint32_t header)
{
    ovs_be32 n_header = htonl(header);
    ofpbuf_put(b, &n_header, sizeof n_header);
}

static void
nxm_put_8(struct ofpbuf *b, uint32_t header, uint8_t value)
{
    nxm_put_header(b, header);
    ofpbuf_put(b, &value, sizeof value);
}

static void
nxm_put_8m(struct ofpbuf *b, uint32_t header, uint8_t value, uint8_t mask)
{
    switch (mask) {
    case 0:
        break;

    case UINT8_MAX:
        nxm_put_8(b, header, value);
        break;

    default:
        nxm_put_header(b, nxm_make_wild_header(header));
        ofpbuf_put(b, &value, sizeof value);
        ofpbuf_put(b, &mask, sizeof mask);
    }
}

static void
nxm_put_16(struct ofpbuf *b, uint32_t header, ovs_be16 value)
{
    nxm_put_header(b, header);
    ofpbuf_put(b, &value, sizeof value);
}

static void
nxm_put_16w(struct ofpbuf *b, uint32_t header, ovs_be16 value, ovs_be16 mask)
{
    nxm_put_header(b, header);
    ofpbuf_put(b, &value, sizeof value);
    ofpbuf_put(b, &mask, sizeof mask);
}

static void
nxm_put_16m(struct ofpbuf *b, uint32_t header, ovs_be16 value, ovs_be16 mask)
{
    switch (mask) {
    case 0:
        break;

    case OVS_BE16_MAX:
        nxm_put_16(b, header, value);
        break;

    default:
        nxm_put_16w(b, nxm_make_wild_header(header), value, mask);
        break;
    }
}

static void
nxm_put_32(struct ofpbuf *b, uint32_t header, ovs_be32 value)
{
    nxm_put_header(b, header);
    ofpbuf_put(b, &value, sizeof value);
}

static void
nxm_put_32w(struct ofpbuf *b, uint32_t header, ovs_be32 value, ovs_be32 mask)
{
    nxm_put_header(b, header);
    ofpbuf_put(b, &value, sizeof value);
    ofpbuf_put(b, &mask, sizeof mask);
}

static void
nxm_put_32m(struct ofpbuf *b, uint32_t header, ovs_be32 value, ovs_be32 mask)
{
    switch (mask) {
    case 0:
        break;

    case OVS_BE32_MAX:
        nxm_put_32(b, header, value);
        break;

    default:
        nxm_put_32w(b, nxm_make_wild_header(header), value, mask);
        break;
    }
}

static void
nxm_put_64(struct ofpbuf *b, uint32_t header, ovs_be64 value)
{
    nxm_put_header(b, header);
    ofpbuf_put(b, &value, sizeof value);
}

static void
nxm_put_64w(struct ofpbuf *b, uint32_t header, ovs_be64 value, ovs_be64 mask)
{
    nxm_put_header(b, header);
    ofpbuf_put(b, &value, sizeof value);
    ofpbuf_put(b, &mask, sizeof mask);
}

static void
nxm_put_64m(struct ofpbuf *b, uint32_t header, ovs_be64 value, ovs_be64 mask)
{
    switch (mask) {
    case 0:
        break;

    case OVS_BE64_MAX:
        nxm_put_64(b, header, value);
        break;

    default:
        nxm_put_64w(b, nxm_make_wild_header(header), value, mask);
        break;
    }
}

static void
nxm_put_eth(struct ofpbuf *b, uint32_t header,
            const uint8_t value[ETH_ADDR_LEN])
{
    nxm_put_header(b, header);
    ofpbuf_put(b, value, ETH_ADDR_LEN);
}

static void
nxm_put_eth_masked(struct ofpbuf *b, uint32_t header,
                   const uint8_t value[ETH_ADDR_LEN],
                   const uint8_t mask[ETH_ADDR_LEN])
{
    if (!eth_addr_is_zero(mask)) {
        if (eth_mask_is_exact(mask)) {
            nxm_put_eth(b, header, value);
        } else {
            nxm_put_header(b, nxm_make_wild_header(header));
            ofpbuf_put(b, value, ETH_ADDR_LEN);
            ofpbuf_put(b, mask, ETH_ADDR_LEN);
        }
    }
}

static void
nxm_put_ipv6(struct ofpbuf *b, uint32_t header,
             const struct in6_addr *value, const struct in6_addr *mask)
{
    if (ipv6_mask_is_any(mask)) {
        return;
    } else if (ipv6_mask_is_exact(mask)) {
        nxm_put_header(b, header);
        ofpbuf_put(b, value, sizeof *value);
    } else {
        nxm_put_header(b, nxm_make_wild_header(header));
        ofpbuf_put(b, value, sizeof *value);
        ofpbuf_put(b, mask, sizeof *mask);
    }
}

static void
nxm_put_frag(struct ofpbuf *b, const struct match *match, enum ofp_version oxm)
{
    uint32_t header = mf_oxm_header(MFF_IP_FRAG, oxm);
    uint8_t nw_frag = match->flow.nw_frag;
    uint8_t nw_frag_mask = match->wc.masks.nw_frag;

    switch (nw_frag_mask) {
    case 0:
        break;

    case FLOW_NW_FRAG_MASK:
        nxm_put_8(b, header, nw_frag);
        break;

    default:
        nxm_put_8m(b, header, nw_frag, nw_frag_mask & FLOW_NW_FRAG_MASK);
        break;
    }
}

/* Appends to 'b' a set of OXM or NXM matches for the IPv4 or IPv6 fields in
 * 'match'.  */
static void
nxm_put_ip(struct ofpbuf *b, const struct match *match, enum ofp_version oxm)
{
    const struct flow *flow = &match->flow;

    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        nxm_put_32m(b, mf_oxm_header(MFF_IPV4_SRC, oxm),
                    flow->nw_src, match->wc.masks.nw_src);
        nxm_put_32m(b, mf_oxm_header(MFF_IPV4_DST, oxm),
                    flow->nw_dst, match->wc.masks.nw_dst);
    } else {
        nxm_put_ipv6(b, mf_oxm_header(MFF_IPV6_SRC, oxm),
                     &flow->ipv6_src, &match->wc.masks.ipv6_src);
        nxm_put_ipv6(b, mf_oxm_header(MFF_IPV6_DST, oxm),
                     &flow->ipv6_dst, &match->wc.masks.ipv6_dst);
    }

    nxm_put_frag(b, match, oxm);

    if (match->wc.masks.nw_tos & IP_DSCP_MASK) {
        if (oxm) {
            nxm_put_8(b, mf_oxm_header(MFF_IP_DSCP_SHIFTED, oxm),
                      flow->nw_tos >> 2);
        } else {
            nxm_put_8(b, mf_oxm_header(MFF_IP_DSCP, oxm),
                      flow->nw_tos & IP_DSCP_MASK);
        }
    }

    if (match->wc.masks.nw_tos & IP_ECN_MASK) {
        nxm_put_8(b, mf_oxm_header(MFF_IP_ECN, oxm),
                  flow->nw_tos & IP_ECN_MASK);
    }

    if (!oxm && match->wc.masks.nw_ttl) {
        nxm_put_8(b, mf_oxm_header(MFF_IP_TTL, oxm), flow->nw_ttl);
    }

    nxm_put_32m(b, mf_oxm_header(MFF_IPV6_LABEL, oxm),
                flow->ipv6_label, match->wc.masks.ipv6_label);

    if (match->wc.masks.nw_proto) {
        nxm_put_8(b, mf_oxm_header(MFF_IP_PROTO, oxm), flow->nw_proto);

        if (flow->nw_proto == IPPROTO_TCP) {
            nxm_put_16m(b, mf_oxm_header(MFF_TCP_SRC, oxm),
                        flow->tp_src, match->wc.masks.tp_src);
            nxm_put_16m(b, mf_oxm_header(MFF_TCP_DST, oxm),
                        flow->tp_dst, match->wc.masks.tp_dst);
            nxm_put_16m(b, mf_oxm_header(MFF_TCP_FLAGS, oxm),
                        flow->tcp_flags, match->wc.masks.tcp_flags);
        } else if (flow->nw_proto == IPPROTO_UDP) {
            nxm_put_16m(b, mf_oxm_header(MFF_UDP_SRC, oxm),
                        flow->tp_src, match->wc.masks.tp_src);
            nxm_put_16m(b, mf_oxm_header(MFF_UDP_DST, oxm),
                        flow->tp_dst, match->wc.masks.tp_dst);
        } else if (flow->nw_proto == IPPROTO_SCTP) {
            nxm_put_16m(b, mf_oxm_header(MFF_SCTP_SRC, oxm), flow->tp_src,
                        match->wc.masks.tp_src);
            nxm_put_16m(b, mf_oxm_header(MFF_SCTP_DST, oxm), flow->tp_dst,
                        match->wc.masks.tp_dst);
        } else if (is_icmpv4(flow)) {
            if (match->wc.masks.tp_src) {
                nxm_put_8(b, mf_oxm_header(MFF_ICMPV4_TYPE, oxm),
                          ntohs(flow->tp_src));
            }
            if (match->wc.masks.tp_dst) {
                nxm_put_8(b, mf_oxm_header(MFF_ICMPV4_CODE, oxm),
                          ntohs(flow->tp_dst));
            }
        } else if (is_icmpv6(flow)) {
            if (match->wc.masks.tp_src) {
                nxm_put_8(b, mf_oxm_header(MFF_ICMPV6_TYPE, oxm),
                          ntohs(flow->tp_src));
            }
            if (match->wc.masks.tp_dst) {
                nxm_put_8(b, mf_oxm_header(MFF_ICMPV6_CODE, oxm),
                          ntohs(flow->tp_dst));
            }
            if (flow->tp_src == htons(ND_NEIGHBOR_SOLICIT) ||
                flow->tp_src == htons(ND_NEIGHBOR_ADVERT)) {
                nxm_put_ipv6(b, mf_oxm_header(MFF_ND_TARGET, oxm),
                             &flow->nd_target, &match->wc.masks.nd_target);
                if (flow->tp_src == htons(ND_NEIGHBOR_SOLICIT)) {
                    nxm_put_eth_masked(b, mf_oxm_header(MFF_ND_SLL, oxm),
                                       flow->arp_sha, match->wc.masks.arp_sha);
                }
                if (flow->tp_src == htons(ND_NEIGHBOR_ADVERT)) {
                    nxm_put_eth_masked(b, mf_oxm_header(MFF_ND_TLL, oxm),
                                       flow->arp_tha, match->wc.masks.arp_tha);
                }
            }
        }
    }
}

/* Appends to 'b' the nx_match format that expresses 'match'.  For Flow Mod and
 * Flow Stats Requests messages, a 'cookie' and 'cookie_mask' may be supplied.
 * Otherwise, 'cookie_mask' should be zero.
 *
 * Specify 'oxm' as 0 to express the match in NXM format; otherwise, specify
 * 'oxm' as the OpenFlow version number for the OXM format to use.
 *
 * This function can cause 'b''s data to be reallocated.
 *
 * Returns the number of bytes appended to 'b', excluding padding.
 *
 * If 'match' is a catch-all rule that matches every packet, then this function
 * appends nothing to 'b' and returns 0. */
static int
nx_put_raw(struct ofpbuf *b, enum ofp_version oxm, const struct match *match,
           ovs_be64 cookie, ovs_be64 cookie_mask)
{
    const struct flow *flow = &match->flow;
    const size_t start_len = ofpbuf_size(b);
    int match_len;
    int i;

    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 27);

    /* Metadata. */
    if (match->wc.masks.dp_hash) {
        nxm_put_32m(b, mf_oxm_header(MFF_DP_HASH, oxm),
                    htonl(flow->dp_hash), htonl(match->wc.masks.dp_hash));
    }

    if (match->wc.masks.recirc_id) {
        nxm_put_32(b, mf_oxm_header(MFF_RECIRC_ID, oxm),
                   htonl(flow->recirc_id));
    }

    if (match->wc.masks.in_port.ofp_port) {
        ofp_port_t in_port = flow->in_port.ofp_port;
        if (oxm) {
            nxm_put_32(b, mf_oxm_header(MFF_IN_PORT_OXM, oxm),
                       ofputil_port_to_ofp11(in_port));
        } else {
            nxm_put_16(b, mf_oxm_header(MFF_IN_PORT, oxm),
                       htons(ofp_to_u16(in_port)));
        }
    }

    /* Ethernet. */
    nxm_put_eth_masked(b, mf_oxm_header(MFF_ETH_SRC, oxm),
                       flow->dl_src, match->wc.masks.dl_src);
    nxm_put_eth_masked(b, mf_oxm_header(MFF_ETH_DST, oxm),
                       flow->dl_dst, match->wc.masks.dl_dst);
    nxm_put_16m(b, mf_oxm_header(MFF_ETH_TYPE, oxm),
                ofputil_dl_type_to_openflow(flow->dl_type),
                match->wc.masks.dl_type);

    /* 802.1Q. */
    if (oxm) {
        ovs_be16 VID_CFI_MASK = htons(VLAN_VID_MASK | VLAN_CFI);
        ovs_be16 vid = flow->vlan_tci & VID_CFI_MASK;
        ovs_be16 mask = match->wc.masks.vlan_tci & VID_CFI_MASK;

        if (mask == htons(VLAN_VID_MASK | VLAN_CFI)) {
            nxm_put_16(b, mf_oxm_header(MFF_VLAN_VID, oxm), vid);
        } else if (mask) {
            nxm_put_16m(b, mf_oxm_header(MFF_VLAN_VID, oxm), vid, mask);
        }

        if (vid && vlan_tci_to_pcp(match->wc.masks.vlan_tci)) {
            nxm_put_8(b, mf_oxm_header(MFF_VLAN_PCP, oxm),
                      vlan_tci_to_pcp(flow->vlan_tci));
        }

    } else {
        nxm_put_16m(b, mf_oxm_header(MFF_VLAN_TCI, oxm), flow->vlan_tci,
                    match->wc.masks.vlan_tci);
    }

    /* MPLS. */
    if (eth_type_mpls(flow->dl_type)) {
        if (match->wc.masks.mpls_lse[0] & htonl(MPLS_TC_MASK)) {
            nxm_put_8(b, mf_oxm_header(MFF_MPLS_TC, oxm),
                      mpls_lse_to_tc(flow->mpls_lse[0]));
        }

        if (match->wc.masks.mpls_lse[0] & htonl(MPLS_BOS_MASK)) {
            nxm_put_8(b, mf_oxm_header(MFF_MPLS_BOS, oxm),
                      mpls_lse_to_bos(flow->mpls_lse[0]));
        }

        if (match->wc.masks.mpls_lse[0] & htonl(MPLS_LABEL_MASK)) {
            nxm_put_32(b, mf_oxm_header(MFF_MPLS_LABEL, oxm),
                       htonl(mpls_lse_to_label(flow->mpls_lse[0])));
        }
    }

    /* L3. */
    if (is_ip_any(flow)) {
        nxm_put_ip(b, match, oxm);
    } else if (flow->dl_type == htons(ETH_TYPE_ARP) ||
               flow->dl_type == htons(ETH_TYPE_RARP)) {
        /* ARP. */
        if (match->wc.masks.nw_proto) {
            nxm_put_16(b, mf_oxm_header(MFF_ARP_OP, oxm),
                       htons(flow->nw_proto));
        }
        nxm_put_32m(b, mf_oxm_header(MFF_ARP_SPA, oxm),
                    flow->nw_src, match->wc.masks.nw_src);
        nxm_put_32m(b, mf_oxm_header(MFF_ARP_TPA, oxm),
                    flow->nw_dst, match->wc.masks.nw_dst);
        nxm_put_eth_masked(b, mf_oxm_header(MFF_ARP_SHA, oxm),
                           flow->arp_sha, match->wc.masks.arp_sha);
        nxm_put_eth_masked(b, mf_oxm_header(MFF_ARP_THA, oxm),
                           flow->arp_tha, match->wc.masks.arp_tha);
    }

    /* Tunnel ID. */
    nxm_put_64m(b, mf_oxm_header(MFF_TUN_ID, oxm),
                flow->tunnel.tun_id, match->wc.masks.tunnel.tun_id);

    /* Other tunnel metadata. */
    nxm_put_32m(b, mf_oxm_header(MFF_TUN_SRC, oxm),
                flow->tunnel.ip_src, match->wc.masks.tunnel.ip_src);
    nxm_put_32m(b, mf_oxm_header(MFF_TUN_DST, oxm),
                flow->tunnel.ip_dst, match->wc.masks.tunnel.ip_dst);

    /* Registers. */
    if (oxm < OFP15_VERSION) {
        for (i = 0; i < FLOW_N_REGS; i++) {
            nxm_put_32m(b, mf_oxm_header(MFF_REG0 + i, oxm),
                        htonl(flow->regs[i]), htonl(match->wc.masks.regs[i]));
        }
    } else {
        for (i = 0; i < FLOW_N_XREGS; i++) {
            nxm_put_64m(b, mf_oxm_header(MFF_XREG0 + i, oxm),
                        htonll(flow_get_xreg(flow, i)),
                        htonll(flow_get_xreg(&match->wc.masks, i)));
        }
    }

    /* Mark. */
    nxm_put_32m(b, mf_oxm_header(MFF_PKT_MARK, oxm), htonl(flow->pkt_mark),
                htonl(match->wc.masks.pkt_mark));

    /* OpenFlow 1.1+ Metadata. */
    nxm_put_64m(b, mf_oxm_header(MFF_METADATA, oxm),
                flow->metadata, match->wc.masks.metadata);

    /* Cookie. */
    nxm_put_64m(b, NXM_NX_COOKIE, cookie & cookie_mask, cookie_mask);

    match_len = ofpbuf_size(b) - start_len;
    return match_len;
}

/* Appends to 'b' the nx_match format that expresses 'match', plus enough zero
 * bytes to pad the nx_match out to a multiple of 8.  For Flow Mod and Flow
 * Stats Requests messages, a 'cookie' and 'cookie_mask' may be supplied.
 * Otherwise, 'cookie_mask' should be zero.
 *
 * This function can cause 'b''s data to be reallocated.
 *
 * Returns the number of bytes appended to 'b', excluding padding.  The return
 * value can be zero if it appended nothing at all to 'b' (which happens if
 * 'cr' is a catch-all rule that matches every packet). */
int
nx_put_match(struct ofpbuf *b, const struct match *match,
             ovs_be64 cookie, ovs_be64 cookie_mask)
{
    int match_len = nx_put_raw(b, 0, match, cookie, cookie_mask);

    ofpbuf_put_zeros(b, PAD_SIZE(match_len, 8));
    return match_len;
}

/* Appends to 'b' an struct ofp11_match_header followed by the OXM format that
 * expresses 'cr', plus enough zero bytes to pad the data appended out to a
 * multiple of 8.
 *
 * OXM differs slightly among versions of OpenFlow.  Specify the OpenFlow
 * version in use as 'version'.
 *
 * This function can cause 'b''s data to be reallocated.
 *
 * Returns the number of bytes appended to 'b', excluding the padding.  Never
 * returns zero. */
int
oxm_put_match(struct ofpbuf *b, const struct match *match,
              enum ofp_version version)
{
    int match_len;
    struct ofp11_match_header *omh;
    size_t start_len = ofpbuf_size(b);
    ovs_be64 cookie = htonll(0), cookie_mask = htonll(0);

    ofpbuf_put_uninit(b, sizeof *omh);
    match_len = (nx_put_raw(b, version, match, cookie, cookie_mask)
                 + sizeof *omh);
    ofpbuf_put_zeros(b, PAD_SIZE(match_len, 8));

    omh = ofpbuf_at(b, start_len, sizeof *omh);
    omh->type = htons(OFPMT_OXM);
    omh->length = htons(match_len);

    return match_len;
}

void
nx_put_header(struct ofpbuf *b, enum mf_field_id field,
              enum ofp_version version, bool masked)
{
    uint32_t header = mf_oxm_header(field, version);
    nxm_put_header(b, masked ? nxm_make_wild_header(header) : header);
}

void
nx_put_entry(struct ofpbuf *b,
             enum mf_field_id field, enum ofp_version version,
             const union mf_value *value, const union mf_value *mask)
{
    int n_bytes = mf_from_id(field)->n_bytes;
    bool masked = mask && !is_all_ones(mask, n_bytes);

    nx_put_header(b, field, version, masked);
    ofpbuf_put(b, value, n_bytes);
    if (masked) {
        ofpbuf_put(b, mask, n_bytes);
    }
}

/* nx_match_to_string() and helpers. */

static void format_nxm_field_name(struct ds *, uint32_t header);

char *
nx_match_to_string(const uint8_t *p, unsigned int match_len)
{
    struct ofpbuf b;
    struct ds s;

    if (!match_len) {
        return xstrdup("<any>");
    }

    ofpbuf_use_const(&b, p, match_len);
    ds_init(&s);
    while (ofpbuf_size(&b)) {
        union mf_value value;
        union mf_value mask;
        enum ofperr error;
        uint32_t header;
        int value_len;

        error = nx_pull_entry__(&b, true, &header, NULL, &value, &mask);
        if (error) {
            break;
        }
        value_len = MIN(sizeof value, nxm_field_bytes(header));

        if (s.length) {
            ds_put_cstr(&s, ", ");
        }

        format_nxm_field_name(&s, header);
        ds_put_char(&s, '(');

        for (int i = 0; i < value_len; i++) {
            ds_put_format(&s, "%02x", ((const uint8_t *) &value)[i]);
        }
        if (nxm_hasmask(header)) {
            ds_put_char(&s, '/');
            for (int i = 0; i < value_len; i++) {
                ds_put_format(&s, "%02x", ((const uint8_t *) &mask)[i]);
            }
        }
        ds_put_char(&s, ')');
    }

    if (ofpbuf_size(&b)) {
        if (s.length) {
            ds_put_cstr(&s, ", ");
        }

        ds_put_format(&s, "<%u invalid bytes>", ofpbuf_size(&b));
    }

    return ds_steal_cstr(&s);
}

char *
oxm_match_to_string(const struct ofpbuf *p, unsigned int match_len)
{
    const struct ofp11_match_header *omh = ofpbuf_data(p);
    uint16_t match_len_;
    struct ds s;

    ds_init(&s);

    if (match_len < sizeof *omh) {
        ds_put_format(&s, "<match too short: %u>", match_len);
        goto err;
    }

    if (omh->type != htons(OFPMT_OXM)) {
        ds_put_format(&s, "<bad match type field: %u>", ntohs(omh->type));
        goto err;
    }

    match_len_ = ntohs(omh->length);
    if (match_len_ < sizeof *omh) {
        ds_put_format(&s, "<match length field too short: %u>", match_len_);
        goto err;
    }

    if (match_len_ != match_len) {
        ds_put_format(&s, "<match length field incorrect: %u != %u>",
                      match_len_, match_len);
        goto err;
    }

    return nx_match_to_string(ofpbuf_at(p, sizeof *omh, 0),
                              match_len - sizeof *omh);

err:
    return ds_steal_cstr(&s);
}

void
nx_format_field_name(enum mf_field_id id, enum ofp_version version,
                     struct ds *s)
{
    format_nxm_field_name(s, mf_oxm_header(id, version));
}

static void
format_nxm_field_name(struct ds *s, uint32_t header)
{
    const struct nxm_field *f = nxm_field_by_header(header);
    if (f) {
        ds_put_cstr(s, f->name);
        if (nxm_hasmask(header)) {
            ds_put_cstr(s, "_W");
        }
    } else if (header == NXM_NX_COOKIE) {
        ds_put_cstr(s, "NXM_NX_COOKIE");
    } else if (header == NXM_NX_COOKIE_W) {
        ds_put_cstr(s, "NXM_NX_COOKIE_W");
    } else {
        ds_put_format(s, "%d:%d", nxm_vendor(header), nxm_field(header));
    }
}

static bool
streq_len(const char *a, size_t a_len, const char *b)
{
    return strlen(b) == a_len && !memcmp(a, b, a_len);
}

static uint32_t
parse_nxm_field_name(const char *name, int name_len)
{
    const struct nxm_field *f;
    bool wild;

    f = mf_parse_subfield_name(name, name_len, &wild);
    if (f) {
        if (!wild) {
            return f->header;
        } else if (mf_from_id(f->id)->maskable != MFM_NONE) {
            return nxm_make_wild_header(f->header);
        }
    }

    if (streq_len(name, name_len, "NXM_NX_COOKIE")) {
        return NXM_NX_COOKIE;
    } else if (streq_len(name, name_len, "NXM_NX_COOKIE_W")) {
        return NXM_NX_COOKIE_W;
    }

    /* Check whether it's a 32-bit field header value as hex.
     * (This isn't ordinarily useful except for testing error behavior.) */
    if (name_len == 8) {
        uint32_t header = hexits_value(name, name_len, NULL);
        if (header != UINT_MAX) {
            return header;
        }
    }

    return 0;
}

/* nx_match_from_string(). */

static int
nx_match_from_string_raw(const char *s, struct ofpbuf *b)
{
    const char *full_s = s;
    const size_t start_len = ofpbuf_size(b);

    if (!strcmp(s, "<any>")) {
        /* Ensure that 'ofpbuf_data(b)' isn't actually null. */
        ofpbuf_prealloc_tailroom(b, 1);
        return 0;
    }

    for (s += strspn(s, ", "); *s; s += strspn(s, ", ")) {
        const char *name;
        uint32_t header;
        int name_len;
        size_t n;

        name = s;
        name_len = strcspn(s, "(");
        if (s[name_len] != '(') {
            ovs_fatal(0, "%s: missing ( at end of nx_match", full_s);
        }

        header = parse_nxm_field_name(name, name_len);
        if (!header) {
            ovs_fatal(0, "%s: unknown field `%.*s'", full_s, name_len, s);
        }

        s += name_len + 1;

        nxm_put_header(b, header);
        s = ofpbuf_put_hex(b, s, &n);
        if (n != nxm_field_bytes(header)) {
            ovs_fatal(0, "%.2s: hex digits expected", s);
        }
        if (nxm_hasmask(header)) {
            s += strspn(s, " ");
            if (*s != '/') {
                ovs_fatal(0, "%s: missing / in masked field %.*s",
                          full_s, name_len, name);
            }
            s = ofpbuf_put_hex(b, s + 1, &n);
            if (n != nxm_field_bytes(header)) {
                ovs_fatal(0, "%.2s: hex digits expected", s);
            }
        }

        s += strspn(s, " ");
        if (*s != ')') {
            ovs_fatal(0, "%s: missing ) following field %.*s",
                      full_s, name_len, name);
        }
        s++;
    }

    return ofpbuf_size(b) - start_len;
}

int
nx_match_from_string(const char *s, struct ofpbuf *b)
{
    int match_len = nx_match_from_string_raw(s, b);
    ofpbuf_put_zeros(b, PAD_SIZE(match_len, 8));
    return match_len;
}

int
oxm_match_from_string(const char *s, struct ofpbuf *b)
{
    int match_len;
    struct ofp11_match_header *omh;
    size_t start_len = ofpbuf_size(b);

    ofpbuf_put_uninit(b, sizeof *omh);
    match_len = nx_match_from_string_raw(s, b) + sizeof *omh;
    ofpbuf_put_zeros(b, PAD_SIZE(match_len, 8));

    omh = ofpbuf_at(b, start_len, sizeof *omh);
    omh->type = htons(OFPMT_OXM);
    omh->length = htons(match_len);

    return match_len;
}

/* Parses 's' as a "move" action, in the form described in ovs-ofctl(8), into
 * '*move'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * WARN_UNUSED_RESULT
nxm_parse_reg_move(struct ofpact_reg_move *move, const char *s)
{
    const char *full_s = s;
    char *error;

    error = mf_parse_subfield__(&move->src, &s);
    if (error) {
        return error;
    }
    if (strncmp(s, "->", 2)) {
        return xasprintf("%s: missing `->' following source", full_s);
    }
    s += 2;
    error = mf_parse_subfield(&move->dst, s);
    if (error) {
        return error;
    }

    if (move->src.n_bits != move->dst.n_bits) {
        return xasprintf("%s: source field is %d bits wide but destination is "
                         "%d bits wide", full_s,
                         move->src.n_bits, move->dst.n_bits);
    }
    return NULL;
}

/* nxm_format_reg_move(). */

void
nxm_format_reg_move(const struct ofpact_reg_move *move, struct ds *s)
{
    ds_put_format(s, "move:");
    mf_format_subfield(&move->src, s);
    ds_put_cstr(s, "->");
    mf_format_subfield(&move->dst, s);
}


enum ofperr
nxm_reg_move_check(const struct ofpact_reg_move *move, const struct flow *flow)
{
    enum ofperr error;

    error = mf_check_src(&move->src, flow);
    if (error) {
        return error;
    }

    return mf_check_dst(&move->dst, NULL);
}

/* nxm_execute_reg_move(). */

void
nxm_execute_reg_move(const struct ofpact_reg_move *move,
                     struct flow *flow, struct flow_wildcards *wc)
{
    union mf_value src_value;
    union mf_value dst_value;

    mf_mask_field_and_prereqs(move->dst.field, &wc->masks);
    mf_mask_field_and_prereqs(move->src.field, &wc->masks);

    mf_get_value(move->dst.field, flow, &dst_value);
    mf_get_value(move->src.field, flow, &src_value);
    bitwise_copy(&src_value, move->src.field->n_bytes, move->src.ofs,
                 &dst_value, move->dst.field->n_bytes, move->dst.ofs,
                 move->src.n_bits);
    mf_set_flow_value(move->dst.field, &dst_value, flow);
}

void
nxm_reg_load(const struct mf_subfield *dst, uint64_t src_data,
             struct flow *flow, struct flow_wildcards *wc)
{
    union mf_subvalue src_subvalue;
    union mf_subvalue mask_value;
    ovs_be64 src_data_be = htonll(src_data);

    memset(&mask_value, 0xff, sizeof mask_value);
    mf_write_subfield_flow(dst, &mask_value, &wc->masks);

    bitwise_copy(&src_data_be, sizeof src_data_be, 0,
                 &src_subvalue, sizeof src_subvalue, 0,
                 sizeof src_data_be * 8);
    mf_write_subfield_flow(dst, &src_subvalue, flow);
}

/* nxm_parse_stack_action, works for both push() and pop(). */

/* Parses 's' as a "push" or "pop" action, in the form described in
 * ovs-ofctl(8), into '*stack_action'.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * WARN_UNUSED_RESULT
nxm_parse_stack_action(struct ofpact_stack *stack_action, const char *s)
{
    char *error;

    error = mf_parse_subfield__(&stack_action->subfield, &s);
    if (error) {
        return error;
    }

    if (*s != '\0') {
        return xasprintf("%s: trailing garbage following push or pop", s);
    }

    return NULL;
}

void
nxm_format_stack_push(const struct ofpact_stack *push, struct ds *s)
{
    ds_put_cstr(s, "push:");
    mf_format_subfield(&push->subfield, s);
}

void
nxm_format_stack_pop(const struct ofpact_stack *pop, struct ds *s)
{
    ds_put_cstr(s, "pop:");
    mf_format_subfield(&pop->subfield, s);
}

enum ofperr
nxm_stack_push_check(const struct ofpact_stack *push,
                     const struct flow *flow)
{
    return mf_check_src(&push->subfield, flow);
}

enum ofperr
nxm_stack_pop_check(const struct ofpact_stack *pop,
                    const struct flow *flow)
{
    return mf_check_dst(&pop->subfield, flow);
}

/* nxm_execute_stack_push(), nxm_execute_stack_pop(). */
static void
nx_stack_push(struct ofpbuf *stack, union mf_subvalue *v)
{
    ofpbuf_put(stack, v, sizeof *v);
}

static union mf_subvalue *
nx_stack_pop(struct ofpbuf *stack)
{
    union mf_subvalue *v = NULL;

    if (ofpbuf_size(stack)) {

        ofpbuf_set_size(stack, ofpbuf_size(stack) - sizeof *v);
        v = (union mf_subvalue *) ofpbuf_tail(stack);
    }

    return v;
}

void
nxm_execute_stack_push(const struct ofpact_stack *push,
                       const struct flow *flow, struct flow_wildcards *wc,
                       struct ofpbuf *stack)
{
    union mf_subvalue mask_value;
    union mf_subvalue dst_value;

    memset(&mask_value, 0xff, sizeof mask_value);
    mf_write_subfield_flow(&push->subfield, &mask_value, &wc->masks);

    mf_read_subfield(&push->subfield, flow, &dst_value);
    nx_stack_push(stack, &dst_value);
}

void
nxm_execute_stack_pop(const struct ofpact_stack *pop,
                      struct flow *flow, struct flow_wildcards *wc,
                      struct ofpbuf *stack)
{
    union mf_subvalue *src_value;

    src_value = nx_stack_pop(stack);

    /* Only pop if stack is not empty. Otherwise, give warning. */
    if (src_value) {
        union mf_subvalue mask_value;

        memset(&mask_value, 0xff, sizeof mask_value);
        mf_write_subfield_flow(&pop->subfield, &mask_value, &wc->masks);
        mf_write_subfield_flow(&pop->subfield, src_value, flow);
    } else {
        if (!VLOG_DROP_WARN(&rl)) {
            char *flow_str = flow_to_string(flow);
            VLOG_WARN_RL(&rl, "Failed to pop from an empty stack. On flow \n"
                           " %s", flow_str);
            free(flow_str);
        }
    }
}

/* Formats 'sf' into 's' in a format normally acceptable to
 * mf_parse_subfield().  (It won't be acceptable if sf->field is NULL or if
 * sf->field has no NXM name.) */
void
mf_format_subfield(const struct mf_subfield *sf, struct ds *s)
{
    if (!sf->field) {
        ds_put_cstr(s, "<unknown>");
    } else {
        const struct nxm_field *f = nxm_field_from_mf_field(sf->field->id, 0);
        ds_put_cstr(s, f ? f->name : sf->field->name);
    }

    if (sf->field && sf->ofs == 0 && sf->n_bits == sf->field->n_bits) {
        ds_put_cstr(s, "[]");
    } else if (sf->n_bits == 1) {
        ds_put_format(s, "[%d]", sf->ofs);
    } else {
        ds_put_format(s, "[%d..%d]", sf->ofs, sf->ofs + sf->n_bits - 1);
    }
}

static const struct nxm_field *
mf_parse_subfield_name(const char *name, int name_len, bool *wild)
{
    *wild = name_len > 2 && !memcmp(&name[name_len - 2], "_W", 2);
    if (*wild) {
        name_len -= 2;
    }

    return nxm_field_by_name(name, name_len);
}

/* Parses a subfield from the beginning of '*sp' into 'sf'.  If successful,
 * returns NULL and advances '*sp' to the first byte following the parsed
 * string.  On failure, returns a malloc()'d error message, does not modify
 * '*sp', and does not properly initialize 'sf'.
 *
 * The syntax parsed from '*sp' takes the form "header[start..end]" where
 * 'header' is the name of an NXM field and 'start' and 'end' are (inclusive)
 * bit indexes.  "..end" may be omitted to indicate a single bit.  "start..end"
 * may both be omitted (the [] are still required) to indicate an entire
 * field. */
char * WARN_UNUSED_RESULT
mf_parse_subfield__(struct mf_subfield *sf, const char **sp)
{
    const struct mf_field *field;
    const struct nxm_field *f;
    const char *name;
    int start, end;
    const char *s;
    int name_len;
    bool wild;

    s = *sp;
    name = s;
    name_len = strcspn(s, "[");
    if (s[name_len] != '[') {
        return xasprintf("%s: missing [ looking for field name", *sp);
    }

    f = mf_parse_subfield_name(name, name_len, &wild);
    if (!f) {
        return xasprintf("%s: unknown field `%.*s'", *sp, name_len, s);
    }
    field = mf_from_id(f->id);

    s += name_len;
    if (ovs_scan(s, "[%d..%d]", &start, &end)) {
        /* Nothing to do. */
    } else if (ovs_scan(s, "[%d]", &start)) {
        end = start;
    } else if (!strncmp(s, "[]", 2)) {
        start = 0;
        end = field->n_bits - 1;
    } else {
        return xasprintf("%s: syntax error expecting [] or [<bit>] or "
                         "[<start>..<end>]", *sp);
    }
    s = strchr(s, ']') + 1;

    if (start > end) {
        return xasprintf("%s: starting bit %d is after ending bit %d",
                         *sp, start, end);
    } else if (start >= field->n_bits) {
        return xasprintf("%s: starting bit %d is not valid because field is "
                         "only %d bits wide", *sp, start, field->n_bits);
    } else if (end >= field->n_bits){
        return xasprintf("%s: ending bit %d is not valid because field is "
                         "only %d bits wide", *sp, end, field->n_bits);
    }

    sf->field = field;
    sf->ofs = start;
    sf->n_bits = end - start + 1;

    *sp = s;
    return NULL;
}

/* Parses a subfield from the entirety of 's' into 'sf'.  Returns NULL if
 * successful, otherwise a malloc()'d string describing the error.  The caller
 * is responsible for freeing the returned string.
 *
 * The syntax parsed from 's' takes the form "header[start..end]" where
 * 'header' is the name of an NXM field and 'start' and 'end' are (inclusive)
 * bit indexes.  "..end" may be omitted to indicate a single bit.  "start..end"
 * may both be omitted (the [] are still required) to indicate an entire
 * field.  */
char * WARN_UNUSED_RESULT
mf_parse_subfield(struct mf_subfield *sf, const char *s)
{
    char *error = mf_parse_subfield__(sf, &s);
    if (!error && s[0]) {
        error = xstrdup("unexpected input following field syntax");
    }
    return error;
}

/* Returns an bitmap in which each bit corresponds to the like-numbered field
 * in the OFPXMC12_OPENFLOW_BASIC OXM class, in which the bit values are taken
 * from the 'fields' bitmap.  Only fields defined in OpenFlow 'version' are
 * considered.
 *
 * This is useful for encoding OpenFlow 1.2 table stats messages. */
ovs_be64
oxm_bitmap_from_mf_bitmap(const struct mf_bitmap *fields,
                          enum ofp_version version)
{
    uint64_t oxm_bitmap = 0;
    int i;

    BITMAP_FOR_EACH_1 (i, MFF_N_IDS, fields->bm) {
        uint32_t oxm = mf_oxm_header(i, version);
        uint32_t vendor = nxm_vendor(oxm);
        int field = nxm_field(oxm);

        if (vendor == OFPXMC12_OPENFLOW_BASIC && field < 64) {
            oxm_bitmap |= UINT64_C(1) << field;
        }
    }
    return htonll(oxm_bitmap);
}

/* Opposite conversion from oxm_bitmap_from_mf_bitmap().
 *
 * This is useful for decoding OpenFlow 1.2 table stats messages. */
struct mf_bitmap
oxm_bitmap_to_mf_bitmap(ovs_be64 oxm_bitmap, enum ofp_version version)
{
    struct mf_bitmap fields = MF_BITMAP_INITIALIZER;

    for (enum mf_field_id id = 0; id < MFF_N_IDS; id++) {
        if (version >= mf_oxm_version(id)) {
            uint32_t oxm = mf_oxm_header(id, version);
            uint32_t vendor = nxm_vendor(oxm);
            int field = nxm_field(oxm);

            if (vendor == OFPXMC12_OPENFLOW_BASIC
                && field < 64
                && oxm_bitmap & htonll(UINT64_C(1) << field)) {
                bitmap_set1(fields.bm, id);
            }
        }
    }
    return fields;
}

/* Returns a bitmap of fields that can be encoded in OXM and that can be
 * modified with a "set_field" action.  */
struct mf_bitmap
oxm_writable_fields(void)
{
    struct mf_bitmap b = MF_BITMAP_INITIALIZER;
    int i;

    for (i = 0; i < MFF_N_IDS; i++) {
        if (mf_oxm_header(i, 0) && mf_from_id(i)->writable) {
            bitmap_set1(b.bm, i);
        }
    }
    return b;
}

/* Returns a bitmap of fields that can be encoded in OXM and that can be
 * matched in a flow table.  */
struct mf_bitmap
oxm_matchable_fields(void)
{
    struct mf_bitmap b = MF_BITMAP_INITIALIZER;
    int i;

    for (i = 0; i < MFF_N_IDS; i++) {
        if (mf_oxm_header(i, 0)) {
            bitmap_set1(b.bm, i);
        }
    }
    return b;
}

/* Returns a bitmap of fields that can be encoded in OXM and that can be
 * matched in a flow table with an arbitrary bitmask.  */
struct mf_bitmap
oxm_maskable_fields(void)
{
    struct mf_bitmap b = MF_BITMAP_INITIALIZER;
    int i;

    for (i = 0; i < MFF_N_IDS; i++) {
        if (mf_oxm_header(i, 0) && mf_from_id(i)->maskable == MFM_FULLY) {
            bitmap_set1(b.bm, i);
        }
    }
    return b;
}

struct nxm_field_index {
    struct hmap_node header_node;
    struct hmap_node name_node;
    struct nxm_field nf;
};

#include "nx-match.inc"

static struct hmap nxm_header_map;
static struct hmap nxm_name_map;
static struct nxm_field *nxm_fields[MFF_N_IDS];
static struct nxm_field *oxm_fields[MFF_N_IDS];

static void
nxm_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    if (ovsthread_once_start(&once)) {
        hmap_init(&nxm_header_map);
        hmap_init(&nxm_name_map);
        for (struct nxm_field_index *nfi = all_nxm_fields;
             nfi < &all_nxm_fields[ARRAY_SIZE(all_nxm_fields)]; nfi++) {
            hmap_insert(&nxm_header_map, &nfi->header_node,
                        hash_int(nfi->nf.header, 0));
            hmap_insert(&nxm_name_map, &nfi->name_node,
                        hash_string(nfi->nf.name, 0));
            if (is_nxm_header(nfi->nf.header)) {
                nxm_fields[nfi->nf.id] = &nfi->nf;
            } else {
                oxm_fields[nfi->nf.id] = &nfi->nf;
            }
        }
        ovsthread_once_done(&once);
    }
}

static const struct nxm_field *
nxm_field_by_header(uint32_t header)
{
    const struct nxm_field_index *nfi;

    nxm_init();
    if (nxm_hasmask(header)) {
        header = nxm_make_exact_header(header);
    }

    HMAP_FOR_EACH_IN_BUCKET (nfi, header_node, hash_int(header, 0),
                             &nxm_header_map) {
        if (header == nfi->nf.header) {
            return &nfi->nf;
        }
    }
    return NULL;
}

static const struct nxm_field *
nxm_field_by_name(const char *name, size_t len)
{
    const struct nxm_field_index *nfi;

    nxm_init();
    HMAP_FOR_EACH_WITH_HASH (nfi, name_node, hash_bytes(name, len, 0),
                             &nxm_name_map) {
        if (strlen(nfi->nf.name) == len && !memcmp(nfi->nf.name, name, len)) {
            return &nfi->nf;
        }
    }
    return NULL;
}

static const struct nxm_field *
nxm_field_by_mf_id(enum mf_field_id id)
{
    nxm_init();
    return nxm_fields[id];
}

static const struct nxm_field *
oxm_field_by_mf_id(enum mf_field_id id)
{
    nxm_init();
    return oxm_fields[id];
}


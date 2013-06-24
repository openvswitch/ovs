/*
 * Copyright (c) 2012, 2013 Nicira, Inc.
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
#include "ofp-errors.h"
#include <errno.h>
#include "byte-order.h"
#include "dynamic-string.h"
#include "ofp-msgs.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ofp_errors);

struct triplet {
    uint32_t vendor;
    int type, code;
};

#include "ofp-errors.inc"

/* Returns an ofperr_domain that corresponds to the OpenFlow version number
 * 'version' (one of the possible values of struct ofp_header's 'version'
 * member).  Returns NULL if the version isn't defined or isn't understood by
 * OVS. */
static const struct ofperr_domain *
ofperr_domain_from_version(enum ofp_version version)
{
    switch (version) {
    case OFP10_VERSION:
        return &ofperr_of10;
    case OFP11_VERSION:
        return &ofperr_of11;
    case OFP12_VERSION:
        return &ofperr_of12;
    case OFP13_VERSION:
        return &ofperr_of13;
    default:
        return NULL;
    }
}

/* Returns the name (e.g. "OpenFlow 1.0") of OpenFlow version 'version'. */
const char *
ofperr_domain_get_name(enum ofp_version version)
{
    const struct ofperr_domain *domain = ofperr_domain_from_version(version);
    return domain ? domain->name : NULL;
}

/* Returns true if 'error' is a valid OFPERR_* value, false otherwise. */
bool
ofperr_is_valid(enum ofperr error)
{
    return error >= OFPERR_OFS && error < OFPERR_OFS + OFPERR_N_ERRORS;
}

/* Returns the OFPERR_* value that corresponds to 'type' and 'code' within
 * 'version', or 0 if either no such OFPERR_* value exists or 'version' is
 * unknown. */
static enum ofperr
ofperr_decode(enum ofp_version version,
              uint32_t vendor, uint16_t type, uint16_t code)
{
    const struct ofperr_domain *domain = ofperr_domain_from_version(version);
    return domain ? domain->decode(vendor, type, code) : 0;
}

/* Returns the name of 'error', e.g. "OFPBRC_BAD_TYPE" if 'error' is
 * OFPBRC_BAD_TYPE, or "<invalid>" if 'error' is not a valid OFPERR_* value.
 *
 * Consider ofperr_to_string() instead, if the error code might be an errno
 * value. */
const char *
ofperr_get_name(enum ofperr error)
{
    return (ofperr_is_valid(error)
            ? error_names[error - OFPERR_OFS]
            : "<invalid>");
}

/* Returns the OFPERR_* value that corresponds for 'name', 0 if none exists.
 * For example, returns OFPERR_OFPHFC_INCOMPATIBLE if 'name' is
 * "OFPHFC_INCOMPATIBLE".
 *
 * This is probably useful only for debugging and testing. */
enum ofperr
ofperr_from_name(const char *name)
{
    int i;

    for (i = 0; i < OFPERR_N_ERRORS; i++) {
        if (!strcmp(name, error_names[i])) {
            return i + OFPERR_OFS;
        }
    }
    return 0;
}

/* Returns an extended description name of 'error', e.g. "ofp_header.type not
 * supported." if 'error' is OFPBRC_BAD_TYPE, or "<invalid>" if 'error' is not
 * a valid OFPERR_* value. */
const char *
ofperr_get_description(enum ofperr error)
{
    return (ofperr_is_valid(error)
            ? error_comments[error - OFPERR_OFS]
            : "<invalid>");
}

static const struct triplet *
ofperr_get_triplet__(enum ofperr error, const struct ofperr_domain *domain)
{
    size_t ofs = error - OFPERR_OFS;

    ovs_assert(ofperr_is_valid(error));
    return &domain->errors[ofs];
}

static struct ofpbuf *
ofperr_encode_msg__(enum ofperr error, enum ofp_version ofp_version,
                    ovs_be32 xid, const void *data, size_t data_len)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    const struct ofperr_domain *domain;
    const struct triplet *triplet;
    struct ofp_error_msg *oem;
    struct ofpbuf *buf;

    /* Get the error domain for 'ofp_version', or fall back to OF1.0. */
    domain = ofperr_domain_from_version(ofp_version);
    if (!domain) {
        VLOG_ERR_RL(&rl, "cannot encode error for unknown OpenFlow "
                    "version 0x%02x", ofp_version);
        domain = &ofperr_of10;
    }

    /* Make sure 'error' is valid in 'domain', or use a fallback error. */
    if (!ofperr_is_valid(error)) {
        /* 'error' seems likely to be a system errno value. */
        VLOG_ERR_RL(&rl, "invalid OpenFlow error code %d (%s)",
                    error, ovs_strerror(error));
        error = OFPERR_NXBRC_UNENCODABLE_ERROR;
    } else if (domain->errors[error - OFPERR_OFS].code < 0) {
        VLOG_ERR_RL(&rl, "cannot encode %s for %s",
                    ofperr_get_name(error), domain->name);
        error = OFPERR_NXBRC_UNENCODABLE_ERROR;
    }

    triplet = ofperr_get_triplet__(error, domain);
    if (!triplet->vendor) {
        buf = ofpraw_alloc_xid(OFPRAW_OFPT_ERROR, domain->version, xid,
                               sizeof *oem + data_len);

        oem = ofpbuf_put_uninit(buf, sizeof *oem);
        oem->type = htons(triplet->type);
        oem->code = htons(triplet->code);
    } else if (ofp_version <= OFP11_VERSION) {
        struct nx_vendor_error *nve;

        buf = ofpraw_alloc_xid(OFPRAW_OFPT_ERROR, domain->version, xid,
                               sizeof *oem + sizeof *nve + data_len);

        oem = ofpbuf_put_uninit(buf, sizeof *oem);
        oem->type = htons(NXET_VENDOR);
        oem->code = htons(NXVC_VENDOR_ERROR);

        nve = ofpbuf_put_uninit(buf, sizeof *nve);
        nve->vendor = htonl(triplet->vendor);
        nve->type = htons(triplet->type);
        nve->code = htons(triplet->code);
    } else {
        ovs_be32 vendor = htonl(triplet->vendor);

        buf = ofpraw_alloc_xid(OFPRAW_OFPT_ERROR, domain->version, xid,
                               sizeof *oem + sizeof(uint32_t) + data_len);

        oem = ofpbuf_put_uninit(buf, sizeof *oem);
        oem->type = htons(OFPET12_EXPERIMENTER);
        oem->code = htons(triplet->type);
        ofpbuf_put(buf, &vendor, sizeof vendor);
    }

    ofpbuf_put(buf, data, data_len);
    ofpmsg_update_length(buf);

    return buf;
}

/* Creates and returns an OpenFlow message of type OFPT_ERROR that conveys the
 * given 'error'.
 *
 * 'oh->version' determines the OpenFlow version of the error reply.
 * 'oh->xid' determines the xid of the error reply.
 * The error reply will contain an initial subsequence of 'oh', up to
 * 'oh->length' or 64 bytes, whichever is shorter.
 *
 * This function isn't appropriate for encoding OFPET_HELLO_FAILED error
 * messages.  Use ofperr_encode_hello() instead. */
struct ofpbuf *
ofperr_encode_reply(enum ofperr error, const struct ofp_header *oh)
{
    uint16_t len = ntohs(oh->length);

    return ofperr_encode_msg__(error, oh->version, oh->xid, oh, MIN(len, 64));
}

/* Creates and returns an OpenFlow message of type OFPT_ERROR that conveys the
 * given 'error', in the error domain 'domain'.  The error message will include
 * the additional null-terminated text string 's'.
 *
 * If 'version' is an unknown version then OFP10_VERSION is used.
 * OFPET_HELLO_FAILED error messages are supposed to be backward-compatible,
 * so in theory this should work. */
struct ofpbuf *
ofperr_encode_hello(enum ofperr error, enum ofp_version ofp_version,
                    const char *s)
{
    return ofperr_encode_msg__(error, ofp_version, htonl(0), s, strlen(s));
}

int
ofperr_get_vendor(enum ofperr error, enum ofp_version version)
{
    const struct ofperr_domain *domain = ofperr_domain_from_version(version);
    return domain ? ofperr_get_triplet__(error, domain)->vendor : -1;
}

/* Returns the value that would go into an OFPT_ERROR message's 'type' for
 * encoding 'error' in 'domain'.  Returns -1 if 'error' is not encodable in
 * 'version' or 'version' is unknown.
 *
 * 'error' must be a valid OFPERR_* code, as checked by ofperr_is_valid(). */
int
ofperr_get_type(enum ofperr error, enum ofp_version version)
{
    const struct ofperr_domain *domain = ofperr_domain_from_version(version);
    return domain ? ofperr_get_triplet__(error, domain)->type : -1;
}

/* Returns the value that would go into an OFPT_ERROR message's 'code' for
 * encoding 'error' in 'domain'.  Returns -1 if 'error' is not encodable in
 * 'version', 'version' is unknown or if 'error' represents a category
 * rather than a specific error.
 *
 *
 * 'error' must be a valid OFPERR_* code, as checked by ofperr_is_valid(). */
int
ofperr_get_code(enum ofperr error, enum ofp_version version)
{
    const struct ofperr_domain *domain = ofperr_domain_from_version(version);
    return domain ? ofperr_get_triplet__(error, domain)->code : -1;
}

/* Tries to decode 'oh', which should be an OpenFlow OFPT_ERROR message.
 * Returns an OFPERR_* constant on success, 0 on failure.
 *
 * If 'payload' is nonnull, on success '*payload' is initialized to the
 * error's payload, and on failure it is cleared. */
enum ofperr
ofperr_decode_msg(const struct ofp_header *oh, struct ofpbuf *payload)
{
    const struct ofp_error_msg *oem;
    enum ofpraw raw;
    uint16_t type, code;
    enum ofperr error;
    uint32_t vendor;
    struct ofpbuf b;

    if (payload) {
        memset(payload, 0, sizeof *payload);
    }

    /* Pull off the error message. */
    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    error = ofpraw_pull(&raw, &b);
    if (error) {
        return 0;
    }
    oem = ofpbuf_pull(&b, sizeof *oem);

    /* Get the error type and code. */
    vendor = 0;
    type = ntohs(oem->type);
    code = ntohs(oem->code);
    if (type == NXET_VENDOR && code == NXVC_VENDOR_ERROR) {
        const struct nx_vendor_error *nve = ofpbuf_try_pull(&b, sizeof *nve);
        if (!nve) {
            return 0;
        }

        vendor = ntohl(nve->vendor);
        type = ntohs(nve->type);
        code = ntohs(nve->code);
    } else if (type == OFPET12_EXPERIMENTER) {
        const ovs_be32 *vendorp = ofpbuf_try_pull(&b, sizeof *vendorp);
        if (!vendorp) {
            return 0;
        }

        vendor = ntohl(*vendorp);
        type = code;
        code = 0;
    }

    /* Translate the error type and code into an ofperr. */
    error = ofperr_decode(oh->version, vendor, type, code);
    if (error && payload) {
        ofpbuf_use_const(payload, b.data, b.size);
    }
    return error;
}

/* If 'error' is a valid OFPERR_* value, returns its name
 * (e.g. "OFPBRC_BAD_TYPE" for OFPBRC_BAD_TYPE).  Otherwise, assumes that
 * 'error' is a positive errno value and returns what ovs_strerror() produces
 * for 'error'.  */
const char *
ofperr_to_string(enum ofperr error)
{
    return (ofperr_is_valid(error)
            ? ofperr_get_name(error)
            : ovs_strerror(error));
}

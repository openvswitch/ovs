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

struct pair {
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

/* Returns true if 'error' is a valid OFPERR_* value that designates a whole
 * category of errors instead of a particular error, e.g. if it is an
 * OFPERR_OFPET_* value, and false otherwise.  */
bool
ofperr_is_category(enum ofperr error)
{
    return (ofperr_is_valid(error)
            && ofperr_of10.errors[error - OFPERR_OFS].code == -1
            && ofperr_of11.errors[error - OFPERR_OFS].code == -1);
}

/* Returns true if 'error' is a valid OFPERR_* value that is a Nicira
 * extension, e.g. if it is an OFPERR_NX* value, and false otherwise. */
bool
ofperr_is_nx_extension(enum ofperr error)
{
    return (ofperr_is_valid(error)
            && (ofperr_of10.errors[error - OFPERR_OFS].code >= 0x100 ||
                ofperr_of11.errors[error - OFPERR_OFS].code >= 0x100));
}

/* Returns true if 'error' can be encoded as an OpenFlow error message in
 * 'domain', false otherwise.
 *
 * A given error may not be encodable in some domains because each OpenFlow
 * version tends to introduce new errors and retire some old ones. */
bool
ofperr_is_encodable(enum ofperr error, enum ofp_version version)
{
    const struct ofperr_domain *domain = ofperr_domain_from_version(version);
    return (ofperr_is_valid(error)
            && domain && domain->errors[error - OFPERR_OFS].code >= 0);
}

/* Returns the OFPERR_* value that corresponds to 'type' and 'code' within
 * 'version', or 0 if either no such OFPERR_* value exists or 'version' is
 * unknown. */
enum ofperr
ofperr_decode(enum ofp_version version, uint16_t type, uint16_t code)
{
    const struct ofperr_domain *domain = ofperr_domain_from_version(version);
    return domain ? domain->decode(type, code) : 0;
}

/* Returns the OFPERR_* value that corresponds to the category 'type' within
 * 'version', or 0 if either no such OFPERR_* value exists or 'version' is
 * unknown. */
enum ofperr
ofperr_decode_type(enum ofp_version version, uint16_t type)
{
    const struct ofperr_domain *domain = ofperr_domain_from_version(version);
    return domain ? domain->decode_type(type) : 0;
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

static const struct pair *
ofperr_get_pair__(enum ofperr error, const struct ofperr_domain *domain)
{
    size_t ofs = error - OFPERR_OFS;

    assert(ofperr_is_valid(error));
    return &domain->errors[ofs];
}

static struct ofpbuf *
ofperr_encode_msg__(enum ofperr error, enum ofp_version ofp_version,
                    ovs_be32 xid, const void *data, size_t data_len)
{
    struct ofp_error_msg *oem;
    const struct pair *pair;
    struct ofpbuf *buf;
    const struct ofperr_domain *domain;

    domain = ofperr_domain_from_version(ofp_version);
    if (!domain) {
        return NULL;
    }

    if (!ofperr_is_encodable(error, ofp_version)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        if (!ofperr_is_valid(error)) {
            /* 'error' seems likely to be a system errno value. */
            VLOG_WARN_RL(&rl, "invalid OpenFlow error code %d (%s)",
                         error, strerror(error));
        } else {
            const char *s = ofperr_get_name(error);
            if (ofperr_is_category(error)) {
                VLOG_WARN_RL(&rl, "cannot encode error category (%s)", s);
            } else {
                VLOG_WARN_RL(&rl, "cannot encode %s for %s", s, domain->name);
            }
        }

        return NULL;
    }

    pair = ofperr_get_pair__(error, domain);
    if (!ofperr_is_nx_extension(error)) {
        buf = ofpraw_alloc_xid(OFPRAW_OFPT_ERROR, domain->version, xid,
                               sizeof *oem + data_len);

        oem = ofpbuf_put_uninit(buf, sizeof *oem);
        oem->type = htons(pair->type);
        oem->code = htons(pair->code);
    } else {
        struct nx_vendor_error *nve;

        buf = ofpraw_alloc_xid(OFPRAW_OFPT_ERROR, domain->version, xid,
                               sizeof *oem + sizeof *nve + data_len);

        oem = ofpbuf_put_uninit(buf, sizeof *oem);
        oem->type = htons(NXET_VENDOR);
        oem->code = htons(NXVC_VENDOR_ERROR);

        nve = ofpbuf_put_uninit(buf, sizeof *nve);
        nve->vendor = htonl(NX_VENDOR_ID);
        nve->type = htons(pair->type);
        nve->code = htons(pair->code);
    }

    ofpbuf_put(buf, data, data_len);

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
 * Returns NULL if 'error' is not an OpenFlow error code or if 'error' cannot
 * be encoded as OpenFlow version 'oh->version'.
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
 * so in theory this should work.
 *
 * Returns NULL if 'error' is not an OpenFlow error code or if 'error' cannot
 * be encoded in 'domain'. */
struct ofpbuf *
ofperr_encode_hello(enum ofperr error, enum ofp_version ofp_version,
                    const char *s)
{
    switch (ofp_version) {
    case OFP10_VERSION:
    case OFP11_VERSION:
    case OFP12_VERSION:
        break;

    default:
        ofp_version = OFP10_VERSION;
    }

    return ofperr_encode_msg__(error, ofp_version, htonl(0), s, strlen(s));
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
    return domain ? ofperr_get_pair__(error, domain)->type : -1;
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
    return domain ? ofperr_get_pair__(error, domain)->code : -1;
}

/* Tries to decodes 'oh', which should be an OpenFlow OFPT_ERROR message.
 * Returns an OFPERR_* constant on success, 0 on failure.
 *
 * If 'payload' is nonnull, on success '*payload' is initialized to the
 * error's payload, and on failure it is cleared. */
enum ofperr
ofperr_decode_msg(const struct ofp_header *oh, struct ofpbuf *payload)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    const struct ofp_error_msg *oem;
    enum ofpraw raw;
    uint16_t type, code;
    enum ofperr error;
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
    type = ntohs(oem->type);
    code = ntohs(oem->code);
    if (type == NXET_VENDOR && code == NXVC_VENDOR_ERROR) {
        const struct nx_vendor_error *nve = ofpbuf_try_pull(&b, sizeof *nve);
        if (!nve) {
            return 0;
        }

        if (nve->vendor != htonl(NX_VENDOR_ID)) {
            VLOG_WARN_RL(&rl, "error contains unknown vendor ID %#"PRIx32,
                         ntohl(nve->vendor));
            return 0;
        }
        type = ntohs(nve->type);
        code = ntohs(nve->code);
    }

    /* Translate the error type and code into an ofperr.
     * If we don't know the error type and code, at least try for the type. */
    error = ofperr_decode(oh->version, type, code);
    if (!error) {
        error = ofperr_decode_type(oh->version, type);
    }
    if (error && payload) {
        ofpbuf_use_const(payload, b.data, b.size);
    }
    return error;
}

/* If 'error' is a valid OFPERR_* value, returns its name
 * (e.g. "OFPBRC_BAD_TYPE" for OFPBRC_BAD_TYPE).  Otherwise, assumes that
 * 'error' is a positive errno value and returns what strerror() produces for
 * 'error'.  */
const char *
ofperr_to_string(enum ofperr error)
{
    return ofperr_is_valid(error) ? ofperr_get_name(error) : strerror(error);
}

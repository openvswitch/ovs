#include <config.h>
#include "ofp-errors.h"
#include <errno.h>
#include "byte-order.h"
#include "dynamic-string.h"
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
const struct ofperr_domain *
ofperr_domain_from_version(uint8_t version)
{
    return (version == ofperr_of10.version ? &ofperr_of10
            : version == ofperr_of11.version ? &ofperr_of11
            : version == ofperr_of12.version ? &ofperr_of12
            : NULL);
}

/* Returns the name (e.g. "OpenFlow 1.0") of OpenFlow error domain 'domain'. */
const char *
ofperr_domain_get_name(const struct ofperr_domain *domain)
{
    return domain->name;
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
ofperr_is_encodable(enum ofperr error, const struct ofperr_domain *domain)
{
    return (ofperr_is_valid(error)
            && domain->errors[error - OFPERR_OFS].code >= 0);
}

/* Returns the OFPERR_* value that corresponds to 'type' and 'code' within
 * 'domain', or 0 if no such OFPERR_* value exists. */
enum ofperr
ofperr_decode(const struct ofperr_domain *domain, uint16_t type, uint16_t code)
{
    return domain->decode(type, code);
}

/* Returns the OFPERR_* value that corresponds to the category 'type' within
 * 'domain', or 0 if no such OFPERR_* value exists. */
enum ofperr
ofperr_decode_type(const struct ofperr_domain *domain, uint16_t type)
{
    return domain->decode_type(type);
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
ofperr_encode_msg__(enum ofperr error, const struct ofperr_domain *domain,
                    ovs_be32 xid, const void *data, size_t data_len)
{
    struct ofp_error_msg *oem;
    const struct pair *pair;
    struct ofpbuf *buf;

    if (!domain) {
        return NULL;
    }

    if (!ofperr_is_encodable(error, domain)) {
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
        oem = make_openflow_xid(data_len + sizeof *oem, OFPT_ERROR, xid, &buf);
        oem->type = htons(pair->type);
        oem->code = htons(pair->code);
    } else {
        struct nx_vendor_error *nve;

        oem = make_openflow_xid(data_len + sizeof *oem + sizeof *nve,
                                OFPT_ERROR, xid, &buf);
        oem->type = htons(NXET_VENDOR);
        oem->code = htons(NXVC_VENDOR_ERROR);

        nve = (struct nx_vendor_error *) oem->data;
        nve->vendor = htonl(NX_VENDOR_ID);
        nve->type = htons(pair->type);
        nve->code = htons(pair->code);
    }
    oem->header.version = domain->version;

    buf->size -= data_len;
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
    const struct ofperr_domain *domain;
    uint16_t len = ntohs(oh->length);

    domain = ofperr_domain_from_version(oh->version);
    return ofperr_encode_msg__(error, domain, oh->xid, oh, MIN(len, 64));
}

/* Creates and returns an OpenFlow message of type OFPT_ERROR that conveys the
 * given 'error', in the error domain 'domain'.  The error message will include
 * the additional null-terminated text string 's'.
 *
 * If 'domain' is NULL, uses the OpenFlow 1.0 error domain.  OFPET_HELLO_FAILED
 * error messages are supposed to be backward-compatible, so in theory this
 * should work.
 *
 * Returns NULL if 'error' is not an OpenFlow error code or if 'error' cannot
 * be encoded in 'domain'. */
struct ofpbuf *
ofperr_encode_hello(enum ofperr error, const struct ofperr_domain *domain,
                    const char *s)
{
    if (!domain) {
        domain = &ofperr_of10;
    }
    return ofperr_encode_msg__(error, domain, htonl(0), s, strlen(s));
}

/* Returns the value that would go into an OFPT_ERROR message's 'type' for
 * encoding 'error' in 'domain'.  Returns -1 if 'error' is not encodable in
 * 'domain'.
 *
 * 'error' must be a valid OFPERR_* code, as checked by ofperr_is_valid(). */
int
ofperr_get_type(enum ofperr error, const struct ofperr_domain *domain)
{
    return ofperr_get_pair__(error, domain)->type;
}

/* Returns the value that would go into an OFPT_ERROR message's 'code' for
 * encoding 'error' in 'domain'.  Returns -1 if 'error' is not encodable in
 * 'domain' or if 'error' represents a category rather than a specific error.
 *
 * 'error' must be a valid OFPERR_* code, as checked by ofperr_is_valid(). */
int
ofperr_get_code(enum ofperr error, const struct ofperr_domain *domain)
{
    return ofperr_get_pair__(error, domain)->code;
}

/* Tries to decodes 'oh', which should be an OpenFlow OFPT_ERROR message.
 * Returns an OFPERR_* constant on success, 0 on failure.
 *
 * If 'payload_ofs' is nonnull, on success '*payload_ofs' is set to the offset
 * to the payload starting from 'oh' and on failure it is set to 0. */
enum ofperr
ofperr_decode_msg(const struct ofp_header *oh, size_t *payload_ofs)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    const struct ofperr_domain *domain;
    const struct ofp_error_msg *oem;
    uint16_t type, code;
    enum ofperr error;
    struct ofpbuf b;

    if (payload_ofs) {
        *payload_ofs = 0;
    }

    /* Pull off the error message. */
    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    oem = ofpbuf_try_pull(&b, sizeof *oem);
    if (!oem) {
        return 0;
    }

    /* Check message type and version. */
    if (oh->type != OFPT_ERROR) {
        return 0;
    }
    domain = ofperr_domain_from_version(oh->version);
    if (!domain) {
        return 0;
    }

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
    error = ofperr_decode(domain, type, code);
    if (!error) {
        error = ofperr_decode_type(domain, type);
    }
    if (error && payload_ofs) {
        *payload_ofs = (uint8_t *) b.data - (uint8_t *) oh;
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

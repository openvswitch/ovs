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
#include "openvswitch/ofp-protocol.h"
#include <ctype.h>
#include "openvswitch/dynamic-string.h"
#include "openvswitch/ofp-flow.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ofp_protocol);

/* Protocols. */

struct proto_abbrev {
    enum ofputil_protocol protocol;
    const char *name;
};

/* Most users really don't care about some of the differences between
 * protocols.  These abbreviations help with that. */
static const struct proto_abbrev proto_abbrevs[] = {
    { OFPUTIL_P_ANY,          "any" },
    { OFPUTIL_P_OF10_STD_ANY, "OpenFlow10" },
    { OFPUTIL_P_OF10_NXM_ANY, "NXM" },
    { OFPUTIL_P_ANY_OXM,      "OXM" },
};
#define N_PROTO_ABBREVS ARRAY_SIZE(proto_abbrevs)

enum ofputil_protocol ofputil_flow_dump_protocols[] = {
    OFPUTIL_P_OF16_OXM,
    OFPUTIL_P_OF15_OXM,
    OFPUTIL_P_OF14_OXM,
    OFPUTIL_P_OF13_OXM,
    OFPUTIL_P_OF12_OXM,
    OFPUTIL_P_OF11_STD,
    OFPUTIL_P_OF10_NXM,
    OFPUTIL_P_OF10_STD,
};
size_t ofputil_n_flow_dump_protocols = ARRAY_SIZE(ofputil_flow_dump_protocols);

/* Returns the set of ofputil_protocols that are supported with the given
 * OpenFlow 'version'.  'version' should normally be an 8-bit OpenFlow version
 * identifier (e.g. 0x01 for OpenFlow 1.0, 0x02 for OpenFlow 1.1).  Returns 0
 * if 'version' is not supported or outside the valid range.  */
enum ofputil_protocol
ofputil_protocols_from_ofp_version(enum ofp_version version)
{
    switch (version) {
    case OFP10_VERSION:
        return OFPUTIL_P_OF10_STD_ANY | OFPUTIL_P_OF10_NXM_ANY;
    case OFP11_VERSION:
        return OFPUTIL_P_OF11_STD;
    case OFP12_VERSION:
        return OFPUTIL_P_OF12_OXM;
    case OFP13_VERSION:
        return OFPUTIL_P_OF13_OXM;
    case OFP14_VERSION:
        return OFPUTIL_P_OF14_OXM;
    case OFP15_VERSION:
        return OFPUTIL_P_OF15_OXM;
    case OFP16_VERSION:
        return OFPUTIL_P_OF16_OXM;
    default:
        return 0;
    }
}

/* Returns the ofputil_protocol that is initially in effect on an OpenFlow
 * connection that has negotiated the given 'version'.  'version' should
 * normally be an 8-bit OpenFlow version identifier (e.g. 0x01 for OpenFlow
 * 1.0, 0x02 for OpenFlow 1.1).  Returns 0 if 'version' is not supported or
 * outside the valid range.  */
enum ofputil_protocol
ofputil_protocol_from_ofp_version(enum ofp_version version)
{
    return rightmost_1bit(ofputil_protocols_from_ofp_version(version));
}

/* Returns the OpenFlow protocol version number (e.g. OFP10_VERSION,
 * etc.) that corresponds to 'protocol'. */
enum ofp_version
ofputil_protocol_to_ofp_version(enum ofputil_protocol protocol)
{
    switch (protocol) {
    case OFPUTIL_P_OF10_STD:
    case OFPUTIL_P_OF10_STD_TID:
    case OFPUTIL_P_OF10_NXM:
    case OFPUTIL_P_OF10_NXM_TID:
        return OFP10_VERSION;
    case OFPUTIL_P_OF11_STD:
        return OFP11_VERSION;
    case OFPUTIL_P_OF12_OXM:
        return OFP12_VERSION;
    case OFPUTIL_P_OF13_OXM:
        return OFP13_VERSION;
    case OFPUTIL_P_OF14_OXM:
        return OFP14_VERSION;
    case OFPUTIL_P_OF15_OXM:
        return OFP15_VERSION;
    case OFPUTIL_P_OF16_OXM:
        return OFP16_VERSION;
    }

    OVS_NOT_REACHED();
}

/* Returns a bitmap of OpenFlow versions that are supported by at
 * least one of the 'protocols'. */
uint32_t
ofputil_protocols_to_version_bitmap(enum ofputil_protocol protocols)
{
    uint32_t bitmap = 0;

    for (; protocols; protocols = zero_rightmost_1bit(protocols)) {
        enum ofputil_protocol protocol = rightmost_1bit(protocols);

        bitmap |= 1u << ofputil_protocol_to_ofp_version(protocol);
    }

    return bitmap;
}

/* Returns the set of protocols that are supported on top of the
 * OpenFlow versions included in 'bitmap'. */
enum ofputil_protocol
ofputil_protocols_from_version_bitmap(uint32_t bitmap)
{
    enum ofputil_protocol protocols = 0;

    for (; bitmap; bitmap = zero_rightmost_1bit(bitmap)) {
        enum ofp_version version = rightmost_1bit_idx(bitmap);

        protocols |= ofputil_protocols_from_ofp_version(version);
    }

    return protocols;
}

/* Returns true if 'protocol' is a single OFPUTIL_P_* value, false
 * otherwise. */
bool
ofputil_protocol_is_valid(enum ofputil_protocol protocol)
{
    return protocol & OFPUTIL_P_ANY && is_pow2(protocol);
}

/* Returns the equivalent of 'protocol' with the Nicira flow_mod_table_id
 * extension turned on or off if 'enable' is true or false, respectively.
 *
 * This extension is only useful for protocols whose "standard" version does
 * not allow specific tables to be modified.  In particular, this is true of
 * OpenFlow 1.0.  In later versions of OpenFlow, a flow_mod request always
 * specifies a table ID and so there is no need for such an extension.  When
 * 'protocol' is such a protocol that doesn't need a flow_mod_table_id
 * extension, this function just returns its 'protocol' argument unchanged
 * regardless of the value of 'enable'.  */
enum ofputil_protocol
ofputil_protocol_set_tid(enum ofputil_protocol protocol, bool enable)
{
    switch (protocol) {
    case OFPUTIL_P_OF10_STD:
    case OFPUTIL_P_OF10_STD_TID:
        return enable ? OFPUTIL_P_OF10_STD_TID : OFPUTIL_P_OF10_STD;

    case OFPUTIL_P_OF10_NXM:
    case OFPUTIL_P_OF10_NXM_TID:
        return enable ? OFPUTIL_P_OF10_NXM_TID : OFPUTIL_P_OF10_NXM;

    case OFPUTIL_P_OF11_STD:
        return OFPUTIL_P_OF11_STD;

    case OFPUTIL_P_OF12_OXM:
        return OFPUTIL_P_OF12_OXM;

    case OFPUTIL_P_OF13_OXM:
        return OFPUTIL_P_OF13_OXM;

    case OFPUTIL_P_OF14_OXM:
        return OFPUTIL_P_OF14_OXM;

    case OFPUTIL_P_OF15_OXM:
        return OFPUTIL_P_OF15_OXM;

    case OFPUTIL_P_OF16_OXM:
        return OFPUTIL_P_OF16_OXM;

    default:
        OVS_NOT_REACHED();
    }
}

/* Returns the "base" version of 'protocol'.  That is, if 'protocol' includes
 * some extension to a standard protocol version, the return value is the
 * standard version of that protocol without any extension.  If 'protocol' is a
 * standard protocol version, returns 'protocol' unchanged. */
enum ofputil_protocol
ofputil_protocol_to_base(enum ofputil_protocol protocol)
{
    return ofputil_protocol_set_tid(protocol, false);
}

/* Returns 'new_base' with any extensions taken from 'cur'. */
enum ofputil_protocol
ofputil_protocol_set_base(enum ofputil_protocol cur,
                          enum ofputil_protocol new_base)
{
    bool tid = (cur & OFPUTIL_P_TID) != 0;

    switch (new_base) {
    case OFPUTIL_P_OF10_STD:
    case OFPUTIL_P_OF10_STD_TID:
        return ofputil_protocol_set_tid(OFPUTIL_P_OF10_STD, tid);

    case OFPUTIL_P_OF10_NXM:
    case OFPUTIL_P_OF10_NXM_TID:
        return ofputil_protocol_set_tid(OFPUTIL_P_OF10_NXM, tid);

    case OFPUTIL_P_OF11_STD:
        return ofputil_protocol_set_tid(OFPUTIL_P_OF11_STD, tid);

    case OFPUTIL_P_OF12_OXM:
        return ofputil_protocol_set_tid(OFPUTIL_P_OF12_OXM, tid);

    case OFPUTIL_P_OF13_OXM:
        return ofputil_protocol_set_tid(OFPUTIL_P_OF13_OXM, tid);

    case OFPUTIL_P_OF14_OXM:
        return ofputil_protocol_set_tid(OFPUTIL_P_OF14_OXM, tid);

    case OFPUTIL_P_OF15_OXM:
        return ofputil_protocol_set_tid(OFPUTIL_P_OF15_OXM, tid);

    case OFPUTIL_P_OF16_OXM:
        return ofputil_protocol_set_tid(OFPUTIL_P_OF16_OXM, tid);

    default:
        OVS_NOT_REACHED();
    }
}

/* Returns a string form of 'protocol', if a simple form exists (that is, if
 * 'protocol' is either a single protocol or it is a combination of protocols
 * that have a single abbreviation).  Otherwise, returns NULL. */
const char *
ofputil_protocol_to_string(enum ofputil_protocol protocol)
{
    const struct proto_abbrev *p;

    /* Use a "switch" statement for single-bit names so that we get a compiler
     * warning if we forget any. */
    switch (protocol) {
    case OFPUTIL_P_OF10_NXM:
        return "NXM-table_id";

    case OFPUTIL_P_OF10_NXM_TID:
        return "NXM+table_id";

    case OFPUTIL_P_OF10_STD:
        return "OpenFlow10-table_id";

    case OFPUTIL_P_OF10_STD_TID:
        return "OpenFlow10+table_id";

    case OFPUTIL_P_OF11_STD:
        return "OpenFlow11";

    case OFPUTIL_P_OF12_OXM:
        return "OXM-OpenFlow12";

    case OFPUTIL_P_OF13_OXM:
        return "OXM-OpenFlow13";

    case OFPUTIL_P_OF14_OXM:
        return "OXM-OpenFlow14";

    case OFPUTIL_P_OF15_OXM:
        return "OXM-OpenFlow15";

    case OFPUTIL_P_OF16_OXM:
        return "OXM-OpenFlow16";
    }

    /* Check abbreviations. */
    for (p = proto_abbrevs; p < &proto_abbrevs[N_PROTO_ABBREVS]; p++) {
        if (protocol == p->protocol) {
            return p->name;
        }
    }

    return NULL;
}

/* Returns a string that represents 'protocols'.  The return value might be a
 * comma-separated list if 'protocols' doesn't have a simple name.  The return
 * value is "none" if 'protocols' is 0.
 *
 * The caller must free the returned string (with free()). */
char *
ofputil_protocols_to_string(enum ofputil_protocol protocols)
{
    struct ds s;

    ovs_assert(!(protocols & ~OFPUTIL_P_ANY));
    if (protocols == 0) {
        return xstrdup("none");
    }

    ds_init(&s);
    while (protocols) {
        const struct proto_abbrev *p;
        int i;

        if (s.length) {
            ds_put_char(&s, ',');
        }

        for (p = proto_abbrevs; p < &proto_abbrevs[N_PROTO_ABBREVS]; p++) {
            if ((protocols & p->protocol) == p->protocol) {
                ds_put_cstr(&s, p->name);
                protocols &= ~p->protocol;
                goto match;
            }
        }

        for (i = 0; i < CHAR_BIT * sizeof(enum ofputil_protocol); i++) {
            enum ofputil_protocol bit = 1u << i;

            if (protocols & bit) {
                ds_put_cstr(&s, ofputil_protocol_to_string(bit));
                protocols &= ~bit;
                goto match;
            }
        }
        OVS_NOT_REACHED();

    match: ;
    }
    return ds_steal_cstr(&s);
}

static enum ofputil_protocol
ofputil_protocol_from_string__(const char *s, size_t n)
{
    const struct proto_abbrev *p;
    int i;

    for (i = 0; i < CHAR_BIT * sizeof(enum ofputil_protocol); i++) {
        enum ofputil_protocol bit = 1u << i;
        const char *name = ofputil_protocol_to_string(bit);

        if (name && n == strlen(name) && !strncasecmp(s, name, n)) {
            return bit;
        }
    }

    for (p = proto_abbrevs; p < &proto_abbrevs[N_PROTO_ABBREVS]; p++) {
        if (n == strlen(p->name) && !strncasecmp(s, p->name, n)) {
            return p->protocol;
        }
    }

    return 0;
}

/* Returns the nonempty set of protocols represented by 's', which can be a
 * single protocol name or abbreviation or a comma-separated list of them.
 *
 * Aborts the program with an error message if 's' is invalid. */
enum ofputil_protocol
ofputil_protocols_from_string(const char *s)
{
    const char *orig_s = s;
    enum ofputil_protocol protocols;

    protocols = 0;
    while (*s) {
        enum ofputil_protocol p;
        size_t n;

        n = strcspn(s, ",");
        if (n == 0) {
            s++;
            continue;
        }

        p = ofputil_protocol_from_string__(s, n);
        if (!p) {
            ovs_fatal(0, "%.*s: unknown flow protocol", (int) n, s);
        }
        protocols |= p;

        s += n;
    }

    if (!protocols) {
        ovs_fatal(0, "%s: no flow protocol specified", orig_s);
    }
    return protocols;
}

enum ofp_version
ofputil_version_from_string(const char *s)
{
    if (!strcasecmp(s, "OpenFlow10")) {
        return OFP10_VERSION;
    }
    if (!strcasecmp(s, "OpenFlow11")) {
        return OFP11_VERSION;
    }
    if (!strcasecmp(s, "OpenFlow12")) {
        return OFP12_VERSION;
    }
    if (!strcasecmp(s, "OpenFlow13")) {
        return OFP13_VERSION;
    }
    if (!strcasecmp(s, "OpenFlow14")) {
        return OFP14_VERSION;
    }
    if (!strcasecmp(s, "OpenFlow15")) {
        return OFP15_VERSION;
    }
    if (!strcasecmp(s, "OpenFlow16")) {
        return OFP16_VERSION;
    }
    return 0;
}

static bool
is_delimiter(unsigned char c)
{
    return isspace(c) || c == ',';
}

uint32_t
ofputil_versions_from_string(const char *s)
{
    size_t i = 0;
    uint32_t bitmap = 0;

    while (s[i]) {
        size_t j;
        int version;
        char *key;

        if (is_delimiter(s[i])) {
            i++;
            continue;
        }
        j = 0;
        while (s[i + j] && !is_delimiter(s[i + j])) {
            j++;
        }
        key = xmemdup0(s + i, j);
        version = ofputil_version_from_string(key);
        if (!version) {
            VLOG_FATAL("Unknown OpenFlow version: \"%s\"", key);
        }
        free(key);
        bitmap |= 1u << version;
        i += j;
    }

    return bitmap;
}

uint32_t
ofputil_versions_from_strings(char ** const s, size_t count)
{
    uint32_t bitmap = 0;

    while (count--) {
        int version = ofputil_version_from_string(s[count]);
        if (!version) {
            VLOG_WARN("Unknown OpenFlow version: \"%s\"", s[count]);
        } else {
            bitmap |= 1u << version;
        }
    }

    return bitmap;
}

const char *
ofputil_version_to_string(enum ofp_version ofp_version)
{
    switch (ofp_version) {
    case OFP10_VERSION:
        return "OpenFlow10";
    case OFP11_VERSION:
        return "OpenFlow11";
    case OFP12_VERSION:
        return "OpenFlow12";
    case OFP13_VERSION:
        return "OpenFlow13";
    case OFP14_VERSION:
        return "OpenFlow14";
    case OFP15_VERSION:
        return "OpenFlow15";
    case OFP16_VERSION:
        return "OpenFlow16";
    default:
        OVS_NOT_REACHED();
    }
}

void
ofputil_format_version(struct ds *msg, enum ofp_version version)
{
    ds_put_format(msg, "0x%02x", version);
}

void
ofputil_format_version_name(struct ds *msg, enum ofp_version version)
{
    ds_put_cstr(msg, ofputil_version_to_string(version));
}

static void
ofputil_format_version_bitmap__(struct ds *msg, uint32_t bitmap,
                                void (*format_version)(struct ds *msg,
                                                       enum ofp_version))
{
    while (bitmap) {
        format_version(msg, raw_ctz(bitmap));
        bitmap = zero_rightmost_1bit(bitmap);
        if (bitmap) {
            ds_put_cstr(msg, ", ");
        }
    }
}

void
ofputil_format_version_bitmap(struct ds *msg, uint32_t bitmap)
{
    ofputil_format_version_bitmap__(msg, bitmap, ofputil_format_version);
}

void
ofputil_format_version_bitmap_names(struct ds *msg, uint32_t bitmap)
{
    ofputil_format_version_bitmap__(msg, bitmap, ofputil_format_version_name);
}

/* Returns an OpenFlow message that, sent on an OpenFlow connection whose
 * protocol is 'current', at least partly transitions the protocol to 'want'.
 * Stores in '*next' the protocol that will be in effect on the OpenFlow
 * connection if the switch processes the returned message correctly.  (If
 * '*next != want' then the caller will have to iterate.)
 *
 * If 'current == want', or if it is not possible to transition from 'current'
 * to 'want' (because, for example, 'current' and 'want' use different OpenFlow
 * protocol versions), returns NULL and stores 'current' in '*next'. */
struct ofpbuf *
ofputil_encode_set_protocol(enum ofputil_protocol current,
                            enum ofputil_protocol want,
                            enum ofputil_protocol *next)
{
    enum ofp_version cur_version, want_version;
    enum ofputil_protocol cur_base, want_base;
    bool cur_tid, want_tid;

    cur_version = ofputil_protocol_to_ofp_version(current);
    want_version = ofputil_protocol_to_ofp_version(want);
    if (cur_version != want_version) {
        *next = current;
        return NULL;
    }

    cur_base = ofputil_protocol_to_base(current);
    want_base = ofputil_protocol_to_base(want);
    if (cur_base != want_base) {
        *next = ofputil_protocol_set_base(current, want_base);

        switch (want_base) {
        case OFPUTIL_P_OF10_NXM:
            return ofputil_encode_nx_set_flow_format(NXFF_NXM);

        case OFPUTIL_P_OF10_STD:
            return ofputil_encode_nx_set_flow_format(NXFF_OPENFLOW10);

        case OFPUTIL_P_OF11_STD:
        case OFPUTIL_P_OF12_OXM:
        case OFPUTIL_P_OF13_OXM:
        case OFPUTIL_P_OF14_OXM:
        case OFPUTIL_P_OF15_OXM:
        case OFPUTIL_P_OF16_OXM:
            /* There is only one variant of each OpenFlow 1.1+ protocol, and we
             * verified above that we're not trying to change versions. */
            OVS_NOT_REACHED();

        case OFPUTIL_P_OF10_STD_TID:
        case OFPUTIL_P_OF10_NXM_TID:
            OVS_NOT_REACHED();
        }
    }

    cur_tid = (current & OFPUTIL_P_TID) != 0;
    want_tid = (want & OFPUTIL_P_TID) != 0;
    if (cur_tid != want_tid) {
        *next = ofputil_protocol_set_tid(current, want_tid);
        return ofputil_make_flow_mod_table_id(want_tid);
    }

    ovs_assert(current == want);

    *next = current;
    return NULL;
}

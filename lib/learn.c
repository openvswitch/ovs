/*
 * Copyright (c) 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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

#include "learn.h"

#include "byte-order.h"
#include "dynamic-string.h"
#include "match.h"
#include "meta-flow.h"
#include "nx-match.h"
#include "ofp-actions.h"
#include "ofp-errors.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "unaligned.h"


/* Checks that 'learn' is a valid action on 'flow'.  Returns 0 if it is valid,
 * otherwise an OFPERR_*. */
enum ofperr
learn_check(const struct ofpact_learn *learn, const struct flow *flow)
{
    const struct ofpact_learn_spec *spec;
    struct match match;

    match_init_catchall(&match);
    for (spec = learn->specs; spec < &learn->specs[learn->n_specs]; spec++) {
        enum ofperr error;

        /* Check the source. */
        if (spec->src_type == NX_LEARN_SRC_FIELD) {
            error = mf_check_src(&spec->src, flow);
            if (error) {
                return error;
            }
        }

        /* Check the destination. */
        switch (spec->dst_type) {
        case NX_LEARN_DST_MATCH:
            error = mf_check_src(&spec->dst, &match.flow);
            if (error) {
                return error;
            }

            mf_write_subfield(&spec->dst, &spec->src_imm, &match);
            break;

        case NX_LEARN_DST_LOAD:
            error = mf_check_dst(&spec->dst, &match.flow);
            if (error) {
                return error;
            }
            break;

        case NX_LEARN_DST_OUTPUT:
            /* Nothing to do. */
            break;
        }
    }
    return 0;
}

/* Composes 'fm' so that executing it will implement 'learn' given that the
 * packet being processed has 'flow' as its flow.
 *
 * Uses 'ofpacts' to store the flow mod's actions.  The caller must initialize
 * 'ofpacts' and retains ownership of it.  'fm->ofpacts' will point into the
 * 'ofpacts' buffer.
 *
 * The caller has to actually execute 'fm'. */
void
learn_execute(const struct ofpact_learn *learn, const struct flow *flow,
              struct ofputil_flow_mod *fm, struct ofpbuf *ofpacts)
{
    const struct ofpact_learn_spec *spec;

    match_init_catchall(&fm->match);
    fm->priority = learn->priority;
    fm->cookie = htonll(0);
    fm->cookie_mask = htonll(0);
    fm->new_cookie = learn->cookie;
    fm->modify_cookie = fm->new_cookie != OVS_BE64_MAX;
    fm->table_id = learn->table_id;
    fm->command = OFPFC_MODIFY_STRICT;
    fm->idle_timeout = learn->idle_timeout;
    fm->hard_timeout = learn->hard_timeout;
    fm->importance = 0;
    fm->buffer_id = UINT32_MAX;
    fm->out_port = OFPP_NONE;
    fm->flags = 0;
    if (learn->flags & NX_LEARN_F_SEND_FLOW_REM) {
        fm->flags |= OFPUTIL_FF_SEND_FLOW_REM;
    }
    fm->ofpacts = NULL;
    fm->ofpacts_len = 0;
    fm->delete_reason = OFPRR_DELETE;

    if (learn->fin_idle_timeout || learn->fin_hard_timeout) {
        struct ofpact_fin_timeout *oft;

        oft = ofpact_put_FIN_TIMEOUT(ofpacts);
        oft->fin_idle_timeout = learn->fin_idle_timeout;
        oft->fin_hard_timeout = learn->fin_hard_timeout;
    }

    for (spec = learn->specs; spec < &learn->specs[learn->n_specs]; spec++) {
        struct ofpact_set_field *sf;
        union mf_subvalue value;

        if (spec->src_type == NX_LEARN_SRC_FIELD) {
            mf_read_subfield(&spec->src, flow, &value);
        } else {
            value = spec->src_imm;
        }

        switch (spec->dst_type) {
        case NX_LEARN_DST_MATCH:
            mf_write_subfield(&spec->dst, &value, &fm->match);
            break;

        case NX_LEARN_DST_LOAD:
            sf = ofpact_put_reg_load(ofpacts);
            sf->field = spec->dst.field;
            bitwise_copy(&value, sizeof value, 0,
                         &sf->value, spec->dst.field->n_bytes, spec->dst.ofs,
                         spec->n_bits);
            bitwise_one(&sf->mask, spec->dst.field->n_bytes, spec->dst.ofs,
                        spec->n_bits);
            break;

        case NX_LEARN_DST_OUTPUT:
            if (spec->n_bits <= 16
                || is_all_zeros(value.u8, sizeof value - 2)) {
                ovs_be16 *last_be16 = &value.be16[ARRAY_SIZE(value.be16) - 1];
                ofp_port_t port = u16_to_ofp(ntohs(*last_be16));

                if (ofp_to_u16(port) < ofp_to_u16(OFPP_MAX)
                    || port == OFPP_IN_PORT
                    || port == OFPP_FLOOD
                    || port == OFPP_LOCAL
                    || port == OFPP_ALL) {
                    ofpact_put_OUTPUT(ofpacts)->port = port;
                }
            }
            break;
        }
    }
    ofpact_pad(ofpacts);

    fm->ofpacts = ofpacts->data;
    fm->ofpacts_len = ofpacts->size;
}

/* Perform a bitwise-OR on 'wc''s fields that are relevant as sources in
 * the learn action 'learn'. */
void
learn_mask(const struct ofpact_learn *learn, struct flow_wildcards *wc)
{
    const struct ofpact_learn_spec *spec;
    union mf_subvalue value;

    memset(&value, 0xff, sizeof value);
    for (spec = learn->specs; spec < &learn->specs[learn->n_specs]; spec++) {
        if (spec->src_type == NX_LEARN_SRC_FIELD) {
            mf_write_subfield_flow(&spec->src, &value, &wc->masks);
        }
    }
}

/* Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * OVS_WARN_UNUSED_RESULT
learn_parse_load_immediate(const char *s, struct ofpact_learn_spec *spec)
{
    const char *full_s = s;
    struct mf_subfield dst;
    union mf_subvalue imm;
    char *error;
    int err;

    err = parse_int_string(s, imm.u8, sizeof imm.u8, (char **) &s);
    if (err) {
        return xasprintf("%s: too many bits in immediate value", full_s);
    }

    if (strncmp(s, "->", 2)) {
        return xasprintf("%s: missing `->' following value", full_s);
    }
    s += 2;

    error = mf_parse_subfield(&dst, s);
    if (error) {
        return error;
    }
    if (!mf_nxm_header(dst.field->id)) {
        return xasprintf("%s: experimenter OXM field '%s' not supported",
                         full_s, s);
    }

    if (!bitwise_is_all_zeros(&imm, sizeof imm, dst.n_bits,
                              (8 * sizeof imm) - dst.n_bits)) {
        return xasprintf("%s: value does not fit into %u bits",
                         full_s, dst.n_bits);
    }

    spec->n_bits = dst.n_bits;
    spec->src_type = NX_LEARN_SRC_IMMEDIATE;
    spec->src_imm = imm;
    spec->dst_type = NX_LEARN_DST_LOAD;
    spec->dst = dst;
    return NULL;
}

/* Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * OVS_WARN_UNUSED_RESULT
learn_parse_spec(const char *orig, char *name, char *value,
                 struct ofpact_learn_spec *spec)
{
    if (mf_from_name(name)) {
        const struct mf_field *dst = mf_from_name(name);
        union mf_value imm;
        char *error;

        error = mf_parse_value(dst, value, &imm);
        if (error) {
            return error;
        }

        spec->n_bits = dst->n_bits;
        spec->src_type = NX_LEARN_SRC_IMMEDIATE;
        memset(&spec->src_imm, 0, sizeof spec->src_imm);
        memcpy(&spec->src_imm.u8[sizeof spec->src_imm - dst->n_bytes],
               &imm, dst->n_bytes);
        spec->dst_type = NX_LEARN_DST_MATCH;
        spec->dst.field = dst;
        spec->dst.ofs = 0;
        spec->dst.n_bits = dst->n_bits;
    } else if (strchr(name, '[')) {
        /* Parse destination and check prerequisites. */
        char *error;

        error = mf_parse_subfield(&spec->dst, name);
        if (error) {
            return error;
        }
        if (!mf_nxm_header(spec->dst.field->id)) {
            return xasprintf("%s: experimenter OXM field '%s' not supported",
                             orig, name);
        }

        /* Parse source and check prerequisites. */
        if (value[0] != '\0') {
            error = mf_parse_subfield(&spec->src, value);
            if (error) {
                return error;
            }
            if (spec->src.n_bits != spec->dst.n_bits) {
                return xasprintf("%s: bit widths of %s (%u) and %s (%u) "
                                 "differ", orig, name, spec->src.n_bits, value,
                                 spec->dst.n_bits);
            }
        } else {
            spec->src = spec->dst;
        }

        spec->n_bits = spec->src.n_bits;
        spec->src_type = NX_LEARN_SRC_FIELD;
        spec->dst_type = NX_LEARN_DST_MATCH;
    } else if (!strcmp(name, "load")) {
        if (value[strcspn(value, "[-")] == '-') {
            char *error = learn_parse_load_immediate(value, spec);
            if (error) {
                return error;
            }
        } else {
            struct ofpact_reg_move move;
            char *error;

            error = nxm_parse_reg_move(&move, value);
            if (error) {
                return error;
            }

            spec->n_bits = move.src.n_bits;
            spec->src_type = NX_LEARN_SRC_FIELD;
            spec->src = move.src;
            spec->dst_type = NX_LEARN_DST_LOAD;
            spec->dst = move.dst;
        }
    } else if (!strcmp(name, "output")) {
        char *error = mf_parse_subfield(&spec->src, value);
        if (error) {
            return error;
        }

        spec->n_bits = spec->src.n_bits;
        spec->src_type = NX_LEARN_SRC_FIELD;
        spec->dst_type = NX_LEARN_DST_OUTPUT;
    } else {
        return xasprintf("%s: unknown keyword %s", orig, name);
    }

    return NULL;
}

/* Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * OVS_WARN_UNUSED_RESULT
learn_parse__(char *orig, char *arg, struct ofpbuf *ofpacts)
{
    struct ofpact_learn *learn;
    struct match match;
    char *name, *value;

    learn = ofpact_put_LEARN(ofpacts);
    learn->idle_timeout = OFP_FLOW_PERMANENT;
    learn->hard_timeout = OFP_FLOW_PERMANENT;
    learn->priority = OFP_DEFAULT_PRIORITY;
    learn->table_id = 1;

    match_init_catchall(&match);
    while (ofputil_parse_key_value(&arg, &name, &value)) {
        if (!strcmp(name, "table")) {
            learn->table_id = atoi(value);
            if (learn->table_id == 255) {
                return xasprintf("%s: table id 255 not valid for `learn' "
                                 "action", orig);
            }
        } else if (!strcmp(name, "priority")) {
            learn->priority = atoi(value);
        } else if (!strcmp(name, "idle_timeout")) {
            learn->idle_timeout = atoi(value);
        } else if (!strcmp(name, "hard_timeout")) {
            learn->hard_timeout = atoi(value);
        } else if (!strcmp(name, "fin_idle_timeout")) {
            learn->fin_idle_timeout = atoi(value);
        } else if (!strcmp(name, "fin_hard_timeout")) {
            learn->fin_hard_timeout = atoi(value);
        } else if (!strcmp(name, "cookie")) {
            learn->cookie = htonll(strtoull(value, NULL, 0));
        } else if (!strcmp(name, "send_flow_rem")) {
            learn->flags |= NX_LEARN_F_SEND_FLOW_REM;
        } else if (!strcmp(name, "delete_learned")) {
            learn->flags |= NX_LEARN_F_DELETE_LEARNED;
        } else {
            struct ofpact_learn_spec *spec;
            char *error;

            spec = ofpbuf_put_zeros(ofpacts, sizeof *spec);
            learn = ofpacts->header;
            learn->n_specs++;

            error = learn_parse_spec(orig, name, value, spec);
            if (error) {
                return error;
            }

            /* Update 'match' to allow for satisfying destination
             * prerequisites. */
            if (spec->src_type == NX_LEARN_SRC_IMMEDIATE
                && spec->dst_type == NX_LEARN_DST_MATCH) {
                mf_write_subfield(&spec->dst, &spec->src_imm, &match);
            }
        }
    }
    ofpact_update_len(ofpacts, &learn->ofpact);

    return NULL;
}

/* Parses 'arg' as a set of arguments to the "learn" action and appends a
 * matching OFPACT_LEARN action to 'ofpacts'.  ovs-ofctl(8) describes the
 * format parsed.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string.
 *
 * If 'flow' is nonnull, then it should be the flow from a struct match that is
 * the matching rule for the learning action.  This helps to better validate
 * the action's arguments.
 *
 * Modifies 'arg'. */
char * OVS_WARN_UNUSED_RESULT
learn_parse(char *arg, struct ofpbuf *ofpacts)
{
    char *orig = xstrdup(arg);
    char *error = learn_parse__(orig, arg, ofpacts);
    free(orig);
    return error;
}

/* Appends a description of 'learn' to 's', in the format that ovs-ofctl(8)
 * describes. */
void
learn_format(const struct ofpact_learn *learn, struct ds *s)
{
    const struct ofpact_learn_spec *spec;
    struct match match;

    match_init_catchall(&match);

    ds_put_format(s, "learn(table=%"PRIu8, learn->table_id);
    if (learn->idle_timeout != OFP_FLOW_PERMANENT) {
        ds_put_format(s, ",idle_timeout=%"PRIu16, learn->idle_timeout);
    }
    if (learn->hard_timeout != OFP_FLOW_PERMANENT) {
        ds_put_format(s, ",hard_timeout=%"PRIu16, learn->hard_timeout);
    }
    if (learn->fin_idle_timeout) {
        ds_put_format(s, ",fin_idle_timeout=%"PRIu16, learn->fin_idle_timeout);
    }
    if (learn->fin_hard_timeout) {
        ds_put_format(s, ",fin_hard_timeout=%"PRIu16, learn->fin_hard_timeout);
    }
    if (learn->priority != OFP_DEFAULT_PRIORITY) {
        ds_put_format(s, ",priority=%"PRIu16, learn->priority);
    }
    if (learn->flags & NX_LEARN_F_SEND_FLOW_REM) {
        ds_put_cstr(s, ",send_flow_rem");
    }
    if (learn->flags & NX_LEARN_F_DELETE_LEARNED) {
        ds_put_cstr(s, ",delete_learned");
    }
    if (learn->cookie != 0) {
        ds_put_format(s, ",cookie=%#"PRIx64, ntohll(learn->cookie));
    }

    for (spec = learn->specs; spec < &learn->specs[learn->n_specs]; spec++) {
        ds_put_char(s, ',');

        switch (spec->src_type | spec->dst_type) {
        case NX_LEARN_SRC_IMMEDIATE | NX_LEARN_DST_MATCH:
            if (spec->dst.ofs == 0
                && spec->dst.n_bits == spec->dst.field->n_bits) {
                union mf_value value;

                memset(&value, 0, sizeof value);
                bitwise_copy(&spec->src_imm, sizeof spec->src_imm, 0,
                             &value, spec->dst.field->n_bytes, 0,
                             spec->dst.field->n_bits);
                ds_put_format(s, "%s=", spec->dst.field->name);
                mf_format(spec->dst.field, &value, NULL, s);
            } else {
                mf_format_subfield(&spec->dst, s);
                ds_put_char(s, '=');
                mf_format_subvalue(&spec->src_imm, s);
            }
            break;

        case NX_LEARN_SRC_FIELD | NX_LEARN_DST_MATCH:
            mf_format_subfield(&spec->dst, s);
            if (spec->src.field != spec->dst.field ||
                spec->src.ofs != spec->dst.ofs) {
                ds_put_char(s, '=');
                mf_format_subfield(&spec->src, s);
            }
            break;

        case NX_LEARN_SRC_IMMEDIATE | NX_LEARN_DST_LOAD:
            ds_put_format(s, "load:");
            mf_format_subvalue(&spec->src_imm, s);
            ds_put_cstr(s, "->");
            mf_format_subfield(&spec->dst, s);
            break;

        case NX_LEARN_SRC_FIELD | NX_LEARN_DST_LOAD:
            ds_put_cstr(s, "load:");
            mf_format_subfield(&spec->src, s);
            ds_put_cstr(s, "->");
            mf_format_subfield(&spec->dst, s);
            break;

        case NX_LEARN_SRC_FIELD | NX_LEARN_DST_OUTPUT:
            ds_put_cstr(s, "output:");
            mf_format_subfield(&spec->src, s);
            break;
        }
    }
    ds_put_char(s, ')');
}

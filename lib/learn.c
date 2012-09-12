/*
 * Copyright (c) 2011, 2012 Nicira, Inc.
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

static ovs_be16
get_be16(const void **pp)
{
    const ovs_be16 *p = *pp;
    ovs_be16 value = *p;
    *pp = p + 1;
    return value;
}

static ovs_be32
get_be32(const void **pp)
{
    const ovs_be32 *p = *pp;
    ovs_be32 value = get_unaligned_be32(p);
    *pp = p + 1;
    return value;
}

static void
get_subfield(int n_bits, const void **p, struct mf_subfield *sf)
{
    sf->field = mf_from_nxm_header(ntohl(get_be32(p)));
    sf->ofs = ntohs(get_be16(p));
    sf->n_bits = n_bits;
}

static unsigned int
learn_min_len(uint16_t header)
{
    int n_bits = header & NX_LEARN_N_BITS_MASK;
    int src_type = header & NX_LEARN_SRC_MASK;
    int dst_type = header & NX_LEARN_DST_MASK;
    unsigned int min_len;

    min_len = 0;
    if (src_type == NX_LEARN_SRC_FIELD) {
        min_len += sizeof(ovs_be32); /* src_field */
        min_len += sizeof(ovs_be16); /* src_ofs */
    } else {
        min_len += DIV_ROUND_UP(n_bits, 16);
    }
    if (dst_type == NX_LEARN_DST_MATCH ||
        dst_type == NX_LEARN_DST_LOAD) {
        min_len += sizeof(ovs_be32); /* dst_field */
        min_len += sizeof(ovs_be16); /* dst_ofs */
    }
    return min_len;
}

/* Converts 'nal' into a "struct ofpact_learn" and appends that struct to
 * 'ofpacts'.  Returns 0 if successful, otherwise an OFPERR_*. */
enum ofperr
learn_from_openflow(const struct nx_action_learn *nal, struct ofpbuf *ofpacts)
{
    struct ofpact_learn *learn;
    const void *p, *end;

    if (nal->pad) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    learn = ofpact_put_LEARN(ofpacts);

    learn->idle_timeout = ntohs(nal->idle_timeout);
    learn->hard_timeout = ntohs(nal->hard_timeout);
    learn->priority = ntohs(nal->priority);
    learn->cookie = ntohll(nal->cookie);
    learn->flags = ntohs(nal->flags);
    learn->table_id = nal->table_id;
    learn->fin_idle_timeout = ntohs(nal->fin_idle_timeout);
    learn->fin_hard_timeout = ntohs(nal->fin_hard_timeout);

    if (learn->flags & ~OFPFF_SEND_FLOW_REM || learn->table_id == 0xff) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    end = (char *) nal + ntohs(nal->len);
    for (p = nal + 1; p != end; ) {
        struct ofpact_learn_spec *spec;
        uint16_t header = ntohs(get_be16(&p));

        if (!header) {
            break;
        }

        spec = ofpbuf_put_zeros(ofpacts, sizeof *spec);
        learn = ofpacts->l2;
        learn->n_specs++;

        spec->src_type = header & NX_LEARN_SRC_MASK;
        spec->dst_type = header & NX_LEARN_DST_MASK;
        spec->n_bits = header & NX_LEARN_N_BITS_MASK;

        /* Check for valid src and dst type combination. */
        if (spec->dst_type == NX_LEARN_DST_MATCH ||
            spec->dst_type == NX_LEARN_DST_LOAD ||
            (spec->dst_type == NX_LEARN_DST_OUTPUT &&
             spec->src_type == NX_LEARN_SRC_FIELD)) {
            /* OK. */
        } else {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }

        /* Check that the arguments don't overrun the end of the action. */
        if ((char *) end - (char *) p < learn_min_len(header)) {
            return OFPERR_OFPBAC_BAD_LEN;
        }

        /* Get the source. */
        if (spec->src_type == NX_LEARN_SRC_FIELD) {
            get_subfield(spec->n_bits, &p, &spec->src);
        } else {
            int p_bytes = 2 * DIV_ROUND_UP(spec->n_bits, 16);

            bitwise_copy(p, p_bytes, 0,
                         &spec->src_imm, sizeof spec->src_imm, 0,
                         spec->n_bits);
            p = (const uint8_t *) p + p_bytes;
        }

        /* Get the destination. */
        if (spec->dst_type == NX_LEARN_DST_MATCH ||
            spec->dst_type == NX_LEARN_DST_LOAD) {
            get_subfield(spec->n_bits, &p, &spec->dst);
        }
    }
    ofpact_update_len(ofpacts, &learn->ofpact);

    if (!is_all_zeros(p, (char *) end - (char *) p)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    return 0;
}

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

static void
put_be16(struct ofpbuf *b, ovs_be16 x)
{
    ofpbuf_put(b, &x, sizeof x);
}

static void
put_be32(struct ofpbuf *b, ovs_be32 x)
{
    ofpbuf_put(b, &x, sizeof x);
}

static void
put_u16(struct ofpbuf *b, uint16_t x)
{
    put_be16(b, htons(x));
}

static void
put_u32(struct ofpbuf *b, uint32_t x)
{
    put_be32(b, htonl(x));
}

/* Converts 'learn' into a "struct nx_action_learn" and appends that action to
 * 'ofpacts'. */
void
learn_to_nxast(const struct ofpact_learn *learn, struct ofpbuf *openflow)
{
    const struct ofpact_learn_spec *spec;
    struct nx_action_learn *nal;
    size_t start_ofs;

    start_ofs = openflow->size;
    nal = ofputil_put_NXAST_LEARN(openflow);
    nal->idle_timeout = htons(learn->idle_timeout);
    nal->hard_timeout = htons(learn->hard_timeout);
    nal->fin_idle_timeout = htons(learn->fin_idle_timeout);
    nal->fin_hard_timeout = htons(learn->fin_hard_timeout);
    nal->priority = htons(learn->priority);
    nal->cookie = htonll(learn->cookie);
    nal->flags = htons(learn->flags);
    nal->table_id = learn->table_id;

    for (spec = learn->specs; spec < &learn->specs[learn->n_specs]; spec++) {
        put_u16(openflow, spec->n_bits | spec->dst_type | spec->src_type);

        if (spec->src_type == NX_LEARN_SRC_FIELD) {
            put_u32(openflow, spec->src.field->nxm_header);
            put_u16(openflow, spec->src.ofs);
        } else {
            size_t n_dst_bytes = 2 * DIV_ROUND_UP(spec->n_bits, 16);
            uint8_t *bits = ofpbuf_put_zeros(openflow, n_dst_bytes);
            bitwise_copy(&spec->src_imm, sizeof spec->src_imm, 0,
                         bits, n_dst_bytes, 0,
                         spec->n_bits);
        }

        if (spec->dst_type == NX_LEARN_DST_MATCH ||
            spec->dst_type == NX_LEARN_DST_LOAD) {
            put_u32(openflow, spec->dst.field->nxm_header);
            put_u16(openflow, spec->dst.ofs);
        }
    }

    if ((openflow->size - start_ofs) % 8) {
        ofpbuf_put_zeros(openflow, 8 - (openflow->size - start_ofs) % 8);
    }

    nal = ofpbuf_at_assert(openflow, start_ofs, sizeof *nal);
    nal->len = htons(openflow->size - start_ofs);
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
    fm->new_cookie = htonll(learn->cookie);
    fm->table_id = learn->table_id;
    fm->command = OFPFC_MODIFY_STRICT;
    fm->idle_timeout = learn->idle_timeout;
    fm->hard_timeout = learn->hard_timeout;
    fm->buffer_id = UINT32_MAX;
    fm->out_port = OFPP_NONE;
    fm->flags = learn->flags;
    fm->ofpacts = NULL;
    fm->ofpacts_len = 0;

    if (learn->fin_idle_timeout || learn->fin_hard_timeout) {
        struct ofpact_fin_timeout *oft;

        oft = ofpact_put_FIN_TIMEOUT(ofpacts);
        oft->fin_idle_timeout = learn->fin_idle_timeout;
        oft->fin_hard_timeout = learn->fin_hard_timeout;
    }

    for (spec = learn->specs; spec < &learn->specs[learn->n_specs]; spec++) {
        union mf_subvalue value;
        int chunk, ofs;

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
            for (ofs = 0; ofs < spec->n_bits; ofs += chunk) {
                struct ofpact_reg_load *load;

                chunk = MIN(spec->n_bits - ofs, 64);

                load = ofpact_put_REG_LOAD(ofpacts);
                load->dst.field = spec->dst.field;
                load->dst.ofs = spec->dst.ofs + ofs;
                load->dst.n_bits = chunk;
                bitwise_copy(&value, sizeof value, ofs,
                             &load->subvalue, sizeof load->subvalue, 0,
                             chunk);
            }
            break;

        case NX_LEARN_DST_OUTPUT:
            if (spec->n_bits <= 16
                || is_all_zeros(value.u8, sizeof value - 2)) {
                uint16_t port = ntohs(value.be16[7]);

                if (port < OFPP_MAX
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

static void
learn_parse_load_immediate(const char *s, struct ofpact_learn_spec *spec)
{
    const char *full_s = s;
    const char *arrow = strstr(s, "->");
    struct mf_subfield dst;
    union mf_subvalue imm;

    memset(&imm, 0, sizeof imm);
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X') && arrow) {
        const char *in = arrow - 1;
        uint8_t *out = imm.u8 + sizeof imm.u8 - 1;
        int n = arrow - (s + 2);
        int i;

        for (i = 0; i < n; i++) {
            int hexit = hexit_value(in[-i]);
            if (hexit < 0) {
                ovs_fatal(0, "%s: bad hex digit in value", full_s);
            }
            out[-(i / 2)] |= i % 2 ? hexit << 4 : hexit;
        }
        s = arrow;
    } else {
        imm.be64[1] = htonll(strtoull(s, (char **) &s, 0));
    }

    if (strncmp(s, "->", 2)) {
        ovs_fatal(0, "%s: missing `->' following value", full_s);
    }
    s += 2;

    s = mf_parse_subfield(&dst, s);
    if (*s != '\0') {
        ovs_fatal(0, "%s: trailing garbage following destination", full_s);
    }

    if (!bitwise_is_all_zeros(&imm, sizeof imm, dst.n_bits,
                              (8 * sizeof imm) - dst.n_bits)) {
        ovs_fatal(0, "%s: value does not fit into %u bits",
                  full_s, dst.n_bits);
    }

    spec->n_bits = dst.n_bits;
    spec->src_type = NX_LEARN_SRC_IMMEDIATE;
    spec->src_imm = imm;
    spec->dst_type = NX_LEARN_DST_LOAD;
    spec->dst = dst;
}

static void
learn_parse_spec(const char *orig, char *name, char *value,
                 struct ofpact_learn_spec *spec)
{
    if (mf_from_name(name)) {
        const struct mf_field *dst = mf_from_name(name);
        union mf_value imm;
        char *error;

        error = mf_parse_value(dst, value, &imm);
        if (error) {
            ovs_fatal(0, "%s", error);
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
        if (mf_parse_subfield(&spec->dst, name)[0] != '\0') {
            ovs_fatal(0, "%s: syntax error after NXM field name `%s'",
                      orig, name);
        }

        /* Parse source and check prerequisites. */
        if (value[0] != '\0') {
            if (mf_parse_subfield(&spec->src, value)[0] != '\0') {
                ovs_fatal(0, "%s: syntax error after NXM field name `%s'",
                          orig, value);
            }
            if (spec->src.n_bits != spec->dst.n_bits) {
                ovs_fatal(0, "%s: bit widths of %s (%u) and %s (%u) differ",
                          orig, name, spec->src.n_bits, value,
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
            learn_parse_load_immediate(value, spec);
        } else {
            struct ofpact_reg_move move;

            nxm_parse_reg_move(&move, value);

            spec->n_bits = move.src.n_bits;
            spec->src_type = NX_LEARN_SRC_FIELD;
            spec->src = move.src;
            spec->dst_type = NX_LEARN_DST_LOAD;
            spec->dst = move.dst;
        }
    } else if (!strcmp(name, "output")) {
        if (mf_parse_subfield(&spec->src, value)[0] != '\0') {
            ovs_fatal(0, "%s: syntax error after NXM field name `%s'",
                      orig, name);
        }

        spec->n_bits = spec->src.n_bits;
        spec->src_type = NX_LEARN_SRC_FIELD;
        spec->dst_type = NX_LEARN_DST_OUTPUT;
    } else {
        ovs_fatal(0, "%s: unknown keyword %s", orig, name);
    }
}

/* Parses 'arg' as a set of arguments to the "learn" action and appends a
 * matching OFPACT_LEARN action to 'ofpacts'.  ovs-ofctl(8) describes the
 * format parsed.
 *
 * Prints an error on stderr and aborts the program if 'arg' syntax is invalid.
 *
 * If 'flow' is nonnull, then it should be the flow from a struct match that is
 * the matching rule for the learning action.  This helps to better validate
 * the action's arguments.
 *
 * Modifies 'arg'. */
void
learn_parse(char *arg, const struct flow *flow, struct ofpbuf *ofpacts)
{
    char *orig = xstrdup(arg);
    char *name, *value;

    struct ofpact_learn *learn;
    struct match match;
    enum ofperr error;

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
                ovs_fatal(0, "%s: table id 255 not valid for `learn' action",
                          orig);
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
            learn->cookie = strtoull(value, NULL, 0);
        } else {
            struct ofpact_learn_spec *spec;

            spec = ofpbuf_put_zeros(ofpacts, sizeof *spec);
            learn = ofpacts->l2;
            learn->n_specs++;

            learn_parse_spec(orig, name, value, spec);

            /* Check prerequisites. */
            if (spec->src_type == NX_LEARN_SRC_FIELD
                && flow && !mf_are_prereqs_ok(spec->src.field, flow)) {
                ovs_fatal(0, "%s: cannot specify source field %s because "
                          "prerequisites are not satisfied",
                          orig, spec->src.field->name);
            }
            if ((spec->dst_type == NX_LEARN_DST_MATCH
                 || spec->dst_type == NX_LEARN_DST_LOAD)
                && !mf_are_prereqs_ok(spec->dst.field, &match.flow)) {
                ovs_fatal(0, "%s: cannot specify destination field %s because "
                          "prerequisites are not satisfied",
                          orig, spec->dst.field->name);
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

    /* In theory the above should have caught any errors, but... */
    if (flow) {
        error = learn_check(learn, flow);
        if (error) {
            ovs_fatal(0, "%s: %s", orig, ofperr_to_string(error));
        }
    }
    free(orig);
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
    if (learn->flags & OFPFF_SEND_FLOW_REM) {
        ds_put_cstr(s, ",OFPFF_SEND_FLOW_REM");
    }
    if (learn->cookie != 0) {
        ds_put_format(s, ",cookie=%#"PRIx64, learn->cookie);
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

/*
 * Copyright (c) 2011 Nicira Networks.
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
#include "meta-flow.h"
#include "nx-match.h"
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

static uint64_t
get_bits(int n_bits, const void **p)
{
    int n_segs = DIV_ROUND_UP(n_bits, 16);
    uint64_t value;

    value = 0;
    while (n_segs-- > 0) {
        value = (value << 16) | ntohs(get_be16(p));
    }
    return value;
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

static int
learn_check_header(uint16_t header, size_t len)
{
    int src_type = header & NX_LEARN_SRC_MASK;
    int dst_type = header & NX_LEARN_DST_MASK;

    /* Check for valid src and dst type combination. */
    if (dst_type == NX_LEARN_DST_MATCH ||
        dst_type == NX_LEARN_DST_LOAD ||
        (dst_type == NX_LEARN_DST_OUTPUT &&
         src_type == NX_LEARN_SRC_FIELD)) {
        /* OK. */
    } else {
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
    }

    /* Check that the arguments don't overrun the end of the action. */
    if (len < learn_min_len(header)) {
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    return 0;
}

/* Checks that 'learn' (which must be at least 'sizeof *learn' bytes long) is a
 * valid action on 'flow'. */
int
learn_check(const struct nx_action_learn *learn, const struct flow *flow)
{
    struct cls_rule rule;
    const void *p, *end;

    cls_rule_init_catchall(&rule, 0);

    if (learn->flags & ~htons(OFPFF_SEND_FLOW_REM)
        || !is_all_zeros(learn->pad, sizeof learn->pad)
        || learn->table_id == 0xff) {
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
    }

    end = (char *) learn + ntohs(learn->len);
    for (p = learn + 1; p != end; ) {
        uint16_t header = ntohs(get_be16(&p));
        int n_bits = header & NX_LEARN_N_BITS_MASK;
        int src_type = header & NX_LEARN_SRC_MASK;
        int dst_type = header & NX_LEARN_DST_MASK;

        uint64_t value;
        int error;

        if (!header) {
            break;
        }

        error = learn_check_header(header, (char *) end - (char *) p);
        if (error) {
            return error;
        }

        /* Check the source. */
        if (src_type == NX_LEARN_SRC_FIELD) {
            ovs_be32 src_field = get_be32(&p);
            int src_ofs = ntohs(get_be16(&p));

            error = nxm_src_check(src_field, src_ofs, n_bits, flow);
            if (error) {
                return error;
            }
            value = 0;
        } else {
            value = get_bits(n_bits, &p);
        }

        /* Check the destination. */
        if (dst_type == NX_LEARN_DST_MATCH || dst_type == NX_LEARN_DST_LOAD) {
            ovs_be32 dst_field = get_be32(&p);
            int dst_ofs = ntohs(get_be16(&p));
            int error;

            error = (dst_type == NX_LEARN_DST_LOAD
                     ? nxm_dst_check(dst_field, dst_ofs, n_bits, &rule.flow)
                     : nxm_src_check(dst_field, dst_ofs, n_bits, &rule.flow));
            if (error) {
                return error;
            }

            if (dst_type == NX_LEARN_DST_MATCH
                && src_type == NX_LEARN_SRC_IMMEDIATE) {
                mf_set_subfield(mf_from_nxm_header(ntohl(dst_field)), value,
                                dst_ofs, n_bits, &rule);
            }
        }
    }
    if (!is_all_zeros(p, (char *) end - (char *) p)) {
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
    }

    return 0;
}

void
learn_execute(const struct nx_action_learn *learn, const struct flow *flow,
              struct ofputil_flow_mod *fm)
{
    const void *p, *end;
    struct ofpbuf actions;

    cls_rule_init_catchall(&fm->cr, ntohs(learn->priority));
    fm->cookie = learn->cookie;
    fm->table_id = learn->table_id;
    fm->command = OFPFC_MODIFY_STRICT;
    fm->idle_timeout = ntohs(learn->idle_timeout);
    fm->hard_timeout = ntohs(learn->hard_timeout);
    fm->buffer_id = UINT32_MAX;
    fm->out_port = OFPP_NONE;
    fm->flags = ntohs(learn->flags) & OFPFF_SEND_FLOW_REM;
    fm->actions = NULL;
    fm->n_actions = 0;

    ofpbuf_init(&actions, 64);

    for (p = learn + 1, end = (char *) learn + ntohs(learn->len); p != end; ) {
        uint16_t header = ntohs(get_be16(&p));
        int n_bits = header & NX_LEARN_N_BITS_MASK;
        int src_type = header & NX_LEARN_SRC_MASK;
        int dst_type = header & NX_LEARN_DST_MASK;
        uint64_t value;

        struct nx_action_reg_load *load;
        ovs_be32 dst_field;
        int dst_ofs;

        if (!header) {
            break;
        }

        if (src_type == NX_LEARN_SRC_FIELD) {
            ovs_be32 src_field = get_be32(&p);
            int src_ofs = ntohs(get_be16(&p));

            value = nxm_read_field_bits(src_field,
                                        nxm_encode_ofs_nbits(src_ofs, n_bits),
                                        flow);
        } else {
            value = get_bits(n_bits, &p);
        }

        switch (dst_type) {
        case NX_LEARN_DST_MATCH:
            dst_field = get_be32(&p);
            dst_ofs = ntohs(get_be16(&p));
            mf_set_subfield(mf_from_nxm_header(ntohl(dst_field)), value,
                            dst_ofs, n_bits, &fm->cr);
            break;

        case NX_LEARN_DST_LOAD:
            dst_field = get_be32(&p);
            dst_ofs = ntohs(get_be16(&p));
            load = ofputil_put_NXAST_REG_LOAD(&actions);
            load->ofs_nbits = nxm_encode_ofs_nbits(dst_ofs, n_bits);
            load->dst = dst_field;
            load->value = htonll(value);
            break;

        case NX_LEARN_DST_OUTPUT:
            ofputil_put_OFPAT_OUTPUT(&actions)->port = htons(value);
            break;
        }
    }

    fm->actions = ofpbuf_steal_data(&actions);
    fm->n_actions = actions.size / sizeof(struct ofp_action_header);
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

struct learn_spec {
    int n_bits;

    int src_type;
    const struct mf_field *src;
    int src_ofs;
    uint8_t src_imm[sizeof(union mf_value)];

    int dst_type;
    const struct mf_field *dst;
    int dst_ofs;
};

static void
learn_parse_spec(const char *orig, char *name, char *value,
                 struct learn_spec *spec)
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
        spec->src = NULL;
        spec->src_ofs = 0;
        memcpy(spec->src_imm, &imm, dst->n_bytes);
        spec->dst_type = NX_LEARN_DST_MATCH;
        spec->dst = dst;
        spec->dst_ofs = 0;
    } else if (strchr(name, '[')) {
        uint32_t src_header, dst_header;
        int src_ofs, dst_ofs;
        int n_bits;

        /* Parse destination and check prerequisites. */
        if (nxm_parse_field_bits(name, &dst_header, &dst_ofs,
                                 &n_bits)[0] != '\0') {
            ovs_fatal(0, "%s: syntax error after NXM field name `%s'",
                      orig, name);
        }

        /* Parse source and check prerequisites. */
        if (value[0] != '\0') {
            int src_nbits;

            if (nxm_parse_field_bits(value, &src_header, &src_ofs,
                                     &src_nbits)[0] != '\0') {
                ovs_fatal(0, "%s: syntax error after NXM field name `%s'",
                          orig, value);
            }
            if (src_nbits != n_bits) {
                ovs_fatal(0, "%s: bit widths of %s (%d) and %s (%d) differ",
                          orig, name, dst_header, value, dst_header);
            }
        } else {
            src_header = dst_header;
            src_ofs = dst_ofs;
        }

        spec->n_bits = n_bits;
        spec->src_type = NX_LEARN_SRC_FIELD;
        spec->src = mf_from_nxm_header(src_header);
        spec->src_ofs = src_ofs;
        spec->dst_type = NX_LEARN_DST_MATCH;
        spec->dst = mf_from_nxm_header(dst_header);
        spec->dst_ofs = 0;
    } else if (!strcmp(name, "load")) {
        if (value[strcspn(value, "[-")] == '-') {
            struct nx_action_reg_load load;
            int nbits, imm_bytes;
            uint64_t imm;
            int i;

            nxm_parse_reg_load(&load, value);
            nbits = nxm_decode_n_bits(load.ofs_nbits);
            imm_bytes = DIV_ROUND_UP(nbits, 8);
            imm = ntohll(load.value);

            spec->n_bits = nbits;
            spec->src_type = NX_LEARN_SRC_IMMEDIATE;
            spec->src = NULL;
            spec->src_ofs = 0;
            for (i = 0; i < imm_bytes; i++) {
                spec->src_imm[i] = imm >> ((imm_bytes - i - 1) * 8);
            }
            spec->dst_type = NX_LEARN_DST_LOAD;
            spec->dst = mf_from_nxm_header(ntohl(load.dst));
            spec->dst_ofs = nxm_decode_ofs(load.ofs_nbits);
        } else {
            struct nx_action_reg_move move;

            nxm_parse_reg_move(&move, value);

            spec->n_bits = ntohs(move.n_bits);
            spec->src_type = NX_LEARN_SRC_FIELD;
            spec->src = mf_from_nxm_header(ntohl(move.src));
            spec->src_ofs = ntohs(move.src_ofs);
            spec->dst_type = NX_LEARN_DST_LOAD;
            spec->dst = mf_from_nxm_header(ntohl(move.dst));
            spec->dst_ofs = ntohs(move.dst_ofs);
        }
    } else if (!strcmp(name, "output")) {
        uint32_t header;
        int ofs, n_bits;

        if (nxm_parse_field_bits(value, &header, &ofs, &n_bits)[0] != '\0') {
            ovs_fatal(0, "%s: syntax error after NXM field name `%s'",
                      orig, name);
        }

        spec->n_bits = n_bits;
        spec->src_type = NX_LEARN_SRC_FIELD;
        spec->src = mf_from_nxm_header(header);
        spec->src_ofs = ofs;
        spec->dst_type = NX_LEARN_DST_OUTPUT;
        spec->dst = NULL;
        spec->dst_ofs = 0;
    } else {
        ovs_fatal(0, "%s: unknown keyword %s", orig, name);
    }
}

void
learn_parse(struct ofpbuf *b, char *arg, const struct flow *flow)
{
    char *orig = xstrdup(arg);
    char *name, *value;
    size_t learn_ofs;
    size_t len;
    int error;

    struct nx_action_learn *learn;
    struct cls_rule rule;

    learn_ofs = b->size;
    learn = ofputil_put_NXAST_LEARN(b);
    learn->idle_timeout = htons(OFP_FLOW_PERMANENT);
    learn->hard_timeout = htons(OFP_FLOW_PERMANENT);
    learn->priority = htons(OFP_DEFAULT_PRIORITY);
    learn->cookie = htonll(0);
    learn->flags = htons(0);
    learn->table_id = 1;

    cls_rule_init_catchall(&rule, 0);
    while (ofputil_parse_key_value(&arg, &name, &value)) {
        learn = ofpbuf_at_assert(b, learn_ofs, sizeof *learn);
        if (!strcmp(name, "table")) {
            learn->table_id = atoi(value);
            if (learn->table_id == 255) {
                ovs_fatal(0, "%s: table id 255 not valid for `learn' action",
                          orig);
            }
        } else if (!strcmp(name, "priority")) {
            learn->priority = htons(atoi(value));
        } else if (!strcmp(name, "idle_timeout")) {
            learn->idle_timeout = htons(atoi(value));
        } else if (!strcmp(name, "hard_timeout")) {
            learn->hard_timeout = htons(atoi(value));
        } else if (!strcmp(name, "cookie")) {
            learn->cookie = htonll(strtoull(value, NULL, 0));
        } else {
            struct learn_spec spec;

            learn_parse_spec(orig, name, value, &spec);

            /* Check prerequisites. */
            if (spec.src_type == NX_LEARN_SRC_FIELD
                && !mf_are_prereqs_ok(spec.src, flow)) {
                ovs_fatal(0, "%s: cannot specify source field %s because "
                          "prerequisites are not satisfied",
                          orig, spec.src->name);
            }
            if ((spec.dst_type == NX_LEARN_DST_MATCH
                 || spec.dst_type == NX_LEARN_DST_LOAD)
                && !mf_are_prereqs_ok(spec.dst, &rule.flow)) {
                ovs_fatal(0, "%s: cannot specify destination field %s because "
                          "prerequisites are not satisfied",
                          orig, spec.dst->name);
            }

            /* Update 'rule' to allow for satisfying destination
             * prerequisites. */
            if (spec.src_type == NX_LEARN_SRC_IMMEDIATE
                && spec.dst_type == NX_LEARN_DST_MATCH
                && spec.dst_ofs == 0
                && spec.n_bits == spec.dst->n_bytes * 8) {
                union mf_value imm;

                memcpy(&imm, spec.src_imm, spec.dst->n_bytes);
                mf_set_value(spec.dst, &imm, &rule);
            }

            /* Output the flow_mod_spec. */
            put_u16(b, spec.n_bits | spec.src_type | spec.dst_type);
            if (spec.src_type == NX_LEARN_SRC_IMMEDIATE) {
                int n_bytes = DIV_ROUND_UP(spec.n_bits, 8);
                if (n_bytes % 2) {
                    ofpbuf_put_zeros(b, 1);
                }
                ofpbuf_put(b, spec.src_imm, n_bytes);
            } else {
                put_u32(b, spec.src->nxm_header);
                put_u16(b, spec.src_ofs);
            }
            if (spec.dst_type == NX_LEARN_DST_MATCH ||
                spec.dst_type == NX_LEARN_DST_LOAD) {
                put_u32(b, spec.dst->nxm_header);
                put_u16(b, spec.dst_ofs);
            } else {
                assert(spec.dst_type == NX_LEARN_DST_OUTPUT);
            }
        }
    }

    put_u16(b, 0);

    len = b->size - learn_ofs;
    if (len % 8) {
        ofpbuf_put_zeros(b, 8 - len % 8);
    }

    learn = ofpbuf_at_assert(b, learn_ofs, sizeof *learn);
    learn->len = htons(b->size - learn_ofs);

    /* In theory the above should have caught any errors, but... */
    error = learn_check(learn, flow);
    if (error) {
        char *msg = ofputil_error_to_string(error);
        ovs_fatal(0, "%s: %s", orig, msg);
    }
    free(orig);
}

void
learn_format(const struct nx_action_learn *learn, struct ds *s)
{
    struct cls_rule rule;
    const void *p, *end;

    cls_rule_init_catchall(&rule, 0);

    ds_put_format(s, "learn(table=%"PRIu8, learn->table_id);
    if (learn->idle_timeout != htons(OFP_FLOW_PERMANENT)) {
        ds_put_format(s, ",idle_timeout=%"PRIu16, ntohs(learn->idle_timeout));
    }
    if (learn->hard_timeout != htons(OFP_FLOW_PERMANENT)) {
        ds_put_format(s, ",hard_timeout=%"PRIu16, ntohs(learn->hard_timeout));
    }
    if (learn->priority != htons(OFP_DEFAULT_PRIORITY)) {
        ds_put_format(s, ",priority=%"PRIu16, ntohs(learn->priority));
    }
    if (learn->flags & htons(OFPFF_SEND_FLOW_REM)) {
        ds_put_cstr(s, ",OFPFF_SEND_FLOW_REM");
    }
    if (learn->flags & htons(~OFPFF_SEND_FLOW_REM)) {
        ds_put_format(s, ",***flags=%"PRIu16"***",
                      ntohs(learn->flags) & ~OFPFF_SEND_FLOW_REM);
    }
    if (learn->cookie != htonll(0)) {
        ds_put_format(s, ",cookie=0x%"PRIx64, ntohll(learn->cookie));
    }
    if (!is_all_zeros(learn->pad, sizeof learn->pad)) {
        ds_put_cstr(s, ",***nonzero pad***");
    }

    end = (char *) learn + ntohs(learn->len);
    for (p = learn + 1; p != end; ) {
        uint16_t header = ntohs(get_be16(&p));
        int n_bits = header & NX_LEARN_N_BITS_MASK;

        int src_type = header & NX_LEARN_SRC_MASK;
        uint32_t src_header;
        int src_ofs;
        const uint8_t *src_value;
        int src_value_bytes;

        int dst_type = header & NX_LEARN_DST_MASK;
        uint32_t dst_header;
        int dst_ofs;
        const struct mf_field *dst_field;

        int error;
        int i;

        if (!header) {
            break;
        }

        error = learn_check_header(header, (char *) end - (char *) p);
        if (error == ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT)) {
            ds_put_format(s, ",***bad flow_mod_spec header %"PRIx16"***)",
                          header);
            return;
        } else if (error == ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN)) {
            ds_put_format(s, ",***flow_mod_spec at offset %td is %u bytes "
                          "long but only %td bytes are left***)",
                          (char *) p - (char *) (learn + 1) - 2,
                          learn_min_len(header) + 2,
                          (char *) end - (char *) p + 2);
            return;
        }
        assert(!error);

        /* Get the source. */
        if (src_type == NX_LEARN_SRC_FIELD) {
            src_header = ntohl(get_be32(&p));
            src_ofs = ntohs(get_be16(&p));
            src_value_bytes = 0;
            src_value = NULL;
        } else {
            src_header = 0;
            src_ofs = 0;
            src_value_bytes = 2 * DIV_ROUND_UP(n_bits, 16);
            src_value = p;
            p = (const void *) ((const uint8_t *) p + src_value_bytes);
        }

        /* Get the destination. */
        if (dst_type == NX_LEARN_DST_MATCH || dst_type == NX_LEARN_DST_LOAD) {
            dst_header = ntohl(get_be32(&p));
            dst_field = mf_from_nxm_header(dst_header);
            dst_ofs = ntohs(get_be16(&p));
        } else {
            dst_header = 0;
            dst_field = NULL;
            dst_ofs = 0;
        }

        ds_put_char(s, ',');

        switch (src_type | dst_type) {
        case NX_LEARN_SRC_IMMEDIATE | NX_LEARN_DST_MATCH:
            if (dst_field && dst_ofs == 0 && n_bits == dst_field->n_bits) {
                union mf_value value;
                uint8_t *bytes = (uint8_t *) &value;

                if (src_value_bytes > dst_field->n_bytes) {
                    /* The destination field is an odd number of bytes, which
                     * got rounded up to a multiple of 2 to be put into the
                     * learning action.  Skip over the leading byte, which
                     * should be zero anyway.  Otherwise the memcpy() below
                     * will overrun the start of 'value'. */
                    int diff = src_value_bytes - dst_field->n_bytes;
                    src_value += diff;
                    src_value_bytes -= diff;
                }

                memset(&value, 0, sizeof value);
                memcpy(&bytes[dst_field->n_bytes - src_value_bytes],
                       src_value, src_value_bytes);
                ds_put_format(s, "%s=", dst_field->name);
                mf_format(dst_field, &value, NULL, s);
            } else {
                nxm_format_field_bits(s, dst_header, dst_ofs, n_bits);
                ds_put_cstr(s, "=0x");
                for (i = 0; i < src_value_bytes; i++) {
                    ds_put_format(s, "%02"PRIx8, src_value[i]);
                }
            }
            break;

        case NX_LEARN_SRC_FIELD | NX_LEARN_DST_MATCH:
            nxm_format_field_bits(s, dst_header, dst_ofs, n_bits);
            if (src_header != dst_header || src_ofs != dst_ofs) {
                ds_put_char(s, '=');
                nxm_format_field_bits(s, src_header, src_ofs, n_bits);
            }
            break;

        case NX_LEARN_SRC_IMMEDIATE | NX_LEARN_DST_LOAD:
            ds_put_cstr(s, "load:0x");
            for (i = 0; i < src_value_bytes; i++) {
                ds_put_format(s, "%02"PRIx8, src_value[i]);
            }
            ds_put_cstr(s, "->");
            nxm_format_field_bits(s, dst_header, dst_ofs, n_bits);
            break;

        case NX_LEARN_SRC_FIELD | NX_LEARN_DST_LOAD:
            ds_put_cstr(s, "load:");
            nxm_format_field_bits(s, src_header, src_ofs, n_bits);
            ds_put_cstr(s, "->");
            nxm_format_field_bits(s, dst_header, dst_ofs, n_bits);
            break;

        case NX_LEARN_SRC_FIELD | NX_LEARN_DST_OUTPUT:
            ds_put_cstr(s, "output:");
            nxm_format_field_bits(s, src_header, src_ofs, n_bits);
            break;
        }
    }
    if (!is_all_zeros(p, (char *) end - (char *) p)) {
        ds_put_cstr(s, ",***nonzero trailer***");
    }
    ds_put_char(s, ')');
}

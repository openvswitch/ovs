/*
 * Copyright (c) 2015, 2018 Nicira, Inc.
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
#include "dpif-provider.h"

#include <errno.h>

#include "ct-dpif.h"
#include "openvswitch/ofp-ct.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ct_dpif);

/* Declarations for conntrack entry formatting. */
struct flags {
    uint32_t flag;
    const char *name;
};

static void ct_dpif_format_counters(struct ds *,
                                    const struct ct_dpif_counters *);
static void ct_dpif_format_timestamp(struct ds *,
                                     const struct ct_dpif_timestamp *);
static void ct_dpif_format_protoinfo(struct ds *, const char *title,
                                     const struct ct_dpif_protoinfo *,
                                     bool verbose);
static void ct_dpif_format_helper(struct ds *, const char *title,
                                  const struct ct_dpif_helper *);

/* Dumping */

/* Start dumping the entries from the connection tracker used by 'dpif'.
 *
 * 'dump' must be the address of a pointer to a struct ct_dpif_dump_state,
 * which should be passed (unaltered) to ct_dpif_dump_{next,done}().
 *
 * If 'zone' is not NULL, it should point to an integer identifing a
 * conntrack zone to which the dump will be limited.  If it is NULL,
 * conntrack entries from all zones will be dumped.
 *
 * If there has been a problem the function returns a non-zero value
 * that represents the error.  Otherwise it returns zero. */
int
ct_dpif_dump_start(struct dpif *dpif, struct ct_dpif_dump_state **dump,
                   const uint16_t *zone, int *ptot_bkts)
{
    int err;

    err = (dpif->dpif_class->ct_dump_start
           ? dpif->dpif_class->ct_dump_start(dpif, dump, zone, ptot_bkts)
           : EOPNOTSUPP);

    if (!err) {
        (*dump)->dpif = dpif;
    }

    return err;
}

/* Dump one connection from a tracker, and put it in 'entry'.
 *
 * 'dump' should have been initialized by ct_dpif_dump_start().
 *
 * The function returns 0, if an entry has been dumped succesfully.
 * Otherwise it returns a non-zero value which can be:
 * - EOF: meaning that there are no more entries to dump.
 * - an error value.
 * In both cases, the user should call ct_dpif_dump_done(). */
int
ct_dpif_dump_next(struct ct_dpif_dump_state *dump, struct ct_dpif_entry *entry)
{
    struct dpif *dpif = dump->dpif;

    return (dpif->dpif_class->ct_dump_next
            ? dpif->dpif_class->ct_dump_next(dpif, dump, entry)
            : EOPNOTSUPP);
}

/* Free resources used by 'dump' */
int
ct_dpif_dump_done(struct ct_dpif_dump_state *dump)
{
    struct dpif *dpif = dump->dpif;

    return (dpif->dpif_class->ct_dump_done
            ? dpif->dpif_class->ct_dump_done(dpif, dump)
            : EOPNOTSUPP);
}

/* Flushing. */

static void
ct_dpif_tuple_from_ofp_ct_tuple(const struct ofp_ct_tuple *ofp_tuple,
                                struct ct_dpif_tuple *tuple,
                                uint16_t l3_type, uint8_t ip_proto)
{
    if (l3_type == AF_INET) {
        tuple->src.ip = in6_addr_get_mapped_ipv4(&ofp_tuple->src);
        tuple->dst.ip = in6_addr_get_mapped_ipv4(&ofp_tuple->dst);
    } else {
        tuple->src.in6 = ofp_tuple->src;
        tuple->dst.in6 = ofp_tuple->dst;
    }

    tuple->l3_type = l3_type;
    tuple->ip_proto = ip_proto;
    tuple->src_port = ofp_tuple->src_port;

    if (ip_proto == IPPROTO_ICMP || ip_proto == IPPROTO_ICMPV6) {
        tuple->icmp_code = ofp_tuple->icmp_code;
        tuple->icmp_type = ofp_tuple->icmp_type;
    } else {
        tuple->dst_port = ofp_tuple->dst_port;
    }
}

static inline bool
ct_dpif_inet_addr_cmp_partial(const union ct_dpif_inet_addr *addr,
                              const struct in6_addr *partial, uint16_t l3_type)
{
    if (ipv6_is_zero(partial)) {
        return true;
    }

    if (l3_type == AF_INET && in6_addr_get_mapped_ipv4(partial) != addr->ip) {
        return false;
    }

    if (l3_type == AF_INET6 && !ipv6_addr_equals(partial, &addr->in6)) {
        return false;
    }

    return true;
}

static inline bool
ct_dpif_tuple_ip_cmp_partial(const struct ct_dpif_tuple *tuple,
                             const struct ofp_ct_tuple *partial,
                             uint16_t l3_type, uint8_t ip_proto)
{
    if (!ct_dpif_inet_addr_cmp_partial(&tuple->src, &partial->src, l3_type)) {
        return false;
    }

    if (!ct_dpif_inet_addr_cmp_partial(&tuple->dst, &partial->dst, l3_type)) {
        return false;
    }

    if (ip_proto == IPPROTO_ICMP || ip_proto == IPPROTO_ICMPV6) {
        if (partial->icmp_id != tuple->icmp_id) {
            return false;
        }

        if (partial->icmp_type != tuple->icmp_type) {
            return false;
        }

        if (partial->icmp_code != tuple->icmp_code) {
            return false;
        }
    } else {
        if (partial->src_port && partial->src_port != tuple->src_port) {
            return false;
        }

        if (partial->dst_port && partial->dst_port != tuple->dst_port) {
            return false;
        }
    }

    return true;
}

/* Returns 'true' if all non-zero members of 'match' equal to corresponding
 * members of 'entry'. */
static bool
ct_dpif_entry_cmp(const struct ct_dpif_entry *entry,
                  const struct ofp_ct_match *match)
{
    if (match->l3_type && match->l3_type != entry->tuple_orig.l3_type) {
        return false;
    }

    if (match->ip_proto && match->ip_proto != entry->tuple_orig.ip_proto) {
        return false;
    }

    if (!ct_dpif_tuple_ip_cmp_partial(&entry->tuple_orig, &match->tuple_orig,
                                      match->l3_type, match->ip_proto)) {
        return false;
    }

    if (!ct_dpif_tuple_ip_cmp_partial(&entry->tuple_reply, &match->tuple_reply,
                                      match->l3_type, match->ip_proto)) {
        return false;
    }

    return true;
}

static int
ct_dpif_flush_tuple(struct dpif *dpif, const uint16_t *zone,
                    const struct ofp_ct_match *match)
{
    struct ct_dpif_dump_state *dump;
    struct ct_dpif_entry cte;
    int error;
    int tot_bkts;

    if (!dpif->dpif_class->ct_flush) {
        return EOPNOTSUPP;
    }

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        ofp_ct_match_format(&ds, match);
        VLOG_DBG("%s: ct_flush: zone=%d %s", dpif_name(dpif), zone ? *zone : 0,
                 ds_cstr(&ds));
        ds_destroy(&ds);
    }

    /* If we have full five tuple in original and empty reply tuple just
     * do the flush over original tuple directly. */
    if (ofp_ct_tuple_is_five_tuple(&match->tuple_orig, match->ip_proto) &&
        ofp_ct_tuple_is_zero(&match->tuple_reply, match->ip_proto)) {
        struct ct_dpif_tuple tuple;

        ct_dpif_tuple_from_ofp_ct_tuple(&match->tuple_orig, &tuple,
                                        match->l3_type, match->ip_proto);
        return dpif->dpif_class->ct_flush(dpif, zone, &tuple);
    }

    error = ct_dpif_dump_start(dpif, &dump, zone, &tot_bkts);
    if (error) {
        return error;
    }

    while (!(error = ct_dpif_dump_next(dump, &cte))) {
        if (zone && *zone != cte.zone) {
            continue;
        }

        if (ct_dpif_entry_cmp(&cte, match)) {
            error = dpif->dpif_class->ct_flush(dpif, &cte.zone,
                                               &cte.tuple_orig);
            if (error) {
                break;
            }
        }
    }
    if (error == EOF) {
        error = 0;
    }

    ct_dpif_dump_done(dump);
    return error;
}

/* Flush the entries in the connection tracker used by 'dpif'.  The
 * arguments have the following behavior:
 *
 *   - If both 'zone' is NULL and 'match' is NULL or zero, flush all the
 *     conntrack entries.
 *   - If 'zone' is not NULL, and 'match' is NULL, flush all the conntrack
 *     entries in '*zone'.
 *   - If 'match' is not NULL or zero, flush the conntrack entry specified
 *     by 'match' in '*zone'.  If 'zone' is NULL, use the default zone
 *     (zone 0). */
int
ct_dpif_flush(struct dpif *dpif, const uint16_t *zone,
              const struct ofp_ct_match *match)
{
    if (match && !ofp_ct_match_is_zero(match)) {
        return ct_dpif_flush_tuple(dpif, zone, match);
    } else if (zone) {
        VLOG_DBG("%s: ct_flush: zone %"PRIu16, dpif_name(dpif), *zone);
    } else {
        VLOG_DBG("%s: ct_flush: <all>", dpif_name(dpif));
    }

    return (dpif->dpif_class->ct_flush
            ? dpif->dpif_class->ct_flush(dpif, zone, NULL)
            : EOPNOTSUPP);
}

int
ct_dpif_set_maxconns(struct dpif *dpif, uint32_t maxconns)
{
    return (dpif->dpif_class->ct_set_maxconns
            ? dpif->dpif_class->ct_set_maxconns(dpif, maxconns)
            : EOPNOTSUPP);
}

int
ct_dpif_get_maxconns(struct dpif *dpif, uint32_t *maxconns)
{
    return (dpif->dpif_class->ct_get_maxconns
            ? dpif->dpif_class->ct_get_maxconns(dpif, maxconns)
            : EOPNOTSUPP);
}

int
ct_dpif_get_nconns(struct dpif *dpif, uint32_t *nconns)
{
    return (dpif->dpif_class->ct_get_nconns
            ? dpif->dpif_class->ct_get_nconns(dpif, nconns)
            : EOPNOTSUPP);
}

int
ct_dpif_set_tcp_seq_chk(struct dpif *dpif, bool enabled)
{
    return (dpif->dpif_class->ct_set_tcp_seq_chk
            ? dpif->dpif_class->ct_set_tcp_seq_chk(dpif, enabled)
            : EOPNOTSUPP);
}

int
ct_dpif_get_tcp_seq_chk(struct dpif *dpif, bool *enabled)
{
    return (dpif->dpif_class->ct_get_tcp_seq_chk
            ? dpif->dpif_class->ct_get_tcp_seq_chk(dpif, enabled)
            : EOPNOTSUPP);
}

int
ct_dpif_set_limits(struct dpif *dpif, const uint32_t *default_limit,
                   const struct ovs_list *zone_limits)
{
    return (dpif->dpif_class->ct_set_limits
            ? dpif->dpif_class->ct_set_limits(dpif, default_limit,
                                              zone_limits)
            : EOPNOTSUPP);
}

int
ct_dpif_get_limits(struct dpif *dpif, uint32_t *default_limit,
                   const struct ovs_list *zone_limits_in,
                   struct ovs_list *zone_limits_out)
{
    return (dpif->dpif_class->ct_get_limits
            ? dpif->dpif_class->ct_get_limits(dpif, default_limit,
                                              zone_limits_in,
                                              zone_limits_out)
            : EOPNOTSUPP);
}

int
ct_dpif_del_limits(struct dpif *dpif, const struct ovs_list *zone_limits)
{
    return (dpif->dpif_class->ct_del_limits
            ? dpif->dpif_class->ct_del_limits(dpif, zone_limits)
            : EOPNOTSUPP);
}

int
ct_dpif_ipf_set_enabled(struct dpif *dpif, bool v6, bool enable)
{
    return (dpif->dpif_class->ipf_set_enabled
            ? dpif->dpif_class->ipf_set_enabled(dpif, v6, enable)
            : EOPNOTSUPP);
}

int
ct_dpif_ipf_set_min_frag(struct dpif *dpif, bool v6, uint32_t min_frag)
{
    return (dpif->dpif_class->ipf_set_min_frag
            ? dpif->dpif_class->ipf_set_min_frag(dpif, v6, min_frag)
            : EOPNOTSUPP);
}

int
ct_dpif_ipf_set_max_nfrags(struct dpif *dpif, uint32_t max_frags)
{
    return (dpif->dpif_class->ipf_set_max_nfrags
            ? dpif->dpif_class->ipf_set_max_nfrags(dpif, max_frags)
            : EOPNOTSUPP);
}

int ct_dpif_ipf_get_status(struct dpif *dpif,
                           struct dpif_ipf_status *dpif_ipf_status)
{
    return (dpif->dpif_class->ipf_get_status
            ? dpif->dpif_class->ipf_get_status(dpif, dpif_ipf_status)
            : EOPNOTSUPP);
}

int
ct_dpif_ipf_dump_start(struct dpif *dpif, struct ipf_dump_ctx **dump_ctx)
{
    return (dpif->dpif_class->ipf_dump_start
           ? dpif->dpif_class->ipf_dump_start(dpif, dump_ctx)
           : EOPNOTSUPP);
}

int
ct_dpif_ipf_dump_next(struct dpif *dpif, void *dump_ctx,  char **dump)
{
    return (dpif->dpif_class->ipf_dump_next
            ? dpif->dpif_class->ipf_dump_next(dpif, dump_ctx, dump)
            : EOPNOTSUPP);
}

int
ct_dpif_ipf_dump_done(struct dpif *dpif, void *dump_ctx)
{
    return (dpif->dpif_class->ipf_dump_done
            ? dpif->dpif_class->ipf_dump_done(dpif, dump_ctx)
            : EOPNOTSUPP);
}

void
ct_dpif_entry_uninit(struct ct_dpif_entry *entry)
{
    if (entry) {
        if (entry->helper.name) {
            free(entry->helper.name);
        }
    }
}

static const char *
ct_dpif_status_flags(uint32_t flags)
{
    switch (flags) {
#define CT_DPIF_STATUS_FLAG(FLAG) \
    case CT_DPIF_STATUS_##FLAG: \
        return #FLAG;
    CT_DPIF_STATUS_FLAGS
#undef CT_DPIF_TCP_FLAG
    default:
        return NULL;
    }
}

void
ct_dpif_format_entry(const struct ct_dpif_entry *entry, struct ds *ds,
                     bool verbose, bool print_stats)
{
    ct_dpif_format_ipproto(ds, entry->tuple_orig.ip_proto);

    ds_put_cstr(ds, ",orig=(");
    ct_dpif_format_tuple(ds, &entry->tuple_orig);
    if (print_stats) {
        ct_dpif_format_counters(ds, &entry->counters_orig);
    }
    ds_put_cstr(ds, ")");

    ds_put_cstr(ds, ",reply=(");
    ct_dpif_format_tuple(ds, &entry->tuple_reply);
    if (print_stats) {
        ct_dpif_format_counters(ds, &entry->counters_reply);
    }
    ds_put_cstr(ds, ")");

    if (print_stats) {
        ct_dpif_format_timestamp(ds, &entry->timestamp);
    }
    if (verbose) {
        ds_put_format(ds, ",id=%"PRIu32, entry->id);
    }
    if (entry->zone) {
        ds_put_format(ds, ",zone=%"PRIu16, entry->zone);
    }
    if (verbose) {
        format_flags_masked(ds, ",status", ct_dpif_status_flags,
                            entry->status, CT_DPIF_STATUS_MASK,
                            CT_DPIF_STATUS_MASK);
    }
    if (print_stats) {
        ds_put_format(ds, ",timeout=%"PRIu32, entry->timeout);
    }
    if (entry->mark) {
        ds_put_format(ds, ",mark=%"PRIu32, entry->mark);
    }
    if (!ovs_u128_is_zero(entry->labels)) {
        ovs_be128 value;

        ds_put_cstr(ds, ",labels=");
        value = hton128(entry->labels);
        ds_put_hex(ds, &value, sizeof value);
    }
    ct_dpif_format_protoinfo(ds, ",protoinfo=", &entry->protoinfo, verbose);
    ct_dpif_format_helper(ds, ",helper=", &entry->helper);
    if (verbose && entry->tuple_parent.l3_type != 0) {
        ds_put_cstr(ds, ",parent=(");
        ct_dpif_format_tuple(ds, &entry->tuple_parent);
        ds_put_cstr(ds, ")");
    }
}

void
ct_dpif_format_ipproto(struct ds *ds, uint16_t ipproto)
{
    const char *name;

    name = (ipproto == IPPROTO_ICMP) ? "icmp"
        : (ipproto == IPPROTO_ICMPV6) ? "icmpv6"
        : (ipproto == IPPROTO_TCP) ? "tcp"
        : (ipproto == IPPROTO_UDP) ? "udp"
        : (ipproto == IPPROTO_SCTP) ? "sctp"
        : (ipproto == IPPROTO_UDPLITE) ? "udplite"
        : (ipproto == IPPROTO_DCCP) ? "dccp"
        : (ipproto == IPPROTO_IGMP) ? "igmp"
        : NULL;

    if (name) {
        ds_put_cstr(ds, name);
    } else {
        ds_put_format(ds, "%u", ipproto);
    }
}

static void
ct_dpif_format_counters(struct ds *ds, const struct ct_dpif_counters *counters)
{
    if (counters->packets || counters->bytes) {
        ds_put_format(ds, ",packets=%"PRIu64",bytes=%"PRIu64,
                      counters->packets, counters->bytes);
    }
}

static void
ct_dpif_format_timestamp(struct ds *ds,
                         const struct ct_dpif_timestamp *timestamp)
{
    if (timestamp->start || timestamp->stop) {
        ds_put_strftime_msec(ds, ",start=%Y-%m-%dT%H:%M:%S.###",
                             timestamp->start / UINT64_C(1000000), false);
        if (timestamp->stop) {
            ds_put_strftime_msec(ds, ",stop=%Y-%m-%dT%H:%M:%S.###",
                                 timestamp->stop / UINT64_C(1000000), false);
        }
    }
}

static void
ct_dpif_format_tuple_icmp(struct ds *ds, const struct ct_dpif_tuple *tuple)
{
    ds_put_format(ds, ",id=%u,type=%u,code=%u", ntohs(tuple->icmp_id),
                  tuple->icmp_type, tuple->icmp_code);
}

static void
ct_dpif_format_tuple_tp(struct ds *ds, const struct ct_dpif_tuple *tuple)
{
    ds_put_format(ds, ",sport=%u,dport=%u",
                  ntohs(tuple->src_port), ntohs(tuple->dst_port));
}

void
ct_dpif_format_tuple(struct ds *ds, const struct ct_dpif_tuple *tuple)
{
    if (tuple->l3_type == AF_INET) {
        ds_put_format(ds, "src="IP_FMT",dst="IP_FMT,
                      IP_ARGS(tuple->src.ip), IP_ARGS(tuple->dst.ip));
    } else if (tuple->l3_type == AF_INET6) {
        ds_put_cstr(ds, "src=");
        ipv6_format_addr(&tuple->src.in6, ds);
        ds_put_cstr(ds, ",dst=");
        ipv6_format_addr(&tuple->dst.in6, ds);
    } else {
        ds_put_format(ds, "Unsupported address family: %u. HEX:\n",
                      tuple->l3_type);
        ds_put_hex_dump(ds, tuple, sizeof *tuple, 0, false);
        return;
    }

    if (tuple->ip_proto == IPPROTO_ICMP
        || tuple->ip_proto == IPPROTO_ICMPV6) {
        ct_dpif_format_tuple_icmp(ds, tuple);
    } else {
        ct_dpif_format_tuple_tp(ds, tuple);
    }
}

const char *ct_dpif_tcp_state_string[] = {
#define CT_DPIF_TCP_STATE(STATE) [CT_DPIF_TCPS_##STATE] = #STATE,
    CT_DPIF_TCP_STATES
#undef CT_DPIF_TCP_STATE
};

const char *ct_dpif_sctp_state_string[] = {
#define CT_DPIF_SCTP_STATE(STATE) [CT_DPIF_SCTP_STATE_##STATE] = #STATE,
    CT_DPIF_SCTP_STATES
#undef CT_DPIF_SCTP_STATE
};

static void
ct_dpif_format_enum__(struct ds *ds, const char *title, unsigned int state,
                      const char *names[], unsigned int max)
{
    if (title) {
        ds_put_cstr(ds, title);
    }
    if (state < max) {
        ds_put_cstr(ds, names[state]);
    } else {
        ds_put_format(ds, "[%u]", state);
    }
}

#define ct_dpif_format_enum(DS, TITLE, STATE, NAMES) \
    ct_dpif_format_enum__((DS), (TITLE), (STATE), (NAMES), ARRAY_SIZE(NAMES))

static uint8_t
coalesce_tcp_state(uint8_t state)
{
    /* The Linux kernel connection tracker and the userspace view the
     * tcp states differently in some situations.  If we're formatting
     * the entry without being verbose, it is worth to adjust the
     * differences, to ease writing testcases. */
    switch (state) {
        case CT_DPIF_TCPS_FIN_WAIT_2:
            return CT_DPIF_TCPS_TIME_WAIT;
        case CT_DPIF_TCPS_SYN_RECV:
            return CT_DPIF_TCPS_ESTABLISHED;
        default:
            return state;
    }
}

static void
ct_dpif_format_protoinfo_tcp(struct ds *ds,
                             const struct ct_dpif_protoinfo *protoinfo)
{
    uint8_t tcp_state;

    /* We keep two separate tcp states, but we print just one. The Linux
     * kernel connection tracker internally keeps only one state, so
     * 'state_orig' and 'state_reply', will be the same. */
    tcp_state = MAX(protoinfo->tcp.state_orig, protoinfo->tcp.state_reply);

    tcp_state = coalesce_tcp_state(tcp_state);
    ct_dpif_format_enum(ds, "state=", tcp_state, ct_dpif_tcp_state_string);
}

static const char *
ct_dpif_tcp_flags(uint32_t flags)
{
    switch (flags) {
#define CT_DPIF_TCP_FLAG(FLAG) \
    case CT_DPIF_TCPF_##FLAG: \
        return #FLAG;
    CT_DPIF_TCP_FLAGS
#undef CT_DPIF_TCP_FLAG
    default:
        return NULL;
    }
}

static void
ct_dpif_format_protoinfo_tcp_verbose(struct ds *ds,
                                     const struct ct_dpif_protoinfo *protoinfo)
{
    ct_dpif_format_enum(ds, "state_orig=", protoinfo->tcp.state_orig,
                        ct_dpif_tcp_state_string);
    ct_dpif_format_enum(ds, ",state_reply=", protoinfo->tcp.state_reply,
                        ct_dpif_tcp_state_string);

    if (protoinfo->tcp.wscale_orig || protoinfo->tcp.wscale_reply) {
        ds_put_format(ds, ",wscale_orig=%u,wscale_reply=%u",
                      protoinfo->tcp.wscale_orig,
                      protoinfo->tcp.wscale_reply);
    }

    format_flags_masked(ds, ",flags_orig", ct_dpif_tcp_flags,
                        protoinfo->tcp.flags_orig, CT_DPIF_TCPF_MASK,
                        CT_DPIF_TCPF_MASK);

    format_flags_masked(ds, ",flags_reply", ct_dpif_tcp_flags,
                        protoinfo->tcp.flags_reply, CT_DPIF_TCPF_MASK,
                        CT_DPIF_TCPF_MASK);
}

static void
ct_dpif_format_protoinfo_sctp(struct ds *ds,
                              const struct ct_dpif_protoinfo *protoinfo)
{
    ct_dpif_format_enum(ds, "state=", protoinfo->sctp.state,
                        ct_dpif_sctp_state_string);
    ds_put_format(ds, ",vtag_orig=%" PRIu32 ",vtag_reply=%" PRIu32,
                  protoinfo->sctp.vtag_orig, protoinfo->sctp.vtag_reply);
}

static void
ct_dpif_format_protoinfo(struct ds *ds, const char *title,
                         const struct ct_dpif_protoinfo *protoinfo,
                         bool verbose)
{
    if (protoinfo->proto != 0) {
        if (title) {
            ds_put_format(ds, "%s(", title);
        }
        switch (protoinfo->proto) {
        case IPPROTO_TCP:
            if (verbose) {
                ct_dpif_format_protoinfo_tcp_verbose(ds, protoinfo);
            } else {
                ct_dpif_format_protoinfo_tcp(ds, protoinfo);
            }
            break;
        case IPPROTO_SCTP:
            ct_dpif_format_protoinfo_sctp(ds, protoinfo);
            break;
        }
        if (title) {
            ds_put_cstr(ds, ")");
        }
    }
}

static void
ct_dpif_format_helper(struct ds *ds, const char *title,
                    const struct ct_dpif_helper *helper)
{
    if (helper->name) {
        if (title) {
            ds_put_cstr(ds, title);
        }
        ds_put_cstr(ds, helper->name);
    }
}

uint8_t
ct_dpif_coalesce_tcp_state(uint8_t state)
{
    return coalesce_tcp_state(state);
}

void
ct_dpif_format_tcp_stat(struct ds * ds, int tcp_state, int conn_per_state)
{
    ct_dpif_format_enum(ds, "\t  [", tcp_state, ct_dpif_tcp_state_string);
    ds_put_cstr(ds, "]");
    ds_put_format(ds, "=%u", conn_per_state);
}


void
ct_dpif_push_zone_limit(struct ovs_list *zone_limits, uint16_t zone,
                        uint32_t limit, uint32_t count)
{
    struct ct_dpif_zone_limit *zone_limit = xmalloc(sizeof *zone_limit);
    zone_limit->zone = zone;
    zone_limit->limit = limit;
    zone_limit->count = count;
    ovs_list_push_back(zone_limits, &zone_limit->node);
}

void
ct_dpif_free_zone_limits(struct ovs_list *zone_limits)
{
    while (!ovs_list_is_empty(zone_limits)) {
        struct ovs_list *entry = ovs_list_pop_front(zone_limits);
        struct ct_dpif_zone_limit *cdzl;
        cdzl = CONTAINER_OF(entry, struct ct_dpif_zone_limit, node);
        free(cdzl);
    }
}

/* Parses a specification of a conntrack zone limit from 's' into '*pzone'
 * and '*plimit'.  Returns true on success.  Otherwise, returns false and
 * and puts the error message in 'ds'. */
bool
ct_dpif_parse_zone_limit_tuple(const char *s, uint16_t *pzone,
                               uint32_t *plimit, struct ds *ds)
{
    char *pos, *key, *value, *copy, *err;
    bool parsed_limit = false, parsed_zone = false;

    pos = copy = xstrdup(s);
    while (ofputil_parse_key_value(&pos, &key, &value)) {
        if (!*value) {
            ds_put_format(ds, "field %s missing value", key);
            goto error;
        }

        if (!strcmp(key, "zone")) {
            err = str_to_u16(value, key, pzone);
            if (err) {
                free(err);
                goto error_with_msg;
            }
            parsed_zone = true;
        }  else if (!strcmp(key, "limit")) {
            err = str_to_u32(value, plimit);
            if (err) {
                free(err);
                goto error_with_msg;
            }
            parsed_limit = true;
        } else {
            ds_put_format(ds, "invalid zone limit field: %s", key);
            goto error;
        }
    }

    if (!parsed_zone || !parsed_limit) {
        ds_put_format(ds, "failed to parse zone limit");
        goto error;
    }

    free(copy);
    return true;

error_with_msg:
    ds_put_format(ds, "failed to parse field %s", key);
error:
    free(copy);
    return false;
}

void
ct_dpif_format_zone_limits(uint32_t default_limit,
                           const struct ovs_list *zone_limits, struct ds *ds)
{
    struct ct_dpif_zone_limit *zone_limit;

    ds_put_format(ds, "default limit=%"PRIu32, default_limit);

    LIST_FOR_EACH (zone_limit, node, zone_limits) {
        ds_put_format(ds, "\nzone=%"PRIu16, zone_limit->zone);
        ds_put_format(ds, ",limit=%"PRIu32, zone_limit->limit);
        ds_put_format(ds, ",count=%"PRIu32, zone_limit->count);
    }
}

static const char *const ct_dpif_tp_attr_string[] = {
#define CT_DPIF_TP_TCP_ATTR(ATTR) \
    [CT_DPIF_TP_ATTR_TCP_##ATTR] = "TCP_"#ATTR,
    CT_DPIF_TP_TCP_ATTRS
#undef CT_DPIF_TP_TCP_ATTR
#define CT_DPIF_TP_UDP_ATTR(ATTR) \
    [CT_DPIF_TP_ATTR_UDP_##ATTR] = "UDP_"#ATTR,
    CT_DPIF_TP_UDP_ATTRS
#undef CT_DPIF_TP_UDP_ATTR
#define CT_DPIF_TP_ICMP_ATTR(ATTR) \
    [CT_DPIF_TP_ATTR_ICMP_##ATTR] = "ICMP_"#ATTR,
    CT_DPIF_TP_ICMP_ATTRS
#undef CT_DPIF_TP_ICMP_ATTR
};

static bool
ct_dpif_set_timeout_policy_attr(struct ct_dpif_timeout_policy *tp,
                                uint32_t attr, uint32_t value)
{
    if (tp->present & (1 << attr) && tp->attrs[attr] == value) {
        return false;
    }
    tp->attrs[attr] = value;
    tp->present |= 1 << attr;
    return true;
}

/* Sets a timeout value identified by '*name' to 'value'.
 * Returns true if the attribute is changed */
bool
ct_dpif_set_timeout_policy_attr_by_name(struct ct_dpif_timeout_policy *tp,
                                        const char *name, uint32_t value)
{
    for (uint32_t i = 0; i < CT_DPIF_TP_ATTR_MAX; ++i) {
        if (!strcasecmp(name, ct_dpif_tp_attr_string[i])) {
            return ct_dpif_set_timeout_policy_attr(tp, i, value);
        }
    }
    return false;
}

bool
ct_dpif_timeout_policy_support_ipproto(uint8_t ipproto)
{
    if (ipproto == IPPROTO_TCP || ipproto == IPPROTO_UDP ||
        ipproto == IPPROTO_ICMP || ipproto == IPPROTO_ICMPV6) {
        return true;
    }
    return false;
}

int
ct_dpif_set_timeout_policy(struct dpif *dpif,
                           const struct ct_dpif_timeout_policy *tp)
{
    return (dpif->dpif_class->ct_set_timeout_policy
            ? dpif->dpif_class->ct_set_timeout_policy(dpif, tp)
            : EOPNOTSUPP);
}

int
ct_dpif_del_timeout_policy(struct dpif *dpif, uint32_t tp_id)
{
    return (dpif->dpif_class->ct_del_timeout_policy
            ? dpif->dpif_class->ct_del_timeout_policy(dpif, tp_id)
            : EOPNOTSUPP);
}

int
ct_dpif_get_timeout_policy(struct dpif *dpif, uint32_t tp_id,
                           struct ct_dpif_timeout_policy *tp)
{
    return (dpif->dpif_class->ct_get_timeout_policy
            ? dpif->dpif_class->ct_get_timeout_policy(
                dpif, tp_id, tp) : EOPNOTSUPP);
}

int
ct_dpif_timeout_policy_dump_start(struct dpif *dpif, void **statep)
{
    return (dpif->dpif_class->ct_timeout_policy_dump_start
            ? dpif->dpif_class->ct_timeout_policy_dump_start(dpif, statep)
            : EOPNOTSUPP);
}

int
ct_dpif_timeout_policy_dump_next(struct dpif *dpif, void *state,
                                 struct ct_dpif_timeout_policy *tp)
{
    return (dpif->dpif_class->ct_timeout_policy_dump_next
            ? dpif->dpif_class->ct_timeout_policy_dump_next(dpif, state, tp)
            : EOPNOTSUPP);
}

int
ct_dpif_timeout_policy_dump_done(struct dpif *dpif, void *state)
{
    return (dpif->dpif_class->ct_timeout_policy_dump_done
            ? dpif->dpif_class->ct_timeout_policy_dump_done(dpif, state)
            : EOPNOTSUPP);
}

int
ct_dpif_get_timeout_policy_name(struct dpif *dpif, uint32_t tp_id,
                                uint16_t dl_type, uint8_t nw_proto,
                                char **tp_name, bool *is_generic)
{
    return (dpif->dpif_class->ct_get_timeout_policy_name
            ? dpif->dpif_class->ct_get_timeout_policy_name(
                dpif, tp_id, dl_type, nw_proto, tp_name, is_generic)
            : EOPNOTSUPP);
}

int
ct_dpif_get_features(struct dpif *dpif, enum ct_features *features)
{
    return (dpif->dpif_class->ct_get_features
            ? dpif->dpif_class->ct_get_features(dpif, features)
            : EOPNOTSUPP);
}

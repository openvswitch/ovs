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

#include "openvswitch/ofp-print.h"

#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>

#include "bundle.h"
#include "byte-order.h"
#include "colors.h"
#include "compiler.h"
#include "dp-packet.h"
#include "flow.h"
#include "learn.h"
#include "multipath.h"
#include "netdev.h"
#include "nx-match.h"
#include "odp-util.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-bundle.h"
#include "openvswitch/ofp-connection.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-group.h"
#include "openvswitch/ofp-ipfix.h"
#include "openvswitch/ofp-match.h"
#include "openvswitch/ofp-meter.h"
#include "openvswitch/ofp-monitor.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-port.h"
#include "openvswitch/ofp-queue.h"
#include "openvswitch/ofp-switch.h"
#include "openvswitch/ofp-table.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/type-props.h"
#include "packets.h"
#include "unaligned.h"
#include "util.h"
#include "uuid.h"

static void ofp_print_queue_name(struct ds *string, uint32_t port);
static void ofp_print_error(struct ds *, enum ofperr);

/* Returns a string that represents the contents of the Ethernet frame in the
 * 'len' bytes starting at 'data'.  The caller must free the returned string.*/
char *
ofp_packet_to_string(const void *data, size_t len, ovs_be32 packet_type)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct dp_packet buf;
    struct flow flow;
    size_t l4_size;

    dp_packet_use_const(&buf, data, len);
    buf.packet_type = packet_type;
    flow_extract(&buf, &flow);
    flow_format(&ds, &flow, NULL);

    l4_size = dp_packet_l4_size(&buf);

    if (flow.nw_proto == IPPROTO_TCP && l4_size >= TCP_HEADER_LEN) {
        struct tcp_header *th = dp_packet_l4(&buf);
        ds_put_format(&ds, " tcp_csum:%"PRIx16, ntohs(th->tcp_csum));
    } else if (flow.nw_proto == IPPROTO_UDP && l4_size >= UDP_HEADER_LEN) {
        struct udp_header *uh = dp_packet_l4(&buf);
        ds_put_format(&ds, " udp_csum:%"PRIx16, ntohs(uh->udp_csum));
    } else if (flow.nw_proto == IPPROTO_SCTP && l4_size >= SCTP_HEADER_LEN) {
        struct sctp_header *sh = dp_packet_l4(&buf);
        ds_put_format(&ds, " sctp_csum:%"PRIx32,
                      ntohl(get_16aligned_be32(&sh->sctp_csum)));
    } else if (flow.nw_proto == IPPROTO_ICMP && l4_size >= ICMP_HEADER_LEN) {
        struct icmp_header *icmph = dp_packet_l4(&buf);
        ds_put_format(&ds, " icmp_csum:%"PRIx16,
                      ntohs(icmph->icmp_csum));
    } else if (flow.nw_proto == IPPROTO_ICMPV6 && l4_size >= ICMP6_HEADER_LEN) {
        struct icmp6_header *icmp6h = dp_packet_l4(&buf);
        ds_put_format(&ds, " icmp6_csum:%"PRIx16,
                      ntohs(icmp6h->icmp6_cksum));
    }

    ds_put_char(&ds, '\n');

    return ds_cstr(&ds);
}

char *
ofp_dp_packet_to_string(const struct dp_packet *packet)
{
    return ofp_packet_to_string(dp_packet_data(packet),
                                dp_packet_size(packet),
                                packet->packet_type);
}

static enum ofperr
ofp_print_packet_in(struct ds *string, const struct ofp_header *oh,
                    const struct ofputil_port_map *port_map,
                    const struct ofputil_table_map *table_map, int verbosity)
{
    struct ofputil_packet_in_private pin;
    uint32_t buffer_id;
    size_t total_len;
    enum ofperr error = ofputil_decode_packet_in_private(oh, true, NULL, NULL,
                                                         &pin, &total_len,
                                                         &buffer_id);
    if (!error) {
        ofputil_packet_in_private_format(string, &pin, total_len, buffer_id,
                                         port_map, table_map, verbosity);
        ofputil_packet_in_private_destroy(&pin);
    }
    return error;
}

static enum ofperr
ofp_print_packet_out(struct ds *string, const struct ofp_header *oh,
                     const struct ofputil_port_map *port_map,
                     const struct ofputil_table_map *table_map, int verbosity)
{
    struct ofputil_packet_out po;
    struct ofpbuf ofpacts;
    enum ofperr error;

    ofpbuf_init(&ofpacts, 64);
    error = ofputil_decode_packet_out(&po, oh, NULL, &ofpacts);
    if (!error) {
        ofputil_packet_out_format(string, &po, port_map, table_map, verbosity);
    }
    ofpbuf_uninit(&ofpacts);
    return error;
}

void
ofp_print_bit_names(struct ds *string, uint32_t bits,
                    const char *(*bit_to_name)(uint32_t bit),
                    char separator)
{
    int n = 0;
    int i;

    if (!bits) {
        ds_put_cstr(string, "0");
        return;
    }

    for (i = 0; i < 32; i++) {
        uint32_t bit = UINT32_C(1) << i;

        if (bits & bit) {
            const char *name = bit_to_name(bit);
            if (name) {
                if (n++) {
                    ds_put_char(string, separator);
                }
                ds_put_cstr(string, name);
                bits &= ~bit;
            }
        }
    }

    if (bits) {
        if (n) {
            ds_put_char(string, separator);
        }
        ds_put_format(string, "0x%"PRIx32, bits);
    }
}

static enum ofperr
ofp_print_switch_features(struct ds *string, const struct ofp_header *oh)
{
    struct ofputil_switch_features features;
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofperr error = ofputil_pull_switch_features(&b, &features);
    if (!error) {
        ofputil_switch_features_format(string, &features);
        error = ofputil_phy_ports_format(string, oh->version, &b);
    }
    return error;
}

static enum ofperr
ofp_print_set_config(struct ds *string, const struct ofp_header *oh)
{
    struct ofputil_switch_config config;
    enum ofperr error;

    error = ofputil_decode_set_config(oh, &config);
    if (error) {
        return error;
    }
    ofputil_switch_config_format(string, &config);
    return 0;
}

static enum ofperr
ofp_print_get_config_reply(struct ds *string, const struct ofp_header *oh)
{
    struct ofputil_switch_config config;
    ofputil_decode_get_config_reply(oh, &config);
    ofputil_switch_config_format(string, &config);
    return 0;
}

static enum ofperr
ofp_print_table_features_reply(struct ds *s, const struct ofp_header *oh,
                               const struct ofputil_table_map *table_map)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));

    struct ofputil_table_features prev;
    for (int i = 0; ; i++) {
        struct ofputil_table_features tf;
        int retval;

        retval = ofputil_decode_table_features(&b, &tf, true);
        if (retval) {
            return retval != EOF ? retval : 0;
        }

        ds_put_char(s, '\n');
        ofputil_table_features_format(s, &tf, i ? &prev : NULL, NULL, NULL,
                                      table_map);
        prev = tf;
    }
}

void
ofp_print_duration(struct ds *string, unsigned int sec, unsigned int nsec)
{
    ds_put_format(string, "%u", sec);

    /* If there are no fractional seconds, don't print any decimals.
     *
     * If the fractional seconds can be expressed exactly as milliseconds,
     * print 3 decimals.  Open vSwitch provides millisecond precision for most
     * time measurements, so printing 3 decimals every time makes it easier to
     * spot real changes in flow dumps that refresh themselves quickly.
     *
     * If the fractional seconds are more precise than milliseconds, print the
     * number of decimals needed to express them exactly.
     */
    if (nsec > 0) {
        unsigned int msec = nsec / 1000000;
        if (msec * 1000000 == nsec) {
            ds_put_format(string, ".%03u", msec);
        } else {
            ds_put_format(string, ".%09u", nsec);
            while (string->string[string->length - 1] == '0') {
                string->length--;
            }
        }
    }
    ds_put_char(string, 's');
}

static enum ofperr
ofp_print_flow_removed(struct ds *string, const struct ofp_header *oh,
                       const struct ofputil_port_map *port_map,
                       const struct ofputil_table_map *table_map)
{
    struct ofputil_flow_removed fr;
    enum ofperr error = ofputil_decode_flow_removed(&fr, oh);
    if (!error) {
        ofputil_flow_removed_format(string, &fr, port_map, table_map);
    }
    return error;
}

static enum ofperr
ofp_print_port_mod(struct ds *string, const struct ofp_header *oh,
                   const struct ofputil_port_map *port_map)
{
    struct ofputil_port_mod pm;
    enum ofperr error = ofputil_decode_port_mod(oh, &pm, true);
    if (!error) {
        ofputil_port_mod_format(string, &pm, port_map);
    }
    return error;
}

static enum ofperr
ofp_print_table_mod(struct ds *string, const struct ofp_header *oh,
                  const struct ofputil_table_map *table_map)
{
    struct ofputil_table_mod tm;
    enum ofperr error = ofputil_decode_table_mod(oh, &tm);
    if (!error) {
        ofputil_table_mod_format(string, &tm, table_map);
    }
    return error;
}

static enum ofperr
ofp_print_table_status_message(struct ds *string, const struct ofp_header *oh,
                               const struct ofputil_table_map *table_map)
{
    struct ofputil_table_status ts;
    enum ofperr error;

    error = ofputil_decode_table_status(oh, &ts);
    if (error) {
        return error;
    }

    if (ts.reason == OFPTR_VACANCY_DOWN) {
        ds_put_format(string, " reason=VACANCY_DOWN");
    } else if (ts.reason == OFPTR_VACANCY_UP) {
        ds_put_format(string, " reason=VACANCY_UP");
    }

    ds_put_format(string, "\ntable_desc:-");
    ofputil_table_desc_format(string, &ts.desc, table_map);

    return 0;
}

static enum ofperr
ofp_print_queue_get_config_request(struct ds *string,
                                   const struct ofp_header *oh,
                                   const struct ofputil_port_map *port_map)
{
    enum ofperr error;
    ofp_port_t port;
    uint32_t queue;

    error = ofputil_decode_queue_get_config_request(oh, &port, &queue);
    if (error) {
        return error;
    }

    ds_put_cstr(string, " port=");
    ofputil_format_port(port, port_map, string);

    if (queue != OFPQ_ALL) {
        ds_put_cstr(string, " queue=");
        ofp_print_queue_name(string, queue);
    }

    return 0;
}

static void
print_queue_rate(struct ds *string, const char *name, unsigned int rate)
{
    if (rate <= 1000) {
        ds_put_format(string, " %s:%u.%u%%", name, rate / 10, rate % 10);
    } else if (rate < UINT16_MAX) {
        ds_put_format(string, " %s:(disabled)", name);
    }
}

/* qsort comparison function. */
static int
compare_queues(const void *a_, const void *b_)
{
    const struct ofputil_queue_config *a = a_;
    const struct ofputil_queue_config *b = b_;

    uint16_t ap = ofp_to_u16(a->port);
    uint16_t bp = ofp_to_u16(b->port);
    if (ap != bp) {
        return ap < bp ? -1 : 1;
    }

    uint32_t aq = a->queue;
    uint32_t bq = b->queue;
    return aq < bq ? -1 : aq > bq;
}

static enum ofperr
ofp_print_queue_get_config_reply(struct ds *string,
                                 const struct ofp_header *oh,
                                 const struct ofputil_port_map *port_map)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));

    struct ofputil_queue_config *queues = NULL;
    size_t allocated_queues = 0;
    size_t n = 0;

    int retval = 0;
    for (;;) {
        if (n >= allocated_queues) {
            queues = x2nrealloc(queues, &allocated_queues, sizeof *queues);
        }
        retval = ofputil_pull_queue_get_config_reply(&b, &queues[n]);
        if (retval) {
            break;
        }
        n++;
    }

    qsort(queues, n, sizeof *queues, compare_queues);

    ds_put_char(string, ' ');

    ofp_port_t port = 0;
    for (const struct ofputil_queue_config *q = queues; q < &queues[n]; q++) {
        if (q->port != port) {
            port = q->port;

            ds_put_cstr(string, "port=");
            ofputil_format_port(port, port_map, string);
            ds_put_char(string, '\n');
        }

        ds_put_format(string, "queue %"PRIu32":", q->queue);
        print_queue_rate(string, "min_rate", q->min_rate);
        print_queue_rate(string, "max_rate", q->max_rate);
        ds_put_char(string, '\n');
    }

    ds_chomp(string, ' ');
    free(queues);

    return retval != EOF ? retval : 0;
}

static void
ofp_print_meter_flags(struct ds *s, uint16_t flags)
{
    if (flags & OFPMF13_KBPS) {
        ds_put_cstr(s, "kbps ");
    }
    if (flags & OFPMF13_PKTPS) {
        ds_put_cstr(s, "pktps ");
    }
    if (flags & OFPMF13_BURST) {
        ds_put_cstr(s, "burst ");
    }
    if (flags & OFPMF13_STATS) {
        ds_put_cstr(s, "stats ");
    }

    flags &= ~(OFPMF13_KBPS | OFPMF13_PKTPS | OFPMF13_BURST | OFPMF13_STATS);
    if (flags) {
        ds_put_format(s, "flags:0x%"PRIx16" ", flags);
    }
}

static void
ofp_print_meter_band(struct ds *s, uint16_t flags,
                     const struct ofputil_meter_band *mb)
{
    ds_put_cstr(s, "\ntype=");
    switch (mb->type) {
    case OFPMBT13_DROP:
        ds_put_cstr(s, "drop");
        break;
    case OFPMBT13_DSCP_REMARK:
        ds_put_cstr(s, "dscp_remark");
        break;
    default:
        ds_put_format(s, "%u", mb->type);
    }

    ds_put_format(s, " rate=%"PRIu32, mb->rate);

    if (flags & OFPMF13_BURST) {
        ds_put_format(s, " burst_size=%"PRIu32, mb->burst_size);
    }
    if (mb->type == OFPMBT13_DSCP_REMARK) {
        ds_put_format(s, " prec_level=%"PRIu8, mb->prec_level);
    }
}

static void
ofp_print_meter_id(struct ds *s, uint32_t meter_id, char seperator)
{
    if (meter_id <= OFPM13_MAX) {
        ds_put_format(s, "meter%c%"PRIu32, seperator, meter_id);
    } else {
        const char *name;
        switch (meter_id) {
        case OFPM13_SLOWPATH:
            name = "slowpath";
            break;
        case OFPM13_CONTROLLER:
            name = "controller";
            break;
        case OFPM13_ALL:
            name = "all";
            break;
        default:
            name = "unknown";
        }
        ds_put_format(s, "meter%c%s", seperator, name);
    }
}

static void
ofp_print_meter_stats(struct ds *s, const struct ofputil_meter_stats *ms)
{
    uint16_t i;

    ofp_print_meter_id(s, ms->meter_id, ':');
    ds_put_char(s, ' ');
    ds_put_format(s, "flow_count:%"PRIu32" ", ms->flow_count);
    ds_put_format(s, "packet_in_count:%"PRIu64" ", ms->packet_in_count);
    ds_put_format(s, "byte_in_count:%"PRIu64" ", ms->byte_in_count);
    ds_put_cstr(s, "duration:");
    ofp_print_duration(s, ms->duration_sec, ms->duration_nsec);
    ds_put_char(s, ' ');

    ds_put_cstr(s, "bands:\n");
    for (i = 0; i < ms->n_bands; ++i) {
        ds_put_format(s, "%d: ", i);
        ds_put_format(s, "packet_count:%"PRIu64" ", ms->bands[i].packet_count);
        ds_put_format(s, "byte_count:%"PRIu64"\n", ms->bands[i].byte_count);
    }
}

static void
ofp_print_meter_config(struct ds *s, const struct ofputil_meter_config *mc)
{
    uint16_t i;

    ofp_print_meter_id(s, mc->meter_id, '=');
    ds_put_char(s, ' ');

    ofp_print_meter_flags(s, mc->flags);

    ds_put_cstr(s, "bands=");
    for (i = 0; i < mc->n_bands; ++i) {
        ofp_print_meter_band(s, mc->flags, &mc->bands[i]);
    }
    ds_put_char(s, '\n');
}

static void
ofp_print_meter_mod__(struct ds *s, const struct ofputil_meter_mod *mm)
{
    switch (mm->command) {
    case OFPMC13_ADD:
        ds_put_cstr(s, " ADD ");
        break;
    case OFPMC13_MODIFY:
        ds_put_cstr(s, " MOD ");
        break;
    case OFPMC13_DELETE:
        ds_put_cstr(s, " DEL ");
        break;
    default:
        ds_put_format(s, " cmd:%d ", mm->command);
    }

    ofp_print_meter_config(s, &mm->meter);
}

static enum ofperr
ofp_print_meter_mod(struct ds *s, const struct ofp_header *oh)
{
    struct ofputil_meter_mod mm;
    struct ofpbuf bands;
    enum ofperr error;

    ofpbuf_init(&bands, 64);
    error = ofputil_decode_meter_mod(oh, &mm, &bands);
    if (!error) {
        ofp_print_meter_mod__(s, &mm);
    }
    ofpbuf_uninit(&bands);

    return error;
}

static enum ofperr
ofp_print_meter_stats_request(struct ds *s, const struct ofp_header *oh)
{
    uint32_t meter_id;

    ofputil_decode_meter_request(oh, &meter_id);
    ds_put_char(s, ' ');

    ofp_print_meter_id(s, meter_id, '=');

    return 0;
}

static const char *
ofputil_meter_capabilities_to_name(uint32_t bit)
{
    enum ofp13_meter_flags flag = bit;

    switch (flag) {
    case OFPMF13_KBPS:    return "kbps";
    case OFPMF13_PKTPS:   return "pktps";
    case OFPMF13_BURST:   return "burst";
    case OFPMF13_STATS:   return "stats";
    }

    return NULL;
}

static const char *
ofputil_meter_band_types_to_name(uint32_t bit)
{
    switch (bit) {
    case 1 << OFPMBT13_DROP:          return "drop";
    case 1 << OFPMBT13_DSCP_REMARK:   return "dscp_remark";
    }

    return NULL;
}

static enum ofperr
ofp_print_meter_features_reply(struct ds *s, const struct ofp_header *oh)
{
    struct ofputil_meter_features mf;

    ofputil_decode_meter_features(oh, &mf);

    ds_put_format(s, "\nmax_meter:%"PRIu32, mf.max_meters);
    ds_put_format(s, " max_bands:%"PRIu8, mf.max_bands);
    ds_put_format(s, " max_color:%"PRIu8"\n", mf.max_color);

    ds_put_cstr(s, "band_types: ");
    ofp_print_bit_names(s, mf.band_types,
                        ofputil_meter_band_types_to_name, ' ');
    ds_put_char(s, '\n');

    ds_put_cstr(s, "capabilities: ");
    ofp_print_bit_names(s, mf.capabilities,
                        ofputil_meter_capabilities_to_name, ' ');
    ds_put_char(s, '\n');

    return 0;
}

static enum ofperr
ofp_print_meter_config_reply(struct ds *s, const struct ofp_header *oh)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    struct ofpbuf bands;
    int retval;

    ofpbuf_init(&bands, 64);
    for (;;) {
        struct ofputil_meter_config mc;

        retval = ofputil_decode_meter_config(&b, &mc, &bands);
        if (retval) {
            break;
        }
        ds_put_char(s, '\n');
        ofp_print_meter_config(s, &mc);
    }
    ofpbuf_uninit(&bands);

    return retval != EOF ? retval : 0;
}

static enum ofperr
ofp_print_meter_stats_reply(struct ds *s, const struct ofp_header *oh)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    struct ofpbuf bands;
    int retval;

    ofpbuf_init(&bands, 64);
    for (;;) {
        struct ofputil_meter_stats ms;

        retval = ofputil_decode_meter_stats(&b, &ms, &bands);
        if (retval) {
            break;
        }
        ds_put_char(s, '\n');
        ofp_print_meter_stats(s, &ms);
    }
    ofpbuf_uninit(&bands);

    return retval != EOF ? retval : 0;
}

static void
ofp_print_error(struct ds *string, enum ofperr error)
{
    ds_put_format(string, "***decode error: %s***\n", ofperr_get_name(error));
}

static enum ofperr
ofp_print_hello(struct ds *string, const struct ofp_header *oh)
{
    ofputil_hello_format(string, oh);
    return 0;
}

static enum ofperr
ofp_print_error_msg(struct ds *string, const struct ofp_header *oh,
                    const struct ofputil_port_map *port_map,
                    const struct ofputil_table_map *table_map)
{
    struct ofpbuf payload;
    enum ofperr error = ofperr_decode_msg(oh, &payload);
    if (!error) {
        return OFPERR_OFPBRC_BAD_LEN;
    }
    ofperr_msg_format(string, error, &payload, port_map, table_map);
    ofpbuf_uninit(&payload);

    return 0;
}

static enum ofperr
ofp_print_port_status(struct ds *string, const struct ofp_header *oh)
{
    struct ofputil_port_status ps;
    enum ofperr error = ofputil_decode_port_status(oh, &ps);
    if (!error) {
        ofputil_port_status_format(string, &ps);
    }
    return error;
}

static enum ofperr
ofp_print_ofpst_desc_reply(struct ds *string, const struct ofp_header *oh)
{
    const struct ofp_desc_stats *ods = ofpmsg_body(oh);

    ds_put_char(string, '\n');
    ds_put_format(string, "Manufacturer: %.*s\n",
            (int) sizeof ods->mfr_desc, ods->mfr_desc);
    ds_put_format(string, "Hardware: %.*s\n",
            (int) sizeof ods->hw_desc, ods->hw_desc);
    ds_put_format(string, "Software: %.*s\n",
            (int) sizeof ods->sw_desc, ods->sw_desc);
    ds_put_format(string, "Serial Num: %.*s\n",
            (int) sizeof ods->serial_num, ods->serial_num);
    ds_put_format(string, "DP Description: %.*s\n",
            (int) sizeof ods->dp_desc, ods->dp_desc);

    return 0;
}

static enum ofperr
ofp_print_flow_stats_request(struct ds *string, const struct ofp_header *oh,
                             const struct ofputil_port_map *port_map,
                             const struct ofputil_table_map *table_map)
{
    struct ofputil_flow_stats_request fsr;
    enum ofperr error = ofputil_decode_flow_stats_request(&fsr, oh, NULL,
                                                          NULL);
    if (!error) {
        ofputil_flow_stats_request_format(string, &fsr, port_map, table_map);
    }
    return error;
}

static enum ofperr
ofp_print_flow_stats_reply(struct ds *string, const struct ofp_header *oh,
                           const struct ofputil_port_map *port_map,
                           const struct ofputil_table_map *table_map)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    struct ofpbuf ofpacts;
    int retval;

    ofpbuf_init(&ofpacts, 64);
    for (;;) {
        struct ofputil_flow_stats fs;

        retval = ofputil_decode_flow_stats_reply(&fs, &b, true, &ofpacts);
        if (retval) {
            break;
        }
        ds_put_cstr(string, "\n ");
        ofputil_flow_stats_format(string, &fs, port_map, table_map, true);
     }
    ofpbuf_uninit(&ofpacts);

    return retval != EOF ? retval : 0;
}

static enum ofperr
ofp_print_aggregate_stats_reply(struct ds *string, const struct ofp_header *oh)
{
    struct ofputil_aggregate_stats as;
    enum ofperr error;

    error = ofputil_decode_aggregate_stats_reply(&as, oh);
    if (!error) {
        ofputil_aggregate_stats_format(string, &as);
    }
    return error;
}

static void
print_port_stat(struct ds *string, const char *leader, uint64_t stat, int more)
{
    ds_put_cstr(string, leader);
    if (stat != UINT64_MAX) {
        ds_put_format(string, "%"PRIu64, stat);
    } else {
        ds_put_char(string, '?');
    }
    if (more) {
        ds_put_cstr(string, ", ");
    } else {
        ds_put_cstr(string, "\n");
    }
}

static void
print_port_stat_cond(struct ds *string, const char *leader, uint64_t stat)
{
    if (stat != UINT64_MAX) {
        ds_put_format(string, "%s%"PRIu64", ", leader, stat);
    }
}

static enum ofperr
ofp_print_ofpst_port_request(struct ds *string, const struct ofp_header *oh,
                             const struct ofputil_port_map *port_map)
{
    ofp_port_t ofp10_port;
    enum ofperr error;

    error = ofputil_decode_port_stats_request(oh, &ofp10_port);
    if (error) {
        return error;
    }

    ds_put_cstr(string, " port_no=");
    ofputil_format_port(ofp10_port, port_map, string);

    return 0;
}

static enum ofperr
ofp_print_ofpst_port_reply(struct ds *string, const struct ofp_header *oh,
                           const struct ofputil_port_map *port_map,
                           int verbosity)
{
    uint32_t i;
    ds_put_format(string, " %"PRIuSIZE" ports\n", ofputil_count_port_stats(oh));
    if (verbosity < 1) {
        return 0;
    }

    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    for (;;) {
        struct ofputil_port_stats ps;
        int retval;

        retval = ofputil_decode_port_stats(&ps, &b);
        if (retval) {
            return retval != EOF ? retval : 0;
        }

        ds_put_cstr(string, "  port ");
        if (ofp_to_u16(ps.port_no) < 10) {
            ds_put_char(string, ' ');
        }
        ofputil_format_port(ps.port_no, port_map, string);

        ds_put_cstr(string, ": rx ");
        print_port_stat(string, "pkts=", ps.stats.rx_packets, 1);
        print_port_stat(string, "bytes=", ps.stats.rx_bytes, 1);
        print_port_stat(string, "drop=", ps.stats.rx_dropped, 1);
        print_port_stat(string, "errs=", ps.stats.rx_errors, 1);
        print_port_stat(string, "frame=", ps.stats.rx_frame_errors, 1);
        print_port_stat(string, "over=", ps.stats.rx_over_errors, 1);
        print_port_stat(string, "crc=", ps.stats.rx_crc_errors, 0);

        ds_put_cstr(string, "           tx ");
        print_port_stat(string, "pkts=", ps.stats.tx_packets, 1);
        print_port_stat(string, "bytes=", ps.stats.tx_bytes, 1);
        print_port_stat(string, "drop=", ps.stats.tx_dropped, 1);
        print_port_stat(string, "errs=", ps.stats.tx_errors, 1);
        print_port_stat(string, "coll=", ps.stats.collisions, 0);

        if (ps.duration_sec != UINT32_MAX) {
            ds_put_cstr(string, "           duration=");
            ofp_print_duration(string, ps.duration_sec, ps.duration_nsec);
            ds_put_char(string, '\n');
        }
        struct ds string_ext_stats = DS_EMPTY_INITIALIZER;

        ds_init(&string_ext_stats);

        print_port_stat_cond(&string_ext_stats, "1_to_64_packets=",
                             ps.stats.rx_1_to_64_packets);
        print_port_stat_cond(&string_ext_stats, "65_to_127_packets=",
                             ps.stats.rx_65_to_127_packets);
        print_port_stat_cond(&string_ext_stats, "128_to_255_packets=",
                             ps.stats.rx_128_to_255_packets);
        print_port_stat_cond(&string_ext_stats, "256_to_511_packets=",
                             ps.stats.rx_256_to_511_packets);
        print_port_stat_cond(&string_ext_stats, "512_to_1023_packets=",
                             ps.stats.rx_512_to_1023_packets);
        print_port_stat_cond(&string_ext_stats, "1024_to_1522_packets=",
                             ps.stats.rx_1024_to_1522_packets);
        print_port_stat_cond(&string_ext_stats, "1523_to_max_packets=",
                             ps.stats.rx_1523_to_max_packets);
        print_port_stat_cond(&string_ext_stats, "broadcast_packets=",
                             ps.stats.rx_broadcast_packets);
        print_port_stat_cond(&string_ext_stats, "undersized_errors=",
                             ps.stats.rx_undersized_errors);
        print_port_stat_cond(&string_ext_stats, "oversize_errors=",
                             ps.stats.rx_oversize_errors);
        print_port_stat_cond(&string_ext_stats, "rx_fragmented_errors=",
                             ps.stats.rx_fragmented_errors);
        print_port_stat_cond(&string_ext_stats, "rx_jabber_errors=",
                             ps.stats.rx_jabber_errors);

        if (string_ext_stats.length != 0) {
            /* If at least one statistics counter is reported: */
            ds_put_cstr(string, "           rx rfc2819 ");
            ds_put_buffer(string, string_ext_stats.string,
                          string_ext_stats.length);
            ds_put_cstr(string, "\n");
            ds_destroy(&string_ext_stats);
        }

        ds_init(&string_ext_stats);

        print_port_stat_cond(&string_ext_stats, "1_to_64_packets=",
                             ps.stats.tx_1_to_64_packets);
        print_port_stat_cond(&string_ext_stats, "65_to_127_packets=",
                             ps.stats.tx_65_to_127_packets);
        print_port_stat_cond(&string_ext_stats, "128_to_255_packets=",
                             ps.stats.tx_128_to_255_packets);
        print_port_stat_cond(&string_ext_stats, "256_to_511_packets=",
                             ps.stats.tx_256_to_511_packets);
        print_port_stat_cond(&string_ext_stats, "512_to_1023_packets=",
                             ps.stats.tx_512_to_1023_packets);
        print_port_stat_cond(&string_ext_stats, "1024_to_1522_packets=",
                             ps.stats.tx_1024_to_1522_packets);
        print_port_stat_cond(&string_ext_stats, "1523_to_max_packets=",
                             ps.stats.tx_1523_to_max_packets);
        print_port_stat_cond(&string_ext_stats, "multicast_packets=",
                             ps.stats.tx_multicast_packets);
        print_port_stat_cond(&string_ext_stats, "broadcast_packets=",
                             ps.stats.tx_broadcast_packets);

        if (string_ext_stats.length != 0) {
            /* If at least one statistics counter is reported: */
            ds_put_cstr(string, "           tx rfc2819 ");
            ds_put_buffer(string, string_ext_stats.string,
                          string_ext_stats.length);
            ds_put_cstr(string, "\n");
            ds_destroy(&string_ext_stats);
        }

        if (ps.custom_stats.size) {
            ds_put_cstr(string, "           CUSTOM Statistics");
            for (i = 0; i < ps.custom_stats.size; i++) {
                /* 3 counters in the row */
                if (ps.custom_stats.counters[i].name[0]) {
                    if (i % 3 == 0) {
                        ds_put_cstr(string, "\n");
                        ds_put_cstr(string, "                      ");
                    } else {
                        ds_put_char(string, ' ');
                    }
                    ds_put_format(string, "%s=%"PRIu64",",
                                  ps.custom_stats.counters[i].name,
                                  ps.custom_stats.counters[i].value);
                }
            }
            ds_put_cstr(string, "\n");
        }
    }
}

static enum ofperr
ofp_print_table_stats_reply(struct ds *string, const struct ofp_header *oh,
                            const struct ofputil_table_map *table_map)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&b);

    struct ofputil_table_features prev_features;
    struct ofputil_table_stats prev_stats;
    for (int i = 0;; i++) {
        struct ofputil_table_features features;
        struct ofputil_table_stats stats;
        int retval;

        retval = ofputil_decode_table_stats_reply(&b, &stats, &features);
        if (retval) {
            return retval != EOF ? retval : 0;
        }

        ds_put_char(string, '\n');
        ofputil_table_features_format(string,
                                      &features, i ? &prev_features : NULL,
                                      &stats, i ? &prev_stats : NULL,
                                      table_map);
        prev_features = features;
        prev_stats = stats;
    }
}

static void
ofp_print_queue_name(struct ds *string, uint32_t queue_id)
{
    if (queue_id == OFPQ_ALL) {
        ds_put_cstr(string, "ALL");
    } else {
        ds_put_format(string, "%"PRIu32, queue_id);
    }
}

static enum ofperr
ofp_print_ofpst_queue_request(struct ds *string, const struct ofp_header *oh,
                              const struct ofputil_port_map *port_map)
{
    struct ofputil_queue_stats_request oqsr;
    enum ofperr error;

    error = ofputil_decode_queue_stats_request(oh, &oqsr);
    if (error) {
        return error;
    }

    ds_put_cstr(string, " port=");
    ofputil_format_port(oqsr.port_no, port_map, string);

    ds_put_cstr(string, " queue=");
    ofp_print_queue_name(string, oqsr.queue_id);

    return 0;
}

static enum ofperr
ofp_print_ofpst_queue_reply(struct ds *string, const struct ofp_header *oh,
                            const struct ofputil_port_map *port_map,
                            int verbosity)
{
    ds_put_format(string, " %"PRIuSIZE" queues\n", ofputil_count_queue_stats(oh));
    if (verbosity < 1) {
        return 0;
    }

    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    for (;;) {
        struct ofputil_queue_stats qs;
        int retval;

        retval = ofputil_decode_queue_stats(&qs, &b);
        if (retval) {
            return retval != EOF ? retval : 0;
        }

        ds_put_cstr(string, "  port ");
        ofputil_format_port(qs.port_no, port_map, string);
        ds_put_cstr(string, " queue ");
        ofp_print_queue_name(string, qs.queue_id);
        ds_put_cstr(string, ": ");

        print_port_stat(string, "bytes=", qs.tx_bytes, 1);
        print_port_stat(string, "pkts=", qs.tx_packets, 1);
        print_port_stat(string, "errors=", qs.tx_errors, 1);

        ds_put_cstr(string, "duration=");
        if (qs.duration_sec != UINT32_MAX) {
            ofp_print_duration(string, qs.duration_sec, qs.duration_nsec);
        } else {
            ds_put_char(string, '?');
        }
        ds_put_char(string, '\n');
    }
}

static enum ofperr
ofp_print_ofpst_port_desc_request(struct ds *string,
                                  const struct ofp_header *oh,
                                  const struct ofputil_port_map *port_map)
{
    enum ofperr error;
    ofp_port_t port;

    error = ofputil_decode_port_desc_stats_request(oh, &port);
    if (error) {
        return error;
    }

    ds_put_cstr(string, " port=");
    ofputil_format_port(port, port_map, string);

    return 0;
}

static enum ofperr
ofp_print_ofpst_port_desc_reply(struct ds *string,
                                const struct ofp_header *oh)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    ofpraw_pull_assert(&b);
    ds_put_char(string, '\n');
    return ofputil_phy_ports_format(string, oh->version, &b);
}

static void
ofp_print_stats(struct ds *string, const struct ofp_header *oh)
{
    uint16_t flags = ofpmp_flags(oh);

    if (flags) {
        ds_put_cstr(string, " flags=");
        if ((!ofpmsg_is_stat_request(oh) || oh->version >= OFP13_VERSION)
            && (flags & OFPSF_REPLY_MORE)) {
            ds_put_cstr(string, "[more]");
            flags &= ~OFPSF_REPLY_MORE;
        }
        if (flags) {
            ds_put_format(string, "[***unknown flags 0x%04"PRIx16"***]",
                          flags);
        }
    }
}

static enum ofperr
ofp_print_echo(struct ds *string, const struct ofp_header *oh, int verbosity)
{
    size_t len = ntohs(oh->length);

    ds_put_format(string, " %"PRIuSIZE" bytes of payload\n", len - sizeof *oh);
    if (verbosity > 1) {
        ds_put_hex_dump(string, oh + 1, len - sizeof *oh, 0, true);
    }

    return 0;
}

static void
ofp_print_role_generic(struct ds *string, enum ofp12_controller_role role,
                       uint64_t generation_id)
{
    ds_put_cstr(string, " role=");

    switch (role) {
    case OFPCR12_ROLE_NOCHANGE:
        ds_put_cstr(string, "nochange");
        break;
    case OFPCR12_ROLE_EQUAL:
        ds_put_cstr(string, "equal"); /* OF 1.2 wording */
        break;
    case OFPCR12_ROLE_MASTER:
        ds_put_cstr(string, "master");
        break;
    case OFPCR12_ROLE_SLAVE:
        ds_put_cstr(string, "slave");
        break;
    default:
        OVS_NOT_REACHED();
    }

    if (generation_id != UINT64_MAX) {
        ds_put_format(string, " generation_id=%"PRIu64, generation_id);
    }
}

static enum ofperr
ofp_print_role_message(struct ds *string, const struct ofp_header *oh)
{
    struct ofputil_role_request rr;
    enum ofperr error;

    error = ofputil_decode_role_message(oh, &rr);
    if (error) {
        return error;
    }

    ofp_print_role_generic(string, rr.role, rr.have_generation_id ? rr.generation_id : UINT64_MAX);

    return 0;
}

static enum ofperr
ofp_print_role_status_message(struct ds *string, const struct ofp_header *oh)
{
    struct ofputil_role_status rs;
    enum ofperr error;

    error = ofputil_decode_role_status(oh, &rs);
    if (error) {
        return error;
    }

    ofp_print_role_generic(string, rs.role, rs.generation_id);

    ds_put_cstr(string, " reason=");

    switch (rs.reason) {
    case OFPCRR_MASTER_REQUEST:
        ds_put_cstr(string, "master_request");
        break;
    case OFPCRR_CONFIG:
        ds_put_cstr(string, "configuration_changed");
        break;
    case OFPCRR_EXPERIMENTER:
        ds_put_cstr(string, "experimenter_data_changed");
        break;
    case OFPCRR_N_REASONS:
    default:
        ds_put_cstr(string, "(unknown)");
        break;
    }

    return 0;
}

static enum ofperr
ofp_print_nxt_flow_mod_table_id(struct ds *string, const struct ofp_header *oh)
{
    bool enable = ofputil_decode_nx_flow_mod_table_id(oh);
    ds_put_format(string, " %s", enable ? "enable" : "disable");
    return 0;
}

static enum ofperr
ofp_print_nxt_set_flow_format(struct ds *string, const struct ofp_header *oh)
{
    enum ofputil_protocol p = ofputil_decode_nx_set_flow_format(oh);
    ds_put_format(string, " format=%s",
                  p == OFPUTIL_P_OF10_STD ? "openflow10"
                  : p == OFPUTIL_P_OF10_NXM ? "nxm"
                  : "(unknown)");
    return 0;
}

static enum ofperr
ofp_print_nxt_set_packet_in_format(struct ds *string,
                                   const struct ofp_header *oh)
{
    enum ofputil_packet_in_format format;
    enum ofperr error = ofputil_decode_set_packet_in_format(oh, &format);
    if (!error) {
        ds_put_format(string, " format=%s",
                      ofputil_packet_in_format_to_string(format));
    }
    return error;
}

/* Returns a string form of 'reason'.  The return value is either a statically
 * allocated constant string or the 'bufsize'-byte buffer 'reasonbuf'.
 * 'bufsize' should be at least OFP_PORT_REASON_BUFSIZE. */
#define OFP_PORT_REASON_BUFSIZE (INT_STRLEN(int) + 1)
static const char *
ofp_port_reason_to_string(enum ofp_port_reason reason,
                          char *reasonbuf, size_t bufsize)
{
    switch (reason) {
    case OFPPR_ADD:
        return "add";

    case OFPPR_DELETE:
        return "delete";

    case OFPPR_MODIFY:
        return "modify";

    case OFPPR_N_REASONS:
    default:
        snprintf(reasonbuf, bufsize, "%d", (int) reason);
        return reasonbuf;
    }
}

/* Returns a string form of 'reason'.  The return value is either a statically
 * allocated constant string or the 'bufsize'-byte buffer 'reasonbuf'.
 * 'bufsize' should be at least OFP_ASYNC_CONFIG_REASON_BUFSIZE. */
static const char*
ofp_role_reason_to_string(enum ofp14_controller_role_reason reason,
                          char *reasonbuf, size_t bufsize)
{
    switch (reason) {
    case OFPCRR_MASTER_REQUEST:
        return "master_request";

    case OFPCRR_CONFIG:
        return "configuration_changed";

    case OFPCRR_EXPERIMENTER:
        return "experimenter_data_changed";

    case OFPCRR_N_REASONS:
    default:
        snprintf(reasonbuf, bufsize, "%d", (int) reason);
        return reasonbuf;
    }
}

/* Returns a string form of 'reason'.  The return value is either a statically
 * allocated constant string or the 'bufsize'-byte buffer 'reasonbuf'.
 * 'bufsize' should be at least OFP_ASYNC_CONFIG_REASON_BUFSIZE. */
static const char*
ofp_table_reason_to_string(enum ofp14_table_reason reason,
                           char *reasonbuf, size_t bufsize)
{
    switch (reason) {
    case OFPTR_VACANCY_DOWN:
        return "vacancy_down";

    case OFPTR_VACANCY_UP:
        return "vacancy_up";

    default:
        snprintf(reasonbuf, bufsize, "%d", (int) reason);
        return reasonbuf;
    }
}

/* Returns a string form of 'reason'.  The return value is either a statically
 * allocated constant string or the 'bufsize'-byte buffer 'reasonbuf'.
 * 'bufsize' should be at least OFP_ASYNC_CONFIG_REASON_BUFSIZE. */
static const char*
ofp_requestforward_reason_to_string(enum ofp14_requestforward_reason reason,
                                    char *reasonbuf, size_t bufsize)
{
    switch (reason) {
    case OFPRFR_GROUP_MOD:
        return "group_mod_request";

    case OFPRFR_METER_MOD:
        return "meter_mod_request";

    case OFPRFR_N_REASONS:
    default:
        snprintf(reasonbuf, bufsize, "%d", (int) reason);
        return reasonbuf;
    }
}

static const char *
ofp_async_config_reason_to_string(uint32_t reason,
                                  enum ofputil_async_msg_type type,
                                  char *reasonbuf, size_t bufsize)
{
    switch (type) {
    case OAM_PACKET_IN:
        return ofputil_packet_in_reason_to_string(reason, reasonbuf, bufsize);

    case OAM_PORT_STATUS:
        return ofp_port_reason_to_string(reason, reasonbuf, bufsize);

    case OAM_FLOW_REMOVED:
        return ofp_flow_removed_reason_to_string(reason, reasonbuf, bufsize);

    case OAM_ROLE_STATUS:
        return ofp_role_reason_to_string(reason, reasonbuf, bufsize);

    case OAM_TABLE_STATUS:
        return ofp_table_reason_to_string(reason, reasonbuf, bufsize);

    case OAM_REQUESTFORWARD:
        return ofp_requestforward_reason_to_string(reason, reasonbuf, bufsize);

    case OAM_N_TYPES:
    default:
        return "Unknown asynchronous configuration message type";
    }
}


#define OFP_ASYNC_CONFIG_REASON_BUFSIZE (INT_STRLEN(int) + 1)
static enum ofperr
ofp_print_set_async_config(struct ds *string, const struct ofp_header *oh,
                           enum ofptype ofptype)
{
    struct ofputil_async_cfg basis = OFPUTIL_ASYNC_CFG_INIT;
    struct ofputil_async_cfg ac;

    bool is_reply = ofptype == OFPTYPE_GET_ASYNC_REPLY;
    enum ofperr error = ofputil_decode_set_async_config(oh, is_reply,
                                                        &basis, &ac);
    if (error) {
        return error;
    }

    for (int i = 0; i < 2; i++) {
        ds_put_format(string, "\n %s:\n", i == 0 ? "master" : "slave");
        for (uint32_t type = 0; type < OAM_N_TYPES; type++) {
            ds_put_format(string, "%16s:",
                          ofputil_async_msg_type_to_string(type));

            uint32_t role = i == 0 ? ac.master[type] : ac.slave[type];
            for (int j = 0; j < 32; j++) {
                if (role & (1u << j)) {
                    char reasonbuf[OFP_ASYNC_CONFIG_REASON_BUFSIZE];
                    const char *reason;

                    reason = ofp_async_config_reason_to_string(
                        j, type, reasonbuf, sizeof reasonbuf);
                    if (reason[0]) {
                        ds_put_format(string, " %s", reason);
                    }
                }
            }
            if (!role) {
                ds_put_cstr(string, " (off)");
            }
            ds_put_char(string, '\n');
        }
    }

    return 0;
}

static enum ofperr
ofp_print_nxt_set_controller_id(struct ds *string,
                                const struct nx_controller_id *nci)
{
    ds_put_format(string, " id=%"PRIu16, ntohs(nci->controller_id));
    return 0;
}

static enum ofperr
ofp_print_nxt_flow_monitor_cancel(struct ds *string,
                                  const struct ofp_header *oh)
{
    ds_put_format(string, " id=%"PRIu32,
                  ofputil_decode_flow_monitor_cancel(oh));
    return 0;
}

static enum ofperr
ofp_print_nxst_flow_monitor_request(struct ds *string,
                                    const struct ofp_header *oh,
                                    const struct ofputil_port_map *port_map,
                                    const struct ofputil_table_map *table_map)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    for (;;) {
        struct ofputil_flow_monitor_request request;
        int retval;

        retval = ofputil_decode_flow_monitor_request(&request, &b);
        if (retval) {
            return retval != EOF ? retval : 0;
        }

        ofputil_flow_monitor_request_format(string, &request,
                                            port_map, table_map);
    }
}

static enum ofperr
ofp_print_nxst_flow_monitor_reply(struct ds *string,
                                  const struct ofp_header *oh,
                                  const struct ofputil_port_map *port_map,
                                  const struct ofputil_table_map *table_map)
{
    uint64_t ofpacts_stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));

    for (;;) {
        struct ofputil_flow_update update;
        int retval = ofputil_decode_flow_update(&update, &b, &ofpacts);
        if (retval) {
            ofpbuf_uninit(&ofpacts);
            return retval != EOF ? retval : 0;
        }
        ofputil_flow_update_format(string, &update, port_map, table_map);
    }
}

void
ofp_print_version(const struct ofp_header *oh,
                  struct ds *string)
{
    switch (oh->version) {
    case OFP10_VERSION:
        break;
    case OFP11_VERSION:
        ds_put_cstr(string, " (OF1.1)");
        break;
    case OFP12_VERSION:
        ds_put_cstr(string, " (OF1.2)");
        break;
    case OFP13_VERSION:
        ds_put_cstr(string, " (OF1.3)");
        break;
    case OFP14_VERSION:
        ds_put_cstr(string, " (OF1.4)");
        break;
    case OFP15_VERSION:
        ds_put_cstr(string, " (OF1.5)");
        break;
    case OFP16_VERSION:
        ds_put_cstr(string, " (OF1.6)");
        break;
    default:
        ds_put_format(string, " (OF 0x%02"PRIx8")", oh->version);
        break;
    }
    ds_put_format(string, " (xid=0x%"PRIx32"):", ntohl(oh->xid));
}

static void
ofp_header_to_string__(const struct ofp_header *oh, enum ofpraw raw,
                       struct ds *string)
{
    ds_put_cstr(string, ofpraw_get_name(raw));
    ofp_print_version(oh, string);
}

static enum ofperr
ofp_print_table_desc_reply(struct ds *s, const struct ofp_header *oh,
                           const struct ofputil_table_map *table_map)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    for (;;) {
        struct ofputil_table_desc td;
        int retval;

        retval = ofputil_decode_table_desc(&b, &td, oh->version);
        if (retval) {
            return retval != EOF ? retval : 0;
        }
        ofputil_table_desc_format(s, &td, table_map);
    }
}

static const char *
bundle_flags_to_name(uint32_t bit)
{
    switch (bit) {
    case OFPBF_ATOMIC:
        return "atomic";
    case OFPBF_ORDERED:
        return "ordered";
    default:
        return NULL;
    }
}

static enum ofperr
ofp_print_bundle_ctrl(struct ds *s, const struct ofp_header *oh)
{
    int error;
    struct ofputil_bundle_ctrl_msg bctrl;

    error = ofputil_decode_bundle_ctrl(oh, &bctrl);
    if (error) {
        return error;
    }

    ds_put_char(s, '\n');

    ds_put_format(s, " bundle_id=%#"PRIx32" type=",  bctrl.bundle_id);
    switch (bctrl.type) {
    case OFPBCT_OPEN_REQUEST:
        ds_put_cstr(s, "OPEN_REQUEST");
        break;
    case OFPBCT_OPEN_REPLY:
        ds_put_cstr(s, "OPEN_REPLY");
        break;
    case OFPBCT_CLOSE_REQUEST:
        ds_put_cstr(s, "CLOSE_REQUEST");
        break;
    case OFPBCT_CLOSE_REPLY:
        ds_put_cstr(s, "CLOSE_REPLY");
        break;
    case OFPBCT_COMMIT_REQUEST:
        ds_put_cstr(s, "COMMIT_REQUEST");
        break;
    case OFPBCT_COMMIT_REPLY:
        ds_put_cstr(s, "COMMIT_REPLY");
        break;
    case OFPBCT_DISCARD_REQUEST:
        ds_put_cstr(s, "DISCARD_REQUEST");
        break;
    case OFPBCT_DISCARD_REPLY:
        ds_put_cstr(s, "DISCARD_REPLY");
        break;
    }

    ds_put_cstr(s, " flags=");
    ofp_print_bit_names(s, bctrl.flags, bundle_flags_to_name, ' ');

    return 0;
}

static enum ofperr
ofp_print_bundle_add(struct ds *s, const struct ofp_header *oh,
                     const struct ofputil_port_map *port_map,
                     const struct ofputil_table_map *table_map,
                     int verbosity)
{
    int error;
    struct ofputil_bundle_add_msg badd;

    error = ofputil_decode_bundle_add(oh, &badd, NULL);
    if (error) {
        return error;
    }

    ds_put_char(s, '\n');
    ds_put_format(s, " bundle_id=%#"PRIx32,  badd.bundle_id);
    ds_put_cstr(s, " flags=");
    ofp_print_bit_names(s, badd.flags, bundle_flags_to_name, ' ');

    ds_put_char(s, '\n');
    char *msg = ofp_to_string(badd.msg, ntohs(badd.msg->length), port_map,
                              table_map, verbosity);
    ds_put_and_free_cstr(s, msg);

    return 0;
}

static void
print_tlv_table(struct ds *s, struct ovs_list *mappings)
{
    struct ofputil_tlv_map *map;

    ds_put_cstr(s, " mapping table:\n");
    ds_put_cstr(s, " class\ttype\tlength\tmatch field\n");
    ds_put_cstr(s, " -----\t----\t------\t-----------");

    LIST_FOR_EACH (map, list_node, mappings) {
        ds_put_char(s, '\n');
        ds_put_format(s, " 0x%"PRIx16"\t0x%"PRIx8"\t%"PRIu8"\ttun_metadata%"PRIu16,
                      map->option_class, map->option_type, map->option_len,
                      map->index);
    }
}

static enum ofperr
ofp_print_tlv_table_mod(struct ds *s, const struct ofp_header *oh)
{
    int error;
    struct ofputil_tlv_table_mod ttm;

    error = ofputil_decode_tlv_table_mod(oh, &ttm);
    if (error) {
        return error;
    }

    ds_put_cstr(s, "\n ");

    switch (ttm.command) {
    case NXTTMC_ADD:
        ds_put_cstr(s, "ADD");
        break;
    case NXTTMC_DELETE:
        ds_put_cstr(s, "DEL");
        break;
    case NXTTMC_CLEAR:
        ds_put_cstr(s, "CLEAR");
        break;
    }

    if (ttm.command != NXTTMC_CLEAR) {
        print_tlv_table(s, &ttm.mappings);
    }

    ofputil_uninit_tlv_table(&ttm.mappings);

    return 0;
}

static enum ofperr
ofp_print_tlv_table_reply(struct ds *s, const struct ofp_header *oh)
{
    int error;
    struct ofputil_tlv_table_reply ttr;
    struct ofputil_tlv_map *map;
    int allocated_space = 0;

    error = ofputil_decode_tlv_table_reply(oh, &ttr);
    if (error) {
        return error;
    }

    ds_put_char(s, '\n');

    LIST_FOR_EACH (map, list_node, &ttr.mappings) {
        allocated_space += map->option_len;
    }

    ds_put_format(s, " max option space=%"PRIu32" max fields=%"PRIu16"\n",
                  ttr.max_option_space, ttr.max_fields);
    ds_put_format(s, " allocated option space=%d\n", allocated_space);
    ds_put_char(s, '\n');
    print_tlv_table(s, &ttr.mappings);

    ofputil_uninit_tlv_table(&ttr.mappings);

    return 0;
}

/* This function will print the request forward message. The reason for
 * request forward is taken from rf.request.type */
static enum ofperr
ofp_print_requestforward(struct ds *string, const struct ofp_header *oh,
                         const struct ofputil_port_map *port_map,
                         const struct ofputil_table_map *table_map)
{
    struct ofputil_requestforward rf;
    enum ofperr error;

    error = ofputil_decode_requestforward(oh, &rf);
    if (error) {
        return error;
    }

    ds_put_cstr(string, " reason=");

    switch (rf.reason) {
    case OFPRFR_GROUP_MOD:
        ds_put_cstr(string, "group_mod");
        ofputil_group_mod_format__(string, oh->version, rf.group_mod, port_map,
                                   table_map);
        break;

    case OFPRFR_METER_MOD:
        ds_put_cstr(string, "meter_mod");
        ofp_print_meter_mod__(string, rf.meter_mod);
        break;

    case OFPRFR_N_REASONS:
        OVS_NOT_REACHED();
    }
    ofputil_destroy_requestforward(&rf);

    return 0;
}

static void
print_ipfix_stat(struct ds *string, const char *leader, uint64_t stat, int more)
{
    ds_put_cstr(string, leader);
    if (stat != UINT64_MAX) {
        ds_put_format(string, "%"PRIu64, stat);
    } else {
        ds_put_char(string, '?');
    }
    if (more) {
        ds_put_cstr(string, ", ");
    } else {
        ds_put_cstr(string, "\n");
    }
}

static enum ofperr
ofp_print_nxst_ipfix_bridge_reply(struct ds *string, const struct ofp_header *oh)
{
    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    for (;;) {
        struct ofputil_ipfix_stats is;
        int retval;

        retval = ofputil_pull_ipfix_stats(&is, &b);
        if (retval) {
            return retval != EOF ? retval : 0;
        }

        ds_put_cstr(string, "\n  bridge ipfix: ");
        print_ipfix_stat(string, "flows=", is.total_flows, 1);
        print_ipfix_stat(string, "current flows=", is.current_flows, 1);
        print_ipfix_stat(string, "sampled pkts=", is.pkts, 1);
        print_ipfix_stat(string, "ipv4 ok=", is.ipv4_pkts, 1);
        print_ipfix_stat(string, "ipv6 ok=", is.ipv6_pkts, 1);
        print_ipfix_stat(string, "tx pkts=", is.tx_pkts, 0);
        ds_put_cstr(string, "                ");
        print_ipfix_stat(string, "pkts errs=", is.error_pkts, 1);
        print_ipfix_stat(string, "ipv4 errs=", is.ipv4_error_pkts, 1);
        print_ipfix_stat(string, "ipv6 errs=", is.ipv6_error_pkts, 1);
        print_ipfix_stat(string, "tx errs=", is.tx_errors, 0);
    }
}

static enum ofperr
ofp_print_nxst_ipfix_flow_reply(struct ds *string, const struct ofp_header *oh)
{
    ds_put_format(string, " %"PRIuSIZE" ids\n", ofputil_count_ipfix_stats(oh));

    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    for (;;) {
        struct ofputil_ipfix_stats is;
        int retval;

        retval = ofputil_pull_ipfix_stats(&is, &b);
        if (retval) {
            return retval != EOF ? retval : 0;
        }

        ds_put_cstr(string, "  id");
        ds_put_format(string, " %3"PRIuSIZE": ", (size_t) is.collector_set_id);
        print_ipfix_stat(string, "flows=", is.total_flows, 1);
        print_ipfix_stat(string, "current flows=", is.current_flows, 1);
        print_ipfix_stat(string, "sampled pkts=", is.pkts, 1);
        print_ipfix_stat(string, "ipv4 ok=", is.ipv4_pkts, 1);
        print_ipfix_stat(string, "ipv6 ok=", is.ipv6_pkts, 1);
        print_ipfix_stat(string, "tx pkts=", is.tx_pkts, 0);
        ds_put_cstr(string, "          ");
        print_ipfix_stat(string, "pkts errs=", is.error_pkts, 1);
        print_ipfix_stat(string, "ipv4 errs=", is.ipv4_error_pkts, 1);
        print_ipfix_stat(string, "ipv6 errs=", is.ipv6_error_pkts, 1);
        print_ipfix_stat(string, "tx errs=", is.tx_errors, 0);
    }
}

static enum ofperr
ofp_print_nxt_ct_flush_zone(struct ds *string, const struct nx_zone_id *nzi)
{
    ds_put_format(string, " zone_id=%"PRIu16, ntohs(nzi->zone_id));
    return 0;
}

static enum ofperr
ofp_to_string__(const struct ofp_header *oh,
                const struct ofputil_port_map *port_map,
                const struct ofputil_table_map *table_map, enum ofpraw raw,
                struct ds *string, int verbosity)
{
    if (ofpmsg_is_stat(oh)) {
        ofp_print_stats(string, oh);
    }

    const void *msg = oh;
    enum ofptype type = ofptype_from_ofpraw(raw);
    switch (type) {
    case OFPTYPE_GROUP_STATS_REQUEST:
        return ofputil_group_stats_request_format(string, oh);

    case OFPTYPE_GROUP_STATS_REPLY:
        return ofputil_group_stats_format(string, oh);

    case OFPTYPE_GROUP_DESC_STATS_REQUEST:
        return ofputil_group_desc_request_format(string, oh);

    case OFPTYPE_GROUP_DESC_STATS_REPLY:
        return ofputil_group_desc_format(string, oh, port_map, table_map);

    case OFPTYPE_GROUP_FEATURES_STATS_REQUEST:
        break;

    case OFPTYPE_GROUP_FEATURES_STATS_REPLY:
        return ofputil_group_features_format(string, oh);

    case OFPTYPE_GROUP_MOD:
        return ofputil_group_mod_format(string, oh, port_map, table_map);

    case OFPTYPE_TABLE_FEATURES_STATS_REQUEST:
    case OFPTYPE_TABLE_FEATURES_STATS_REPLY:
        return ofp_print_table_features_reply(string, oh, table_map);

    case OFPTYPE_TABLE_DESC_REQUEST:
    case OFPTYPE_TABLE_DESC_REPLY:
        return ofp_print_table_desc_reply(string, oh, table_map);

    case OFPTYPE_HELLO:
        return ofp_print_hello(string, oh);

    case OFPTYPE_ERROR:
        return ofp_print_error_msg(string, oh, port_map, table_map);

    case OFPTYPE_ECHO_REQUEST:
    case OFPTYPE_ECHO_REPLY:
        return ofp_print_echo(string, oh, verbosity);

    case OFPTYPE_FEATURES_REQUEST:
        break;

    case OFPTYPE_FEATURES_REPLY:
        return ofp_print_switch_features(string, oh);

    case OFPTYPE_GET_CONFIG_REQUEST:
        break;

    case OFPTYPE_GET_CONFIG_REPLY:
        return ofp_print_get_config_reply(string, oh);

    case OFPTYPE_SET_CONFIG:
        return ofp_print_set_config(string, oh);

    case OFPTYPE_PACKET_IN:
        return ofp_print_packet_in(string, oh, port_map, table_map, verbosity);

    case OFPTYPE_FLOW_REMOVED:
        return ofp_print_flow_removed(string, oh, port_map, table_map);

    case OFPTYPE_PORT_STATUS:
        return ofp_print_port_status(string, oh);

    case OFPTYPE_PACKET_OUT:
        return ofp_print_packet_out(string, oh, port_map, table_map,
                                    verbosity);

    case OFPTYPE_FLOW_MOD:
        return ofputil_flow_mod_format(string, oh, port_map, table_map,
                                       verbosity);

    case OFPTYPE_PORT_MOD:
        return ofp_print_port_mod(string, oh, port_map);

    case OFPTYPE_TABLE_MOD:
        return ofp_print_table_mod(string, oh, table_map);

    case OFPTYPE_METER_MOD:
        return ofp_print_meter_mod(string, oh);

    case OFPTYPE_BARRIER_REQUEST:
    case OFPTYPE_BARRIER_REPLY:
        break;

    case OFPTYPE_QUEUE_GET_CONFIG_REQUEST:
        return ofp_print_queue_get_config_request(string, oh, port_map);

    case OFPTYPE_QUEUE_GET_CONFIG_REPLY:
        return ofp_print_queue_get_config_reply(string, oh, port_map);

    case OFPTYPE_ROLE_REQUEST:
    case OFPTYPE_ROLE_REPLY:
        return ofp_print_role_message(string, oh);
    case OFPTYPE_ROLE_STATUS:
        return ofp_print_role_status_message(string, oh);

    case OFPTYPE_REQUESTFORWARD:
        return ofp_print_requestforward(string, oh, port_map, table_map);

    case OFPTYPE_TABLE_STATUS:
        return ofp_print_table_status_message(string, oh, table_map);

    case OFPTYPE_METER_STATS_REQUEST:
    case OFPTYPE_METER_CONFIG_STATS_REQUEST:
        return ofp_print_meter_stats_request(string, oh);

    case OFPTYPE_METER_STATS_REPLY:
        return ofp_print_meter_stats_reply(string, oh);

    case OFPTYPE_METER_CONFIG_STATS_REPLY:
        return ofp_print_meter_config_reply(string, oh);

    case OFPTYPE_METER_FEATURES_STATS_REPLY:
        return ofp_print_meter_features_reply(string, oh);

    case OFPTYPE_DESC_STATS_REQUEST:
    case OFPTYPE_METER_FEATURES_STATS_REQUEST:
        break;

    case OFPTYPE_FLOW_STATS_REQUEST:
    case OFPTYPE_AGGREGATE_STATS_REQUEST:
        return ofp_print_flow_stats_request(string, oh, port_map, table_map);

    case OFPTYPE_TABLE_STATS_REQUEST:
        break;

    case OFPTYPE_PORT_STATS_REQUEST:
        return ofp_print_ofpst_port_request(string, oh, port_map);

    case OFPTYPE_QUEUE_STATS_REQUEST:
        return ofp_print_ofpst_queue_request(string, oh, port_map);

    case OFPTYPE_DESC_STATS_REPLY:
        return ofp_print_ofpst_desc_reply(string, oh);

    case OFPTYPE_FLOW_STATS_REPLY:
        return ofp_print_flow_stats_reply(string, oh, port_map, table_map);

    case OFPTYPE_QUEUE_STATS_REPLY:
        return ofp_print_ofpst_queue_reply(string, oh, port_map, verbosity);

    case OFPTYPE_PORT_STATS_REPLY:
        return ofp_print_ofpst_port_reply(string, oh, port_map, verbosity);

    case OFPTYPE_TABLE_STATS_REPLY:
        return ofp_print_table_stats_reply(string, oh, table_map);

    case OFPTYPE_AGGREGATE_STATS_REPLY:
        return ofp_print_aggregate_stats_reply(string, oh);

    case OFPTYPE_PORT_DESC_STATS_REQUEST:
        return ofp_print_ofpst_port_desc_request(string, oh, port_map);

    case OFPTYPE_PORT_DESC_STATS_REPLY:
        return ofp_print_ofpst_port_desc_reply(string, oh);

    case OFPTYPE_FLOW_MOD_TABLE_ID:
        return ofp_print_nxt_flow_mod_table_id(string, oh);

    case OFPTYPE_SET_FLOW_FORMAT:
        return ofp_print_nxt_set_flow_format(string, oh);

    case OFPTYPE_SET_PACKET_IN_FORMAT:
        return ofp_print_nxt_set_packet_in_format(string, oh);

    case OFPTYPE_FLOW_AGE:
        break;

    case OFPTYPE_SET_CONTROLLER_ID:
        return ofp_print_nxt_set_controller_id(string, ofpmsg_body(oh));

    case OFPTYPE_GET_ASYNC_REPLY:
    case OFPTYPE_SET_ASYNC_CONFIG:
        return ofp_print_set_async_config(string, oh, type);
    case OFPTYPE_GET_ASYNC_REQUEST:
        break;
    case OFPTYPE_FLOW_MONITOR_CANCEL:
        return ofp_print_nxt_flow_monitor_cancel(string, msg);

    case OFPTYPE_FLOW_MONITOR_PAUSED:
    case OFPTYPE_FLOW_MONITOR_RESUMED:
        break;

    case OFPTYPE_FLOW_MONITOR_STATS_REQUEST:
        return ofp_print_nxst_flow_monitor_request(string, msg, port_map,
                                                   table_map);

    case OFPTYPE_FLOW_MONITOR_STATS_REPLY:
        return ofp_print_nxst_flow_monitor_reply(string, msg, port_map,
                                                 table_map);

    case OFPTYPE_BUNDLE_CONTROL:
        return ofp_print_bundle_ctrl(string, msg);

    case OFPTYPE_BUNDLE_ADD_MESSAGE:
        return ofp_print_bundle_add(string, msg, port_map, table_map,
                                    verbosity);

    case OFPTYPE_NXT_TLV_TABLE_MOD:
        return ofp_print_tlv_table_mod(string, msg);

    case OFPTYPE_NXT_TLV_TABLE_REQUEST:
        break;

    case OFPTYPE_NXT_TLV_TABLE_REPLY:
        return ofp_print_tlv_table_reply(string, msg);

    case OFPTYPE_NXT_RESUME:
        return ofp_print_packet_in(string, msg, port_map, table_map,
                                   verbosity);
    case OFPTYPE_IPFIX_BRIDGE_STATS_REQUEST:
        break;
    case OFPTYPE_IPFIX_BRIDGE_STATS_REPLY:
        return ofp_print_nxst_ipfix_bridge_reply(string, oh);
    case OFPTYPE_IPFIX_FLOW_STATS_REQUEST:
        break;
    case OFPTYPE_IPFIX_FLOW_STATS_REPLY:
        return ofp_print_nxst_ipfix_flow_reply(string, oh);

    case OFPTYPE_CT_FLUSH_ZONE:
        return ofp_print_nxt_ct_flush_zone(string, ofpmsg_body(oh));
    }

    return 0;
}

static void
add_newline(struct ds *s)
{
    if (s->length && s->string[s->length - 1] != '\n') {
        ds_put_char(s, '\n');
    }
}

/* Composes and returns a string representing the OpenFlow packet of 'len'
 * bytes at 'oh' at the given 'verbosity' level.  0 is a minimal amount of
 * verbosity and higher numbers increase verbosity.  The caller is responsible
 * for freeing the string. */
char *
ofp_to_string(const void *oh_, size_t len,
              const struct ofputil_port_map *port_map,
              const struct ofputil_table_map *table_map,
              int verbosity)
{
    struct ds string = DS_EMPTY_INITIALIZER;
    const struct ofp_header *oh = oh_;

    if (!len) {
        ds_put_cstr(&string, "OpenFlow message is empty\n");
    } else if (len < sizeof(struct ofp_header)) {
        ds_put_format(&string, "OpenFlow packet too short (only %"PRIuSIZE" bytes):\n",
                      len);
    } else if (ntohs(oh->length) > len) {
        enum ofperr error;
        enum ofpraw raw;

        error = ofpraw_decode_partial(&raw, oh, len);
        if (!error) {
            ofp_header_to_string__(oh, raw, &string);
            ds_put_char(&string, '\n');
        }

        ds_put_format(&string,
                      "(***truncated to %"PRIuSIZE" bytes from %"PRIu16"***)\n",
                      len, ntohs(oh->length));
    } else if (ntohs(oh->length) < len) {
        ds_put_format(&string,
                      "(***only uses %"PRIu16" bytes out of %"PRIuSIZE"***)\n",
                      ntohs(oh->length), len);
    } else {
        enum ofperr error;
        enum ofpraw raw;

        error = ofpraw_decode(&raw, oh);
        if (!error) {
            ofp_header_to_string__(oh, raw, &string);
            size_t header_len = string.length;

            error = ofp_to_string__(oh, port_map, table_map,
                                    raw, &string, verbosity);
            if (error) {
                if (string.length > header_len) {
                    ds_chomp(&string, ' ');
                    add_newline(&string);
                } else {
                    ds_put_char(&string, ' ');
                }
                ofp_print_error(&string, error);
            } else {
                ds_chomp(&string, ' ');
            }
        } else {
            ofp_print_error(&string, error);
        }

        if (verbosity >= 5 || error) {
            add_newline(&string);
            ds_put_hex_dump(&string, oh, len, 0, true);
        }

        add_newline(&string);
        return ds_steal_cstr(&string);
    }
    ds_put_hex_dump(&string, oh, len, 0, true);
    return ds_steal_cstr(&string);
}

static void
print_and_free(FILE *stream, char *string)
{
    fputs(string, stream);
    free(string);
}

/* Pretty-print the OpenFlow packet of 'len' bytes at 'oh' to 'stream' at the
 * given 'verbosity' level.  0 is a minimal amount of verbosity and higher
 * numbers increase verbosity. */
void
ofp_print(FILE *stream, const void *oh, size_t len,
          const struct ofputil_port_map *port_map,
          const struct ofputil_table_map *table_map, int verbosity)
{
    print_and_free(stream, ofp_to_string(oh, len, port_map, table_map,
                                         verbosity));
}

/* Dumps the contents of the Ethernet frame in the 'len' bytes starting at
 * 'data' to 'stream'. */
void
ofp_print_packet(FILE *stream, const void *data, size_t len,
                 ovs_be32 packet_type)
{
    print_and_free(stream, ofp_packet_to_string(data, len, packet_type));
}

void
ofp_print_dp_packet(FILE *stream, const struct dp_packet *packet)
{
    print_and_free(stream, ofp_dp_packet_to_string(packet));
}

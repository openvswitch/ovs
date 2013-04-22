/*
 * Copyright (c) 2012 Nicira, Inc.
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
#include "ofproto-dpif-ipfix.h"
#include "byte-order.h"
#include "collectors.h"
#include "flow.h"
#include "hash.h"
#include "hmap.h"
#include "ofpbuf.h"
#include "ofproto.h"
#include "packets.h"
#include "sset.h"
#include "util.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ipfix);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* Cf. IETF RFC 5101 Section 10.3.4. */
#define IPFIX_DEFAULT_COLLECTOR_PORT 4739

struct dpif_ipfix_exporter {
    struct collectors *collectors;
    uint32_t seq_number;
    time_t last_template_set_time;
};

struct dpif_ipfix_bridge_exporter {
    struct dpif_ipfix_exporter exporter;
    struct ofproto_ipfix_bridge_exporter_options *options;
    uint32_t probability;
};

struct dpif_ipfix_flow_exporter {
    struct dpif_ipfix_exporter exporter;
    struct ofproto_ipfix_flow_exporter_options *options;
};

struct dpif_ipfix_flow_exporter_map_node {
    struct hmap_node node;
    struct dpif_ipfix_flow_exporter exporter;
};

struct dpif_ipfix {
    struct dpif_ipfix_bridge_exporter bridge_exporter;
    struct hmap flow_exporter_map;  /* dpif_ipfix_flow_exporter_map_nodes. */
};

#define IPFIX_VERSION 0x000a

/* When using UDP, IPFIX Template Records must be re-sent regularly.
 * The standard default interval is 10 minutes (600 seconds).
 * Cf. IETF RFC 5101 Section 10.3.6. */
#define IPFIX_TEMPLATE_INTERVAL 600

/* Cf. IETF RFC 5101 Section 3.1. */
struct ipfix_header {
    ovs_be16 version;  /* IPFIX_VERSION. */
    ovs_be16 length;  /* Length in bytes including this header. */
    ovs_be32 export_time;  /* Seconds since the epoch. */
    ovs_be32 seq_number;  /* Message sequence number. */
    ovs_be32 obs_domain_id;  /* Observation Domain ID. */
} __attribute__((packed));
BUILD_ASSERT_DECL(sizeof(struct ipfix_header) == 16);

#define IPFIX_SET_ID_TEMPLATE 2
#define IPFIX_SET_ID_OPTION_TEMPLATE 3

/* Cf. IETF RFC 5101 Section 3.3.2. */
struct ipfix_set_header {
    ovs_be16 set_id;  /* IPFIX_SET_ID_* or valid template ID for Data Sets. */
    ovs_be16 length;  /* Length of the set in bytes including header. */
} __attribute__((packed));
BUILD_ASSERT_DECL(sizeof(struct ipfix_set_header) == 4);

/* Alternatives for templates at each layer.  A template is defined by
 * a combination of one value for each layer. */
enum ipfix_proto_l2 {
    IPFIX_PROTO_L2_ETH = 0,  /* No VLAN. */
    IPFIX_PROTO_L2_VLAN,
    NUM_IPFIX_PROTO_L2
};
enum ipfix_proto_l3 {
    IPFIX_PROTO_L3_UNKNOWN = 0,
    IPFIX_PROTO_L3_IPV4,
    IPFIX_PROTO_L3_IPV6,
    NUM_IPFIX_PROTO_L3
};
enum ipfix_proto_l4 {
    IPFIX_PROTO_L4_UNKNOWN = 0,
    IPFIX_PROTO_L4_TCP_UDP,
    NUM_IPFIX_PROTO_L4
};

/* Any Template ID > 255 is usable for Template Records. */
#define IPFIX_TEMPLATE_ID_MIN 256

/* Cf. IETF RFC 5101 Section 3.4.1. */
struct ipfix_template_record_header {
    ovs_be16 template_id;
    ovs_be16 field_count;
} __attribute__((packed));
BUILD_ASSERT_DECL(sizeof(struct ipfix_template_record_header) == 4);

enum ipfix_entity_id {
#define IPFIX_ENTITY(ENUM, ID, SIZE, NAME)  IPFIX_ENTITY_ID_##ENUM = ID,
#include "ofproto/ipfix-entities.def"
};

enum ipfix_entity_size {
#define IPFIX_ENTITY(ENUM, ID, SIZE, NAME)  IPFIX_ENTITY_SIZE_##ENUM = SIZE,
#include "ofproto/ipfix-entities.def"
};

struct ipfix_template_field_specifier {
    ovs_be16 element_id;  /* IPFIX_ENTITY_ID_*. */
    ovs_be16 field_length;  /* Length of the field's value, in bytes. */
    /* No Enterprise ID, since only standard element IDs are specified. */
} __attribute__((packed));
BUILD_ASSERT_DECL(sizeof(struct ipfix_template_field_specifier) == 4);

/* Part of data record for common metadata and Ethernet entities. */
struct ipfix_data_record_common {
    ovs_be32 observation_point_id;  /* OBSERVATION_POINT_ID */
    ovs_be64 packet_delta_count;  /* PACKET_DELTA_COUNT */
    ovs_be64 layer2_octet_delta_count;  /* LAYER2_OCTET_DELTA_COUNT */
    uint8_t source_mac_address[6];  /* SOURCE_MAC_ADDRESS */
    uint8_t destination_mac_address[6];  /* DESTINATION_MAC_ADDRESS */
    ovs_be16 ethernet_type;  /* ETHERNET_TYPE */
    ovs_be16 ethernet_total_length;  /* ETHERNET_TOTAL_LENGTH */
    uint8_t ethernet_header_length;  /* ETHERNET_HEADER_LENGTH */
} __attribute__((packed));
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_common) == 37);

/* Part of data record for VLAN entities. */
struct ipfix_data_record_vlan {
    ovs_be16 vlan_id;  /* VLAN_ID */
    ovs_be16 dot1q_vlan_id;  /* DOT1Q_VLAN_ID */
    uint8_t dot1q_priority;  /* DOT1Q_PRIORITY */
} __attribute__((packed));
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_vlan) == 5);

/* Part of data record for IP entities. */
struct ipfix_data_record_ip {
    uint8_t ip_version;  /* IP_VERSION */
    uint8_t ip_ttl;  /* IP_TTL */
    uint8_t protocol_identifier;  /* PROTOCOL_IDENTIFIER */
    uint8_t ip_diff_serv_code_point;  /* IP_DIFF_SERV_CODE_POINT */
    uint8_t ip_precedence;  /* IP_PRECEDENCE */
    uint8_t ip_class_of_service;  /* IP_CLASS_OF_SERVICE */
} __attribute__((packed));
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_ip) == 6);

/* Part of data record for IPv4 entities. */
struct ipfix_data_record_ipv4 {
    ovs_be32 source_ipv4_address;  /* SOURCE_IPV4_ADDRESS */
    ovs_be32 destination_ipv4_address;  /* DESTINATION_IPV4_ADDRESS */
} __attribute__((packed));
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_ipv4) == 8);

/* Part of data record for IPv4 entities. */
struct ipfix_data_record_ipv6 {
    uint8_t source_ipv6_address[16];  /* SOURCE_IPV6_ADDRESS */
    uint8_t destination_ipv6_address[16];  /* DESTINATION_IPV6_ADDRESS */
    ovs_be32 flow_label_ipv6;  /* FLOW_LABEL_IPV6 */
} __attribute__((packed));
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_ipv6) == 36);

/* Part of data record for TCP/UDP entities. */
struct ipfix_data_record_tcpudp {
    ovs_be16 source_transport_port;  /* SOURCE_TRANSPORT_PORT */
    ovs_be16 destination_transport_port;  /* DESTINATION_TRANSPORT_PORT */
} __attribute__((packed));
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_tcpudp) == 4);

static bool
ofproto_ipfix_bridge_exporter_options_equal(
    const struct ofproto_ipfix_bridge_exporter_options *a,
    const struct ofproto_ipfix_bridge_exporter_options *b)
{
    return (a->obs_domain_id == b->obs_domain_id
            && a->obs_point_id == b->obs_point_id
            && a->sampling_rate == b->sampling_rate
            && sset_equals(&a->targets, &b->targets));
}

static struct ofproto_ipfix_bridge_exporter_options *
ofproto_ipfix_bridge_exporter_options_clone(
    const struct ofproto_ipfix_bridge_exporter_options *old)
{
    struct ofproto_ipfix_bridge_exporter_options *new =
        xmemdup(old, sizeof *old);
    sset_clone(&new->targets, &old->targets);
    return new;
}

static void
ofproto_ipfix_bridge_exporter_options_destroy(
    struct ofproto_ipfix_bridge_exporter_options *options)
{
    if (options) {
        sset_destroy(&options->targets);
        free(options);
    }
}

static bool
ofproto_ipfix_flow_exporter_options_equal(
    const struct ofproto_ipfix_flow_exporter_options *a,
    const struct ofproto_ipfix_flow_exporter_options *b)
{
    return (a->collector_set_id == b->collector_set_id
            && sset_equals(&a->targets, &b->targets));
}

static struct ofproto_ipfix_flow_exporter_options *
ofproto_ipfix_flow_exporter_options_clone(
    const struct ofproto_ipfix_flow_exporter_options *old)
{
    struct ofproto_ipfix_flow_exporter_options *new =
        xmemdup(old, sizeof *old);
    sset_clone(&new->targets, &old->targets);
    return new;
}

static void
ofproto_ipfix_flow_exporter_options_destroy(
    struct ofproto_ipfix_flow_exporter_options *options)
{
    if (options) {
        sset_destroy(&options->targets);
        free(options);
    }
}

static void
dpif_ipfix_exporter_clear(struct dpif_ipfix_exporter *exporter)
{
    collectors_destroy(exporter->collectors);
    exporter->collectors = NULL;
    exporter->seq_number = 1;
    exporter->last_template_set_time = TIME_MIN;
}

static bool
dpif_ipfix_exporter_set_options(struct dpif_ipfix_exporter *exporter,
                                const struct sset *targets)
{
    collectors_destroy(exporter->collectors);
    collectors_create(targets, IPFIX_DEFAULT_COLLECTOR_PORT,
                      &exporter->collectors);
    if (exporter->collectors == NULL) {
        VLOG_WARN_RL(&rl, "no collectors could be initialized, "
                     "IPFIX exporter disabled");
        dpif_ipfix_exporter_clear(exporter);
        return false;
    }
    return true;
}

static void
dpif_ipfix_bridge_exporter_clear(struct dpif_ipfix_bridge_exporter *exporter)
{
    dpif_ipfix_exporter_clear(&exporter->exporter);
    ofproto_ipfix_bridge_exporter_options_destroy(exporter->options);
    exporter->options = NULL;
    exporter->probability = 0;
}

static void
dpif_ipfix_bridge_exporter_set_options(
    struct dpif_ipfix_bridge_exporter *exporter,
    const struct ofproto_ipfix_bridge_exporter_options *options)
{
    bool options_changed;

    if (!options || sset_is_empty(&options->targets)) {
        /* No point in doing any work if there are no targets. */
        dpif_ipfix_bridge_exporter_clear(exporter);
        return;
    }

    options_changed = (
        !exporter->options
        || !ofproto_ipfix_bridge_exporter_options_equal(
            options, exporter->options));

    /* Configure collectors if options have changed or if we're
     * shortchanged in collectors (which indicates that opening one or
     * more of the configured collectors failed, so that we should
     * retry). */
    if (options_changed
        || collectors_count(exporter->exporter.collectors)
            < sset_count(&options->targets)) {
        if (!dpif_ipfix_exporter_set_options(&exporter->exporter,
                                             &options->targets)) {
            return;
        }
    }

    /* Avoid reconfiguring if options didn't change. */
    if (!options_changed) {
        return;
    }

    ofproto_ipfix_bridge_exporter_options_destroy(exporter->options);
    exporter->options = ofproto_ipfix_bridge_exporter_options_clone(options);
    exporter->probability =
        MAX(1, UINT32_MAX / exporter->options->sampling_rate);
}

static struct dpif_ipfix_flow_exporter_map_node*
dpif_ipfix_find_flow_exporter_map_node(
    const struct dpif_ipfix *di, const uint32_t collector_set_id)
{
    struct dpif_ipfix_flow_exporter_map_node *exporter_node;

    HMAP_FOR_EACH_WITH_HASH (exporter_node, node,
                             hash_int(collector_set_id, 0),
                             &di->flow_exporter_map) {
        if (exporter_node->exporter.options->collector_set_id
            == collector_set_id) {
            return exporter_node;
        }
    }

    return NULL;
}

static void
dpif_ipfix_flow_exporter_clear(struct dpif_ipfix_flow_exporter *exporter)
{
    dpif_ipfix_exporter_clear(&exporter->exporter);
    ofproto_ipfix_flow_exporter_options_destroy(exporter->options);
    exporter->options = NULL;
}

static bool
dpif_ipfix_flow_exporter_set_options(
    struct dpif_ipfix_flow_exporter *exporter,
    const struct ofproto_ipfix_flow_exporter_options *options)
{
    bool options_changed;

    if (sset_is_empty(&options->targets)) {
        /* No point in doing any work if there are no targets. */
        dpif_ipfix_flow_exporter_clear(exporter);
        return true;
    }

    options_changed = (
        !exporter->options
        || !ofproto_ipfix_flow_exporter_options_equal(
            options, exporter->options));

    /* Configure collectors if options have changed or if we're
     * shortchanged in collectors (which indicates that opening one or
     * more of the configured collectors failed, so that we should
     * retry). */
    if (options_changed
        || collectors_count(exporter->exporter.collectors)
            < sset_count(&options->targets)) {
        if (!dpif_ipfix_exporter_set_options(&exporter->exporter,
                                             &options->targets)) {
            return false;
        }
    }

    /* Avoid reconfiguring if options didn't change. */
    if (!options_changed) {
        return true;
    }

    ofproto_ipfix_flow_exporter_options_destroy(exporter->options);
    exporter->options = ofproto_ipfix_flow_exporter_options_clone(options);

    return true;
}

void
dpif_ipfix_set_options(
    struct dpif_ipfix *di,
    const struct ofproto_ipfix_bridge_exporter_options *bridge_exporter_options,
    const struct ofproto_ipfix_flow_exporter_options *flow_exporters_options,
    size_t n_flow_exporters_options)
{
    int i;
    struct ofproto_ipfix_flow_exporter_options *options;
    struct dpif_ipfix_flow_exporter_map_node *node, *next;
    size_t n_broken_flow_exporters_options = 0;

    dpif_ipfix_bridge_exporter_set_options(&di->bridge_exporter,
                                           bridge_exporter_options);

    /* Add new flow exporters and update current flow exporters. */
    options = (struct ofproto_ipfix_flow_exporter_options *)
        flow_exporters_options;
    for (i = 0; i < n_flow_exporters_options; i++) {
        node = dpif_ipfix_find_flow_exporter_map_node(
            di, options->collector_set_id);
        if (!node) {
            node = xzalloc(sizeof *node);
            dpif_ipfix_exporter_clear(&node->exporter.exporter);
            hmap_insert(&di->flow_exporter_map, &node->node,
                        hash_int(options->collector_set_id, 0));
        }
        if (!dpif_ipfix_flow_exporter_set_options(&node->exporter, options)) {
            n_broken_flow_exporters_options++;
        }
        options++;
    }

    ovs_assert(hmap_count(&di->flow_exporter_map) >=
               (n_flow_exporters_options - n_broken_flow_exporters_options));

    /* Remove dropped flow exporters, if any needs to be removed. */
    if (hmap_count(&di->flow_exporter_map) > n_flow_exporters_options) {
        HMAP_FOR_EACH_SAFE (node, next, node, &di->flow_exporter_map) {
            /* This is slow but doesn't take any extra memory, and
             * this table is not supposed to contain many rows anyway. */
            options = (struct ofproto_ipfix_flow_exporter_options *)
                flow_exporters_options;
            for (i = 0; i < n_flow_exporters_options; i++) {
              if (node->exporter.options->collector_set_id
                  == options->collector_set_id) {
                  break;
              }
              options++;
            }
            if (i == n_flow_exporters_options) {  // Not found.
                hmap_remove(&di->flow_exporter_map, &node->node);
                dpif_ipfix_flow_exporter_clear(&node->exporter);
                free(node);
            }
        }
    }

    ovs_assert(hmap_count(&di->flow_exporter_map) ==
               (n_flow_exporters_options - n_broken_flow_exporters_options));
}

struct dpif_ipfix *
dpif_ipfix_create(void)
{
    struct dpif_ipfix *di;
    di = xzalloc(sizeof *di);
    dpif_ipfix_exporter_clear(&di->bridge_exporter.exporter);
    hmap_init(&di->flow_exporter_map);
    return di;
}

uint32_t
dpif_ipfix_get_bridge_exporter_probability(const struct dpif_ipfix *di)
{
    return di->bridge_exporter.probability;
}

static void
dpif_ipfix_clear(struct dpif_ipfix *di)
{
    struct dpif_ipfix_flow_exporter_map_node *node, *next;

    dpif_ipfix_bridge_exporter_clear(&di->bridge_exporter);

    HMAP_FOR_EACH_SAFE (node, next, node, &di->flow_exporter_map) {
        hmap_remove(&di->flow_exporter_map, &node->node);
        dpif_ipfix_flow_exporter_clear(&node->exporter);
        free(node);
    }
}

void
dpif_ipfix_destroy(struct dpif_ipfix *di)
{
    if (di) {
        dpif_ipfix_clear(di);
        hmap_destroy(&di->flow_exporter_map);
        free(di);
    }
}

static void
ipfix_init_header(uint32_t seq_number, uint32_t obs_domain_id,
                  struct ofpbuf *msg)
{
    struct ipfix_header *hdr;

    hdr = ofpbuf_put_zeros(msg, sizeof *hdr);
    hdr->version = htons(IPFIX_VERSION);
    hdr->length = htons(sizeof *hdr);  /* Updated in ipfix_send_msg. */
    hdr->export_time = htonl(time_wall());
    hdr->seq_number = htonl(seq_number);
    hdr->obs_domain_id = htonl(obs_domain_id);
}

static void
ipfix_send_msg(const struct collectors *collectors, struct ofpbuf *msg)
{
    struct ipfix_header *hdr;

    /* Adjust the length in the header. */
    hdr = msg->data;
    hdr->length = htons(msg->size);

    collectors_send(collectors, msg->data, msg->size);
    msg->size = 0;
}

static uint16_t
ipfix_get_template_id(enum ipfix_proto_l2 l2, enum ipfix_proto_l3 l3,
                      enum ipfix_proto_l4 l4)
{
    uint16_t template_id;
    template_id = l2;
    template_id = template_id * NUM_IPFIX_PROTO_L3 + l3;
    template_id = template_id * NUM_IPFIX_PROTO_L4 + l4;
    return IPFIX_TEMPLATE_ID_MIN + template_id;
}

static void
ipfix_define_template_entity(enum ipfix_entity_id id,
                             enum ipfix_entity_size size, struct ofpbuf *msg)
{
    struct ipfix_template_field_specifier *field;

    field = ofpbuf_put_zeros(msg, sizeof *field);
    field->element_id = htons(id);
    field->field_length = htons(size);
}

static uint16_t
ipfix_define_template_fields(enum ipfix_proto_l2 l2, enum ipfix_proto_l3 l3,
                             enum ipfix_proto_l4 l4, struct ofpbuf *msg)
{
    uint16_t count = 0;

#define DEF(ID) \
    { \
        ipfix_define_template_entity(IPFIX_ENTITY_ID_##ID, \
                                     IPFIX_ENTITY_SIZE_##ID, msg); \
        count++; \
    }

    DEF(OBSERVATION_POINT_ID);
    DEF(PACKET_DELTA_COUNT);
    DEF(LAYER2_OCTET_DELTA_COUNT);

    /* Common Ethernet entities. */
    DEF(SOURCE_MAC_ADDRESS);
    DEF(DESTINATION_MAC_ADDRESS);
    DEF(ETHERNET_TYPE);
    DEF(ETHERNET_TOTAL_LENGTH);
    DEF(ETHERNET_HEADER_LENGTH);

    if (l2 == IPFIX_PROTO_L2_VLAN) {
        DEF(VLAN_ID);
        DEF(DOT1Q_VLAN_ID);
        DEF(DOT1Q_PRIORITY);
    }

    if (l3 != IPFIX_PROTO_L3_UNKNOWN) {
        DEF(IP_VERSION);
        DEF(IP_TTL);
        DEF(PROTOCOL_IDENTIFIER);
        DEF(IP_DIFF_SERV_CODE_POINT);
        DEF(IP_PRECEDENCE);
        DEF(IP_CLASS_OF_SERVICE);

        if (l3 == IPFIX_PROTO_L3_IPV4) {
            DEF(SOURCE_IPV4_ADDRESS);
            DEF(DESTINATION_IPV4_ADDRESS);
        } else {  /* l3 == IPFIX_PROTO_L3_IPV6 */
            DEF(SOURCE_IPV6_ADDRESS);
            DEF(DESTINATION_IPV6_ADDRESS);
            DEF(FLOW_LABEL_IPV6);
        }
    }

    if (l4 != IPFIX_PROTO_L4_UNKNOWN) {
        DEF(SOURCE_TRANSPORT_PORT);
        DEF(DESTINATION_TRANSPORT_PORT);
    }

#undef DEF

    return count;
}

static void
ipfix_send_template_msg(struct dpif_ipfix_exporter *exporter,
                        uint32_t obs_domain_id)
{
    uint64_t msg_stub[DIV_ROUND_UP(1500, 8)];
    struct ofpbuf msg;
    size_t set_hdr_offset, tmpl_hdr_offset;
    struct ipfix_set_header *set_hdr;
    struct ipfix_template_record_header *tmpl_hdr;
    uint16_t field_count;
    enum ipfix_proto_l2 l2;
    enum ipfix_proto_l3 l3;
    enum ipfix_proto_l4 l4;

    ofpbuf_use_stub(&msg, msg_stub, sizeof msg_stub);

    ipfix_init_header(exporter->seq_number, obs_domain_id, &msg);
    set_hdr_offset = msg.size;

    /* Add a Template Set. */
    set_hdr = ofpbuf_put_zeros(&msg, sizeof *set_hdr);
    set_hdr->set_id = htons(IPFIX_SET_ID_TEMPLATE);

    /* Define one template for each possible combination of
     * protocols. */
    for (l2 = 0; l2 < NUM_IPFIX_PROTO_L2; l2++) {
        for (l3 = 0; l3 < NUM_IPFIX_PROTO_L3; l3++) {
            for (l4 = 0; l4 < NUM_IPFIX_PROTO_L4; l4++) {
                if (l3 == IPFIX_PROTO_L3_UNKNOWN &&
                    l4 != IPFIX_PROTO_L4_UNKNOWN) {
                    continue;
                }
                tmpl_hdr_offset = msg.size;
                tmpl_hdr = ofpbuf_put_zeros(&msg, sizeof *tmpl_hdr);
                tmpl_hdr->template_id = htons(
                    ipfix_get_template_id(l2, l3, l4));
                field_count = ipfix_define_template_fields(l2, l3, l4, &msg);
                tmpl_hdr = (struct ipfix_template_record_header*)
                    ((uint8_t*)msg.data + tmpl_hdr_offset);
                tmpl_hdr->field_count = htons(field_count);
            }
        }
    }

    set_hdr = (struct ipfix_set_header*)((uint8_t*)msg.data + set_hdr_offset);
    set_hdr->length = htons(msg.size - set_hdr_offset);

    /* TODO: Add Options Template Sets, at least to define a Flow Keys
     * Option Template. */

    ipfix_send_msg(exporter->collectors, &msg);

    ofpbuf_uninit(&msg);
}

static void
ipfix_send_data_msg(struct dpif_ipfix_exporter *exporter, struct ofpbuf *packet,
                    const struct flow *flow, uint64_t packet_delta_count,
                    uint32_t obs_domain_id, uint32_t obs_point_id)
{
    uint64_t msg_stub[DIV_ROUND_UP(1500, 8)];
    struct ofpbuf msg;
    size_t set_hdr_offset;
    struct ipfix_set_header *set_hdr;
    enum ipfix_proto_l2 l2;
    enum ipfix_proto_l3 l3;
    enum ipfix_proto_l4 l4;

    ofpbuf_use_stub(&msg, msg_stub, sizeof msg_stub);

    ipfix_init_header(exporter->seq_number, obs_domain_id, &msg);
    exporter->seq_number++;
    set_hdr_offset = msg.size;

    /* Choose the right template ID matching the protocols in the
     * sampled packet. */
    l2 = (flow->vlan_tci == 0) ? IPFIX_PROTO_L2_ETH : IPFIX_PROTO_L2_VLAN;

    switch(ntohs(flow->dl_type)) {
    case ETH_TYPE_IP:
        l3 = IPFIX_PROTO_L3_IPV4;
        break;
    case ETH_TYPE_IPV6:
        l3 = IPFIX_PROTO_L3_IPV6;
        break;
    default:
        l3 = IPFIX_PROTO_L3_UNKNOWN;
    }

    l4 = IPFIX_PROTO_L4_UNKNOWN;
    if (l3 != IPFIX_PROTO_L3_UNKNOWN) {
        switch(flow->nw_proto) {
        case IPPROTO_TCP:  /* TCP */
        case IPPROTO_UDP:  /* UDP */
            l4 = IPFIX_PROTO_L4_TCP_UDP;
            break;
        }
    }

    /* Add a Data Set. */
    set_hdr = ofpbuf_put_zeros(&msg, sizeof *set_hdr);
    set_hdr->set_id = htons(ipfix_get_template_id(l2, l3, l4));

    /* The fields defined in the ipfix_data_record_* structs and sent
     * below must match exactly the templates defined in
     * ipfix_define_template_fields. */

    /* Common Ethernet entities. */
    {
        struct ipfix_data_record_common *data_common;
        uint16_t ethernet_total_length;
        uint8_t ethernet_header_length;
        uint64_t layer2_octet_delta_count;

        ethernet_total_length = packet->size;
        ethernet_header_length = (l2 == IPFIX_PROTO_L2_VLAN)
            ? VLAN_ETH_HEADER_LEN : ETH_HEADER_LEN;

        /* Calculate the total matched octet count by considering as
         * an approximation that all matched packets have the same
         * length. */
        layer2_octet_delta_count = packet_delta_count * ethernet_total_length;

        data_common = ofpbuf_put_zeros(&msg, sizeof *data_common);
        data_common->observation_point_id = htonl(obs_point_id);
        data_common->packet_delta_count = htonll(packet_delta_count);
        data_common->layer2_octet_delta_count =
            htonll(layer2_octet_delta_count);
        memcpy(data_common->source_mac_address, flow->dl_src,
               sizeof flow->dl_src);
        memcpy(data_common->destination_mac_address, flow->dl_dst,
               sizeof flow->dl_dst);
        data_common->ethernet_type = flow->dl_type;
        data_common->ethernet_total_length = htons(ethernet_total_length);
        data_common->ethernet_header_length = ethernet_header_length;
    }

    if (l2 == IPFIX_PROTO_L2_VLAN) {
        struct ipfix_data_record_vlan *data_vlan;
        uint16_t vlan_id = vlan_tci_to_vid(flow->vlan_tci);
        uint8_t priority = vlan_tci_to_pcp(flow->vlan_tci);

        data_vlan = ofpbuf_put_zeros(&msg, sizeof *data_vlan);
        data_vlan->vlan_id = htons(vlan_id);
        data_vlan->dot1q_vlan_id = htons(vlan_id);
        data_vlan->dot1q_priority = priority;
    }

    if (l3 != IPFIX_PROTO_L3_UNKNOWN) {
        struct ipfix_data_record_ip *data_ip;

        data_ip = ofpbuf_put_zeros(&msg, sizeof *data_ip);
        data_ip->ip_version = (l3 == IPFIX_PROTO_L3_IPV4) ? 4 : 6;
        data_ip->ip_ttl = flow->nw_ttl;
        data_ip->protocol_identifier = flow->nw_proto;
        data_ip->ip_diff_serv_code_point = flow->nw_tos >> 2;
        data_ip->ip_precedence = flow->nw_tos >> 5;
        data_ip->ip_class_of_service = flow->nw_tos;

        if (l3 == IPFIX_PROTO_L3_IPV4) {
            struct ipfix_data_record_ipv4 *data_ipv4;
            data_ipv4 = ofpbuf_put_zeros(&msg, sizeof *data_ipv4);
            data_ipv4->source_ipv4_address = flow->nw_src;
            data_ipv4->destination_ipv4_address = flow->nw_dst;
        } else {  /* l3 == IPFIX_PROTO_L3_IPV6 */
            struct ipfix_data_record_ipv6 *data_ipv6;

            data_ipv6 = ofpbuf_put_zeros(&msg, sizeof *data_ipv6);
            memcpy(data_ipv6->source_ipv6_address, &flow->ipv6_src,
                   sizeof flow->ipv6_src);
            memcpy(data_ipv6->destination_ipv6_address, &flow->ipv6_dst,
                   sizeof flow->ipv6_dst);
            data_ipv6->flow_label_ipv6 = flow->ipv6_label;
        }
    }

    if (l4 != IPFIX_PROTO_L4_UNKNOWN) {
        struct ipfix_data_record_tcpudp *data_tcpudp;

        data_tcpudp = ofpbuf_put_zeros(&msg, sizeof *data_tcpudp);
        data_tcpudp->source_transport_port = flow->tp_src;
        data_tcpudp->destination_transport_port = flow->tp_dst;
    }

    set_hdr = (struct ipfix_set_header*)((uint8_t*)msg.data + set_hdr_offset);
    set_hdr->length = htons(msg.size - set_hdr_offset);

    ipfix_send_msg(exporter->collectors, &msg);

    ofpbuf_uninit(&msg);
}

static void
dpif_ipfix_sample(struct dpif_ipfix_exporter *exporter,
                  struct ofpbuf *packet, const struct flow *flow,
                  uint64_t packet_delta_count, uint32_t obs_domain_id,
                  uint32_t obs_point_id)
{
    time_t now = time_wall();
    if ((exporter->last_template_set_time + IPFIX_TEMPLATE_INTERVAL) <= now) {
        ipfix_send_template_msg(exporter, obs_domain_id);
        exporter->last_template_set_time = now;
    }

    ipfix_send_data_msg(exporter, packet, flow, packet_delta_count,
                        obs_domain_id, obs_point_id);
}

void
dpif_ipfix_bridge_sample(struct dpif_ipfix *di, struct ofpbuf *packet,
                         const struct flow *flow)
{
    /* Use the sampling probability as an approximation of the number
     * of matched packets. */
    uint64_t packet_delta_count = UINT32_MAX / di->bridge_exporter.probability;

    dpif_ipfix_sample(&di->bridge_exporter.exporter, packet, flow,
                      packet_delta_count,
                      di->bridge_exporter.options->obs_domain_id,
                      di->bridge_exporter.options->obs_point_id);
}

void
dpif_ipfix_flow_sample(struct dpif_ipfix *di, struct ofpbuf *packet,
                       const struct flow *flow, uint32_t collector_set_id,
                       uint16_t probability, uint32_t obs_domain_id,
                       uint32_t obs_point_id)
{
    struct dpif_ipfix_flow_exporter_map_node *node;
    /* Use the sampling probability as an approximation of the number
     * of matched packets. */
    uint64_t packet_delta_count = USHRT_MAX / probability;

    node = dpif_ipfix_find_flow_exporter_map_node(di, collector_set_id);

    if (!node) {
        return;
    }

    dpif_ipfix_sample(&node->exporter.exporter, packet, flow,
                      packet_delta_count, obs_domain_id, obs_point_id);
}

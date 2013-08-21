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
#include <sys/time.h>
#include "byte-order.h"
#include "collectors.h"
#include "flow.h"
#include "hash.h"
#include "hmap.h"
#include "list.h"
#include "ofpbuf.h"
#include "ofproto.h"
#include "packets.h"
#include "poll-loop.h"
#include "sset.h"
#include "util.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ipfix);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;

/* Cf. IETF RFC 5101 Section 10.3.4. */
#define IPFIX_DEFAULT_COLLECTOR_PORT 4739

struct dpif_ipfix_exporter {
    struct collectors *collectors;
    uint32_t seq_number;
    time_t last_template_set_time;
    struct hmap cache_flow_key_map;  /* ipfix_flow_cache_entry. */
    struct list cache_flow_start_timestamp_list;  /* ipfix_flow_cache_entry. */
    uint32_t cache_active_timeout;  /* In seconds. */
    uint32_t cache_max_flows;
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
    struct hmap flow_exporter_map;  /* dpif_ipfix_flow_exporter_map_node. */
    atomic_int ref_cnt;
};

#define IPFIX_VERSION 0x000a

/* When using UDP, IPFIX Template Records must be re-sent regularly.
 * The standard default interval is 10 minutes (600 seconds).
 * Cf. IETF RFC 5101 Section 10.3.6. */
#define IPFIX_TEMPLATE_INTERVAL 600

/* Cf. IETF RFC 5101 Section 3.1. */
OVS_PACKED(
struct ipfix_header {
    ovs_be16 version;  /* IPFIX_VERSION. */
    ovs_be16 length;  /* Length in bytes including this header. */
    ovs_be32 export_time;  /* Seconds since the epoch. */
    ovs_be32 seq_number;  /* Message sequence number. */
    ovs_be32 obs_domain_id;  /* Observation Domain ID. */
});
BUILD_ASSERT_DECL(sizeof(struct ipfix_header) == 16);

#define IPFIX_SET_ID_TEMPLATE 2
#define IPFIX_SET_ID_OPTION_TEMPLATE 3

/* Cf. IETF RFC 5101 Section 3.3.2. */
OVS_PACKED(
struct ipfix_set_header {
    ovs_be16 set_id;  /* IPFIX_SET_ID_* or valid template ID for Data Sets. */
    ovs_be16 length;  /* Length of the set in bytes including header. */
});
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
OVS_PACKED(
struct ipfix_template_record_header {
    ovs_be16 template_id;
    ovs_be16 field_count;
});
BUILD_ASSERT_DECL(sizeof(struct ipfix_template_record_header) == 4);

enum ipfix_entity_id {
#define IPFIX_ENTITY(ENUM, ID, SIZE, NAME)  IPFIX_ENTITY_ID_##ENUM = ID,
#include "ofproto/ipfix-entities.def"
};

enum ipfix_entity_size {
#define IPFIX_ENTITY(ENUM, ID, SIZE, NAME)  IPFIX_ENTITY_SIZE_##ENUM = SIZE,
#include "ofproto/ipfix-entities.def"
};

OVS_PACKED(
struct ipfix_template_field_specifier {
    ovs_be16 element_id;  /* IPFIX_ENTITY_ID_*. */
    ovs_be16 field_length;  /* Length of the field's value, in bytes. */
    /* No Enterprise ID, since only standard element IDs are specified. */
});
BUILD_ASSERT_DECL(sizeof(struct ipfix_template_field_specifier) == 4);

/* Part of data record flow key for common metadata and Ethernet entities. */
OVS_PACKED(
struct ipfix_data_record_flow_key_common {
    ovs_be32 observation_point_id;  /* OBSERVATION_POINT_ID */
    uint8_t source_mac_address[6];  /* SOURCE_MAC_ADDRESS */
    uint8_t destination_mac_address[6];  /* DESTINATION_MAC_ADDRESS */
    ovs_be16 ethernet_type;  /* ETHERNET_TYPE */
    uint8_t ethernet_header_length;  /* ETHERNET_HEADER_LENGTH */
});
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_flow_key_common) == 19);

/* Part of data record flow key for VLAN entities. */
OVS_PACKED(
struct ipfix_data_record_flow_key_vlan {
    ovs_be16 vlan_id;  /* VLAN_ID */
    ovs_be16 dot1q_vlan_id;  /* DOT1Q_VLAN_ID */
    uint8_t dot1q_priority;  /* DOT1Q_PRIORITY */
});
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_flow_key_vlan) == 5);

/* Part of data record flow key for IP entities. */
/* XXX: Replace IP_TTL with MINIMUM_TTL and MAXIMUM_TTL? */
OVS_PACKED(
struct ipfix_data_record_flow_key_ip {
    uint8_t ip_version;  /* IP_VERSION */
    uint8_t ip_ttl;  /* IP_TTL */
    uint8_t protocol_identifier;  /* PROTOCOL_IDENTIFIER */
    uint8_t ip_diff_serv_code_point;  /* IP_DIFF_SERV_CODE_POINT */
    uint8_t ip_precedence;  /* IP_PRECEDENCE */
    uint8_t ip_class_of_service;  /* IP_CLASS_OF_SERVICE */
});
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_flow_key_ip) == 6);

/* Part of data record flow key for IPv4 entities. */
OVS_PACKED(
struct ipfix_data_record_flow_key_ipv4 {
    ovs_be32 source_ipv4_address;  /* SOURCE_IPV4_ADDRESS */
    ovs_be32 destination_ipv4_address;  /* DESTINATION_IPV4_ADDRESS */
});
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_flow_key_ipv4) == 8);

/* Part of data record flow key for IPv6 entities. */
OVS_PACKED(
struct ipfix_data_record_flow_key_ipv6 {
    uint8_t source_ipv6_address[16];  /* SOURCE_IPV6_ADDRESS */
    uint8_t destination_ipv6_address[16];  /* DESTINATION_IPV6_ADDRESS */
    ovs_be32 flow_label_ipv6;  /* FLOW_LABEL_IPV6 */
});
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_flow_key_ipv6) == 36);

/* Part of data record flow key for TCP/UDP entities. */
OVS_PACKED(
struct ipfix_data_record_flow_key_tcpudp {
    ovs_be16 source_transport_port;  /* SOURCE_TRANSPORT_PORT */
    ovs_be16 destination_transport_port;  /* DESTINATION_TRANSPORT_PORT */
});
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_flow_key_tcpudp) == 4);

/* Cf. IETF RFC 5102 Section 5.11.3. */
enum ipfix_flow_end_reason {
    IDLE_TIMEOUT = 0x01,
    ACTIVE_TIMEOUT = 0x02,
    END_OF_FLOW_DETECTED = 0x03,
    FORCED_END = 0x04,
    LACK_OF_RESOURCES = 0x05
};

/* Part of data record for common aggregated elements. */
OVS_PACKED(
struct ipfix_data_record_aggregated_common {
    ovs_be32 flow_start_delta_microseconds; /* FLOW_START_DELTA_MICROSECONDS */
    ovs_be32 flow_end_delta_microseconds; /* FLOW_END_DELTA_MICROSECONDS */
    ovs_be64 packet_delta_count;  /* PACKET_DELTA_COUNT */
    ovs_be64 layer2_octet_delta_count;  /* LAYER2_OCTET_DELTA_COUNT */
    uint8_t flow_end_reason;  /* FLOW_END_REASON */
});
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_aggregated_common) == 25);

/* Part of data record for IP aggregated elements. */
OVS_PACKED(
struct ipfix_data_record_aggregated_ip {
    ovs_be64 octet_delta_sum_of_squares;  /* OCTET_DELTA_SUM_OF_SQUARES */
    ovs_be64 minimum_ip_total_length;  /* MINIMUM_IP_TOTAL_LENGTH */
    ovs_be64 maximum_ip_total_length;  /* MAXIMUM_IP_TOTAL_LENGTH */
});
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_aggregated_ip) == 24);

#define MAX_FLOW_KEY_LEN                                 \
    (sizeof(struct ipfix_data_record_flow_key_common)    \
     + sizeof(struct ipfix_data_record_flow_key_vlan)    \
     + sizeof(struct ipfix_data_record_flow_key_ip)      \
     + sizeof(struct ipfix_data_record_flow_key_ipv6)    \
     + sizeof(struct ipfix_data_record_flow_key_tcpudp))

#define MAX_DATA_RECORD_LEN                                 \
    (MAX_FLOW_KEY_LEN                                       \
     + sizeof(struct ipfix_data_record_aggregated_common)   \
     + sizeof(struct ipfix_data_record_aggregated_ip))

/* Max length of a data set.  To simplify the implementation, each
 * data record is sent in a separate data set, so each data set
 * contains at most one data record. */
#define MAX_DATA_SET_LEN             \
    (sizeof(struct ipfix_set_header) \
     + MAX_DATA_RECORD_LEN)

/* Max length of an IPFIX message. Arbitrarily set to accomodate low
 * MTU. */
#define MAX_MESSAGE_LEN 1024

/* Cache structures. */

/* Flow key. */
struct ipfix_flow_key {
    uint32_t obs_domain_id;
    uint16_t template_id;
    size_t flow_key_msg_part_size;
    uint64_t flow_key_msg_part[DIV_ROUND_UP(MAX_FLOW_KEY_LEN, 8)];
};

/* Flow cache entry. */
struct ipfix_flow_cache_entry {
    struct hmap_node flow_key_map_node;
    struct list cache_flow_start_timestamp_list_node;
    struct ipfix_flow_key flow_key;
    /* Common aggregated elements. */
    uint64_t flow_start_timestamp_usec;
    uint64_t flow_end_timestamp_usec;
    uint64_t packet_delta_count;
    uint64_t layer2_octet_delta_count;
    uint64_t octet_delta_sum_of_squares;  /* 0 if not IP. */
    uint16_t minimum_ip_total_length;  /* 0 if not IP. */
    uint16_t maximum_ip_total_length;  /* 0 if not IP. */
};

static void dpif_ipfix_cache_expire(struct dpif_ipfix_exporter *, bool,
                                    const uint64_t, const uint32_t);

static void get_export_time_now(uint64_t *, uint32_t *);

static void dpif_ipfix_cache_expire_now(struct dpif_ipfix_exporter *, bool);

static bool
ofproto_ipfix_bridge_exporter_options_equal(
    const struct ofproto_ipfix_bridge_exporter_options *a,
    const struct ofproto_ipfix_bridge_exporter_options *b)
{
    return (a->obs_domain_id == b->obs_domain_id
            && a->obs_point_id == b->obs_point_id
            && a->sampling_rate == b->sampling_rate
            && a->cache_active_timeout == b->cache_active_timeout
            && a->cache_max_flows == b->cache_max_flows
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
            && a->cache_active_timeout == b->cache_active_timeout
            && a->cache_max_flows == b->cache_max_flows
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
dpif_ipfix_exporter_init(struct dpif_ipfix_exporter *exporter)
{
    exporter->collectors = NULL;
    exporter->seq_number = 1;
    exporter->last_template_set_time = TIME_MIN;
    hmap_init(&exporter->cache_flow_key_map);
    list_init(&exporter->cache_flow_start_timestamp_list);
    exporter->cache_active_timeout = 0;
    exporter->cache_max_flows = 0;
}

static void
dpif_ipfix_exporter_clear(struct dpif_ipfix_exporter *exporter)
{
    /* Flush the cache with flow end reason "forced end." */
    dpif_ipfix_cache_expire_now(exporter, true);

    collectors_destroy(exporter->collectors);
    exporter->collectors = NULL;
    exporter->seq_number = 1;
    exporter->last_template_set_time = TIME_MIN;
    exporter->cache_active_timeout = 0;
    exporter->cache_max_flows = 0;
}

static void
dpif_ipfix_exporter_destroy(struct dpif_ipfix_exporter *exporter)
{
    dpif_ipfix_exporter_clear(exporter);
    hmap_destroy(&exporter->cache_flow_key_map);
}

static bool
dpif_ipfix_exporter_set_options(struct dpif_ipfix_exporter *exporter,
                                const struct sset *targets,
                                const uint32_t cache_active_timeout,
                                const uint32_t cache_max_flows)
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
    exporter->cache_active_timeout = cache_active_timeout;
    exporter->cache_max_flows = cache_max_flows;
    return true;
}

static void
dpif_ipfix_bridge_exporter_init(struct dpif_ipfix_bridge_exporter *exporter)
{
    dpif_ipfix_exporter_init(&exporter->exporter);
    exporter->options = NULL;
    exporter->probability = 0;
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
dpif_ipfix_bridge_exporter_destroy(struct dpif_ipfix_bridge_exporter *exporter)
{
    dpif_ipfix_bridge_exporter_clear(exporter);
    dpif_ipfix_exporter_destroy(&exporter->exporter);
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
        if (!dpif_ipfix_exporter_set_options(
                &exporter->exporter, &options->targets,
                options->cache_active_timeout, options->cache_max_flows)) {
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

    /* Run over the cache as some entries might have expired after
     * changing the timeouts. */
    dpif_ipfix_cache_expire_now(&exporter->exporter, false);
}

static struct dpif_ipfix_flow_exporter_map_node*
dpif_ipfix_find_flow_exporter_map_node(
    const struct dpif_ipfix *di, const uint32_t collector_set_id)
    OVS_REQUIRES(mutex)
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
dpif_ipfix_flow_exporter_init(struct dpif_ipfix_flow_exporter *exporter)
{
    dpif_ipfix_exporter_init(&exporter->exporter);
    exporter->options = NULL;
}

static void
dpif_ipfix_flow_exporter_clear(struct dpif_ipfix_flow_exporter *exporter)
{
    dpif_ipfix_exporter_clear(&exporter->exporter);
    ofproto_ipfix_flow_exporter_options_destroy(exporter->options);
    exporter->options = NULL;
}

static void
dpif_ipfix_flow_exporter_destroy(struct dpif_ipfix_flow_exporter *exporter)
{
    dpif_ipfix_flow_exporter_clear(exporter);
    dpif_ipfix_exporter_destroy(&exporter->exporter);
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
        if (!dpif_ipfix_exporter_set_options(
                &exporter->exporter, &options->targets,
                options->cache_active_timeout, options->cache_max_flows)) {
            return false;
        }
    }

    /* Avoid reconfiguring if options didn't change. */
    if (!options_changed) {
        return true;
    }

    ofproto_ipfix_flow_exporter_options_destroy(exporter->options);
    exporter->options = ofproto_ipfix_flow_exporter_options_clone(options);

    /* Run over the cache as some entries might have expired after
     * changing the timeouts. */
    dpif_ipfix_cache_expire_now(&exporter->exporter, false);

    return true;
}

void
dpif_ipfix_set_options(
    struct dpif_ipfix *di,
    const struct ofproto_ipfix_bridge_exporter_options *bridge_exporter_options,
    const struct ofproto_ipfix_flow_exporter_options *flow_exporters_options,
    size_t n_flow_exporters_options) OVS_EXCLUDED(mutex)
{
    int i;
    struct ofproto_ipfix_flow_exporter_options *options;
    struct dpif_ipfix_flow_exporter_map_node *node, *next;
    size_t n_broken_flow_exporters_options = 0;

    ovs_mutex_lock(&mutex);
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
            dpif_ipfix_flow_exporter_init(&node->exporter);
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
                dpif_ipfix_flow_exporter_destroy(&node->exporter);
                free(node);
            }
        }
    }

    ovs_assert(hmap_count(&di->flow_exporter_map) ==
               (n_flow_exporters_options - n_broken_flow_exporters_options));
    ovs_mutex_unlock(&mutex);
}

struct dpif_ipfix *
dpif_ipfix_create(void)
{
    struct dpif_ipfix *di;
    di = xzalloc(sizeof *di);
    dpif_ipfix_bridge_exporter_init(&di->bridge_exporter);
    hmap_init(&di->flow_exporter_map);
    atomic_init(&di->ref_cnt, 1);
    return di;
}

struct dpif_ipfix *
dpif_ipfix_ref(const struct dpif_ipfix *di_)
{
    struct dpif_ipfix *di = CONST_CAST(struct dpif_ipfix *, di_);
    if (di) {
        int orig;
        atomic_add(&di->ref_cnt, 1, &orig);
        ovs_assert(orig > 0);
    }
    return di;
}

uint32_t
dpif_ipfix_get_bridge_exporter_probability(const struct dpif_ipfix *di)
    OVS_EXCLUDED(mutex)
{
    uint32_t ret;
    ovs_mutex_lock(&mutex);
    ret = di->bridge_exporter.probability;
    ovs_mutex_unlock(&mutex);
    return ret;
}

static void
dpif_ipfix_clear(struct dpif_ipfix *di) OVS_REQUIRES(mutex)
{
    struct dpif_ipfix_flow_exporter_map_node *exp_node, *exp_next;

    dpif_ipfix_bridge_exporter_clear(&di->bridge_exporter);

    HMAP_FOR_EACH_SAFE (exp_node, exp_next, node, &di->flow_exporter_map) {
        hmap_remove(&di->flow_exporter_map, &exp_node->node);
        dpif_ipfix_flow_exporter_destroy(&exp_node->exporter);
        free(exp_node);
    }
}

void
dpif_ipfix_unref(struct dpif_ipfix *di) OVS_EXCLUDED(mutex)
{
    int orig;

    if (!di) {
        return;
    }

    atomic_sub(&di->ref_cnt, 1, &orig);
    ovs_assert(orig > 0);
    if (orig == 1) {
        ovs_mutex_lock(&mutex);
        dpif_ipfix_clear(di);
        dpif_ipfix_bridge_exporter_destroy(&di->bridge_exporter);
        hmap_destroy(&di->flow_exporter_map);
        free(di);
        ovs_mutex_unlock(&mutex);
    }
}

static void
ipfix_init_header(uint32_t export_time_sec, uint32_t seq_number,
                  uint32_t obs_domain_id, struct ofpbuf *msg)
{
    struct ipfix_header *hdr;

    hdr = ofpbuf_put_zeros(msg, sizeof *hdr);
    hdr->version = htons(IPFIX_VERSION);
    hdr->length = htons(sizeof *hdr);  /* Updated in ipfix_send_msg. */
    hdr->export_time = htonl(export_time_sec);
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

    /* 1. Flow key. */

    DEF(OBSERVATION_POINT_ID);

    /* Common Ethernet entities. */
    DEF(SOURCE_MAC_ADDRESS);
    DEF(DESTINATION_MAC_ADDRESS);
    DEF(ETHERNET_TYPE);
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

    /* 2. Flow aggregated data. */

    DEF(FLOW_START_DELTA_MICROSECONDS);
    DEF(FLOW_END_DELTA_MICROSECONDS);
    DEF(PACKET_DELTA_COUNT);
    DEF(LAYER2_OCTET_DELTA_COUNT);
    DEF(FLOW_END_REASON);

    if (l3 != IPFIX_PROTO_L3_UNKNOWN) {
        DEF(OCTET_DELTA_SUM_OF_SQUARES);
        DEF(MINIMUM_IP_TOTAL_LENGTH);
        DEF(MAXIMUM_IP_TOTAL_LENGTH);
    }

#undef DEF

    return count;
}

static void
ipfix_send_template_msg(struct dpif_ipfix_exporter *exporter,
                        uint32_t export_time_sec, uint32_t obs_domain_id)
{
    uint64_t msg_stub[DIV_ROUND_UP(MAX_MESSAGE_LEN, 8)];
    struct ofpbuf msg;
    size_t set_hdr_offset, tmpl_hdr_offset;
    struct ipfix_set_header *set_hdr;
    struct ipfix_template_record_header *tmpl_hdr;
    uint16_t field_count;
    enum ipfix_proto_l2 l2;
    enum ipfix_proto_l3 l3;
    enum ipfix_proto_l4 l4;

    ofpbuf_use_stub(&msg, msg_stub, sizeof msg_stub);

    ipfix_init_header(export_time_sec, exporter->seq_number, obs_domain_id,
                      &msg);
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

    /* XXX: Add Options Template Sets, at least to define a Flow Keys
     * Option Template. */

    ipfix_send_msg(exporter->collectors, &msg);

    ofpbuf_uninit(&msg);
}

static inline uint32_t
ipfix_hash_flow_key(const struct ipfix_flow_key *flow_key, uint32_t basis)
{
    uint32_t hash;
    hash = hash_int(flow_key->obs_domain_id, basis);
    hash = hash_int(flow_key->template_id, hash);
    hash = hash_bytes(flow_key->flow_key_msg_part,
                      flow_key->flow_key_msg_part_size, hash);
    return hash;
}

static bool
ipfix_flow_key_equal(const struct ipfix_flow_key *a,
                     const struct ipfix_flow_key *b)
{
    /* The template ID determines the flow key size, so not need to
     * compare it. */
    return (a->obs_domain_id == b->obs_domain_id
            && a->template_id == b->template_id
            && memcmp(a->flow_key_msg_part, b->flow_key_msg_part,
                      a->flow_key_msg_part_size) == 0);
}

static struct ipfix_flow_cache_entry*
ipfix_cache_find_entry(const struct dpif_ipfix_exporter *exporter,
                       const struct ipfix_flow_key *flow_key)
{
    struct ipfix_flow_cache_entry *entry;

    HMAP_FOR_EACH_WITH_HASH (entry, flow_key_map_node,
                             ipfix_hash_flow_key(flow_key, 0),
                             &exporter->cache_flow_key_map) {
        if (ipfix_flow_key_equal(&entry->flow_key, flow_key)) {
            return entry;
        }
    }

    return NULL;
}

static bool
ipfix_cache_next_timeout_msec(const struct dpif_ipfix_exporter *exporter,
                              long long int *next_timeout_msec)
{
    struct ipfix_flow_cache_entry *entry;

    LIST_FOR_EACH (entry, cache_flow_start_timestamp_list_node,
                   &exporter->cache_flow_start_timestamp_list) {
        *next_timeout_msec = entry->flow_start_timestamp_usec / 1000LL
            + 1000LL * exporter->cache_active_timeout;
        return true;
    }

    return false;
}

static void
ipfix_cache_aggregate_entries(struct ipfix_flow_cache_entry *from_entry,
                              struct ipfix_flow_cache_entry *to_entry)
{
    uint64_t *to_start, *to_end, *from_start, *from_end;
    uint16_t *to_min_len, *to_max_len, *from_min_len, *from_max_len;

    to_start = &to_entry->flow_start_timestamp_usec;
    to_end = &to_entry->flow_end_timestamp_usec;
    from_start = &from_entry->flow_start_timestamp_usec;
    from_end = &from_entry->flow_end_timestamp_usec;

    if (*to_start > *from_start) {
        *to_start = *from_start;
    }
    if (*to_end < *from_end) {
        *to_end = *from_end;
    }

    to_entry->packet_delta_count += from_entry->packet_delta_count;
    to_entry->layer2_octet_delta_count += from_entry->layer2_octet_delta_count;

    to_entry->octet_delta_sum_of_squares +=
        from_entry->octet_delta_sum_of_squares;

    to_min_len = &to_entry->minimum_ip_total_length;
    to_max_len = &to_entry->maximum_ip_total_length;
    from_min_len = &from_entry->minimum_ip_total_length;
    from_max_len = &from_entry->maximum_ip_total_length;

    if (!*to_min_len || (*from_min_len && *to_min_len > *from_min_len)) {
        *to_min_len = *from_min_len;
    }
    if (*to_max_len < *from_max_len) {
        *to_max_len = *from_max_len;
    }
}

/* Add an entry into a flow cache.  The entry is either aggregated into
 * an existing entry with the same flow key and free()d, or it is
 * inserted into the cache. */
static void
ipfix_cache_update(struct dpif_ipfix_exporter *exporter,
                   struct ipfix_flow_cache_entry *entry)
{
    struct ipfix_flow_cache_entry *old_entry;

    old_entry = ipfix_cache_find_entry(exporter, &entry->flow_key);

    if (old_entry == NULL) {
        hmap_insert(&exporter->cache_flow_key_map, &entry->flow_key_map_node,
                    ipfix_hash_flow_key(&entry->flow_key, 0));

        /* As the latest entry added into the cache, it should
         * logically have the highest flow_start_timestamp_usec, so
         * append it at the tail. */
        list_push_back(&exporter->cache_flow_start_timestamp_list,
                       &entry->cache_flow_start_timestamp_list_node);

        /* Enforce exporter->cache_max_flows limit. */
        if (hmap_count(&exporter->cache_flow_key_map)
            > exporter->cache_max_flows) {
            dpif_ipfix_cache_expire_now(exporter, false);
        }
    } else {
        ipfix_cache_aggregate_entries(entry, old_entry);
        free(entry);
    }
}

static void
ipfix_cache_entry_init(struct ipfix_flow_cache_entry *entry,
                       struct ofpbuf *packet, const struct flow *flow,
                       uint64_t packet_delta_count, uint32_t obs_domain_id,
                       uint32_t obs_point_id)
{
    struct ipfix_flow_key *flow_key;
    struct ofpbuf msg;
    enum ipfix_proto_l2 l2;
    enum ipfix_proto_l3 l3;
    enum ipfix_proto_l4 l4;
    uint8_t ethernet_header_length;
    uint16_t ethernet_total_length;

    flow_key = &entry->flow_key;
    ofpbuf_use_stack(&msg, flow_key->flow_key_msg_part,
                     sizeof flow_key->flow_key_msg_part);

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

    flow_key->obs_domain_id = obs_domain_id;
    flow_key->template_id = ipfix_get_template_id(l2, l3, l4);

    /* The fields defined in the ipfix_data_record_* structs and sent
     * below must match exactly the templates defined in
     * ipfix_define_template_fields. */

    ethernet_header_length = (l2 == IPFIX_PROTO_L2_VLAN)
        ? VLAN_ETH_HEADER_LEN : ETH_HEADER_LEN;
    ethernet_total_length = packet->size;

    /* Common Ethernet entities. */
    {
        struct ipfix_data_record_flow_key_common *data_common;

        data_common = ofpbuf_put_zeros(&msg, sizeof *data_common);
        data_common->observation_point_id = htonl(obs_point_id);
        memcpy(data_common->source_mac_address, flow->dl_src,
               sizeof flow->dl_src);
        memcpy(data_common->destination_mac_address, flow->dl_dst,
               sizeof flow->dl_dst);
        data_common->ethernet_type = flow->dl_type;
        data_common->ethernet_header_length = ethernet_header_length;
    }

    if (l2 == IPFIX_PROTO_L2_VLAN) {
        struct ipfix_data_record_flow_key_vlan *data_vlan;
        uint16_t vlan_id = vlan_tci_to_vid(flow->vlan_tci);
        uint8_t priority = vlan_tci_to_pcp(flow->vlan_tci);

        data_vlan = ofpbuf_put_zeros(&msg, sizeof *data_vlan);
        data_vlan->vlan_id = htons(vlan_id);
        data_vlan->dot1q_vlan_id = htons(vlan_id);
        data_vlan->dot1q_priority = priority;
    }

    if (l3 != IPFIX_PROTO_L3_UNKNOWN) {
        struct ipfix_data_record_flow_key_ip *data_ip;

        data_ip = ofpbuf_put_zeros(&msg, sizeof *data_ip);
        data_ip->ip_version = (l3 == IPFIX_PROTO_L3_IPV4) ? 4 : 6;
        data_ip->ip_ttl = flow->nw_ttl;
        data_ip->protocol_identifier = flow->nw_proto;
        data_ip->ip_diff_serv_code_point = flow->nw_tos >> 2;
        data_ip->ip_precedence = flow->nw_tos >> 5;
        data_ip->ip_class_of_service = flow->nw_tos;

        if (l3 == IPFIX_PROTO_L3_IPV4) {
            struct ipfix_data_record_flow_key_ipv4 *data_ipv4;
            data_ipv4 = ofpbuf_put_zeros(&msg, sizeof *data_ipv4);
            data_ipv4->source_ipv4_address = flow->nw_src;
            data_ipv4->destination_ipv4_address = flow->nw_dst;
        } else {  /* l3 == IPFIX_PROTO_L3_IPV6 */
            struct ipfix_data_record_flow_key_ipv6 *data_ipv6;

            data_ipv6 = ofpbuf_put_zeros(&msg, sizeof *data_ipv6);
            memcpy(data_ipv6->source_ipv6_address, &flow->ipv6_src,
                   sizeof flow->ipv6_src);
            memcpy(data_ipv6->destination_ipv6_address, &flow->ipv6_dst,
                   sizeof flow->ipv6_dst);
            data_ipv6->flow_label_ipv6 = flow->ipv6_label;
        }
    }

    if (l4 != IPFIX_PROTO_L4_UNKNOWN) {
        struct ipfix_data_record_flow_key_tcpudp *data_tcpudp;

        data_tcpudp = ofpbuf_put_zeros(&msg, sizeof *data_tcpudp);
        data_tcpudp->source_transport_port = flow->tp_src;
        data_tcpudp->destination_transport_port = flow->tp_dst;
    }

    flow_key->flow_key_msg_part_size = msg.size;

    {
        struct timeval now;
        uint64_t layer2_octet_delta_count;

        /* Calculate the total matched octet count by considering as
         * an approximation that all matched packets have the same
         * length. */
        layer2_octet_delta_count = packet_delta_count * ethernet_total_length;

        xgettimeofday(&now);
        entry->flow_end_timestamp_usec = now.tv_usec + 1000000LL * now.tv_sec;
        entry->flow_start_timestamp_usec = entry->flow_end_timestamp_usec;
        entry->packet_delta_count = packet_delta_count;
        entry->layer2_octet_delta_count = layer2_octet_delta_count;
    }

    if (l3 != IPFIX_PROTO_L3_UNKNOWN) {
        uint16_t ip_total_length =
            ethernet_total_length - ethernet_header_length;

        entry->octet_delta_sum_of_squares =
            packet_delta_count * ip_total_length * ip_total_length;
        entry->minimum_ip_total_length = ip_total_length;
        entry->maximum_ip_total_length = ip_total_length;
    } else {
        entry->octet_delta_sum_of_squares = 0;
        entry->minimum_ip_total_length = 0;
        entry->maximum_ip_total_length = 0;
    }
}

/* Send each single data record in its own data set, to simplify the
 * implementation by avoiding having to group record by template ID
 * before sending. */
static void
ipfix_put_data_set(uint32_t export_time_sec,
                   struct ipfix_flow_cache_entry *entry,
                   enum ipfix_flow_end_reason flow_end_reason,
                   struct ofpbuf *msg)
{
    size_t set_hdr_offset;
    struct ipfix_set_header *set_hdr;

    set_hdr_offset = msg->size;

    /* Put a Data Set. */
    set_hdr = ofpbuf_put_zeros(msg, sizeof *set_hdr);
    set_hdr->set_id = htons(entry->flow_key.template_id);

    /* Copy the flow key part of the data record. */

    ofpbuf_put(msg, entry->flow_key.flow_key_msg_part,
               entry->flow_key.flow_key_msg_part_size);

    /* Put the non-key part of the data record. */

    {
        struct ipfix_data_record_aggregated_common *data_aggregated_common;
        uint64_t export_time_usec, flow_start_delta_usec, flow_end_delta_usec;

        /* Calculate the negative deltas relative to the export time
         * in seconds sent in the header, not the exact export
         * time. */
        export_time_usec = 1000000LL * export_time_sec;
        flow_start_delta_usec = export_time_usec
            - entry->flow_start_timestamp_usec;
        flow_end_delta_usec = export_time_usec
            - entry->flow_end_timestamp_usec;

        data_aggregated_common = ofpbuf_put_zeros(
            msg, sizeof *data_aggregated_common);
        data_aggregated_common->flow_start_delta_microseconds = htonl(
            flow_start_delta_usec);
        data_aggregated_common->flow_end_delta_microseconds = htonl(
            flow_end_delta_usec);
        data_aggregated_common->packet_delta_count = htonll(
            entry->packet_delta_count);
        data_aggregated_common->layer2_octet_delta_count = htonll(
            entry->layer2_octet_delta_count);
        data_aggregated_common->flow_end_reason = flow_end_reason;
    }

    if (entry->octet_delta_sum_of_squares) {  /* IP packet. */
        struct ipfix_data_record_aggregated_ip *data_aggregated_ip;

        data_aggregated_ip = ofpbuf_put_zeros(
            msg, sizeof *data_aggregated_ip);
        data_aggregated_ip->octet_delta_sum_of_squares = htonll(
            entry->octet_delta_sum_of_squares);
        data_aggregated_ip->minimum_ip_total_length = htonll(
            entry->minimum_ip_total_length);
        data_aggregated_ip->maximum_ip_total_length = htonll(
            entry->maximum_ip_total_length);
    }

    set_hdr = (struct ipfix_set_header*)((uint8_t*)msg->data + set_hdr_offset);
    set_hdr->length = htons(msg->size - set_hdr_offset);
}

/* Send an IPFIX message with a single data record. */
static void
ipfix_send_data_msg(struct dpif_ipfix_exporter *exporter,
                    uint32_t export_time_sec,
                    struct ipfix_flow_cache_entry *entry,
                    enum ipfix_flow_end_reason flow_end_reason)
{
    uint64_t msg_stub[DIV_ROUND_UP(MAX_MESSAGE_LEN, 8)];
    struct ofpbuf msg;
    ofpbuf_use_stub(&msg, msg_stub, sizeof msg_stub);

    ipfix_init_header(export_time_sec, exporter->seq_number++,
                      entry->flow_key.obs_domain_id, &msg);
    ipfix_put_data_set(export_time_sec, entry, flow_end_reason, &msg);
    ipfix_send_msg(exporter->collectors, &msg);

    ofpbuf_uninit(&msg);
}

static void
dpif_ipfix_sample(struct dpif_ipfix_exporter *exporter,
                  struct ofpbuf *packet, const struct flow *flow,
                  uint64_t packet_delta_count, uint32_t obs_domain_id,
                  uint32_t obs_point_id)
{
    struct ipfix_flow_cache_entry *entry;

    /* Create a flow cache entry from the sample. */
    entry = xmalloc(sizeof *entry);
    ipfix_cache_entry_init(entry, packet, flow, packet_delta_count,
                           obs_domain_id, obs_point_id);
    ipfix_cache_update(exporter, entry);
}

void
dpif_ipfix_bridge_sample(struct dpif_ipfix *di, struct ofpbuf *packet,
                         const struct flow *flow) OVS_EXCLUDED(mutex)
{
    uint64_t packet_delta_count;

    ovs_mutex_lock(&mutex);
    /* Use the sampling probability as an approximation of the number
     * of matched packets. */
    packet_delta_count = UINT32_MAX / di->bridge_exporter.probability;
    dpif_ipfix_sample(&di->bridge_exporter.exporter, packet, flow,
                      packet_delta_count,
                      di->bridge_exporter.options->obs_domain_id,
                      di->bridge_exporter.options->obs_point_id);
    ovs_mutex_unlock(&mutex);
}

void
dpif_ipfix_flow_sample(struct dpif_ipfix *di, struct ofpbuf *packet,
                       const struct flow *flow, uint32_t collector_set_id,
                       uint16_t probability, uint32_t obs_domain_id,
                       uint32_t obs_point_id) OVS_EXCLUDED(mutex)
{
    struct dpif_ipfix_flow_exporter_map_node *node;
    /* Use the sampling probability as an approximation of the number
     * of matched packets. */
    uint64_t packet_delta_count = USHRT_MAX / probability;

    ovs_mutex_lock(&mutex);
    node = dpif_ipfix_find_flow_exporter_map_node(di, collector_set_id);
    if (node) {
        dpif_ipfix_sample(&node->exporter.exporter, packet, flow,
                          packet_delta_count, obs_domain_id, obs_point_id);
    }
    ovs_mutex_unlock(&mutex);
}

static void
dpif_ipfix_cache_expire(struct dpif_ipfix_exporter *exporter,
                        bool forced_end, const uint64_t export_time_usec,
                        const uint32_t export_time_sec)
{
    struct ipfix_flow_cache_entry *entry, *next_entry;
    uint64_t max_flow_start_timestamp_usec;
    bool template_msg_sent = false;
    enum ipfix_flow_end_reason flow_end_reason;

    if (list_is_empty(&exporter->cache_flow_start_timestamp_list)) {
        return;
    }

    max_flow_start_timestamp_usec = export_time_usec -
        1000000LL * exporter->cache_active_timeout;

    LIST_FOR_EACH_SAFE (entry, next_entry, cache_flow_start_timestamp_list_node,
                        &exporter->cache_flow_start_timestamp_list) {
        if (forced_end) {
            flow_end_reason = FORCED_END;
        } else if (entry->flow_start_timestamp_usec
                   <= max_flow_start_timestamp_usec) {
            flow_end_reason = ACTIVE_TIMEOUT;
        } else if (hmap_count(&exporter->cache_flow_key_map)
                   > exporter->cache_max_flows) {
            /* Enforce exporter->cache_max_flows. */
            flow_end_reason = LACK_OF_RESOURCES;
        } else {
            /* Remaining flows haven't expired yet. */
            break;
        }

        list_remove(&entry->cache_flow_start_timestamp_list_node);
        hmap_remove(&exporter->cache_flow_key_map,
                    &entry->flow_key_map_node);

        if (!template_msg_sent
            && (exporter->last_template_set_time + IPFIX_TEMPLATE_INTERVAL)
                <= export_time_sec) {
            ipfix_send_template_msg(exporter, export_time_sec,
                                    entry->flow_key.obs_domain_id);
            exporter->last_template_set_time = export_time_sec;
            template_msg_sent = true;
        }

        /* XXX: Group multiple data records for the same obs domain id
         * into the same message. */
        ipfix_send_data_msg(exporter, export_time_sec, entry, flow_end_reason);
        free(entry);
    }
}

static void
get_export_time_now(uint64_t *export_time_usec, uint32_t *export_time_sec)
{
    struct timeval export_time;
    xgettimeofday(&export_time);

    *export_time_usec = export_time.tv_usec + 1000000LL * export_time.tv_sec;

    /* The IPFIX start and end deltas are negative deltas relative to
     * the export time, so set the export time 1 second off to
     * calculate those deltas. */
    if (export_time.tv_usec == 0) {
        *export_time_sec = export_time.tv_sec;
    } else {
        *export_time_sec = export_time.tv_sec + 1;
    }
}

static void
dpif_ipfix_cache_expire_now(struct dpif_ipfix_exporter *exporter,
                            bool forced_end)
{
    uint64_t export_time_usec;
    uint32_t export_time_sec;

    get_export_time_now(&export_time_usec, &export_time_sec);
    dpif_ipfix_cache_expire(exporter, forced_end, export_time_usec,
                            export_time_sec);
}

void
dpif_ipfix_run(struct dpif_ipfix *di) OVS_EXCLUDED(mutex)
{
    uint64_t export_time_usec;
    uint32_t export_time_sec;
    struct dpif_ipfix_flow_exporter_map_node *flow_exporter_node;

    ovs_mutex_lock(&mutex);
    get_export_time_now(&export_time_usec, &export_time_sec);
    if (di->bridge_exporter.probability > 0) {  /* Bridge exporter enabled. */
      dpif_ipfix_cache_expire(
          &di->bridge_exporter.exporter, false, export_time_usec,
          export_time_sec);
    }
    HMAP_FOR_EACH (flow_exporter_node, node, &di->flow_exporter_map) {
        dpif_ipfix_cache_expire(
            &flow_exporter_node->exporter.exporter, false, export_time_usec,
            export_time_sec);
    }
    ovs_mutex_unlock(&mutex);
}

void
dpif_ipfix_wait(struct dpif_ipfix *di) OVS_EXCLUDED(mutex)
{
    long long int next_timeout_msec = LLONG_MAX;
    struct dpif_ipfix_flow_exporter_map_node *flow_exporter_node;

    ovs_mutex_lock(&mutex);
    if (di->bridge_exporter.probability > 0) {  /* Bridge exporter enabled. */
        if (ipfix_cache_next_timeout_msec(
                &di->bridge_exporter.exporter, &next_timeout_msec)) {
            poll_timer_wait_until(next_timeout_msec);
        }
    }
    HMAP_FOR_EACH (flow_exporter_node, node, &di->flow_exporter_map) {
        if (ipfix_cache_next_timeout_msec(
                &flow_exporter_node->exporter.exporter, &next_timeout_msec)) {
            poll_timer_wait_until(next_timeout_msec);
        }
    }
    ovs_mutex_unlock(&mutex);
}

/*
 * Copyright (c) 2012, 2013, 2014, 2015 Nicira, Inc.
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
#include "netdev.h"
#include "openvswitch/list.h"
#include "openvswitch/ofpbuf.h"
#include "ofproto.h"
#include "ofproto-dpif.h"
#include "dp-packet.h"
#include "packets.h"
#include "poll-loop.h"
#include "sset.h"
#include "util.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ipfix);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;

/* Cf. IETF RFC 5101 Section 10.3.4. */
#define IPFIX_DEFAULT_COLLECTOR_PORT 4739

/* Cf. IETF RFC 5881 Setion 8. */
#define BFD_CONTROL_DEST_PORT        3784
#define BFD_ECHO_DEST_PORT           3785

/* The standard layer2SegmentId (ID 351) element is included in vDS to send
 * the VxLAN tunnel's VNI. It is 64-bit long, the most significant byte is
 * used to indicate the type of tunnel (0x01 = VxLAN, 0x02 = GRE) and the three
 * least significant bytes hold the value of the layer 2 overlay network
 * segment identifier: a 24-bit VxLAN tunnel's VNI or a 24-bit GRE tunnel's
 * TNI. This is not compatible with STT, as implemented in OVS, as
 * its tunnel IDs is 64-bit.
 *
 * Two new enterprise information elements are defined which are similar to
 * laryerSegmentId but support 64-bit IDs:
 *     tunnelType (ID 891) and tunnelKey (ID 892).
 *
 * The enum dpif_ipfix_tunnel_type is to declare the types supported in the
 * tunnelType element.
 * The number of ipfix tunnel types includes two reserverd types: 0x04 and 0x06.
 */
enum dpif_ipfix_tunnel_type {
    DPIF_IPFIX_TUNNEL_UNKNOWN = 0x00,
    DPIF_IPFIX_TUNNEL_VXLAN = 0x01,
    DPIF_IPFIX_TUNNEL_GRE = 0x02,
    DPIF_IPFIX_TUNNEL_LISP = 0x03,
    DPIF_IPFIX_TUNNEL_STT = 0x04,
    DPIF_IPFIX_TUNNEL_IPSEC_GRE = 0x05,
    DPIF_IPFIX_TUNNEL_GENEVE = 0x07,
    NUM_DPIF_IPFIX_TUNNEL
};

struct dpif_ipfix_port {
    struct hmap_node hmap_node; /* In struct dpif_ipfix's "tunnel_ports" hmap. */
    struct ofport *ofport;      /* To retrieve port stats. */
    odp_port_t odp_port;
    enum dpif_ipfix_tunnel_type tunnel_type;
    uint8_t tunnel_key_length;
};

struct dpif_ipfix_exporter {
    struct collectors *collectors;
    uint32_t seq_number;
    time_t last_template_set_time;
    struct hmap cache_flow_key_map;  /* ipfix_flow_cache_entry. */
    struct ovs_list cache_flow_start_timestamp_list;  /* ipfix_flow_cache_entry. */
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
    struct hmap tunnel_ports;       /* Contains "struct dpif_ipfix_port"s.
                                     * It makes tunnel port lookups faster in
                                     * sampling upcalls. */
    struct ovs_refcount ref_cnt;
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
    IPFIX_PROTO_L4_TCP_UDP_SCTP,
    IPFIX_PROTO_L4_ICMP,
    NUM_IPFIX_PROTO_L4
};
enum ipfix_proto_tunnel {
    IPFIX_PROTO_NOT_TUNNELED = 0,
    IPFIX_PROTO_TUNNELED,  /* Support gre, lisp and vxlan. */
    NUM_IPFIX_PROTO_TUNNEL
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
/* standard IPFIX elements */
#define IPFIX_ENTITY(ENUM, ID, SIZE, NAME)  IPFIX_ENTITY_ID_##ENUM = ID,
#include "ofproto/ipfix-entities.def"
/* non-standard IPFIX elements */
#define IPFIX_SET_ENTERPRISE(v) (((v) | 0x8000))
#define IPFIX_ENTERPRISE_ENTITY(ENUM, ID, SIZE, NAME, ENTERPRISE) \
    IPFIX_ENTITY_ID_##ENUM = IPFIX_SET_ENTERPRISE(ID),
#include "ofproto/ipfix-enterprise-entities.def"
};

enum ipfix_entity_size {
/* standard IPFIX elements */
#define IPFIX_ENTITY(ENUM, ID, SIZE, NAME)  IPFIX_ENTITY_SIZE_##ENUM = SIZE,
#include "ofproto/ipfix-entities.def"
/* non-standard IPFIX elements */
#define IPFIX_ENTERPRISE_ENTITY(ENUM, ID, SIZE, NAME, ENTERPRISE) \
    IPFIX_ENTITY_SIZE_##ENUM = SIZE,
#include "ofproto/ipfix-enterprise-entities.def"
};

enum ipfix_entity_enterprise {
/* standard IPFIX elements */
#define IPFIX_ENTITY(ENUM, ID, SIZE, NAME)  IPFIX_ENTITY_ENTERPRISE_##ENUM = 0,
#include "ofproto/ipfix-entities.def"
/* non-standard IPFIX elements */
#define IPFIX_ENTERPRISE_ENTITY(ENUM, ID, SIZE, NAME, ENTERPRISE) \
    IPFIX_ENTITY_ENTERPRISE_##ENUM = ENTERPRISE,
#include "ofproto/ipfix-enterprise-entities.def"
};

OVS_PACKED(
struct ipfix_template_field_specifier {
    ovs_be16 element_id;  /* IPFIX_ENTITY_ID_*. */
    ovs_be16 field_length;  /* Length of the field's value, in bytes.
                             * For Variable-Length element, it should be 65535.
                             */
    ovs_be32 enterprise;  /* Enterprise number */
});
BUILD_ASSERT_DECL(sizeof(struct ipfix_template_field_specifier) == 8);

/* Cf. IETF RFC 5102 Section 5.11.6. */
enum ipfix_flow_direction {
    INGRESS_FLOW = 0x00,
    EGRESS_FLOW = 0x01
};

/* Part of data record flow key for common metadata and Ethernet entities. */
OVS_PACKED(
struct ipfix_data_record_flow_key_common {
    ovs_be32 observation_point_id;  /* OBSERVATION_POINT_ID */
    uint8_t flow_direction;  /* FLOW_DIRECTION */
    struct eth_addr source_mac_address; /* SOURCE_MAC_ADDRESS */
    struct eth_addr destination_mac_address; /* DESTINATION_MAC_ADDRESS */
    ovs_be16 ethernet_type;  /* ETHERNET_TYPE */
    uint8_t ethernet_header_length;  /* ETHERNET_HEADER_LENGTH */
});
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_flow_key_common) == 20);

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

/* Part of data record flow key for TCP/UDP/SCTP entities. */
OVS_PACKED(
struct ipfix_data_record_flow_key_transport {
    ovs_be16 source_transport_port;  /* SOURCE_TRANSPORT_PORT */
    ovs_be16 destination_transport_port;  /* DESTINATION_TRANSPORT_PORT */
});
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_flow_key_transport) == 4);

/* Part of data record flow key for ICMP entities. */
OVS_PACKED(
struct ipfix_data_record_flow_key_icmp {
    uint8_t icmp_type;  /* ICMP_TYPE_IPV4 / ICMP_TYPE_IPV6 */
    uint8_t icmp_code;  /* ICMP_CODE_IPV4 / ICMP_CODE_IPV6 */
});
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_flow_key_icmp) == 2);

/* For the tunnel type that is on the top of IPSec, the protocol identifier
 * of the upper tunnel type is used.
 */
static uint8_t tunnel_protocol[NUM_DPIF_IPFIX_TUNNEL] = {
    0,              /* reserved */
    IPPROTO_UDP,    /* DPIF_IPFIX_TUNNEL_VXLAN */
    IPPROTO_GRE,    /* DPIF_IPFIX_TUNNEL_GRE */
    IPPROTO_UDP,    /* DPIF_IPFIX_TUNNEL_LISP*/
    IPPROTO_TCP,    /* DPIF_IPFIX_TUNNEL_STT*/
    IPPROTO_GRE,    /* DPIF_IPFIX_TUNNEL_IPSEC_GRE */
    0          ,    /* reserved */
    IPPROTO_UDP,    /* DPIF_IPFIX_TUNNEL_GENEVE*/
};

OVS_PACKED(
struct ipfix_data_record_flow_key_tunnel {
    ovs_be32 tunnel_source_ipv4_address;  /* TUNNEL_SOURCE_IPV4_ADDRESS */
    ovs_be32 tunnel_destination_ipv4_address;  /* TUNNEL_DESTINATION_IPV4_ADDRESS */
    uint8_t tunnel_protocol_identifier;  /* TUNNEL_PROTOCOL_IDENTIFIER */
    ovs_be16 tunnel_source_transport_port;  /* TUNNEL_SOURCE_TRANSPORT_PORT */
    ovs_be16 tunnel_destination_transport_port;  /* TUNNEL_DESTINATION_TRANSPORT_PORT */
    uint8_t tunnel_type;  /* TUNNEL_TYPE */
    uint8_t tunnel_key_length;  /* length of TUNNEL_KEY */
    uint8_t tunnel_key[];  /* data of  TUNNEL_KEY */
});
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_flow_key_tunnel) == 15);

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
    ovs_be64 octet_delta_count;  /* OCTET_DELTA_COUNT */
    ovs_be64 octet_delta_sum_of_squares;  /* OCTET_DELTA_SUM_OF_SQUARES */
    ovs_be64 minimum_ip_total_length;  /* MINIMUM_IP_TOTAL_LENGTH */
    ovs_be64 maximum_ip_total_length;  /* MAXIMUM_IP_TOTAL_LENGTH */
});
BUILD_ASSERT_DECL(sizeof(struct ipfix_data_record_aggregated_ip) == 32);

/*
 * support tunnel key for:
 * VxLAN: 24-bit VIN,
 * GRE: 32-bit key,
 * LISP: 24-bit instance ID
 * STT: 64-bit key
 */
#define MAX_TUNNEL_KEY_LEN 8

#define MAX_FLOW_KEY_LEN                                        \
    (sizeof(struct ipfix_data_record_flow_key_common)           \
     + sizeof(struct ipfix_data_record_flow_key_vlan)           \
     + sizeof(struct ipfix_data_record_flow_key_ip)             \
     + MAX(sizeof(struct ipfix_data_record_flow_key_ipv4),      \
           sizeof(struct ipfix_data_record_flow_key_ipv6))      \
     + MAX(sizeof(struct ipfix_data_record_flow_key_icmp),      \
           sizeof(struct ipfix_data_record_flow_key_transport)) \
     + sizeof(struct ipfix_data_record_flow_key_tunnel)         \
     + MAX_TUNNEL_KEY_LEN)

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

/* Max length of an IPFIX message. Arbitrarily set to accommodate low
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
    struct ovs_list cache_flow_start_timestamp_list_node;
    struct ipfix_flow_key flow_key;
    /* Common aggregated elements. */
    uint64_t flow_start_timestamp_usec;
    uint64_t flow_end_timestamp_usec;
    uint64_t packet_delta_count;
    uint64_t layer2_octet_delta_count;
    uint64_t octet_delta_count;
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
            && a->enable_tunnel_sampling == b->enable_tunnel_sampling
            && a->enable_input_sampling == b->enable_input_sampling
            && a->enable_output_sampling == b->enable_output_sampling
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
    ovs_list_init(&exporter->cache_flow_start_timestamp_list);
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

static struct dpif_ipfix_port *
dpif_ipfix_find_port(const struct dpif_ipfix *di,
                     odp_port_t odp_port) OVS_REQUIRES(mutex)
{
    struct dpif_ipfix_port *dip;

    HMAP_FOR_EACH_IN_BUCKET (dip, hmap_node, hash_odp_port(odp_port),
                             &di->tunnel_ports) {
        if (dip->odp_port == odp_port) {
            return dip;
        }
    }
    return NULL;
}

static void
dpif_ipfix_del_port(struct dpif_ipfix *di,
                      struct dpif_ipfix_port *dip)
    OVS_REQUIRES(mutex)
{
    hmap_remove(&di->tunnel_ports, &dip->hmap_node);
    free(dip);
}

void
dpif_ipfix_add_tunnel_port(struct dpif_ipfix *di, struct ofport *ofport,
                           odp_port_t odp_port) OVS_EXCLUDED(mutex)
{
    struct dpif_ipfix_port *dip;
    const char *type;

    ovs_mutex_lock(&mutex);
    dip = dpif_ipfix_find_port(di, odp_port);
    if (dip) {
        dpif_ipfix_del_port(di, dip);
    }

    type = netdev_get_type(ofport->netdev);
    if (type == NULL) {
        goto out;
    }

    /* Add to table of tunnel ports. */
    dip = xmalloc(sizeof *dip);
    dip->ofport = ofport;
    dip->odp_port = odp_port;
    if (strcmp(type, "gre") == 0) {
        /* 32-bit key gre */
        dip->tunnel_type = DPIF_IPFIX_TUNNEL_GRE;
        dip->tunnel_key_length = 4;
    } else if (strcmp(type, "ipsec_gre") == 0) {
        /* 32-bit key ipsec_gre */
        dip->tunnel_type = DPIF_IPFIX_TUNNEL_IPSEC_GRE;
        dip->tunnel_key_length = 4;
    } else if (strcmp(type, "vxlan") == 0) {
        dip->tunnel_type = DPIF_IPFIX_TUNNEL_VXLAN;
        dip->tunnel_key_length = 3;
    } else if (strcmp(type, "lisp") == 0) {
        dip->tunnel_type = DPIF_IPFIX_TUNNEL_LISP;
        dip->tunnel_key_length = 3;
    } else if (strcmp(type, "geneve") == 0) {
        dip->tunnel_type = DPIF_IPFIX_TUNNEL_GENEVE;
        dip->tunnel_key_length = 3;
    } else if (strcmp(type, "stt") == 0) {
        dip->tunnel_type = DPIF_IPFIX_TUNNEL_STT;
        dip->tunnel_key_length = 8;
    } else {
        free(dip);
        goto out;
    }
    hmap_insert(&di->tunnel_ports, &dip->hmap_node, hash_odp_port(odp_port));

out:
    ovs_mutex_unlock(&mutex);
}

void
dpif_ipfix_del_tunnel_port(struct dpif_ipfix *di, odp_port_t odp_port)
    OVS_EXCLUDED(mutex)
{
    struct dpif_ipfix_port *dip;
    ovs_mutex_lock(&mutex);
    dip = dpif_ipfix_find_port(di, odp_port);
    if (dip) {
        dpif_ipfix_del_port(di, dip);
    }
    ovs_mutex_unlock(&mutex);
}

bool
dpif_ipfix_get_tunnel_port(const struct dpif_ipfix *di, odp_port_t odp_port)
    OVS_EXCLUDED(mutex)
{
    struct dpif_ipfix_port *dip;
    ovs_mutex_lock(&mutex);
    dip = dpif_ipfix_find_port(di, odp_port);
    ovs_mutex_unlock(&mutex);
    return dip != NULL;
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
    hmap_init(&di->tunnel_ports);
    ovs_refcount_init(&di->ref_cnt);
    return di;
}

struct dpif_ipfix *
dpif_ipfix_ref(const struct dpif_ipfix *di_)
{
    struct dpif_ipfix *di = CONST_CAST(struct dpif_ipfix *, di_);
    if (di) {
        ovs_refcount_ref(&di->ref_cnt);
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

bool
dpif_ipfix_get_bridge_exporter_input_sampling(const struct dpif_ipfix *di)
    OVS_EXCLUDED(mutex)
{
    bool ret = true;
    ovs_mutex_lock(&mutex);
    if (di->bridge_exporter.options) {
        ret = di->bridge_exporter.options->enable_input_sampling;
    }
    ovs_mutex_unlock(&mutex);
    return ret;
}

bool
dpif_ipfix_get_bridge_exporter_output_sampling(const struct dpif_ipfix *di)
    OVS_EXCLUDED(mutex)
{
    bool ret = true;
    ovs_mutex_lock(&mutex);
    if (di->bridge_exporter.options) {
        ret = di->bridge_exporter.options->enable_output_sampling;
    }
    ovs_mutex_unlock(&mutex);
    return ret;
}

bool
dpif_ipfix_get_bridge_exporter_tunnel_sampling(const struct dpif_ipfix *di)
    OVS_EXCLUDED(mutex)
{
    bool ret = false;
    ovs_mutex_lock(&mutex);
    if (di->bridge_exporter.options) {
        ret = di->bridge_exporter.options->enable_tunnel_sampling;
    }
    ovs_mutex_unlock(&mutex);
    return ret;
}

static void
dpif_ipfix_clear(struct dpif_ipfix *di) OVS_REQUIRES(mutex)
{
    struct dpif_ipfix_flow_exporter_map_node *exp_node;
    struct dpif_ipfix_port *dip, *next;

    dpif_ipfix_bridge_exporter_clear(&di->bridge_exporter);

    HMAP_FOR_EACH_POP (exp_node, node, &di->flow_exporter_map) {
        dpif_ipfix_flow_exporter_destroy(&exp_node->exporter);
        free(exp_node);
    }

    HMAP_FOR_EACH_SAFE (dip, next, hmap_node, &di->tunnel_ports) {
        dpif_ipfix_del_port(di, dip);
    }
}

void
dpif_ipfix_unref(struct dpif_ipfix *di) OVS_EXCLUDED(mutex)
{
    if (di && ovs_refcount_unref_relaxed(&di->ref_cnt) == 1) {
        ovs_mutex_lock(&mutex);
        dpif_ipfix_clear(di);
        dpif_ipfix_bridge_exporter_destroy(&di->bridge_exporter);
        hmap_destroy(&di->flow_exporter_map);
        hmap_destroy(&di->tunnel_ports);
        free(di);
        ovs_mutex_unlock(&mutex);
    }
}

static void
ipfix_init_header(uint32_t export_time_sec, uint32_t seq_number,
                  uint32_t obs_domain_id, struct dp_packet *msg)
{
    struct ipfix_header *hdr;

    hdr = dp_packet_put_zeros(msg, sizeof *hdr);
    hdr->version = htons(IPFIX_VERSION);
    hdr->length = htons(sizeof *hdr);  /* Updated in ipfix_send_msg. */
    hdr->export_time = htonl(export_time_sec);
    hdr->seq_number = htonl(seq_number);
    hdr->obs_domain_id = htonl(obs_domain_id);
}

static void
ipfix_send_msg(const struct collectors *collectors, struct dp_packet *msg)
{
    struct ipfix_header *hdr;

    /* Adjust the length in the header. */
    hdr = dp_packet_data(msg);
    hdr->length = htons(dp_packet_size(msg));

    collectors_send(collectors, dp_packet_data(msg), dp_packet_size(msg));
    dp_packet_set_size(msg, 0);
}

static uint16_t
ipfix_get_template_id(enum ipfix_proto_l2 l2, enum ipfix_proto_l3 l3,
                      enum ipfix_proto_l4 l4, enum ipfix_proto_tunnel tunnel)
{
    uint16_t template_id;
    template_id = l2;
    template_id = template_id * NUM_IPFIX_PROTO_L3 + l3;
    template_id = template_id * NUM_IPFIX_PROTO_L4 + l4;
    template_id = template_id * NUM_IPFIX_PROTO_TUNNEL + tunnel;
    return IPFIX_TEMPLATE_ID_MIN + template_id;
}

static void
ipfix_define_template_entity(enum ipfix_entity_id id,
                             enum ipfix_entity_size size,
                             enum ipfix_entity_enterprise enterprise,
                             struct dp_packet *msg)
{
    struct ipfix_template_field_specifier *field;
    size_t field_size;

    if (enterprise) {
        field_size = sizeof *field;
    } else {
        /* No enterprise number */
        field_size = sizeof *field - sizeof(ovs_be32);
    }
    field = dp_packet_put_zeros(msg, field_size);
    field->element_id = htons(id);
    if (size) {
        field->field_length = htons(size);
    } else {
        /* RFC 5101, Section 7. Variable-Length Information Element */
        field->field_length = OVS_BE16_MAX;
    }
    if (enterprise) {
        field->enterprise = htonl(enterprise);
    }

}

static uint16_t
ipfix_define_template_fields(enum ipfix_proto_l2 l2, enum ipfix_proto_l3 l3,
                             enum ipfix_proto_l4 l4, enum ipfix_proto_tunnel tunnel,
                             struct dp_packet *msg)
{
    uint16_t count = 0;

#define DEF(ID) \
    { \
        ipfix_define_template_entity(IPFIX_ENTITY_ID_##ID, \
                                     IPFIX_ENTITY_SIZE_##ID, \
                                     IPFIX_ENTITY_ENTERPRISE_##ID, msg); \
        count++; \
    }

    /* 1. Flow key. */

    DEF(OBSERVATION_POINT_ID);
    DEF(FLOW_DIRECTION);

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
            if (l4 == IPFIX_PROTO_L4_TCP_UDP_SCTP) {
                DEF(SOURCE_TRANSPORT_PORT);
                DEF(DESTINATION_TRANSPORT_PORT);
            } else if (l4 == IPFIX_PROTO_L4_ICMP) {
                DEF(ICMP_TYPE_IPV4);
                DEF(ICMP_CODE_IPV4);
            }
        } else {  /* l3 == IPFIX_PROTO_L3_IPV6 */
            DEF(SOURCE_IPV6_ADDRESS);
            DEF(DESTINATION_IPV6_ADDRESS);
            DEF(FLOW_LABEL_IPV6);
            if (l4 == IPFIX_PROTO_L4_TCP_UDP_SCTP) {
                DEF(SOURCE_TRANSPORT_PORT);
                DEF(DESTINATION_TRANSPORT_PORT);
            } else if (l4 == IPFIX_PROTO_L4_ICMP) {
                DEF(ICMP_TYPE_IPV6);
                DEF(ICMP_CODE_IPV6);
            }
        }
    }

    if (tunnel != IPFIX_PROTO_NOT_TUNNELED) {
        DEF(TUNNEL_SOURCE_IPV4_ADDRESS);
        DEF(TUNNEL_DESTINATION_IPV4_ADDRESS);
        DEF(TUNNEL_PROTOCOL_IDENTIFIER);
        DEF(TUNNEL_SOURCE_TRANSPORT_PORT);
        DEF(TUNNEL_DESTINATION_TRANSPORT_PORT);
        DEF(TUNNEL_TYPE);
        DEF(TUNNEL_KEY);
    }

    /* 2. Flow aggregated data. */

    DEF(FLOW_START_DELTA_MICROSECONDS);
    DEF(FLOW_END_DELTA_MICROSECONDS);
    DEF(PACKET_DELTA_COUNT);
    DEF(LAYER2_OCTET_DELTA_COUNT);
    DEF(FLOW_END_REASON);

    if (l3 != IPFIX_PROTO_L3_UNKNOWN) {
        DEF(OCTET_DELTA_COUNT);
        DEF(OCTET_DELTA_SUM_OF_SQUARES);
        DEF(MINIMUM_IP_TOTAL_LENGTH);
        DEF(MAXIMUM_IP_TOTAL_LENGTH);
    }


#undef DEF

    return count;
}

static void
ipfix_init_template_msg(void *msg_stub, uint32_t export_time_sec,
                        uint32_t seq_number, uint32_t obs_domain_id,
                        struct dp_packet *msg, size_t *set_hdr_offset)
{
    struct ipfix_set_header *set_hdr;

    dp_packet_use_stub(msg, msg_stub, sizeof msg_stub);

    ipfix_init_header(export_time_sec, seq_number, obs_domain_id, msg);
    *set_hdr_offset = dp_packet_size(msg);

    /* Add a Template Set. */
    set_hdr = dp_packet_put_zeros(msg, sizeof *set_hdr);
    set_hdr->set_id = htons(IPFIX_SET_ID_TEMPLATE);
}

static void
ipfix_send_template_msg(const struct collectors *collectors,
                        struct dp_packet *msg, size_t set_hdr_offset)
{
    struct ipfix_set_header *set_hdr;

    /* Send template message. */
    set_hdr = (struct ipfix_set_header*)
              ((uint8_t*)dp_packet_data(msg) + set_hdr_offset);
    set_hdr->length = htons(dp_packet_size(msg) - set_hdr_offset);

    ipfix_send_msg(collectors, msg);

    dp_packet_uninit(msg);
}

static void
ipfix_send_template_msgs(struct dpif_ipfix_exporter *exporter,
                         uint32_t export_time_sec, uint32_t obs_domain_id)
{
    uint64_t msg_stub[DIV_ROUND_UP(MAX_MESSAGE_LEN, 8)];
    struct dp_packet msg;
    size_t set_hdr_offset, tmpl_hdr_offset;
    struct ipfix_template_record_header *tmpl_hdr;
    uint16_t field_count;
    enum ipfix_proto_l2 l2;
    enum ipfix_proto_l3 l3;
    enum ipfix_proto_l4 l4;
    enum ipfix_proto_tunnel tunnel;

    ipfix_init_template_msg(msg_stub, export_time_sec, exporter->seq_number,
                            obs_domain_id, &msg, &set_hdr_offset);
    /* Define one template for each possible combination of
     * protocols. */
    for (l2 = 0; l2 < NUM_IPFIX_PROTO_L2; l2++) {
        for (l3 = 0; l3 < NUM_IPFIX_PROTO_L3; l3++) {
            for (l4 = 0; l4 < NUM_IPFIX_PROTO_L4; l4++) {
                if (l3 == IPFIX_PROTO_L3_UNKNOWN &&
                    l4 != IPFIX_PROTO_L4_UNKNOWN) {
                    continue;
                }
                for (tunnel = 0; tunnel < NUM_IPFIX_PROTO_TUNNEL; tunnel++) {
                    /* When the size of the template packet reaches
                     * MAX_MESSAGE_LEN(1024), send it out.
                     * And then reinitialize the msg to construct a new
                     * packet for the following templates.
                     */
                    if (dp_packet_size(&msg) >= MAX_MESSAGE_LEN) {
                        /* Send template message. */
                        ipfix_send_template_msg(exporter->collectors,
                                                &msg, set_hdr_offset);

                        /* Reinitialize the template msg. */
                        ipfix_init_template_msg(msg_stub, export_time_sec,
                                                exporter->seq_number,
                                                obs_domain_id, &msg,
                                                &set_hdr_offset);
                    }

                    tmpl_hdr_offset = dp_packet_size(&msg);
                    tmpl_hdr = dp_packet_put_zeros(&msg, sizeof *tmpl_hdr);
                    tmpl_hdr->template_id = htons(
                        ipfix_get_template_id(l2, l3, l4, tunnel));
                    field_count =
                        ipfix_define_template_fields(l2, l3, l4, tunnel, &msg);
                    tmpl_hdr = (struct ipfix_template_record_header*)
                        ((uint8_t*)dp_packet_data(&msg) + tmpl_hdr_offset);
                    tmpl_hdr->field_count = htons(field_count);
                }
            }
        }
    }

    /* Send template message. */
    ipfix_send_template_msg(exporter->collectors, &msg, set_hdr_offset);

    /* XXX: Add Options Template Sets, at least to define a Flow Keys
     * Option Template. */

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

    to_entry->octet_delta_count += from_entry->octet_delta_count;
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
        ovs_list_push_back(&exporter->cache_flow_start_timestamp_list,
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
                       const struct dp_packet *packet, const struct flow *flow,
                       uint64_t packet_delta_count, uint32_t obs_domain_id,
                       uint32_t obs_point_id, odp_port_t output_odp_port,
                       const struct dpif_ipfix_port *tunnel_port,
                       const struct flow_tnl *tunnel_key)
{
    struct ipfix_flow_key *flow_key;
    struct dp_packet msg;
    enum ipfix_proto_l2 l2;
    enum ipfix_proto_l3 l3;
    enum ipfix_proto_l4 l4;
    enum ipfix_proto_tunnel tunnel = IPFIX_PROTO_NOT_TUNNELED;
    uint8_t ethernet_header_length;
    uint16_t ethernet_total_length;

    flow_key = &entry->flow_key;
    dp_packet_use_stub(&msg, flow_key->flow_key_msg_part,
                       sizeof flow_key->flow_key_msg_part);

    /* Choose the right template ID matching the protocols in the
     * sampled packet. */
    l2 = (flow->vlan_tci == 0) ? IPFIX_PROTO_L2_ETH : IPFIX_PROTO_L2_VLAN;

    switch(ntohs(flow->dl_type)) {
    case ETH_TYPE_IP:
        l3 = IPFIX_PROTO_L3_IPV4;
        switch(flow->nw_proto) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_SCTP:
            l4 = IPFIX_PROTO_L4_TCP_UDP_SCTP;
            break;
        case IPPROTO_ICMP:
            l4 = IPFIX_PROTO_L4_ICMP;
            break;
        default:
            l4 = IPFIX_PROTO_L4_UNKNOWN;
        }
        break;
    case ETH_TYPE_IPV6:
        l3 = IPFIX_PROTO_L3_IPV6;
        switch(flow->nw_proto) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_SCTP:
            l4 = IPFIX_PROTO_L4_TCP_UDP_SCTP;
            break;
        case IPPROTO_ICMPV6:
            l4 = IPFIX_PROTO_L4_ICMP;
            break;
        default:
            l4 = IPFIX_PROTO_L4_UNKNOWN;
        }
        break;
    default:
        l3 = IPFIX_PROTO_L3_UNKNOWN;
        l4 = IPFIX_PROTO_L4_UNKNOWN;
    }

    if (tunnel_port && tunnel_key) {
       tunnel = IPFIX_PROTO_TUNNELED;
    }

    flow_key->obs_domain_id = obs_domain_id;
    flow_key->template_id = ipfix_get_template_id(l2, l3, l4, tunnel);

    /* The fields defined in the ipfix_data_record_* structs and sent
     * below must match exactly the templates defined in
     * ipfix_define_template_fields. */

    ethernet_header_length = (l2 == IPFIX_PROTO_L2_VLAN)
        ? VLAN_ETH_HEADER_LEN : ETH_HEADER_LEN;
    ethernet_total_length = dp_packet_size(packet);

    /* Common Ethernet entities. */
    {
        struct ipfix_data_record_flow_key_common *data_common;

        data_common = dp_packet_put_zeros(&msg, sizeof *data_common);
        data_common->observation_point_id = htonl(obs_point_id);
        data_common->flow_direction =
            (output_odp_port == ODPP_NONE) ? INGRESS_FLOW : EGRESS_FLOW;
        data_common->source_mac_address = flow->dl_src;
        data_common->destination_mac_address = flow->dl_dst;
        data_common->ethernet_type = flow->dl_type;
        data_common->ethernet_header_length = ethernet_header_length;
    }

    if (l2 == IPFIX_PROTO_L2_VLAN) {
        struct ipfix_data_record_flow_key_vlan *data_vlan;
        uint16_t vlan_id = vlan_tci_to_vid(flow->vlan_tci);
        uint8_t priority = vlan_tci_to_pcp(flow->vlan_tci);

        data_vlan = dp_packet_put_zeros(&msg, sizeof *data_vlan);
        data_vlan->vlan_id = htons(vlan_id);
        data_vlan->dot1q_vlan_id = htons(vlan_id);
        data_vlan->dot1q_priority = priority;
    }

    if (l3 != IPFIX_PROTO_L3_UNKNOWN) {
        struct ipfix_data_record_flow_key_ip *data_ip;

        data_ip = dp_packet_put_zeros(&msg, sizeof *data_ip);
        data_ip->ip_version = (l3 == IPFIX_PROTO_L3_IPV4) ? 4 : 6;
        data_ip->ip_ttl = flow->nw_ttl;
        data_ip->protocol_identifier = flow->nw_proto;
        data_ip->ip_diff_serv_code_point = flow->nw_tos >> 2;
        data_ip->ip_precedence = flow->nw_tos >> 5;
        data_ip->ip_class_of_service = flow->nw_tos;

        if (l3 == IPFIX_PROTO_L3_IPV4) {
            struct ipfix_data_record_flow_key_ipv4 *data_ipv4;

            data_ipv4 = dp_packet_put_zeros(&msg, sizeof *data_ipv4);
            data_ipv4->source_ipv4_address = flow->nw_src;
            data_ipv4->destination_ipv4_address = flow->nw_dst;
        } else {  /* l3 == IPFIX_PROTO_L3_IPV6 */
            struct ipfix_data_record_flow_key_ipv6 *data_ipv6;

            data_ipv6 = dp_packet_put_zeros(&msg, sizeof *data_ipv6);
            memcpy(data_ipv6->source_ipv6_address, &flow->ipv6_src,
                   sizeof flow->ipv6_src);
            memcpy(data_ipv6->destination_ipv6_address, &flow->ipv6_dst,
                   sizeof flow->ipv6_dst);
            data_ipv6->flow_label_ipv6 = flow->ipv6_label;
        }
    }

    if (l4 == IPFIX_PROTO_L4_TCP_UDP_SCTP) {
        struct ipfix_data_record_flow_key_transport *data_transport;

        data_transport = dp_packet_put_zeros(&msg, sizeof *data_transport);
        data_transport->source_transport_port = flow->tp_src;
        data_transport->destination_transport_port = flow->tp_dst;
    } else if (l4 == IPFIX_PROTO_L4_ICMP) {
        struct ipfix_data_record_flow_key_icmp *data_icmp;

        data_icmp = dp_packet_put_zeros(&msg, sizeof *data_icmp);
        data_icmp->icmp_type = ntohs(flow->tp_src) & 0xff;
        data_icmp->icmp_code = ntohs(flow->tp_dst) & 0xff;
    }

    if (tunnel == IPFIX_PROTO_TUNNELED) {
        struct ipfix_data_record_flow_key_tunnel *data_tunnel;
        const uint8_t *tun_id;

        data_tunnel = dp_packet_put_zeros(&msg, sizeof *data_tunnel +
                                             tunnel_port->tunnel_key_length);
        data_tunnel->tunnel_source_ipv4_address = tunnel_key->ip_src;
        data_tunnel->tunnel_destination_ipv4_address = tunnel_key->ip_dst;
        /* The tunnel_protocol_identifier is from tunnel_proto array, which
         * contains protocol_identifiers of each tunnel type.
         * For the tunnel type on the top of IPSec, which uses the protocol
         * identifier of the upper tunnel type is used, the tcp_src and tcp_dst
         * are decided based on the protocol identifiers.
         * E.g:
         * The protocol identifier of DPIF_IPFIX_TUNNEL_IPSEC_GRE is IPPROTO_GRE,
         * and both tp_src and tp_dst are zero.
         */
        data_tunnel->tunnel_protocol_identifier =
            tunnel_protocol[tunnel_port->tunnel_type];
        data_tunnel->tunnel_source_transport_port = tunnel_key->tp_src;
        data_tunnel->tunnel_destination_transport_port = tunnel_key->tp_dst;
        data_tunnel->tunnel_type = tunnel_port->tunnel_type;
        data_tunnel->tunnel_key_length = tunnel_port->tunnel_key_length;
        /* tun_id is in network order, and tunnel key is in low bits. */
        tun_id = (const uint8_t *) &tunnel_key->tun_id;
	memcpy(data_tunnel->tunnel_key,
               &tun_id[8 - tunnel_port->tunnel_key_length],
               tunnel_port->tunnel_key_length);
    }

    flow_key->flow_key_msg_part_size = dp_packet_size(&msg);

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
        uint64_t octet_delta_count;

        /* Calculate the total matched octet count by considering as
         * an approximation that all matched packets have the same
         * length. */
        octet_delta_count = packet_delta_count * ip_total_length;

        entry->octet_delta_count = octet_delta_count;
        entry->octet_delta_sum_of_squares = octet_delta_count * ip_total_length;
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
                   struct dp_packet *msg)
{
    size_t set_hdr_offset;
    struct ipfix_set_header *set_hdr;

    set_hdr_offset = dp_packet_size(msg);

    /* Put a Data Set. */
    set_hdr = dp_packet_put_zeros(msg, sizeof *set_hdr);
    set_hdr->set_id = htons(entry->flow_key.template_id);

    /* Copy the flow key part of the data record. */

    dp_packet_put(msg, entry->flow_key.flow_key_msg_part,
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

        data_aggregated_common = dp_packet_put_zeros(
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

        data_aggregated_ip = dp_packet_put_zeros(
            msg, sizeof *data_aggregated_ip);
        data_aggregated_ip->octet_delta_count = htonll(
            entry->octet_delta_count);
        data_aggregated_ip->octet_delta_sum_of_squares = htonll(
            entry->octet_delta_sum_of_squares);
        data_aggregated_ip->minimum_ip_total_length = htonll(
            entry->minimum_ip_total_length);
        data_aggregated_ip->maximum_ip_total_length = htonll(
            entry->maximum_ip_total_length);
    }

    set_hdr = (struct ipfix_set_header*)((uint8_t*)dp_packet_data(msg) + set_hdr_offset);
    set_hdr->length = htons(dp_packet_size(msg) - set_hdr_offset);
}

/* Send an IPFIX message with a single data record. */
static void
ipfix_send_data_msg(struct dpif_ipfix_exporter *exporter,
                    uint32_t export_time_sec,
                    struct ipfix_flow_cache_entry *entry,
                    enum ipfix_flow_end_reason flow_end_reason)
{
    uint64_t msg_stub[DIV_ROUND_UP(MAX_MESSAGE_LEN, 8)];
    struct dp_packet msg;
    dp_packet_use_stub(&msg, msg_stub, sizeof msg_stub);

    ipfix_init_header(export_time_sec, exporter->seq_number++,
                      entry->flow_key.obs_domain_id, &msg);
    ipfix_put_data_set(export_time_sec, entry, flow_end_reason, &msg);
    ipfix_send_msg(exporter->collectors, &msg);

    dp_packet_uninit(&msg);
}

static void
dpif_ipfix_sample(struct dpif_ipfix_exporter *exporter,
                  const struct dp_packet *packet, const struct flow *flow,
                  uint64_t packet_delta_count, uint32_t obs_domain_id,
                  uint32_t obs_point_id, odp_port_t output_odp_port,
                  const struct dpif_ipfix_port *tunnel_port,
                  const struct flow_tnl *tunnel_key)
{
    struct ipfix_flow_cache_entry *entry;

    /* Create a flow cache entry from the sample. */
    entry = xmalloc(sizeof *entry);
    ipfix_cache_entry_init(entry, packet, flow, packet_delta_count,
                           obs_domain_id, obs_point_id,
                           output_odp_port, tunnel_port, tunnel_key);
    ipfix_cache_update(exporter, entry);
}

static bool
bridge_exporter_enabled(struct dpif_ipfix *di)
{
    return di->bridge_exporter.probability > 0;
}

void
dpif_ipfix_bridge_sample(struct dpif_ipfix *di, const struct dp_packet *packet,
                         const struct flow *flow,
                         odp_port_t input_odp_port, odp_port_t output_odp_port,
                         const struct flow_tnl *output_tunnel_key)
    OVS_EXCLUDED(mutex)
{
    uint64_t packet_delta_count;
    const struct flow_tnl *tunnel_key = NULL;
    struct dpif_ipfix_port * tunnel_port = NULL;

    ovs_mutex_lock(&mutex);
    if (!bridge_exporter_enabled(di)) {
        ovs_mutex_unlock(&mutex);
        return;
    }

    /* Skip BFD packets:
     * Bidirectional Forwarding Detection(BFD) packets are for monitoring
     * the tunnel link status and consumed by ovs itself. No need to
     * smaple them.
     * CF  IETF RFC 5881, BFD control packet is the UDP packet with
     * destination port 3784, and BFD echo packet is the UDP packet with
     * destination port 3785.
     */
    if (is_ip_any(flow) &&
        flow->nw_proto == IPPROTO_UDP &&
        (flow->tp_dst == htons(BFD_CONTROL_DEST_PORT) ||
         flow->tp_dst == htons(BFD_ECHO_DEST_PORT))) {
        ovs_mutex_unlock(&mutex);
        return;
    }

    /* Use the sampling probability as an approximation of the number
     * of matched packets. */
    packet_delta_count = UINT32_MAX / di->bridge_exporter.probability;
    if (di->bridge_exporter.options->enable_tunnel_sampling) {
        if (output_odp_port == ODPP_NONE && flow->tunnel.ip_dst) {
            /* Input tunnel. */
            tunnel_key = &flow->tunnel;
            tunnel_port = dpif_ipfix_find_port(di, input_odp_port);
        }
        if (output_odp_port != ODPP_NONE && output_tunnel_key) {
            /* Output tunnel, output_tunnel_key must be valid. */
            tunnel_key = output_tunnel_key;
            tunnel_port = dpif_ipfix_find_port(di, output_odp_port);
        }
    }

    dpif_ipfix_sample(&di->bridge_exporter.exporter, packet, flow,
                      packet_delta_count,
                      di->bridge_exporter.options->obs_domain_id,
                      di->bridge_exporter.options->obs_point_id,
                      output_odp_port, tunnel_port, tunnel_key);
    ovs_mutex_unlock(&mutex);
}

void
dpif_ipfix_flow_sample(struct dpif_ipfix *di, const struct dp_packet *packet,
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
                          packet_delta_count, obs_domain_id, obs_point_id,
                          ODPP_NONE, NULL, NULL);
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

    if (ovs_list_is_empty(&exporter->cache_flow_start_timestamp_list)) {
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

        ovs_list_remove(&entry->cache_flow_start_timestamp_list_node);
        hmap_remove(&exporter->cache_flow_key_map,
                    &entry->flow_key_map_node);

        if (!template_msg_sent
            && (exporter->last_template_set_time + IPFIX_TEMPLATE_INTERVAL)
                <= export_time_sec) {
            ipfix_send_template_msgs(exporter, export_time_sec,
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
    if (bridge_exporter_enabled(di)) {
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
    if (bridge_exporter_enabled(di)) {
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

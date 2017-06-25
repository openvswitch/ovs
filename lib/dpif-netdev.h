/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
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

#ifndef DPIF_NETDEV_H
#define DPIF_NETDEV_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "dpif.h"
#include "openvswitch/types.h"
#include "cmap.h"
#include "conntrack.h"
#include "coverage.h"
#include "ct-dpif.h"
#include "csum.h"
#include "dp-packet.h"
#include "dpif-provider.h"
#include "dummy.h"
#include "fat-rwlock.h"
#include "flow.h"
#include "hmapx.h"
#include "latch.h"
#include "netdev.h"
#include "netdev-vport.h"
#include "netlink.h"
#include "odp-execute.h"
#include "odp-util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"
#include "ovs-numa.h"
#include "ovs-rcu.h"
#include "packets.h"
#include "openvswitch/thread.h"
#include "openvswitch/types.h"
#include "ovs-atomic.h"
#include "hw-pipeline.h"
#ifdef  __cplusplus
extern "C" {
#endif

/* Enough headroom to add a vlan tag, plus an extra 2 bytes to allow IP
 * headers to be aligned on a 4-byte boundary.  */
enum { DP_NETDEV_HEADROOM = 2 + VLAN_HEADER_LEN };

bool dpif_is_netdev(const struct dpif *);

#define NR_QUEUE   1
#define NR_PMD_THREADS 1

struct netdev_flow_key {
    uint32_t hash;       /* Hash function differs for different users. */
    uint32_t len;        /* Length of the following miniflow (incl. map). */
    struct miniflow mf;
    uint64_t buf[FLOW_MAX_PACKET_U64S];
};

/* Contained by struct dp_netdev_flow's 'stats' member.  */
struct dp_netdev_flow_stats {
    atomic_llong used;             /* Last used time, in monotonic msecs. */
    atomic_ullong packet_count;    /* Number of packets matched. */
    atomic_ullong byte_count;      /* Number of bytes matched. */
    atomic_uint16_t tcp_flags;     /* Bitwise-OR of seen tcp_flags values. */
};

/* A rule to be inserted to the classifier. */
struct dpcls_rule {
    struct cmap_node cmap_node;   /* Within struct dpcls_subtable 'rules'. */
    struct netdev_flow_key *mask; /* Subtable's mask. */
    struct netdev_flow_key flow;  /* Matching key. */
    uint32_t flow_tag;
    ovs_u128 *ufidp;
    /* 'flow' must be the last field, additional space is allocated here. */
};

struct dp_netdev_actions {
    /* These members are immutable: they do not change during the struct's
     * lifetime.  */
    unsigned int size;          /* Size of 'actions', in bytes. */
    struct nlattr actions[];    /* Sequence of OVS_ACTION_ATTR_* attributes. */
};

struct dp_netdev_flow {
    const struct flow flow;      /* Unmasked flow that created this entry. */
    /* Hash table index by unmasked flow. */
    const struct cmap_node node; /* In owning dp_netdev_pmd_thread's */
                                 /* 'flow_table'. */
    const ovs_u128 ufid;         /* Unique flow identifier. */
    const unsigned pmd_id;       /* The 'core_id' of pmd thread owning this */
                                 /* flow. */

    /* Number of references.
     * The classifier owns one reference.
     * Any thread trying to keep a rule from being freed should hold its own
     * reference. */
    struct ovs_refcount ref_cnt;

    bool dead;

    /* Statistics. */
    struct dp_netdev_flow_stats stats;

    /* Actions. */
    OVSRCU_TYPE(struct dp_netdev_actions *) actions;

    /* While processing a group of input packets, the datapath uses the next
     * member to store a pointer to the output batch for the flow.  It is
     * reset after the batch has been sent out (See dp_netdev_queue_batches(),
     * packet_batch_per_flow_init() and packet_batch_per_flow_execute()). */
    struct packet_batch_per_flow *batch;

    /* Packet classification. */
    struct dpcls_rule cr;        /* In owning dp_netdev's 'cls'. */
    /* 'cr' must be the last member. */

};

struct dp_netdev_actions *dp_netdev_flow_get_actions(
    const struct dp_netdev_flow *);

struct save_hw_flows{
    struct ovs_list node;
    struct rte_flow *hw_flow;
}save_hw_flows;

typedef struct flow_elem {
    struct dp_netdev_flow *sw_flow;
    struct rte_flow       *hw_flow_h;
    bool                  is_tunnel;
    bool                  valid;
    uint32_t              next;
    rte_spinlock_t        lock;
} flow_elem;

typedef struct msg_hw_flow{
    odp_port_t             in_port;
    uint32_t               flow_tag;
    ovs_u128               ufid;
}msg_hw_flow;

typedef struct msg_sw_flow{
    struct dp_netdev_flow  sw_flow;
    struct flow            sw_flow_mask;
    odp_port_t             in_port;
    int                    rxqid;
}msg_sw_flow;

typedef struct msg_queue_elem {
    union{
        msg_hw_flow    rm_flow;
        msg_sw_flow    sw_flow;
    }data;
    int    mode;
} msg_queue_elem;

typedef struct flow_tag_pool {
     uint32_t head;
     uint32_t tail;
     uint32_t pool_size;
     rte_spinlock_t lock;
     flow_elem *ft_data; // flow_elem;
}flow_tag_pool;

typedef struct msg_queue {
     int writeFd;
     int readFd;
     struct timeval tv;
     char pipeName[20];
}msg_queue;


struct dp_meter_band {
    struct ofputil_meter_band up; /* type, prec_level, pad, rate, burst_size */
    uint32_t bucket; /* In 1/1000 packets (for PKTPS), or in bits (for KBPS) */
    uint64_t packet_count;
    uint64_t byte_count;
};

struct dp_meter {
    uint16_t flags;
    uint16_t n_bands;
    uint32_t max_delta_t;
    uint64_t used;
    uint64_t packet_count;
    uint64_t byte_count;
    struct dp_meter_band bands[];
};

/* Datapath based on the network device interface from netdev.h.
 *
 *
 * Thread-safety
 * =============
 *
 * Some members, marked 'const', are immutable.  Accessing other members
 * requires synchronization, as noted in more detail below.
 *
 * Acquisition order is, from outermost to innermost:
 *
 *    dp_netdev_mutex (global)
 *    port_mutex
 *    non_pmd_mutex
 */
enum { MAX_METERS = 65536 };    /* Maximum number of meters. */
enum { N_METER_LOCKS = 64 };    /* Maximum number of meters. */

struct dp_netdev {
    const struct dpif_class *const class;
    const char *const name;
    struct dpif *dpif;
    struct ovs_refcount ref_cnt;
    atomic_flag destroyed;

    /* Ports.
     *
     * Any lookup into 'ports' or any access to the dp_netdev_ports found
     * through 'ports' requires taking 'port_mutex'. */
    struct ovs_mutex port_mutex;
    struct hmap ports;
    struct seq *port_seq;       /* Incremented whenever a port changes. */

    /* Meters. */
    struct ovs_mutex meter_locks[N_METER_LOCKS];
    struct dp_meter *meters[MAX_METERS]; /* Meter bands. */
    uint32_t meter_free;                 /* Next free meter. */

    /* Protects access to ofproto-dpif-upcall interface during revalidator
     * thread synchronization. */
    struct fat_rwlock upcall_rwlock;
    upcall_callback *upcall_cb;  /* Callback function for executing upcalls. */
    void *upcall_aux;

    /* Callback function for notifying the purging of dp flows (during
     * reseting pmd deletion). */
    dp_purge_callback *dp_purge_cb;
    void *dp_purge_aux;

    /* Stores all 'struct dp_netdev_pmd_thread's. */
    struct cmap poll_threads;

    /* Protects the access of the 'struct dp_netdev_pmd_thread'
     * instance for non-pmd thread. */
    struct ovs_mutex non_pmd_mutex;

    /* Each pmd thread will store its pointer to
     * 'struct dp_netdev_pmd_thread' in 'per_pmd_key'. */
    ovsthread_key_t per_pmd_key;

    struct seq *reconfigure_seq;
    uint64_t last_reconfigure_seq;

    /* Cpu mask for pin of pmd threads. */
    char *pmd_cmask;

    uint64_t last_tnl_conf_seq;

    struct conntrack conntrack;

    /* Probability of EMC insertions is a factor of 'emc_insert_min'.*/
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE) atomic_uint32_t emc_insert_min;
    flow_tag_pool ft_pool;
    msg_queue 	  message_queue;
    struct pipeline_md ppl_md;
    pthread_t thread_ofload;
};

/* A port in a netdev-based datapath. */
struct dp_netdev_port {
    odp_port_t port_no;
    struct netdev *netdev;
    struct hmap_node node;      /* Node in dp_netdev's 'ports'. */
    struct netdev_saved_flags *sf;
    struct dp_netdev_rxq *rxqs;
    unsigned n_rxq;      /* Number of elements in 'rxq' */
    bool dynamic_txqs;   /* If true XPS will be used. */
    unsigned *txq_used;  /* Number of threads that uses each tx queue. */
    struct ovs_mutex txq_used_mutex;
    char *type;                 /* Port type as requested by user. */
    char *rxq_affinity_list;    /* Requested affinity of rx queues. */
    bool need_reconfigure;      /* True if we should reconfigure netdev. */
};

/* Functions of dpif-netdev.c used by hw_pipeline*/

int get_port_by_number(struct dp_netdev *dp,odp_port_t port_no,
        struct dp_netdev_port **portp);
int dpif_netdev_is_vport(struct dp_netdev *dp,odp_port_t port_no);
int dpif_netdev_vport_is_tunnel(struct dp_netdev *dp,odp_port_t port);
void dpif_netdev_find_action_active( struct dp_netdev_flow *flow,
        bool *found_tun_pop, bool *no_drop_action);

/* Functions of hw_pipeline used by dpif-netdev.c*/
flow_elem *hw_pipeline_ft_pool_read_elem(struct dp_netdev *dp,uint32_t handle);

int hw_pipeline_flow_stats_get(struct dp_netdev *dp,
        struct dp_netdev_flow *netdev_flow,
        void *stats);
void *hw_pipeline_thread(void *dp);
bool hw_pipeline_ft_pool_tunnel_mode_get(flow_tag_pool *p,uint32_t flow_tag,
        bool *is_tun);
int hw_pipeline_init(struct dp_netdev *dp);
int hw_pipeline_uninit(struct dp_netdev *dp);

void hw_pipeline_get_packet_md(struct netdev *netdev, struct dp_packet *packet,
        struct pipeline_md *ppl_md);

uint32_t hw_pipeline_ft_pool_search(flow_tag_pool *p,const ovs_u128 *ufid);

void hw_pipeline_dpcls_insert(struct dp_netdev *dp,
                              struct dp_netdev_flow *netdev_flow,
                              struct dpcls_rule *rule,
                              odp_port_t in_port,
                              struct flow *wc_masks,
                              int rxqid);

void hw_pipeline_dpcls_remove(struct dp_netdev *dp,
                              struct dpcls_rule *rule);

bool hw_pipeline_dpcls_lookup(struct dp_netdev *dp,
                              struct pipeline_md *md_tags,
                              const size_t cnt,
                              int *lookup_cnt);

struct dp_netdev_flow *hw_pipeline_lookup_flow(struct dp_netdev *dp,
                              uint32_t flow_tag,
                              int *lookup_cnt);

struct set_rte_item {
    void (*set)(struct flow *, struct rte_flow_item *, size_t *,int);
};

#define GRE_PROTOCOL    47

#ifdef  __cplusplus
}
#endif

#endif /* netdev.h */

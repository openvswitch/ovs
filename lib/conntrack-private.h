/*
 * Copyright (c) 2015, 2016, 2017 Nicira, Inc.
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

#ifndef CONNTRACK_PRIVATE_H
#define CONNTRACK_PRIVATE_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include "conntrack.h"
#include "ct-dpif.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/types.h"
#include "packets.h"
#include "unaligned.h"
#include "dp-packet.h"

struct ct_endpoint {
    union ct_addr addr;
    union {
        ovs_be16 port;
        struct {
            ovs_be16 icmp_id;
            uint8_t icmp_type;
            uint8_t icmp_code;
        };
    };
};

/* Verify that there is no padding in struct ct_endpoint, to facilitate
 * hashing in ct_endpoint_hash_add(). */
BUILD_ASSERT_DECL(sizeof(struct ct_endpoint) == sizeof(union ct_addr) + 4);

/* Changes to this structure need to be reflected in conn_key_hash()
 * and conn_key_cmp(). */
struct conn_key {
    struct ct_endpoint src;
    struct ct_endpoint dst;

    ovs_be16 dl_type;
    uint16_t zone;
    uint8_t nw_proto;
};

struct nat_conn_key_node {
    struct hmap_node node;
    struct conn_key key;
    struct conn_key value;
};

/* This is used for alg expectations; an expectation is a
 * context created in preparation for establishing a data
 * connection. The expectation is created by the control
 * connection. */
struct alg_exp_node {
    /* Node in alg_expectations. */
    struct hmap_node node;
    /* Node in alg_expectation_refs. */
    struct hindex_node node_ref;
    /* Key of data connection to be created. */
    struct conn_key key;
    /* Corresponding key of the control connection. */
    struct conn_key master_key;
    /* The NAT replacement address to be used by the data connection. */
    union ct_addr alg_nat_repl_addr;
    /* The data connection inherits the master control
     * connection label and mark. */
    ovs_u128 master_label;
    uint32_t master_mark;
    /* True if for NAT application, the alg replaces the dest address;
     * otherwise, the source address is replaced.  */
    bool nat_rpl_dst;
};

struct conn {
    struct conn_key key;
    struct conn_key rev_key;
    /* Only used for orig_tuple support. */
    struct conn_key master_key;
    long long expiration;
    struct ovs_list exp_node;
    struct hmap_node node;
    ovs_u128 label;
    /* XXX: consider flattening. */
    struct nat_action_info_t *nat_info;
    char *alg;
    int seq_skew;
    uint32_t mark;
    uint8_t conn_type;
    /* TCP sequence skew due to NATTing of FTP control messages. */
    uint8_t seq_skew_dir;
    /* True if alg data connection. */
    uint8_t alg_related;
};

enum ct_update_res {
    CT_UPDATE_INVALID,
    CT_UPDATE_VALID,
    CT_UPDATE_NEW,
};

enum ct_conn_type {
    CT_CONN_TYPE_DEFAULT,
    CT_CONN_TYPE_UN_NAT,
};

/* 'struct ct_lock' is a wrapper for an adaptive mutex.  It's useful to try
 * different types of locks (e.g. spinlocks) */

struct OVS_LOCKABLE ct_lock {
    struct ovs_mutex lock;
};

static inline void ct_lock_init(struct ct_lock *lock)
{
    ovs_mutex_init_adaptive(&lock->lock);
}

static inline void ct_lock_lock(struct ct_lock *lock)
    OVS_ACQUIRES(lock)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    ovs_mutex_lock(&lock->lock);
}

static inline void ct_lock_unlock(struct ct_lock *lock)
    OVS_RELEASES(lock)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    ovs_mutex_unlock(&lock->lock);
}

static inline void ct_lock_destroy(struct ct_lock *lock)
{
    ovs_mutex_destroy(&lock->lock);
}

struct OVS_LOCKABLE ct_rwlock {
    struct ovs_rwlock lock;
};

static inline void ct_rwlock_init(struct ct_rwlock *lock)
{
    ovs_rwlock_init(&lock->lock);
}


static inline void ct_rwlock_wrlock(struct ct_rwlock *lock)
    OVS_ACQ_WRLOCK(lock)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    ovs_rwlock_wrlock(&lock->lock);
}

static inline void ct_rwlock_rdlock(struct ct_rwlock *lock)
    OVS_ACQ_RDLOCK(lock)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    ovs_rwlock_rdlock(&lock->lock);
}

static inline void ct_rwlock_unlock(struct ct_rwlock *lock)
    OVS_RELEASES(lock)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    ovs_rwlock_unlock(&lock->lock);
}

static inline void ct_rwlock_destroy(struct ct_rwlock *lock)
{
    ovs_rwlock_destroy(&lock->lock);
}

/* Timeouts: all the possible timeout states passed to update_expiration()
 * are listed here. The name will be prefix by CT_TM_ and the value is in
 * milliseconds */
#define CT_TIMEOUTS \
    CT_TIMEOUT(TCP_FIRST_PACKET, 30 * 1000) \
    CT_TIMEOUT(TCP_OPENING, 30 * 1000) \
    CT_TIMEOUT(TCP_ESTABLISHED, 24 * 60 * 60 * 1000) \
    CT_TIMEOUT(TCP_CLOSING, 15 * 60 * 1000) \
    CT_TIMEOUT(TCP_FIN_WAIT, 45 * 1000) \
    CT_TIMEOUT(TCP_CLOSED, 30 * 1000) \
    CT_TIMEOUT(OTHER_FIRST, 60 * 1000) \
    CT_TIMEOUT(OTHER_MULTIPLE, 60 * 1000) \
    CT_TIMEOUT(OTHER_BIDIR, 30 * 1000) \
    CT_TIMEOUT(ICMP_FIRST, 60 * 1000) \
    CT_TIMEOUT(ICMP_REPLY, 30 * 1000)

/* The smallest of the above values: it is used as an upper bound for the
 * interval between two rounds of cleanup of expired entries */
#define CT_TM_MIN (30 * 1000)

#define CT_TIMEOUT(NAME, VAL) BUILD_ASSERT_DECL(VAL >= CT_TM_MIN);
    CT_TIMEOUTS
#undef CT_TIMEOUT

enum ct_timeout {
#define CT_TIMEOUT(NAME, VALUE) CT_TM_##NAME,
    CT_TIMEOUTS
#undef CT_TIMEOUT
    N_CT_TM
};


/* Locking:
 *
 * The connections are kept in different buckets, which are completely
 * independent. The connection bucket is determined by the hash of its key.
 *
 * Each bucket has two locks. Acquisition order is, from outermost to
 * innermost:
 *
 *    cleanup_mutex
 *    lock
 *
 * */
struct conntrack_bucket {
    /* Protects 'connections' and 'exp_lists'.  Used in the fast path */
    struct ct_lock lock;
    /* Contains the connections in the bucket, indexed by 'struct conn_key' */
    struct hmap connections OVS_GUARDED;
    /* For each possible timeout we have a list of connections. When the
     * timeout of a connection is updated, we move it to the back of the list.
     * Since the connection in a list have the same relative timeout, the list
     * will be ordered, with the oldest connections to the front. */
    struct ovs_list exp_lists[N_CT_TM] OVS_GUARDED;

    /* Protects 'next_cleanup'. Used to make sure that there's only one thread
     * performing the cleanup. */
    struct ovs_mutex cleanup_mutex;
    long long next_cleanup OVS_GUARDED;
};

#define CONNTRACK_BUCKETS_SHIFT 8
#define CONNTRACK_BUCKETS (1 << CONNTRACK_BUCKETS_SHIFT)

struct conntrack {
    /* Independent buckets containing the connections */
    struct conntrack_bucket buckets[CONNTRACK_BUCKETS];

    /* Salt for hashing a connection key. */
    uint32_t hash_basis;
    /* The thread performing periodic cleanup of the connection
     * tracker. */
    pthread_t clean_thread;
    /* Latch to destroy the 'clean_thread' */
    struct latch clean_thread_exit;

    /* Number of connections currently in the connection tracker. */
    atomic_count n_conn;
    /* Connections limit. When this limit is reached, no new connection
     * will be accepted. */
    atomic_uint n_conn_limit;

    /* The following resources are referenced during nat connection
     * creation and deletion. */
    struct hmap nat_conn_keys OVS_GUARDED;
    /* Hash table for alg expectations. Expectations are created
     * by control connections to help create data connections. */
    struct hmap alg_expectations OVS_GUARDED;
    /* Used to lookup alg expectations from the control context. */
    struct hindex alg_expectation_refs OVS_GUARDED;
    /* Expiry list for alg expectations. */
    struct ovs_list alg_exp_list OVS_GUARDED;
    /* This lock is used during NAT connection creation and deletion;
     * it is taken after a bucket lock and given back before that
     * bucket unlock.
     * This lock is similarly used to guard alg_expectations and
     * alg_expectation_refs. If a bucket lock is also held during
     * the normal code flow, then is must be taken first and released
     * last.
     */
    struct ct_rwlock resources_lock;

    /* Fragmentation handling context. */
    struct ipf *ipf;

};

struct ct_l4_proto {
    struct conn *(*new_conn)(struct conntrack_bucket *, struct dp_packet *pkt,
                             long long now);
    bool (*valid_new)(struct dp_packet *pkt);
    enum ct_update_res (*conn_update)(struct conn *conn,
                                      struct conntrack_bucket *,
                                      struct dp_packet *pkt, bool reply,
                                      long long now);
    void (*conn_get_protoinfo)(const struct conn *,
                               struct ct_dpif_protoinfo *);
};

extern struct ct_l4_proto ct_proto_tcp;
extern struct ct_l4_proto ct_proto_other;
extern struct ct_l4_proto ct_proto_icmp4;
extern struct ct_l4_proto ct_proto_icmp6;

extern long long ct_timeout_val[];

static inline void
conn_init_expiration(struct conntrack_bucket *ctb, struct conn *conn,
                        enum ct_timeout tm, long long now)
{
    conn->expiration = now + ct_timeout_val[tm];
    ovs_list_push_back(&ctb->exp_lists[tm], &conn->exp_node);
}

static inline void
conn_update_expiration(struct conntrack_bucket *ctb, struct conn *conn,
                       enum ct_timeout tm, long long now)
{
    ovs_list_remove(&conn->exp_node);
    conn_init_expiration(ctb, conn, tm, now);
}

static inline uint32_t
tcp_payload_length(struct dp_packet *pkt)
{
    const char *tcp_payload = dp_packet_get_tcp_payload(pkt);
    if (tcp_payload) {
        return ((char *) dp_packet_tail(pkt) - dp_packet_l2_pad_size(pkt)
                - tcp_payload);
    } else {
        return 0;
    }
}

#endif /* conntrack-private.h */

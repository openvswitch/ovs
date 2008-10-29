/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

#include <config.h>
#include "mac-learning.h"

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>

#include "hash.h"
#include "list.h"
#include "openflow/openflow.h"
#include "timeval.h"
#include "util.h"

#define THIS_MODULE VLM_mac_learning
#include "vlog.h"

#define MAC_HASH_BITS 10
#define MAC_HASH_MASK (MAC_HASH_SIZE - 1)
#define MAC_HASH_SIZE (1u << MAC_HASH_BITS)

#define MAC_MAX 1024

/* A MAC learning table entry. */
struct mac_entry {
    struct list hash_node;      /* Element in a mac_learning 'table' list. */
    struct list lru_node;       /* Element in mac_learning 'lrus' list. */
    time_t used;                /* Last used time. */
    uint8_t mac[ETH_ADDR_LEN];  /* Known MAC address. */
    int port;                   /* Port on which MAC was most recently seen. */
};

/* MAC learning table. */
struct mac_learning {
    struct list lrus;           /* All entries, least recently used at the
                                   front, most recently used at the back. */
    struct list table[MAC_HASH_SIZE]; /* Hash table. */
    struct mac_entry entries[MAC_MAX]; /* All entries. */
};

static struct list *
mac_table_bucket(const struct mac_learning *ml,
                 const uint8_t mac[ETH_ADDR_LEN])
{
    uint32_t hash = hash_fnv(mac, ETH_ADDR_LEN, HASH_FNV_BASIS);
    const struct list *list = &ml->table[hash & MAC_HASH_BITS];
    return (struct list *) list;
}

static struct mac_entry *
search_bucket(struct list *bucket, const uint8_t mac[ETH_ADDR_LEN]) 
{
    struct mac_entry *e;
    LIST_FOR_EACH (e, struct mac_entry, hash_node, bucket) {
        if (eth_addr_equals(e->mac, mac)) {
            return e;
        }
    }
    return NULL;
}

/* Creates and returns a new MAC learning table. */
struct mac_learning *
mac_learning_create(void)
{
    struct mac_learning *ml;
    int i;

    ml = xmalloc(sizeof *ml);
    list_init(&ml->lrus);
    for (i = 0; i < MAC_HASH_SIZE; i++) {
        list_init(&ml->table[i]);
    }
    for (i = 0; i < MAC_MAX; i++) {
        struct mac_entry *s = &ml->entries[i];
        list_push_front(&ml->lrus, &s->lru_node);
        s->hash_node.next = NULL;
    }
    return ml;
}

/* Destroys MAC learning table 'ml'. */
void
mac_learning_destroy(struct mac_learning *ml)
{
    free(ml);
}

/* Attempts to make 'ml' learn from the fact that a frame from 'src_mac' was
 * just observed arriving on 'src_port'.  Returns true if we actually learned
 * something from this, false if it just confirms what we already knew. */
bool
mac_learning_learn(struct mac_learning *ml,
                   const uint8_t src_mac[ETH_ADDR_LEN], uint16_t src_port)
{
    struct mac_entry *e;
    struct list *bucket;

    if (eth_addr_is_multicast(src_mac)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 30);
        VLOG_DBG_RL(&rl, "multicast packet source "ETH_ADDR_FMT,
                    ETH_ADDR_ARGS(src_mac));
        return false;
    }

    bucket = mac_table_bucket(ml, src_mac);
    e = search_bucket(bucket, src_mac);
    if (!e) {
        e = CONTAINER_OF(ml->lrus.next, struct mac_entry, lru_node);
        memcpy(e->mac, src_mac, ETH_ADDR_LEN);
        if (e->hash_node.next) {
            list_remove(&e->hash_node);
        }
        list_push_front(bucket, &e->hash_node);
        e->port = -1;
    }

    /* Make the entry most-recently-used. */
    list_remove(&e->lru_node);
    list_push_back(&ml->lrus, &e->lru_node);
    e->used = time_now();

    /* Did we learn something? */
    if (e->port != src_port) {
        e->port = src_port;
        return true;
    }
    return false;
}

/* Looks up address 'dst' in 'ml'.  Returns the port on which a frame destined
 * for 'dst' should be sent, OFPP_FLOOD if unknown. */
uint16_t
mac_learning_lookup(const struct mac_learning *ml,
                    const uint8_t dst[ETH_ADDR_LEN])
{
    if (!eth_addr_is_multicast(dst)) {
        struct mac_entry *e = search_bucket(mac_table_bucket(ml, dst), dst);
        if (e && time_now() - e->used < 60) {
            return e->port;
        }
    }
    return OFPP_FLOOD;
}

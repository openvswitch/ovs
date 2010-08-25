/*
 * Copyright (c) 2010 Nicira Networks.
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

#ifndef WDP_H
#define WDP_H 1

#include "classifier.h"
#include "list.h"
#include "tag.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct ofhooks;
struct ofpbuf;
struct svec;
struct wdp;
struct wdp_class;
union ofp_action;

struct wdp_table_stats {
    /* Flows. */
    unsigned int n_flows;       /* Number of flows in table. */
    unsigned int cur_capacity;  /* Current flow table capacity. */
    unsigned int max_capacity;  /* Maximum expansion of flow table capacity. */

    /* Lookups. */
    unsigned long long int n_hit;    /* Number of flow table matches. */
    unsigned long long int n_missed; /* Number of flow table misses. */
    unsigned long long int n_lost;   /* Misses dropped due to buffer limits. */
};

struct wdp_stats {
    unsigned int max_ports;     /* Maximum supported number of ports. */
};

struct wdp_rule {
    struct cls_rule cr;

    long long int created;      /* Time created, in ms since the epoch. */
    uint16_t idle_timeout;      /* In seconds from time of last use. */
    uint16_t hard_timeout;      /* In seconds from time of creation. */
    uint8_t ofp_table_id;       /* OpenFlow table_id in e.g. ofp_flow_stats.
                                 * Supported range is at most 0...31. */

    /* OpenFlow actions.
     *
     * 'n_actions' is the number of elements in the 'actions' array.  A single
     * action may take up more more than one element's worth of space.
     *
     * A subrule has no actions (it uses the super-rule's actions). */
    union ofp_action *actions;  /* OpenFlow actions. */
    int n_actions;              /* Number of elements in 'actions' array. */

    void *client_data;
};

void wdp_rule_init(struct wdp_rule *, const union ofp_action *actions,
                     size_t n_actions);
void wdp_rule_uninit(struct wdp_rule *);

void wdp_run(void);
void wdp_wait(void);

int wdp_register_provider(const struct wdp_class *);
int wdp_unregister_provider(const char *type);
void wdp_enumerate_types(struct svec *types);

int wdp_enumerate_names(const char *type, struct svec *names);
void wdp_parse_name(const char *datapath_name, char **name, char **type);

int wdp_open(const char *name, const char *type, struct wdp **);
int wdp_create(const char *name, const char *type, struct wdp **);
int wdp_create_and_open(const char *name, const char *type, struct wdp **);
void wdp_close(struct wdp *);

const char *wdp_name(const struct wdp *);
const char *wdp_base_name(const struct wdp *);
int wdp_get_all_names(const struct wdp *, struct svec *);

int wdp_delete(struct wdp *);

int wdp_get_features(const struct wdp *, struct ofpbuf **featuresp);
int wdp_get_wdp_stats(const struct wdp *, struct wdp_stats *);
int wdp_get_table_stats(const struct wdp *, struct ofpbuf *stats);

int wdp_get_drop_frags(const struct wdp *, bool *drop_frags);
int wdp_set_drop_frags(struct wdp *, bool drop_frags);

struct wdp_port {
    struct netdev *netdev;
    struct ofp_phy_port opp;    /* In *host* byte order. */
    char *devname;              /* Network device name. */
    bool internal;
};
void wdp_port_clear(struct wdp_port *);
void wdp_port_copy(struct wdp_port *, const struct wdp_port *);
void wdp_port_free(struct wdp_port *);
void wdp_port_array_free(struct wdp_port *, size_t n);

int wdp_port_add(struct wdp *, const char *devname, bool internal,
                   uint16_t *port_no);
int wdp_port_del(struct wdp *, uint16_t port_no);
int wdp_port_query_by_number(const struct wdp *, uint16_t port_no,
                             struct wdp_port *);
int wdp_port_query_by_name(const struct wdp *, const char *devname,
                           struct wdp_port *);
int wdp_port_get_name(struct wdp *, uint16_t port_no, char **namep);
int wdp_port_list(const struct wdp *, struct wdp_port **, size_t *n_ports);

int wdp_port_set_config(struct wdp *, uint16_t port_no, uint32_t config);

typedef void wdp_port_poll_cb_func(const struct ofp_phy_port *opp,
                                   uint8_t reason, void *aux);
int wdp_port_poll(struct wdp *, wdp_port_poll_cb_func *cb, void *aux);
int wdp_port_poll_wait(const struct wdp *);

int wdp_flow_flush(struct wdp *);

struct wdp_flow_stats {
    unsigned long long int n_packets; /* Number of matched packets. */
    unsigned long long int n_bytes;   /* Number of matched bytes. */
    long long int inserted;           /* Time inserted into flow table. */
    long long int used;               /* Time last used. */
    uint8_t tcp_flags;                /* Bitwise-OR of TCP flags seen. */
    uint8_t ip_tos;                   /* IP TOS for most recent packet. */
};

/* Finding and inspecting flows. */
struct wdp_rule *wdp_flow_get(struct wdp *, const flow_t *,
                              unsigned int include);
struct wdp_rule *wdp_flow_match(struct wdp *, const flow_t *);

typedef int wdp_flow_cb_func(struct wdp_rule *, void *aux);
int wdp_flow_for_each_match(const struct wdp *, const flow_t *,
                            unsigned int include, wdp_flow_cb_func *,
                            void *aux);

int wdp_flow_get_stats(const struct wdp *, const struct wdp_rule *,
                         struct wdp_flow_stats *);
bool wdp_flow_overlaps(const struct wdp *, const flow_t *);

/* Modifying flows. */
enum wdp_flow_put_flags {
    /* At least one of these flags should be set. */
    WDP_PUT_CREATE = 1 << 0,    /* Allow creating a new flow. */
    WDP_PUT_MODIFY = 1 << 1,    /* Allow modifying an existing flow. */

    /* Options used only for modifying existing flows. */
    WDP_PUT_COUNTERS = 1 << 2,  /* Clear counters, TCP flags, IP TOS, used. */
    WDP_PUT_ACTIONS = 1 << 3,   /* Update actions. */
    WDP_PUT_INSERTED = 1 << 4,  /* Update 'inserted' to current time. */
    WDP_PUT_TIMEOUTS = 1 << 5,  /* Update 'idle_timeout' and 'hard_timeout'. */
    WDP_PUT_ALL = (WDP_PUT_COUNTERS | WDP_PUT_ACTIONS
                   | WDP_PUT_INSERTED | WDP_PUT_TIMEOUTS)
};

struct wdp_flow_put {
    enum wdp_flow_put_flags flags;

    const flow_t *flow;

    const union ofp_action *actions;
    size_t n_actions;

    unsigned short int idle_timeout;
    unsigned short int hard_timeout;

    /* OpenFlow 'table_id' to which a new flow is to be added.  Value 0xff
     * means that the WDP implementation should select a table. */
    uint8_t ofp_table_id;

    /* If this is a new flow being created due to an OpenFlow OFPT_FLOW_MOD
     * request, these values are copied from the ofp_header and ofp_flow_mod,
     * respectively, in network byte order.  Otherwise they are zero.
     *
     * These values are provided to enable better logging.  The WDP provider
     * may otherwise ignore them. */
    uint64_t cookie;
    uint32_t xid;
};

int wdp_flow_put(struct wdp *, struct wdp_flow_put *,
                   struct wdp_flow_stats *old_stats,
                   struct wdp_rule **rulep)
    WARN_UNUSED_RESULT;
int wdp_flow_delete(struct wdp *, struct wdp_rule *,
                      struct wdp_flow_stats *final_stats)
    WARN_UNUSED_RESULT;

/* Sending packets in flows. */
int wdp_flow_inject(struct wdp *, struct wdp_rule *,
                      uint16_t in_port, const struct ofpbuf *);
int wdp_execute(struct wdp *, uint16_t in_port,
                  const union ofp_action[], size_t n_actions,
                  const struct ofpbuf *);

/* ovs-vswitchd interface.
 *
 * This needs to be redesigned, because it only makes sense for wdp-xflow.  The
 * ofhooks are currently the key to implementing the OFPP_NORMAL feature of
 * ovs-vswitchd. */

int wdp_set_ofhooks(struct wdp *, const struct ofhooks *, void *aux);
void wdp_revalidate(struct wdp *, tag_type);
void wdp_revalidate_all(struct wdp *);

/* Receiving packets that miss the flow table. */
enum wdp_channel {
    WDP_CHAN_MISS,              /* Packet missed in flow table. */
    WDP_CHAN_ACTION,            /* Packet output to OFPP_CONTROLLER. */
    WDP_CHAN_SFLOW,             /* sFlow samples. */
    WDP_N_CHANS
};

struct wdp_packet {
    struct list list;
    enum wdp_channel channel;
    uint32_t tun_id;
    uint16_t in_port;
    int send_len;
    struct ofpbuf *payload;
};

struct wdp_packet *wdp_packet_clone(const struct wdp_packet *, size_t);
void wdp_packet_destroy(struct wdp_packet *);

int wdp_recv_get_mask(const struct wdp *, int *listen_mask);
int wdp_recv_set_mask(struct wdp *, int listen_mask);
int wdp_get_sflow_probability(const struct wdp *, uint32_t *probability);
int wdp_set_sflow_probability(struct wdp *, uint32_t probability);
int wdp_recv(struct wdp *, struct wdp_packet *);
int wdp_recv_purge(struct wdp *);
void wdp_recv_wait(struct wdp *);

void wdp_get_netflow_ids(const struct wdp *,
                           uint8_t *engine_type, uint8_t *engine_id);

#ifdef  __cplusplus
}
#endif

#endif /* wdp.h */

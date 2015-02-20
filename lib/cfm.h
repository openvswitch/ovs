/* Copyright (c) 2010, 2011, 2015 Nicira, Inc.
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

#ifndef CFM_H
#define CFM_H 1

#include <stdint.h>

#include "hmap.h"
#include "openvswitch/types.h"
#include "packets.h"

struct flow;
struct dp_packet;
struct netdev;
struct flow_wildcards;

#define CFM_RANDOM_VLAN UINT16_MAX

#define CFM_FAULT_REASONS                  \
    CFM_FAULT_REASON(RECV, recv)           \
    CFM_FAULT_REASON(RDI, rdi)             \
    CFM_FAULT_REASON(MAID, maid)           \
    CFM_FAULT_REASON(LOOPBACK, loopback)   \
    CFM_FAULT_REASON(OVERFLOW, overflow)   \
    CFM_FAULT_REASON(OVERRIDE, override)

enum cfm_fault_bit_index {
#define CFM_FAULT_REASON(NAME, STR) CFM_FAULT_INDEX_##NAME,
    CFM_FAULT_REASONS
#undef CFM_FAULT_REASON
    CFM_FAULT_N_REASONS
};

enum cfm_fault_reason {
#define CFM_FAULT_REASON(NAME, STR) \
    CFM_FAULT_##NAME = 1 << CFM_FAULT_INDEX_##NAME,
    CFM_FAULT_REASONS
#undef CFM_FAULT_REASON
};

struct cfm_settings {
    uint64_t mpid;              /* The MPID of this CFM. */
    int interval;               /* The requested transmission interval. */
    bool extended;              /* Run in extended mode. */
    bool demand;                /* Run in demand mode. */
    bool opup;                  /* Operational State. */
    uint16_t ccm_vlan;          /* CCM Vlan tag. Zero if none.
                                   CFM_RANDOM_VLAN if random. */
    uint8_t ccm_pcp;            /* CCM Priority. Zero if none. */

    bool check_tnl_key;         /* Verify inbound packet key? */
};

/* CFM status query. */
struct cfm_status {
    /* 0 if not faulted, otherwise a combination of one or more reasons. */
    enum cfm_fault_reason faults;

    /* 0 if the remote CFM endpoint is operationally down,
     * 1 if the remote CFM endpoint is operationally up,
     * -1 if we don't know because the remote CFM endpoint is not in extended
     * mode. */
    int remote_opstate;

    uint64_t flap_count;

    /* Ordinarily a "health status" in the range 0...100 inclusive, with 0
     * being worst and 100 being best, or -1 if the health status is not
     * well-defined. */
    int health;

    /* MPIDs of remote maintenance points whose CCMs have been received. */
    uint64_t *rmps;
    size_t n_rmps;
};

void cfm_init(void);
struct cfm *cfm_create(const struct netdev *);
struct cfm *cfm_ref(const struct cfm *);
void cfm_unref(struct cfm *);
void cfm_run(struct cfm *);
bool cfm_should_send_ccm(struct cfm *);
void cfm_compose_ccm(struct cfm *, struct dp_packet *,
                     const uint8_t eth_src[ETH_ADDR_LEN]);
long long int cfm_wait(struct cfm *);
bool cfm_configure(struct cfm *, const struct cfm_settings *);
void cfm_set_netdev(struct cfm *, const struct netdev *);
bool cfm_should_process_flow(const struct cfm *cfm, const struct flow *,
                             struct flow_wildcards *);
void cfm_process_heartbeat(struct cfm *, const struct dp_packet *packet);
bool cfm_check_status_change(struct cfm *);
int cfm_get_fault(const struct cfm *);
uint64_t cfm_get_flap_count(const struct cfm *);
int cfm_get_health(const struct cfm *);
int cfm_get_opup(const struct cfm *);
void cfm_get_remote_mpids(const struct cfm *, uint64_t **rmps, size_t *n_rmps);
void cfm_get_status(const struct cfm *, struct cfm_status *);
const char *cfm_fault_reason_to_str(int fault);

long long int cfm_wake_time(struct cfm*);
#endif /* cfm.h */

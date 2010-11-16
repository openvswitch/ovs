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

#ifndef CFM_H
#define CFM_H 1

#include <stdint.h>

#include "hmap.h"
#include "packets.h"

struct flow;

/* A 'cfm' represent a local Maintenance Point (MP) and its Connectivity Fault
 * Management (CFM) state machine.  Its configuration variables should be set
 * by clients of the CFM library. */
struct cfm {
    /* Configuration Variables. */
    uint16_t mpid;              /* The MPID of this CFM. */
    uint8_t maid[CCM_MAID_LEN]; /* The MAID of this CFM. */
    int interval;               /* The requested transmission interval. */
    uint8_t eth_src[ETH_ADDR_LEN];

    /* Statistics. */
    struct hmap remote_mps;     /* Expected remote MPs. */
    struct hmap x_remote_mps;   /* Unexpected remote MPs. */
    struct hmap x_remote_maids; /* Unexpected remote MAIDs. */
    bool fault;                 /* Indicates connectivity vaults. */
};

/* Remote MPs represent foreign network entities that are configured to have
 * the same MAID as this CFM instance. */
struct remote_mp {
    uint16_t mpid;         /* The Maintenance Point ID of this 'remote_mp'. */
    struct hmap_node node; /* In 'cfm' 'remote_mps' or 'x_remote_mps'. */

    long long recv_time; /* Time the most recent CCM was received. */
    bool fault;          /* Indicates a connectivity fault. */
};

/* Remote MAIDs keep track of incoming CCM messages which have a different MAID
 * than this CFM instance. */
struct remote_maid {
    uint8_t maid[CCM_MAID_LEN]; /* The remote MAID. */
    struct hmap_node node;      /* In 'cfm' 'x_remote_maids'. */

    long long recv_time; /* Most recent receive time for this 'remote_maid'. */
};

struct cfm *cfm_create(void);

void cfm_destroy(struct cfm *);

struct ofpbuf *cfm_run(struct cfm *);

void cfm_wait(struct cfm *);

bool cfm_configure(struct cfm *);

void cfm_update_remote_mps(struct cfm *, const uint16_t *mpid, size_t n_mpids);

const struct remote_mp *cfm_get_remote_mp(const struct cfm *, uint16_t mpid);

bool cfm_generate_maid(const char *md_name, const char *ma_name,
                       uint8_t maid[CCM_MAID_LEN]);

bool cfm_should_process_flow(const struct flow *);

void cfm_process_heartbeat(struct cfm *, const struct ofpbuf *packet);

#endif /* cfm.h */

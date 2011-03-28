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
#include "openvswitch/types.h"

struct flow;
struct ofpbuf;
struct ds;

/* Ethernet destination address of CCM packets. */
static const uint8_t eth_addr_ccm[6] OVS_UNUSED
    = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x30 };

#define ETH_TYPE_CFM 0x8902

/* A 'ccm' represents a Continuity Check Message from the 802.1ag
 * specification.  Continuity Check Messages are broadcast periodically so that
 * hosts can determine who they have connectivity to. */
#define CCM_LEN 74
#define CCM_MAID_LEN 48
struct ccm {
    uint8_t  mdlevel_version; /* MD Level and Version */
    uint8_t  opcode;
    uint8_t  flags;
    uint8_t  tlv_offset;
    ovs_be32 seq;
    ovs_be16 mpid;
    uint8_t  maid[CCM_MAID_LEN];
    uint8_t  zero[16]; /* Defined by ITU-T Y.1731 should be zero */
} __attribute__((packed));
BUILD_ASSERT_DECL(CCM_LEN == sizeof(struct ccm));

/* A 'cfm' represent a local Maintenance Point (MP) and its Connectivity Fault
 * Management (CFM) state machine.  Its configuration variables should be set
 * by clients of the CFM library. */
struct cfm {
    /* Configuration Variables. */
    uint16_t mpid;              /* The MPID of this CFM. */
    uint8_t maid[CCM_MAID_LEN]; /* The MAID of this CFM. */
    int interval;               /* The requested transmission interval. */

    /* Statistics. */
    struct hmap remote_mps;     /* Expected remote MPs. */
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

struct cfm *cfm_create(void);

void cfm_destroy(struct cfm *);

void cfm_run(struct cfm *);

bool cfm_should_send_ccm(struct cfm *);

void cfm_compose_ccm(struct cfm *, struct ccm *);

void cfm_wait(struct cfm *);

bool cfm_configure(struct cfm *);

void cfm_update_remote_mps(struct cfm *, const uint16_t *mpid, size_t n_mpids);

const struct remote_mp *cfm_get_remote_mp(const struct cfm *, uint16_t mpid);

bool cfm_generate_maid(const char *md_name, const char *ma_name,
                       uint8_t maid[CCM_MAID_LEN]);

bool cfm_should_process_flow(const struct flow *);

void cfm_process_heartbeat(struct cfm *, const struct ofpbuf *packet);

void cfm_dump_ds(const struct cfm *, struct ds *);

#endif /* cfm.h */

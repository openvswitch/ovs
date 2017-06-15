/*
 * Copyright (c) 2016 VMware, Inc.
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

#include "NetProto.h"
#include "Conntrack.h"
#include <stddef.h>

enum icmp_state {
    ICMPS_FIRST,
    ICMPS_REPLY,
};

struct conn_icmp {
    struct OVS_CT_ENTRY up;
    enum icmp_state state;
};
C_ASSERT(offsetof(struct conn_icmp, up) == 0);

static const enum ct_timeout icmp_timeouts[] = {
    [ICMPS_FIRST] = 60 * CT_INTERVAL_SEC,
    [ICMPS_REPLY] = 30 * CT_INTERVAL_SEC,
};

static __inline struct conn_icmp *
OvsCastConntrackEntryToIcmpEntry(OVS_CT_ENTRY* conn)
{
    return CONTAINER_OF(conn, struct conn_icmp, up);
}

enum CT_UPDATE_RES
OvsConntrackUpdateIcmpEntry(OVS_CT_ENTRY* conn_,
                            BOOLEAN reply,
                            UINT64 now)
{
    struct conn_icmp *conn = OvsCastConntrackEntryToIcmpEntry(conn_);

    if (reply && conn->state != ICMPS_REPLY) {
        conn->state = ICMPS_REPLY;
    }

    OvsConntrackUpdateExpiration(&conn->up, now,
                                 icmp_timeouts[conn->state]);

    return CT_UPDATE_VALID;
}

BOOLEAN
OvsConntrackValidateIcmpPacket(const ICMPHdr *icmp)
{
    if (!icmp) {
        return FALSE;
    }

    return icmp->type == ICMP4_ECHO_REQUEST
           || icmp->type == ICMP4_INFO_REQUEST
           || icmp->type == ICMP4_TIMESTAMP_REQUEST;
}

OVS_CT_ENTRY *
OvsConntrackCreateIcmpEntry(UINT64 now)
{
    struct conn_icmp *conn;

    conn = OvsAllocateMemoryWithTag(sizeof(struct conn_icmp),
                                    OVS_CT_POOL_TAG);
    if (!conn) {
        return NULL;
    }
    conn->up = (OVS_CT_ENTRY) {0};
    conn->state = ICMPS_FIRST;

    OvsConntrackUpdateExpiration(&conn->up, now,
                                 icmp_timeouts[conn->state]);

    return &conn->up;
}

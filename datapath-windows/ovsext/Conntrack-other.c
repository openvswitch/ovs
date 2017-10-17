/*
 * Copyright (c) 2015, 2016 VMware, Inc.
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

#include "Conntrack.h"
#include <stddef.h>

enum other_state {
    OTHERS_FIRST,
    OTHERS_MULTIPLE,
    OTHERS_BIDIR,
};

struct conn_other {
    struct OVS_CT_ENTRY up;
    enum other_state state;
};
C_ASSERT(offsetof(struct conn_other, up) == 0);

static const long long other_timeouts[] = {
    [OTHERS_FIRST] = 60 * CT_INTERVAL_SEC,
    [OTHERS_MULTIPLE] = 60 * CT_INTERVAL_SEC,
    [OTHERS_BIDIR] = 30 * CT_INTERVAL_SEC,
};

static __inline struct conn_other*
OvsCastConntrackEntryToOtherEntry(OVS_CT_ENTRY *conn)
{
    ASSERT(conn);
    return CONTAINER_OF(conn, struct conn_other, up);
}

enum CT_UPDATE_RES
OvsConntrackUpdateOtherEntry(OVS_CT_ENTRY *conn_,
                             BOOLEAN reply,
                             UINT64 now)
{
    ASSERT(conn_);
    struct conn_other *conn = OvsCastConntrackEntryToOtherEntry(conn_);

    if (reply && conn->state != OTHERS_BIDIR) {
        conn->state = OTHERS_BIDIR;
    } else if (conn->state == OTHERS_FIRST) {
        conn->state = OTHERS_MULTIPLE;
    }

    OvsConntrackUpdateExpiration(&conn->up, now,
                                 other_timeouts[conn->state]);

    return CT_UPDATE_VALID;
}

OVS_CT_ENTRY *
OvsConntrackCreateOtherEntry(UINT64 now)
{
    struct conn_other *conn;
    conn = OvsAllocateMemoryWithTag(sizeof(struct conn_other),
                                    OVS_CT_POOL_TAG);
    if (!conn) {
        return NULL;
    }
    conn->up = (OVS_CT_ENTRY) {0};
    conn->state = OTHERS_FIRST;
    OvsConntrackUpdateExpiration(&conn->up, now,
                                 other_timeouts[conn->state]);
    return &conn->up;
}

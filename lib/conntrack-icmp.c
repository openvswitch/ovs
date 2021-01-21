/*
 * Copyright (c) 2015-2019 Nicira, Inc.
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

#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include "conntrack-private.h"
#include "conntrack-tp.h"
#include "dp-packet.h"

enum OVS_PACKED_ENUM icmp_state {
    ICMPS_FIRST,
    ICMPS_REPLY,
};

struct conn_icmp {
    struct conn up;
    enum icmp_state state; /* 'conn' lock protected. */
};

static const enum ct_timeout icmp_timeouts[] = {
    [ICMPS_FIRST] = CT_TM_ICMP_FIRST,
    [ICMPS_REPLY] = CT_TM_ICMP_REPLY,
};

static struct conn_icmp *
conn_icmp_cast(const struct conn *conn)
{
    return CONTAINER_OF(conn, struct conn_icmp, up);
}

static enum ct_update_res
icmp_conn_update(struct conntrack *ct, struct conn *conn_,
                 struct dp_packet *pkt OVS_UNUSED, bool reply, long long now)
{
    struct conn_icmp *conn = conn_icmp_cast(conn_);
    enum ct_update_res ret = CT_UPDATE_VALID;

    if (reply && conn->state == ICMPS_FIRST) {
       conn->state = ICMPS_REPLY;
    } else if (conn->state == ICMPS_FIRST) {
        ret = CT_UPDATE_VALID_NEW;
    }

    conn_update_expiration(ct, &conn->up, icmp_timeouts[conn->state], now);
    return ret;
}

static bool
icmp4_valid_new(struct dp_packet *pkt)
{
    struct icmp_header *icmp = dp_packet_l4(pkt);

    return icmp->icmp_type == ICMP4_ECHO_REQUEST
           || icmp->icmp_type == ICMP4_INFOREQUEST
           || icmp->icmp_type == ICMP4_TIMESTAMP;
}

static bool
icmp6_valid_new(struct dp_packet *pkt)
{
    struct icmp6_header *icmp6 = dp_packet_l4(pkt);

    return icmp6->icmp6_type == ICMP6_ECHO_REQUEST;
}

static struct conn *
icmp_new_conn(struct conntrack *ct, struct dp_packet *pkt OVS_UNUSED,
              long long now, uint32_t tp_id)
{
    struct conn_icmp *conn = xzalloc(sizeof *conn);
    conn->state = ICMPS_FIRST;
    conn->up.tp_id = tp_id;

    conn_init_expiration(ct, &conn->up, icmp_timeouts[conn->state], now);
    return &conn->up;
}

struct ct_l4_proto ct_proto_icmp4 = {
    .new_conn = icmp_new_conn,
    .valid_new = icmp4_valid_new,
    .conn_update = icmp_conn_update,
};

struct ct_l4_proto ct_proto_icmp6 = {
    .new_conn = icmp_new_conn,
    .valid_new = icmp6_valid_new,
    .conn_update = icmp_conn_update,
};

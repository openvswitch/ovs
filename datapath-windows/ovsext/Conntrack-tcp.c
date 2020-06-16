/*-
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002 - 2008 Henning Brauer
 * Copyright (c) 2012 Gleb Smirnoff <glebius@FreeBSD.org>
 * Copyright (c) 2015, 2016 VMware, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Effort sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F30602-01-2-0537.
 *
 *      $OpenBSD: pf.c,v 1.634 2009/02/27 12:37:45 henning Exp $
 */

#include "Conntrack.h"
#include <stddef.h>

struct tcp_peer {
    enum ct_dpif_tcp_state state;
    uint32_t               seqlo;  /* Max sequence number sent     */
    uint32_t               seqhi;  /* Max the other end ACKd + win */
    uint16_t               max_win;/* largest window (pre scaling) */
    uint8_t                wscale; /* window scaling factor        */
};

struct conn_tcp {
    struct OVS_CT_ENTRY up;
    struct tcp_peer peer[2];
};
C_ASSERT(offsetof(struct conn_tcp, up) == 0);

enum {
    TCPOPT_EOL,
    TCPOPT_NOP,
    TCPOPT_WINDOW = 3,
};

/* TCP sequence numbers are 32 bit integers operated
 * on with modular arithmetic.  These macros can be
 * used to compare such integers. */
#define SEQ_LT(a,b)     ((int)((a)-(b)) < 0)
#define SEQ_LEQ(a,b)    ((int)((a)-(b)) <= 0)
#define SEQ_GT(a,b)     ((int)((a)-(b)) > 0)
#define SEQ_GEQ(a,b)    ((int)((a)-(b)) >= 0)

#define SEQ_MIN(a, b)   ((SEQ_LT(a, b)) ? (a) : (b))
#define SEQ_MAX(a, b)   ((SEQ_GT(a, b)) ? (a) : (b))

#define TCP_FIN 0x001
#define TCP_SYN 0x002
#define TCP_RST 0x004
#define TCP_PSH 0x008
#define TCP_ACK 0x010
#define TCP_URG 0x020
#define TCP_ECE 0x040
#define TCP_CWR 0x080
#define TCP_NS  0x100

#define CT_DPIF_TCP_FLAGS \
    CT_DPIF_TCP_FLAG(WINDOW_SCALE) \
    CT_DPIF_TCP_FLAG(SACK_PERM) \
    CT_DPIF_TCP_FLAG(CLOSE_INIT) \
    CT_DPIF_TCP_FLAG(BE_LIBERAL) \
    CT_DPIF_TCP_FLAG(DATA_UNACKNOWLEDGED) \
    CT_DPIF_TCP_FLAG(MAXACK_SET) \

enum ct_dpif_tcp_flags_count_ {
#define CT_DPIF_TCP_FLAG(FLAG) FLAG##_COUNT_,
    CT_DPIF_TCP_FLAGS
#undef CT_DPIF_TCP_FLAG
};

enum ct_dpif_tcp_flags {
#define CT_DPIF_TCP_FLAG(FLAG) CT_DPIF_TCPF_##FLAG = (1 << \
                                                      FLAG##_COUNT_),
    CT_DPIF_TCP_FLAGS
#undef CT_DPIF_TCP_FLAG
};


#define CT_DPIF_TCP_STATES \
    CT_DPIF_TCP_STATE(CLOSED) \
    CT_DPIF_TCP_STATE(LISTEN) \
    CT_DPIF_TCP_STATE(SYN_SENT) \
    CT_DPIF_TCP_STATE(SYN_RECV) \
    CT_DPIF_TCP_STATE(ESTABLISHED) \
    CT_DPIF_TCP_STATE(CLOSE_WAIT) \
    CT_DPIF_TCP_STATE(FIN_WAIT_1) \
    CT_DPIF_TCP_STATE(CLOSING) \
    CT_DPIF_TCP_STATE(LAST_ACK) \
    CT_DPIF_TCP_STATE(FIN_WAIT_2) \
    CT_DPIF_TCP_STATE(TIME_WAIT)

enum ct_dpif_tcp_state {
#define CT_DPIF_TCP_STATE(STATE) CT_DPIF_TCPS_##STATE,
    CT_DPIF_TCP_STATES
#undef CT_DPIF_TCP_STATE
};

#define TCP_MAX_WSCALE 14
#define CT_WSCALE_FLAG 0x80
#define CT_WSCALE_UNKNOWN 0x40
#define CT_WSCALE_MASK 0xf

/* pf does this in in pf_normalize_tcp(), and it is called only if scrub
 * is enabled.  We're not scrubbing, but this check seems reasonable.  */
static __inline BOOLEAN
OvsCtInvalidTcpFlags(uint16_t flags)
{
    if (flags & TCP_SYN) {
        if (flags & TCP_RST || flags & TCP_FIN) {
            return TRUE;
        }
    } else {
        /* Illegal packet */
        if (!(flags & (TCP_ACK|TCP_RST))) {
            return TRUE;
        }
    }

    if (!(flags & TCP_ACK)) {
        /* These flags are only valid if ACK is set */
        if ((flags & TCP_FIN) || (flags & TCP_PSH) || (flags & TCP_URG)) {
            return TRUE;
        }
    }

    return FALSE;
}

static __inline uint8_t
OvsTcpGetWscale(const TCPHdr *tcp)
{
    int len = tcp->doff * 4 - sizeof *tcp;
    const uint8_t *opt = (const uint8_t *)(tcp + 1);
    uint8_t wscale = 0;
    uint8_t optlen;

    while (len >= 3) {
        switch (*opt) {
        case TCPOPT_EOL:
            return wscale;
        case TCPOPT_NOP:
            opt++;
            len--;
            break;
        case TCPOPT_WINDOW:
            wscale = MIN(opt[2], TCP_MAX_WSCALE);
            wscale |= CT_WSCALE_FLAG;
            /* fall through */
        default:
            optlen = opt[1];
            if (optlen < 2) {
                optlen = 2;
            }
            len -= optlen;
            opt += optlen;
        }
    }

    return wscale;
}

static __inline struct conn_tcp*
OvsCastConntrackEntryToTcpEntry(OVS_CT_ENTRY* conn)
{
    return CONTAINER_OF(conn, struct conn_tcp, up);
}

enum CT_UPDATE_RES
OvsConntrackUpdateTcpEntry(OVS_CT_ENTRY* conn_,
                           const TCPHdr *tcp,
                           BOOLEAN reply,
                           UINT64 now,
                           UINT32 tcpPayloadLen)
{
    struct conn_tcp *conn = OvsCastConntrackEntryToTcpEntry(conn_);
    /* The peer that sent 'pkt' */
    struct tcp_peer *src = &conn->peer[reply ? 1 : 0];
    /* The peer that should receive 'pkt' */
    struct tcp_peer *dst = &conn->peer[reply ? 0 : 1];
    uint8_t sws = 0, dws = 0;
    UINT16 tcp_flags = ntohs(tcp->flags);
    uint16_t win = ntohs(tcp->window);
    uint32_t ack, end, seq, orig_seq;
    int ackskew;

    if (OvsCtInvalidTcpFlags(tcp_flags)) {
        return CT_UPDATE_INVALID;
    }

    if ((tcp_flags & (TCP_SYN|TCP_ACK)) == TCP_SYN) {
        if (dst->state >= CT_DPIF_TCPS_FIN_WAIT_2
            && src->state >= CT_DPIF_TCPS_FIN_WAIT_2) {
            src->state = dst->state = CT_DPIF_TCPS_CLOSED;
            return CT_UPDATE_NEW;
        } else if (src->state <= CT_DPIF_TCPS_SYN_SENT) {
            src->state = CT_DPIF_TCPS_SYN_SENT;
            OvsConntrackUpdateExpiration(&conn->up, now,
                                         30 * CT_INTERVAL_SEC);
            return CT_UPDATE_VALID_NEW;
        }
    }

    if (src->wscale & CT_WSCALE_FLAG
        && dst->wscale & CT_WSCALE_FLAG
        && !(tcp_flags & TCP_SYN)) {

        sws = src->wscale & CT_WSCALE_MASK;
        dws = dst->wscale & CT_WSCALE_MASK;

    } else if (src->wscale & CT_WSCALE_UNKNOWN
        && dst->wscale & CT_WSCALE_UNKNOWN
        && !(tcp_flags & TCP_SYN)) {

        sws = TCP_MAX_WSCALE;
        dws = TCP_MAX_WSCALE;
    }

    /*
     * Sequence tracking algorithm from Guido van Rooij's paper:
     *   http://www.madison-gurkha.com/publications/tcp_filtering/
     *      tcp_filtering.ps
     */

    orig_seq = seq = ntohl(tcp->seq);
    if (src->state < CT_DPIF_TCPS_SYN_SENT) {
        /* First packet from this end. Set its state */

        ack = ntohl(tcp->ack_seq);

        end = seq + tcpPayloadLen;
        if (tcp_flags & TCP_SYN) {
            end++;
            if (dst->wscale & CT_WSCALE_FLAG) {
                src->wscale = OvsTcpGetWscale(tcp);
                if (src->wscale & CT_WSCALE_FLAG) {
                    /* Remove scale factor from initial window */
                    sws = src->wscale & CT_WSCALE_MASK;
                    win = DIV_ROUND_UP((uint32_t) win, 1 << sws);
                    dws = dst->wscale & CT_WSCALE_MASK;
                } else {
                    /* fixup other window */
                    dst->max_win <<= dst->wscale & CT_WSCALE_MASK;
                    /* in case of a retrans SYN|ACK */
                    dst->wscale = 0;
                }
            }
        }
        if (tcp_flags & TCP_FIN) {
            end++;
        }

        src->seqlo = seq;
        src->state = CT_DPIF_TCPS_SYN_SENT;
        /*
         * May need to slide the window (seqhi may have been set by
         * the crappy stack check or if we picked up the connection
         * after establishment)
         */
        if (src->seqhi == 1 ||
                SEQ_GEQ(end + MAX(1, dst->max_win << dws), src->seqhi)) {
            src->seqhi = end + MAX(1, dst->max_win << dws);
        }
        if (win > src->max_win) {
            src->max_win = win;
        }

    } else {
        ack = ntohl(tcp->ack_seq);
        end = seq + tcpPayloadLen;
        if (tcp_flags & TCP_SYN) {
            end++;
        }
        if (tcp_flags & TCP_FIN) {
            end++;
        }
    }

    if ((tcp_flags & TCP_ACK) == 0) {
        /* Let it pass through the ack skew check */
        ack = dst->seqlo;
    } else if ((ack == 0
                && (tcp_flags & (TCP_ACK|TCP_RST)) == (TCP_ACK|TCP_RST))
               /* broken tcp stacks do not set ack */) {
        /* Many stacks (ours included) will set the ACK number in an
         * FIN|ACK if the SYN times out -- no sequence to ACK. */
        ack = dst->seqlo;
    }

    if (seq == end) {
        /* Ease sequencing restrictions on no data packets */
        seq = src->seqlo;
        end = seq;
    }

    ackskew = dst->seqlo - ack;
#define MAXACKWINDOW (0xffff + 1500) /* 1500 is an arbitrary fudge factor */
    if (SEQ_GEQ(src->seqhi, end)
        /* Last octet inside other's window space */
        && SEQ_GEQ(seq, src->seqlo - (dst->max_win << dws))
        /* Retrans: not more than one window back */
        && (ackskew >= -MAXACKWINDOW)
        /* Acking not more than one reassembled fragment backwards */
        && (ackskew <= (MAXACKWINDOW << sws))
        /* Acking not more than one window forward */
        && ((tcp_flags & TCP_RST) == 0 || orig_seq == src->seqlo
            || (orig_seq == src->seqlo + 1)
            || (orig_seq + 1 == src->seqlo))) {
        /* Require an exact/+1 sequence match on resets when possible */

        /* update max window */
        if (src->max_win < win) {
            src->max_win = win;
        }
        /* synchronize sequencing */
        if (SEQ_GT(end, src->seqlo)) {
            src->seqlo = end;
        }
        /* slide the window of what the other end can send */
        if (SEQ_GEQ(ack + (win << sws), dst->seqhi)) {
            dst->seqhi = ack + MAX((win << sws), 1);
        }

        /* update states */
        if (tcp_flags & TCP_SYN && src->state < CT_DPIF_TCPS_SYN_SENT) {
                src->state = CT_DPIF_TCPS_SYN_SENT;
        }
        if (tcp_flags & TCP_FIN && src->state < CT_DPIF_TCPS_CLOSING) {
                src->state = CT_DPIF_TCPS_CLOSING;
        }
        if (tcp_flags & TCP_ACK) {
            if (dst->state == CT_DPIF_TCPS_SYN_SENT) {
                dst->state = CT_DPIF_TCPS_ESTABLISHED;
            } else if (dst->state == CT_DPIF_TCPS_CLOSING) {
                dst->state = CT_DPIF_TCPS_FIN_WAIT_2;
            }
        }
        if (tcp_flags & TCP_RST) {
            src->state = dst->state = CT_DPIF_TCPS_TIME_WAIT;
        }

        if (src->state >= CT_DPIF_TCPS_FIN_WAIT_2
            && dst->state >= CT_DPIF_TCPS_FIN_WAIT_2) {
            OvsConntrackUpdateExpiration(&conn->up, now,
                                         30 * CT_INTERVAL_SEC);
        } else if (src->state >= CT_DPIF_TCPS_CLOSING
                   && dst->state >= CT_DPIF_TCPS_CLOSING) {
            OvsConntrackUpdateExpiration(&conn->up, now,
                                         45 * CT_INTERVAL_SEC);
        } else if (src->state < CT_DPIF_TCPS_ESTABLISHED
                   || dst->state < CT_DPIF_TCPS_ESTABLISHED) {
            OvsConntrackUpdateExpiration(&conn->up, now,
                                         30 * CT_INTERVAL_SEC);
        } else if (src->state >= CT_DPIF_TCPS_CLOSING
                   || dst->state >= CT_DPIF_TCPS_CLOSING) {
            OvsConntrackUpdateExpiration(&conn->up, now,
                                         15 * 60 * CT_INTERVAL_SEC);
        } else {
            OvsConntrackUpdateExpiration(&conn->up, now,
                                         24 * 60 * 60 * CT_INTERVAL_SEC);
        }
    } else if ((dst->state < CT_DPIF_TCPS_SYN_SENT
                || dst->state >= CT_DPIF_TCPS_FIN_WAIT_2
                || src->state >= CT_DPIF_TCPS_FIN_WAIT_2)
               && SEQ_GEQ(src->seqhi + MAXACKWINDOW, end)
               /* Within a window forward of the originating packet */
               && SEQ_GEQ(seq, src->seqlo - MAXACKWINDOW)) {
               /* Within a window backward of the originating packet */

        /*
         * This currently handles three situations:
         *  1) Stupid stacks will shotgun SYNs before their peer
         *     replies.
         *  2) When PF catches an already established stream (the
         *     firewall rebooted, the state table was flushed, routes
         *     changed...)
         *  3) Packets get funky immediately after the connection
         *     closes (this should catch Solaris spurious ACK|FINs
         *     that web servers like to spew after a close)
         *
         * This must be a little more careful than the above code
         * since packet floods will also be caught here. We don't
         * update the TTL here to mitigate the damage of a packet
         * flood and so the same code can handle awkward establishment
         * and a loosened connection close.
         * In the establishment case, a correct peer response will
         * validate the connection, go through the normal state code
         * and keep updating the state TTL.
         */

        /* update max window */
        if (src->max_win < win) {
            src->max_win = win;
        }
        /* synchronize sequencing */
        if (SEQ_GT(end, src->seqlo)) {
            src->seqlo = end;
        }
        /* slide the window of what the other end can send */
        if (SEQ_GEQ(ack + (win << sws), dst->seqhi)) {
            dst->seqhi = ack + MAX((win << sws), 1);
        }

        /*
         * Cannot set dst->seqhi here since this could be a shotgunned
         * SYN and not an already established connection.
         */

        if (tcp_flags & TCP_FIN && src->state < CT_DPIF_TCPS_CLOSING) {
            src->state = CT_DPIF_TCPS_CLOSING;
        }

        if (tcp_flags & TCP_RST) {
            src->state = dst->state = CT_DPIF_TCPS_TIME_WAIT;
        }
    } else {
        return CT_UPDATE_INVALID;
    }

    return CT_UPDATE_VALID;
}

BOOLEAN
OvsConntrackValidateTcpPacket(const TCPHdr *tcp)
{
    if (!tcp) {
        OVS_LOG_TRACE("Invalid TCP packet detected, header cannot be NULL");
        return FALSE;
    }

    UINT16 tcp_flags = ntohs(tcp->flags);

    if (OvsCtInvalidTcpFlags(tcp_flags)) {
        OVS_LOG_TRACE("Invalid TCP packet detected, tcp_flags %hu", tcp_flags);
        return FALSE;
    }

    /* A syn+ack is not allowed to create a connection.  We want to allow
     * totally new connections (syn) or already established, not partially
     * open (syn+ack). */
    if ((tcp_flags & TCP_SYN) && (tcp_flags & TCP_ACK)) {
        OVS_LOG_TRACE("Invalid TCP packet detected, SYN+ACK flags not allowed,"
                      "tcp_flags %hu", tcp_flags);
        return FALSE;
    }

    return TRUE;
}

OVS_CT_ENTRY *
OvsConntrackCreateTcpEntry(const TCPHdr *tcp,
                           UINT64 now,
                           UINT32 tcpPayloadLen)
{
    struct conn_tcp* newconn;
    struct tcp_peer *src, *dst;

    newconn = OvsAllocateMemoryWithTag(sizeof(struct conn_tcp),
                                       OVS_CT_POOL_TAG);
    if (!newconn) {
        return NULL;
    }

    newconn->up = (OVS_CT_ENTRY) {0};
    src = &newconn->peer[0];
    dst = &newconn->peer[1];

    src->seqlo = ntohl(tcp->seq);
    src->seqhi = src->seqlo + tcpPayloadLen + 1;

    if (tcp->flags & TCP_SYN) {
        src->seqhi++;
        src->wscale = OvsTcpGetWscale(tcp);
    } else {
        src->wscale = CT_WSCALE_UNKNOWN;
        dst->wscale = CT_WSCALE_UNKNOWN;
    }
    src->max_win = MAX(ntohs(tcp->window), 1);
    if (src->wscale & CT_WSCALE_MASK) {
        /* Remove scale factor from initial window */
        uint8_t sws = src->wscale & CT_WSCALE_MASK;
        src->max_win = DIV_ROUND_UP((uint32_t) src->max_win, 1 << sws);
    }
    if (tcp->flags & TCP_FIN) {
        src->seqhi++;
    }
    dst->seqhi = 1;
    dst->max_win = 1;
    src->state = CT_DPIF_TCPS_SYN_SENT;
    dst->state = CT_DPIF_TCPS_CLOSED;

    OvsConntrackUpdateExpiration(&newconn->up, now, CT_ENTRY_TIMEOUT);

    return &newconn->up;
}

static __inline uint8_t
OvsCtTcpPeerToProtoInfoFlags(const struct tcp_peer *peer)
{
    uint8_t res = 0;

    if (peer->wscale & CT_WSCALE_FLAG) {
        res |= CT_DPIF_TCPF_WINDOW_SCALE;
    }

    if (peer->wscale & CT_WSCALE_UNKNOWN) {
        res |= CT_DPIF_TCPF_BE_LIBERAL;
    }

    return res;
}

NDIS_STATUS
OvsCtMapTcpProtoInfoToNl(PNL_BUFFER nlBuf, OVS_CT_ENTRY *conn_)
{
    struct conn_tcp *conn = OvsCastConntrackEntryToTcpEntry(conn_);
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    UINT32 offset = 0;

    offset = NlMsgStartNested(nlBuf, CTA_PROTOINFO_TCP);
    if (!offset) {
        return NDIS_STATUS_FAILURE;
    }

    if (!NlMsgPutTailU8(nlBuf, CTA_PROTOINFO_TCP_STATE,
                        conn->peer[0].state)) {
        status = NDIS_STATUS_FAILURE;
        goto done;
    }
    if (!NlMsgPutTailU8(nlBuf, CTA_PROTOINFO_TCP_WSCALE_ORIGINAL,
                        (conn->peer[0].wscale & CT_WSCALE_MASK))) {
        status = NDIS_STATUS_FAILURE;
        goto done;
    }
    if (!NlMsgPutTailU8(nlBuf, CTA_PROTOINFO_TCP_WSCALE_REPLY,
                        (conn->peer[1].wscale & CT_WSCALE_MASK))) {
        status = NDIS_STATUS_FAILURE;
        goto done;
    }
    if (!NlMsgPutTailU16(nlBuf, CTA_PROTOINFO_TCP_FLAGS_ORIGINAL,
                         OvsCtTcpPeerToProtoInfoFlags(&conn->peer[0]))) {
        status = NDIS_STATUS_FAILURE;
        goto done;
    }
    if (!NlMsgPutTailU16(nlBuf, CTA_PROTOINFO_TCP_FLAGS_REPLY,
                         OvsCtTcpPeerToProtoInfoFlags(&conn->peer[1]))) {
        status = NDIS_STATUS_FAILURE;
        goto done;
    }

done:
    NlMsgEndNested(nlBuf, offset);
    return status;
}

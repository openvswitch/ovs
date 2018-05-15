/*-
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002 - 2008 Henning Brauer
 * Copyright (c) 2012 Gleb Smirnoff <glebius@FreeBSD.org>
 * Copyright (c) 2015, 2016 Nicira, Inc.
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

#include <config.h>

#include "conntrack-private.h"
#include "ct-dpif.h"
#include "dp-packet.h"
#include "util.h"

struct tcp_peer {
    enum ct_dpif_tcp_state state;
    uint32_t               seqlo;          /* Max sequence number sent     */
    uint32_t               seqhi;          /* Max the other end ACKd + win */
    uint16_t               max_win;        /* largest window (pre scaling) */
    uint8_t                wscale;         /* window scaling factor        */
};

struct conn_tcp {
    struct conn up;
    struct tcp_peer peer[2];
};

enum {
    TCPOPT_EOL,
    TCPOPT_NOP,
    TCPOPT_WINDOW = 3,
};

/* TCP sequence numbers are 32 bit integers operated
 * on with modular arithmetic.  These macros can be
 * used to compare such integers. */
#define SEQ_LT(a,b)     INT_MOD_LT(a, b)
#define SEQ_LEQ(a,b)    INT_MOD_LEQ(a, b)
#define SEQ_GT(a,b)     INT_MOD_GT(a, b)
#define SEQ_GEQ(a,b)    INT_MOD_GEQ(a, b)

#define SEQ_MIN(a, b)   INT_MOD_MIN(a, b)
#define SEQ_MAX(a, b)   INT_MOD_MAX(a, b)

static struct conn_tcp*
conn_tcp_cast(const struct conn* conn)
{
    return CONTAINER_OF(conn, struct conn_tcp, up);
}

/* pf does this in in pf_normalize_tcp(), and it is called only if scrub
 * is enabled.  We're not scrubbing, but this check seems reasonable.  */
static bool
tcp_invalid_flags(uint16_t flags)
{

    if (flags & TCP_SYN) {
        if (flags & TCP_RST || flags & TCP_FIN) {
            return true;
        }
    } else {
        /* Illegal packet */
        if (!(flags & (TCP_ACK|TCP_RST))) {
            return true;
        }
    }

    if (!(flags & TCP_ACK)) {
        /* These flags are only valid if ACK is set */
        if ((flags & TCP_FIN) || (flags & TCP_PSH) || (flags & TCP_URG)) {
            return true;
        }
    }

    return false;
}

#define TCP_MAX_WSCALE 14
#define CT_WSCALE_FLAG 0x80
#define CT_WSCALE_UNKNOWN 0x40
#define CT_WSCALE_MASK 0xf

static uint8_t
tcp_get_wscale(const struct tcp_header *tcp)
{
    int len = TCP_OFFSET(tcp->tcp_ctl) * 4 - sizeof *tcp;
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

static enum ct_update_res
tcp_conn_update(struct conn *conn_, struct conntrack_bucket *ctb,
                struct dp_packet *pkt, bool reply, long long now)
{
    struct conn_tcp *conn = conn_tcp_cast(conn_);
    struct tcp_header *tcp = dp_packet_l4(pkt);
    /* The peer that sent 'pkt' */
    struct tcp_peer *src = &conn->peer[reply ? 1 : 0];
    /* The peer that should receive 'pkt' */
    struct tcp_peer *dst = &conn->peer[reply ? 0 : 1];
    uint8_t sws = 0, dws = 0;
    uint16_t tcp_flags = TCP_FLAGS(tcp->tcp_ctl);

    uint16_t win = ntohs(tcp->tcp_winsz);
    uint32_t ack, end, seq, orig_seq;
    uint32_t p_len = tcp_payload_length(pkt);

    if (tcp_invalid_flags(tcp_flags)) {
        return CT_UPDATE_INVALID;
    }

    if (((tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN)
        && dst->state >= CT_DPIF_TCPS_FIN_WAIT_2
        && src->state >= CT_DPIF_TCPS_FIN_WAIT_2) {
        src->state = dst->state = CT_DPIF_TCPS_CLOSED;
        return CT_UPDATE_NEW;
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

    orig_seq = seq = ntohl(get_16aligned_be32(&tcp->tcp_seq));
    bool check_ackskew = true;
    if (src->state < CT_DPIF_TCPS_SYN_SENT) {
        /* First packet from this end. Set its state */

        ack = ntohl(get_16aligned_be32(&tcp->tcp_ack));

        end = seq + p_len;
        if (tcp_flags & TCP_SYN) {
            end++;
            if (dst->wscale & CT_WSCALE_FLAG) {
                src->wscale = tcp_get_wscale(tcp);
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
        if (src->seqhi == 1
                || SEQ_GEQ(end + MAX(1, dst->max_win << dws), src->seqhi)) {
            src->seqhi = end + MAX(1, dst->max_win << dws);
            /* We are either picking up a new connection or a connection which
             * was already in place.  We are more permissive in terms of
             * ackskew checking in these cases.
             */
            check_ackskew = false;
        }
        if (win > src->max_win) {
            src->max_win = win;
        }

    } else {
        ack = ntohl(get_16aligned_be32(&tcp->tcp_ack));
        end = seq + p_len;
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

    int ackskew = check_ackskew ? dst->seqlo - ack : 0;
#define MAXACKWINDOW (0xffff + 1500)    /* 1500 is an arbitrary fudge factor */
    if (SEQ_GEQ(src->seqhi, end)
        /* Last octet inside other's window space */
        && SEQ_GEQ(seq, src->seqlo - (dst->max_win << dws))
        /* Retrans: not more than one window back */
        && (ackskew >= -MAXACKWINDOW)
        /* Acking not more than one reassembled fragment backwards */
        && (ackskew <= (MAXACKWINDOW << sws))
        /* Acking not more than one window forward */
        && ((tcp_flags & TCP_RST) == 0 || orig_seq == src->seqlo
            || (orig_seq == src->seqlo + 1) || (orig_seq + 1 == src->seqlo))) {
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
            conn_update_expiration(ctb, &conn->up, CT_TM_TCP_CLOSED, now);
        } else if (src->state >= CT_DPIF_TCPS_CLOSING
                   && dst->state >= CT_DPIF_TCPS_CLOSING) {
            conn_update_expiration(ctb, &conn->up, CT_TM_TCP_FIN_WAIT, now);
        } else if (src->state < CT_DPIF_TCPS_ESTABLISHED
                   || dst->state < CT_DPIF_TCPS_ESTABLISHED) {
            conn_update_expiration(ctb, &conn->up, CT_TM_TCP_OPENING, now);
        } else if (src->state >= CT_DPIF_TCPS_CLOSING
                   || dst->state >= CT_DPIF_TCPS_CLOSING) {
            conn_update_expiration(ctb, &conn->up, CT_TM_TCP_CLOSING, now);
        } else {
            conn_update_expiration(ctb, &conn->up, CT_TM_TCP_ESTABLISHED, now);
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

static bool
tcp_valid_new(struct dp_packet *pkt)
{
    struct tcp_header *tcp = dp_packet_l4(pkt);
    uint16_t tcp_flags = TCP_FLAGS(tcp->tcp_ctl);

    if (tcp_invalid_flags(tcp_flags)) {
        return false;
    }

    /* A syn+ack is not allowed to create a connection.  We want to allow
     * totally new connections (syn) or already established, not partially
     * open (syn+ack). */
    if ((tcp_flags & TCP_SYN) && (tcp_flags & TCP_ACK)) {
        return false;
    }

    return true;
}

static struct conn *
tcp_new_conn(struct conntrack_bucket *ctb, struct dp_packet *pkt,
             long long now)
{
    struct conn_tcp* newconn = NULL;
    struct tcp_header *tcp = dp_packet_l4(pkt);
    struct tcp_peer *src, *dst;
    uint16_t tcp_flags = TCP_FLAGS(tcp->tcp_ctl);

    newconn = xzalloc(sizeof *newconn);

    src = &newconn->peer[0];
    dst = &newconn->peer[1];

    src->seqlo = ntohl(get_16aligned_be32(&tcp->tcp_seq));
    src->seqhi = src->seqlo + tcp_payload_length(pkt) + 1;

    if (tcp_flags & TCP_SYN) {
        src->seqhi++;
        src->wscale = tcp_get_wscale(tcp);
    } else {
        src->wscale = CT_WSCALE_UNKNOWN;
        dst->wscale = CT_WSCALE_UNKNOWN;
    }
    src->max_win = MAX(ntohs(tcp->tcp_winsz), 1);
    if (src->wscale & CT_WSCALE_MASK) {
        /* Remove scale factor from initial window */
        uint8_t sws = src->wscale & CT_WSCALE_MASK;
        src->max_win = DIV_ROUND_UP((uint32_t) src->max_win, 1 << sws);
    }
    if (tcp_flags & TCP_FIN) {
        src->seqhi++;
    }
    dst->seqhi = 1;
    dst->max_win = 1;
    src->state = CT_DPIF_TCPS_SYN_SENT;
    dst->state = CT_DPIF_TCPS_CLOSED;

    conn_init_expiration(ctb, &newconn->up, CT_TM_TCP_FIRST_PACKET,
                         now);

    return &newconn->up;
}

static uint8_t
tcp_peer_to_protoinfo_flags(const struct tcp_peer *peer)
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

static void
tcp_conn_get_protoinfo(const struct conn *conn_,
                       struct ct_dpif_protoinfo *protoinfo)
{
    const struct conn_tcp *conn = conn_tcp_cast(conn_);

    protoinfo->proto = IPPROTO_TCP;
    protoinfo->tcp.state_orig = conn->peer[0].state;
    protoinfo->tcp.state_reply = conn->peer[1].state;

    protoinfo->tcp.wscale_orig = conn->peer[0].wscale & CT_WSCALE_MASK;
    protoinfo->tcp.wscale_reply = conn->peer[1].wscale & CT_WSCALE_MASK;

    protoinfo->tcp.flags_orig = tcp_peer_to_protoinfo_flags(&conn->peer[0]);
    protoinfo->tcp.flags_reply = tcp_peer_to_protoinfo_flags(&conn->peer[1]);
}

struct ct_l4_proto ct_proto_tcp = {
    .new_conn = tcp_new_conn,
    .valid_new = tcp_valid_new,
    .conn_update = tcp_conn_update,
    .conn_get_protoinfo = tcp_conn_get_protoinfo,
};

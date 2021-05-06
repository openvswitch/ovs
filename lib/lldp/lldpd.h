/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2015 Nicira, Inc.
 * Copyright (c) 2008 Vincent Bernat <bernat@luffy.cx>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _LLDPD_H
#define _LLDPD_H

#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "dp-packet.h"
#include "openvswitch/list.h"
#include "lldpd-structs.h"
#include "lldp-tlv.h"
#include "packets.h"
#include "openvswitch/vlog.h"

#define ETHERTYPE_LLDP 0x88cc

#define LLDPD_TX_INTERVAL      5
#define LLDPD_TX_HOLD          4
#define LLDPD_TTL              (LLDPD_TX_INTERVAL * LLDPD_TX_HOLD)

#define PROTO_SEND_SIG struct lldpd *, struct lldpd_hardware *,struct dp_packet *
#define PROTO_DECODE_SIG struct lldpd *, char *, int, struct lldpd_hardware *,\
    struct lldpd_chassis **, struct lldpd_port **
#define PROTO_GUESS_SIG char *, int

struct protocol {
    int  mode;       /* > 0 mode identifier (unique per protocol) */
    int  enabled;    /* Is this protocol enabled? */
    char *name;      /* Name of protocol */
    char arg;        /* Argument to enable this protocol */
    int(*send)(PROTO_SEND_SIG);    /* How to send a frame */
    int(*decode)(PROTO_DECODE_SIG); /* How to decode a frame */
    int(*guess)(PROTO_GUESS_SIG);   /* Can be NULL, use MAC address in this
                                     * case
                                     */
    struct eth_addr mac;  /* Destination MAC address used by this protocol */
};

#define SMART_HIDDEN(port) (port->p_hidden_in)

struct lldpd {
    struct lldpd_config g_config;
    struct protocol     *g_protocols;
    int                 g_lastrid;

    struct ovs_list     g_chassis; /* Contains "struct lldp_chassis". */
    struct ovs_list     g_hardware; /* Contains "struct lldpd_hardware". */
};

static inline struct lldpd_hardware *
lldpd_first_hardware(struct lldpd *lldpd)
{
    return CONTAINER_OF(ovs_list_front(&lldpd->g_hardware),
                        struct lldpd_hardware, h_entries);
}

/* lldpd.c */
struct lldpd_hardware *lldpd_get_hardware(struct lldpd *,
    char *, int, struct lldpd_ops *);
struct lldpd_hardware *lldpd_alloc_hardware(struct lldpd *, const char *, int);
void lldpd_hardware_cleanup(struct lldpd*, struct lldpd_hardware *);
struct lldpd_mgmt *lldpd_alloc_mgmt(int family, void *addr, size_t addrsize,
    u_int32_t iface);
void lldpd_recv(struct lldpd *, struct lldpd_hardware *, char *, size_t);
uint32_t lldpd_send(struct lldpd_hardware *, struct dp_packet *);
void lldpd_loop(struct lldpd *);

int lldpd_main(int, char **);
void lldpd_update_localports(struct lldpd *);
void lldpd_cleanup(struct lldpd *);

void lldpd_assign_cfg_to_protocols(struct lldpd *);

/* lldp.c */
int lldp_send(PROTO_SEND_SIG);
int lldp_decode(PROTO_DECODE_SIG);

#endif /* _LLDPD_H */

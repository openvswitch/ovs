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

#ifndef _LLDPD_STRUCTS_H
#define _LLDPD_STRUCTS_H

#include <net/if.h>
#ifndef _WIN32
#include <netinet/in.h>
#endif
#include <sys/socket.h>
#include <sys/types.h>
#include "aa-structs.h"
#include "lldp-const.h"
#include "packets.h"

enum {
    LLDPD_AF_UNSPEC = 0,
    LLDPD_AF_IPV4,
    LLDPD_AF_IPV6,
    LLDPD_AF_LAST
};

inline static int
lldpd_af(int af)
{
    switch (af) {
    case LLDPD_AF_IPV4: return AF_INET;
    case LLDPD_AF_IPV6: return AF_INET6;
    case LLDPD_AF_LAST: return AF_MAX;
    default: return AF_UNSPEC;
    }
}

#define LLDPD_MGMT_MAXADDRSIZE 16 /* sizeof(struct in6_addr) */
struct lldpd_mgmt {
    struct ovs_list m_entries;
    int             m_family;
    union {
        struct in_addr  inet;
        struct in6_addr inet6;
        u_int8_t        octets[LLDPD_MGMT_MAXADDRSIZE];
    } m_addr;
    size_t    m_addrsize;
    u_int32_t m_iface;
};

struct lldpd_chassis {
    struct ovs_list list;
    u_int16_t       c_refcount;   /* Reference count by ports */
    u_int16_t       c_index;      /* Monotonic index */
    u_int8_t        c_protocol;   /* Protocol used to get this chassis */
    u_int8_t        c_id_subtype;
    uint8_t         *c_id;        /* Typically an Ethernet address. */
    int             c_id_len;
    char            *c_name;
    char            *c_descr;

    u_int16_t       c_cap_available;
    u_int16_t       c_cap_enabled;

    u_int16_t       c_ttl;

    struct ovs_list c_mgmt;     /* Contains "struct lldp_mgmt"s. */
};
/* WARNING: any change to this structure should also be reflected into
   `lldpd_copy_chassis()` which is not using marshaling. */

struct lldpd_port {
    struct ovs_list      p_entries;
    struct lldpd_chassis *p_chassis; /* Attached chassis */
    time_t               p_lastchange; /* Time of last change of values */
    time_t               p_lastupdate; /* Time of last update received */
    struct lldpd_frame   *p_lastframe; /* Frame received during last update */
    u_int8_t             p_protocol;   /* Protocol used to get this port */
    u_int8_t             p_hidden_in:1; /* Considered hidden for reception */
    u_int8_t             p_hidden_out:1; /* Considered hidden for emission */
    /* Important: all fields that should be ignored to check if a port has
     * been changed should be before p_id_subtype. Check
     * `lldpd_reset_timer()`.
     */
    u_int8_t             p_id_subtype;
    char                 *p_id;
    int                  p_id_len;
    char                 *p_descr;
    u_int16_t            p_mfs;
    struct lldpd_aa_element_tlv        p_element;
    struct ovs_list p_isid_vlan_maps; /* Contains "struct lldpd_aa_isid_vlan_maps_tlv"s. */
};

/* Smart mode / Hide mode */
#define SMART_INCOMING_FILTER     (1<<0) /* Incoming filtering enabled */
#define SMART_INCOMING_ONE_PROTO  (1<<1) /* On reception, keep only 1 proto */
#define SMART_INCOMING_ONE_NEIGH  (1<<2) /* On recep., keep only 1 neighbor */
#define SMART_OUTGOING_FILTER     (1<<3) /* Outgoing filtering enabled */
#define SMART_OUTGOING_ONE_PROTO  (1<<4) /* On emission, keep only one proto */
#define SMART_OUTGOING_ONE_NEIGH  (1<<5) /* On emission, consider only
                                            one neighbor */
#define SMART_INCOMING (SMART_INCOMING_FILTER | \
             SMART_INCOMING_ONE_PROTO |         \
             SMART_INCOMING_ONE_NEIGH)
#define SMART_OUTGOING (SMART_OUTGOING_FILTER | \
            SMART_OUTGOING_ONE_PROTO |          \
            SMART_OUTGOING_ONE_NEIGH)

struct lldpd_config {
    int c_paused;           /* lldpd is paused */
    int c_tx_interval;      /* Transmit interval */
    int c_smart;            /* Bitmask for smart configuration (see SMART_*) */
    int c_receiveonly;      /* Receive only mode */
    int c_max_neighbors;    /* Maximum number of neighbors (per protocol) */

    char *c_mgmt_pattern;   /* Pattern to match a management address */
    char *c_cid_pattern;    /* Pattern to match interfaces to use for chassis
                             * ID */
    char *c_iface_pattern;  /* Pattern to match interfaces to use */

    char *c_platform;       /* Override platform description (for CDP) */
    char *c_description;    /* Override chassis description */
    char *c_hostname;       /* Override system name */
    int c_advertise_version; /* Should the precise version be advertised? */
    int c_set_ifdescr;      /* Set interface description */
    int c_promisc;          /* Interfaces should be in promiscuous mode */
    int c_tx_hold;          /* Transmit hold */
    int c_bond_slave_src_mac_type; /* Src mac type in lldp frames over bond
                                    * slaves */
    int c_lldp_portid_type; /* The PortID type */
};

struct lldpd_frame {
    int size;
    unsigned char frame[];
};

struct lldpd_hardware;
struct lldpd;
struct lldpd_ops {
    int (*send)(struct lldpd *,
                struct lldpd_hardware *,
                char *, size_t); /* Function to send a frame */
    int (*recv)(struct lldpd *,
                struct lldpd_hardware *,
                int, char *, size_t); /* Function to receive a frame */
    int (*cleanup)(struct lldpd *, struct lldpd_hardware *); /* Cleanup */
};

/* An interface is uniquely identified by h_ifindex, h_ifname and h_ops. This
 * means if an interface becomes enslaved, it will be considered as a new
 * interface. The same applies for renaming and we include the index in case of
 * renaming to an existing interface.
 */
struct lldpd_hardware {
    struct ovs_list   h_entries;

    struct lldpd      *h_cfg;     /* Pointer to main configuration */
    void              *h_recv;    /* FD for reception */
    int               h_sendfd;   /* FD for sending, only used by h_ops */
    int               h_mangle;   /* 1 if we have to mangle the MAC address */
    struct lldpd_ops  *h_ops;     /* Hardware-dependent functions */
    void              *h_data;    /* Hardware-dependent data */
    void              *h_timer;   /* Timer for this port */

    int               h_mtu;
    int               h_flags;    /* Packets will be sent only
                                   * if IFF_RUNNING. Will be
                                   * removed if this is left
                                   * to 0. */
    int               h_ifindex;  /* Interface index, used by SNMP */
    char              h_ifname[IFNAMSIZ]; /* Should be unique */
    struct eth_addr   h_lladdr;

    u_int64_t         h_tx_cnt;
    u_int64_t         h_rx_cnt;
    u_int64_t         h_rx_discarded_cnt;
    u_int64_t         h_rx_unrecognized_cnt;
    u_int64_t         h_ageout_cnt;
    u_int64_t         h_insert_cnt;
    u_int64_t         h_delete_cnt;
    u_int64_t         h_drop_cnt;

    u_int16_t         h_lport_cksum; /* Checksum on local port to see if there
                                      * is a change
                                      */
    struct lldpd_port h_lport;  /* Port attached to this hardware port */
    struct ovs_list h_rports;   /* Contains "struct lldp_port"s. */
};

struct lldpd_interface;
struct lldpd_interface_list;

struct lldpd_neighbor_change {
    char              *ifname;
#define NEIGHBOR_CHANGE_DELETED -1
#define NEIGHBOR_CHANGE_ADDED    1
#define NEIGHBOR_CHANGE_UPDATED  0
    int               state;
    struct lldpd_port *neighbor;
};

/* Cleanup functions */
void lldpd_chassis_mgmt_cleanup(struct lldpd_chassis *);
void lldpd_chassis_cleanup(struct lldpd_chassis *, bool all);
void lldpd_remote_cleanup(struct lldpd_hardware *,
    void (*expire)(struct lldpd_hardware *, struct lldpd_port *), bool all);
void lldpd_port_cleanup(struct lldpd_port *, bool all);
void lldpd_config_cleanup(struct lldpd_config *);

#endif

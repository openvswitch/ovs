/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2008 Vincent Bernat <bernat@luffy.cx>
 * Copyright (c) 2014 Michael Chapman
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

#include <config.h>
#include "lldpd.h"
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "compiler.h"
#include "dp-packet.h"
#include "packets.h"

VLOG_DEFINE_THIS_MODULE(lldp);

/* This set of macro are used to build packets. The current position in buffer
 * is `pos'. The length of the remaining space in buffer is `length'. `type'
 * should be a member of `types'.
 *
 * This was stolen from ladvd which was adapted from Net::CDP. The original
 * author of those macros, Michael Chapman, has relicensed those macros under
 * the ISC license.
 */

#define POKE(value, type, func)               \
    ((length >= sizeof type) &&              \
        (                                     \
            type = func(value),               \
            memcpy(pos, &type, sizeof type), \
            length -= sizeof type,           \
            pos += sizeof type,              \
            1                                 \
        )                                     \
    )
#define POKE_UINT8(value) POKE(value, types.f_uint8, )
#define POKE_UINT16(value) POKE(value, types.f_uint16, htons)
#define POKE_UINT32(value) POKE(value, types.f_uint32, htonl)
#define POKE_BYTES(value, bytes)       \
    ((length >= (bytes)) &&            \
        (                              \
            memcpy(pos, value, bytes), \
            length -= (bytes),         \
            pos += (bytes),            \
            1                          \
        )                              \
    )
#define POKE_SAVE(where) (where = pos, 1)
#define POKE_RESTORE(where)            \
    do {                               \
        if ((where) > pos)             \
            length -= ((where) - pos); \
        else                           \
            length += (pos - (where)); \
        pos = (where);                 \
    } while(0)

/* This set of macro are used to parse packets. The same variable as for POKE_
 * are used. There is no check on boundaries.
 */

#define PEEK(type, func)                  \
    (                                     \
        memcpy(&type, pos, sizeof type), \
        length -= sizeof type,           \
        pos += sizeof type,              \
        func(type)                        \
    )
#define PEEK_UINT8 PEEK(types.f_uint8, )
#define PEEK_UINT16 PEEK(types.f_uint16, ntohs)
#define PEEK_UINT32 PEEK(types.f_uint32, ntohl)
#define PEEK_BYTES(value, bytes)   \
    do {                           \
        memcpy(value, pos, bytes); \
        length -= (bytes);         \
        pos += (bytes);            \
    } while (0)
#define PEEK_DISCARD(bytes) \
    do {                    \
        length -= (bytes);  \
        pos += (bytes);     \
    } while (0)
#define PEEK_DISCARD_UINT8 PEEK_DISCARD(1)
#define PEEK_DISCARD_UINT16 PEEK_DISCARD(2)
#define PEEK_DISCARD_UINT32 PEEK_DISCARD(3)
#define PEEK_CMP(value, bytes) \
     (length -= (bytes),       \
     pos += (bytes),           \
     memcmp(pos-bytes, value, bytes))
#define PEEK_SAVE POKE_SAVE
#define PEEK_RESTORE POKE_RESTORE

/* LLDP specific. We need a `tlv' pointer. */
#define POKE_START_LLDP_TLV(type) \
    (                             \
        tlv = pos,                \
        POKE_UINT16(type << 9)    \
    )
#define POKE_END_LLDP_TLV                                    \
    (                                                        \
        memcpy(&types.f_uint16, tlv, sizeof(uint16_t)),      \
        types.f_uint16 |= htons((pos - (tlv + 2)) & 0x01ff), \
        memcpy(tlv, &types.f_uint16, sizeof(uint16_t)),      \
        1                                                    \
    )

#define CHECK_TLV_SIZE(x, name)                             \
    do {                                                    \
        if (tlv_size < (x)) {                               \
            VLOG_WARN(name " TLV too short received on %s", \
                      hardware->h_ifname);                  \
            goto malformed;                                 \
        }                                                   \
    } while (0)

static union {
    uint8_t  f_uint8;
    ovs_be16 f_uint16;
    ovs_be32 f_uint32;
} types;

static int
lldpd_af_to_lldp_proto(int af)
{
    switch (af) {
    case LLDPD_AF_IPV4:
        return LLDP_MGMT_ADDR_IP4;
    case LLDPD_AF_IPV6:
        return LLDP_MGMT_ADDR_IP6;
    default:
        return LLDP_MGMT_ADDR_NONE;
    }
}

static int
lldpd_af_from_lldp_proto(int proto)
{
    switch (proto) {
    case LLDP_MGMT_ADDR_IP4:
        return LLDPD_AF_IPV4;
    case LLDP_MGMT_ADDR_IP6:
        return LLDPD_AF_IPV6;
    default:
        return LLDPD_AF_UNSPEC;
    }
}

int
lldp_send(struct lldpd *global OVS_UNUSED,
          struct lldpd_hardware *hardware,
          struct dp_packet *p)
{
    struct lldpd_port *port;
    struct lldpd_chassis *chassis;
    struct lldpd_frame *frame;
    uint8_t *packet, *pos, *tlv;
    struct lldpd_mgmt *mgmt;
    int length, proto;
    const uint8_t avaya[] = LLDP_TLV_ORG_AVAYA;
    struct lldpd_aa_isid_vlan_maps_tlv *vlan_isid_map;
    uint8_t msg_auth_digest[LLDP_TLV_AA_ISID_VLAN_DIGEST_LENGTH];

    port = &hardware->h_lport;
    chassis = port->p_chassis;

    /* The ethernet header is filled in elsewhere, we must save room for it. */
    length = hardware->h_mtu - sizeof(struct eth_header);
    packet = dp_packet_l3(p);
    VLOG_DBG("LLDP PDU send to %s mtu %d incoming with ptr=%p",
              hardware->h_ifname, hardware->h_mtu, packet);
    pos = packet;

    /*
     * Make room in dp_packet for chassis ID, Port ID, System Name, System
     * Descr, System Cap
     */
    pos = dp_packet_put_uninit(p, sizeof chassis->c_id_subtype +
                               chassis->c_id_len +
                               sizeof port->p_id_subtype +
                               port->p_id_len +
                               sizeof chassis->c_ttl +
                               strlen(chassis->c_name) +
                               strlen(chassis->c_descr) +
                               sizeof chassis->c_cap_available +
                               sizeof chassis->c_cap_enabled + 12);

    /* Chassis ID */
    if (!(POKE_START_LLDP_TLV(LLDP_TLV_CHASSIS_ID) &&
          POKE_UINT8(chassis->c_id_subtype) &&
          POKE_BYTES(chassis->c_id, chassis->c_id_len) &&
          POKE_END_LLDP_TLV)) {
        goto toobig;
    }

    /* Port ID */
    if (!(POKE_START_LLDP_TLV(LLDP_TLV_PORT_ID) &&
          POKE_UINT8(port->p_id_subtype) &&
          POKE_BYTES(port->p_id, port->p_id_len) &&
          POKE_END_LLDP_TLV)) {
        goto toobig;
    }

    /* Time to live */
    if (!(POKE_START_LLDP_TLV(LLDP_TLV_TTL) &&
          POKE_UINT16(chassis->c_ttl) &&
          POKE_END_LLDP_TLV)) {
        goto toobig;
    }

    /* System name */
    if (chassis->c_name && *chassis->c_name != '\0') {
        if (!(POKE_START_LLDP_TLV(LLDP_TLV_SYSTEM_NAME) &&
              POKE_BYTES(chassis->c_name, strlen(chassis->c_name)) &&
              POKE_END_LLDP_TLV)) {
            goto toobig;
        }
    }

    /* System description (skip it if empty) */
    if (chassis->c_descr && *chassis->c_descr != '\0') {
        if (!(POKE_START_LLDP_TLV(LLDP_TLV_SYSTEM_DESCR) &&
              POKE_BYTES(chassis->c_descr, strlen(chassis->c_descr)) &&
              POKE_END_LLDP_TLV)) {
            goto toobig;
        }
    }

    /* System capabilities */
    if (!(POKE_START_LLDP_TLV(LLDP_TLV_SYSTEM_CAP) &&
          POKE_UINT16(chassis->c_cap_available) &&
          POKE_UINT16(chassis->c_cap_enabled) &&
          POKE_END_LLDP_TLV)) {
        goto toobig;
    }

    LIST_FOR_EACH (mgmt, m_entries, &chassis->c_mgmt.m_entries) {
       /*
        * Make room for 1 mgmt interface
        */
        dp_packet_put_uninit(p, 2 + sizeof(uint8_t) +
                             sizeof(uint8_t) +
                             mgmt->m_addrsize +
                             sizeof(uint8_t) +
                             sizeof(uint32_t) +
                             sizeof(uint8_t));

        proto = lldpd_af_to_lldp_proto(mgmt->m_family);
        if (!(POKE_START_LLDP_TLV(LLDP_TLV_MGMT_ADDR) &&
              /* Size of the address, including its type */
              POKE_UINT8(mgmt->m_addrsize + 1) &&
              POKE_UINT8(proto) &&
              POKE_BYTES(&mgmt->m_addr, mgmt->m_addrsize))) {
            goto toobig;
        }

        /* Interface port type, OID */
        if (mgmt->m_iface == 0) {
            if (!(/* We don't know the management interface */
                  POKE_UINT8(LLDP_MGMT_IFACE_UNKNOWN) &&
                  POKE_UINT32(0))) {
                goto toobig;
            }
        } else {
            if (!(/* We have the index of the management interface */
                  POKE_UINT8(LLDP_MGMT_IFACE_IFINDEX) &&
                  POKE_UINT32(mgmt->m_iface))) {
                goto toobig;
            }
        }
        if (!(/* We don't provide an OID for management */
              POKE_UINT8(0) &&
              POKE_END_LLDP_TLV)) {
            goto toobig;
        }
    }

    /* Port description */
    if (port->p_descr && *port->p_descr != '\0') {
        /* make room for port descr */
        dp_packet_put_uninit(p, 2 + strlen(port->p_descr));

        if (!(POKE_START_LLDP_TLV(LLDP_TLV_PORT_DESCR) &&
              POKE_BYTES(port->p_descr, strlen(port->p_descr)) &&
              POKE_END_LLDP_TLV)) {
            goto toobig;
        }
    }

    /* Add Auto Attach tlvs to packet */
    /* AA-ELEMENT */
    if (port->p_element.type != 0) {
        u_int8_t aa_element_first_byte;
        u_int8_t aa_element_second_byte = 0;
        u_int8_t aa_elem_sys_id_first_byte;
        u_int8_t aa_elem_sys_id_second_byte;

        /* Element type should be first 4 most significant bits, so bitwise OR
         * that with the first 4 bits of the 12-bit-wide mgmt_vlan
         */
        aa_element_first_byte = ((port->p_element.type & 0xF) << 4) |
            ((port->p_element.mgmt_vlan >> 8) & 0xF);

        /* Second byte should just be the remaining 8 bits of .mgmt_vlan */
        aa_element_second_byte = port->p_element.mgmt_vlan & 0x0FF;

        /* .conn_type should be 4 most sig. bits, so bitwise OR that
         * with the first 4 bits of the 12-bit-wide .smlt_id
         */
        aa_elem_sys_id_first_byte =
            ((port->p_element.system_id.conn_type & 0xF) << 4) |
            ((port->p_element.system_id.smlt_id >> 8) & 0xF);

        /* Second byte should just be the remaining 8 bits of .smlt_id */
        aa_elem_sys_id_second_byte = port->p_element.system_id.smlt_id & 0x0FF;

        /* make room for element type tlv */
        dp_packet_put_uninit(p, 2 + sizeof avaya +
                             sizeof(uint8_t) +
                             sizeof aa_element_first_byte +
                             sizeof aa_element_second_byte +
                             sizeof port->p_element.system_id.system_mac +
                             sizeof aa_elem_sys_id_first_byte +
                             sizeof aa_elem_sys_id_second_byte +
                             sizeof port->p_element.system_id.mlt_id);

        if (!(POKE_START_LLDP_TLV(LLDP_TLV_ORG) &&
              POKE_BYTES(avaya, sizeof avaya) &&
              POKE_UINT8(LLDP_TLV_AA_ELEMENT_SUBTYPE) &&
              POKE_UINT8(aa_element_first_byte) &&
              POKE_UINT8(aa_element_second_byte) &&
              POKE_BYTES(&port->p_element.system_id.system_mac,
              sizeof port->p_element.system_id.system_mac) &&
              POKE_UINT8(aa_elem_sys_id_first_byte) &&
              POKE_UINT8(aa_elem_sys_id_second_byte) &&
              POKE_BYTES(&port->p_element.system_id.mlt_id,
              sizeof port->p_element.system_id.mlt_id) &&
              POKE_END_LLDP_TLV)) {
            goto toobig;
        }
    }

    if (!list_is_empty(&port->p_isid_vlan_maps.m_entries)) {
        int j;

       /*
        * make room for aa_isid_digest
        */
        dp_packet_put_uninit(p, 2 + sizeof avaya +
                             sizeof(uint8_t) +
                             sizeof msg_auth_digest);

        for (j = 0; j < LLDP_TLV_AA_ISID_VLAN_DIGEST_LENGTH; j++) {
            msg_auth_digest[j] = 0;
        }

        if (!(POKE_START_LLDP_TLV(LLDP_TLV_ORG) &&
              POKE_BYTES(avaya, sizeof avaya) &&
              POKE_UINT8(LLDP_TLV_AA_ISID_VLAN_ASGNS_SUBTYPE) &&
              POKE_BYTES(msg_auth_digest, sizeof msg_auth_digest))) {
            goto toobig;
        }

        LIST_FOR_EACH (vlan_isid_map,
                       m_entries,
                       &hardware->h_lport.p_isid_vlan_maps.m_entries) {
            u_int16_t status_vlan_word;
            status_vlan_word =
                (vlan_isid_map->isid_vlan_data.status << 12) |
                vlan_isid_map->isid_vlan_data.vlan;

            /*
             * Make room for one isid-vlan mapping
             */
            dp_packet_put_uninit(p, sizeof status_vlan_word +
                                 sizeof vlan_isid_map->isid_vlan_data.isid);

            if (!(POKE_UINT16(status_vlan_word) &&
                  POKE_BYTES(&vlan_isid_map->isid_vlan_data.isid,
                      sizeof vlan_isid_map->isid_vlan_data.isid))) {
                goto toobig;
            }
        }

        if (!(POKE_END_LLDP_TLV)) {
           goto toobig;
        }
    }

    /* Make room for the End TLV 0x0000 */
    dp_packet_put_uninit(p, sizeof(uint16_t));

    /* END */
    if (!(POKE_START_LLDP_TLV(LLDP_TLV_END) &&
          POKE_END_LLDP_TLV)) {
        goto toobig;
    }

    hardware->h_tx_cnt++;

    /* We assume that LLDP frame is the reference */
    if ((frame = malloc(sizeof(int) + pos - packet)) != NULL) {
        frame->size = pos - packet;
        length = frame->size;
        memcpy(&frame->frame, packet, frame->size);

        if ((hardware->h_lport.p_lastframe == NULL) ||
            (hardware->h_lport.p_lastframe->size != frame->size) ||
            (memcmp(hardware->h_lport.p_lastframe->frame, frame->frame,
            frame->size) != 0)) {
            free(hardware->h_lport.p_lastframe);
            hardware->h_lport.p_lastframe = frame;
            hardware->h_lport.p_lastchange = time(NULL);
        } else {
            free(frame);
        }
    }

    return length;

toobig:
    free(packet);

    return E2BIG;
}

int
lldp_decode(struct lldpd *cfg OVS_UNUSED, char *frame, int s,
    struct lldpd_hardware *hardware, struct lldpd_chassis **newchassis,
    struct lldpd_port **newport)
{
    struct lldpd_chassis *chassis;
    struct lldpd_port *port;
    const char lldpaddr[] = LLDP_MULTICAST_ADDR;
    const char dot1[] = LLDP_TLV_ORG_DOT1;
    const char dot3[] = LLDP_TLV_ORG_DOT3;
    const char med[] = LLDP_TLV_ORG_MED;
    const char avaya_oid[] = LLDP_TLV_ORG_AVAYA;
    const char dcbx[] = LLDP_TLV_ORG_DCBX;
    char orgid[3];
    int length, gotend = 0, ttl_received = 0, af;
    int tlv_size, tlv_type, tlv_subtype;
    u_int8_t *pos, *tlv;
    char *b;
    struct lldpd_aa_isid_vlan_maps_tlv *isid_vlan_map = NULL;
    u_int8_t msg_auth_digest[LLDP_TLV_AA_ISID_VLAN_DIGEST_LENGTH];
    struct lldpd_mgmt *mgmt;
    u_int8_t addr_str_length, addr_str_buffer[32];
    u_int8_t addr_family, addr_length, *addr_ptr, iface_subtype;
    u_int32_t iface_number, iface;

    VLOG_DBG("receive LLDP PDU on %s", hardware->h_ifname);

    if ((chassis = calloc(1, sizeof *chassis)) == NULL) {
        VLOG_WARN("failed to allocate remote chassis");
        return -1;
    }
    list_init(&chassis->c_mgmt.m_entries);

    if ((port = calloc(1, sizeof *port)) == NULL) {
        VLOG_WARN("failed to allocate remote port");
        free(chassis);
        return -1;
    }
    list_init(&port->p_isid_vlan_maps.m_entries);

    length = s;
    pos = (u_int8_t*) frame;

    if (length < 2 * ETH_ADDR_LEN + sizeof(u_int16_t)) {
        VLOG_WARN("too short frame received on %s", hardware->h_ifname);
        goto malformed;
    }
    if (PEEK_CMP(lldpaddr, ETH_ADDR_LEN) != 0) {
        VLOG_INFO("frame not targeted at LLDP multicast address "
                  "received on %s", hardware->h_ifname);
        goto malformed;
    }
    PEEK_DISCARD(ETH_ADDR_LEN); /* Skip source address */
    if (PEEK_UINT16 != ETHERTYPE_LLDP) {
        VLOG_INFO("non LLDP frame received on %s", hardware->h_ifname);
        goto malformed;
    }

    while (length && (!gotend)) {
        if (length < 2) {
            VLOG_WARN("tlv header too short received on %s",
                      hardware->h_ifname);
            goto malformed;
        }
        tlv_size = PEEK_UINT16;
        tlv_type = tlv_size >> 9;
        tlv_size = tlv_size & 0x1ff;
        (void) PEEK_SAVE(tlv);
        if (length < tlv_size) {
            VLOG_WARN("frame too short for tlv received on %s",
                      hardware->h_ifname);
            goto malformed;
        }

        switch (tlv_type) {
        case LLDP_TLV_END:
            if (tlv_size != 0) {
                VLOG_WARN("lldp end received with size not null on %s",
                          hardware->h_ifname);
                goto malformed;
            }
            if (length) {
                VLOG_DBG("extra data after lldp end on %s",
                         hardware->h_ifname);
            }
            gotend = 1;
            break;

        case LLDP_TLV_CHASSIS_ID:
        case LLDP_TLV_PORT_ID:
            CHECK_TLV_SIZE(2, "Port Id");
            tlv_subtype = PEEK_UINT8;
            if ((tlv_subtype == 0) || (tlv_subtype > 7)) {
                VLOG_WARN("unknown subtype for tlv id received on %s",
                          hardware->h_ifname);
                goto malformed;
            }
            if ((b = (char *) calloc(1, tlv_size - 1)) == NULL) {
                VLOG_WARN("unable to allocate memory for id tlv received "
                          "on %s",
                          hardware->h_ifname);
                goto malformed;
            }
            PEEK_BYTES(b, tlv_size - 1);
            if (tlv_type == LLDP_TLV_PORT_ID) {
                port->p_id_subtype = tlv_subtype;
                port->p_id = b;
                port->p_id_len = tlv_size - 1;
            } else {
                chassis->c_id_subtype = tlv_subtype;
                chassis->c_id = b;
                chassis->c_id_len = tlv_size - 1;
            }
            break;

        case LLDP_TLV_TTL:
            CHECK_TLV_SIZE(2, "TTL");
            chassis->c_ttl = PEEK_UINT16;
            ttl_received = 1;
            break;

        case LLDP_TLV_PORT_DESCR:
        case LLDP_TLV_SYSTEM_NAME:
        case LLDP_TLV_SYSTEM_DESCR:
            if (tlv_size < 1) {
                VLOG_DBG("empty tlv received on %s", hardware->h_ifname);
                break;
            }
            if ((b = (char *) calloc(1, tlv_size + 1)) == NULL) {
                VLOG_WARN("unable to allocate memory for string tlv "
                          "received on %s",
                          hardware->h_ifname);
                goto malformed;
            }
            PEEK_BYTES(b, tlv_size);
            if (tlv_type == LLDP_TLV_PORT_DESCR) {
                port->p_descr = b;
            } else if (tlv_type == LLDP_TLV_SYSTEM_NAME) {
                chassis->c_name = b;
            } else {
                chassis->c_descr = b;
            }
            break;

        case LLDP_TLV_SYSTEM_CAP:
            CHECK_TLV_SIZE(4, "System capabilities");
            chassis->c_cap_available = PEEK_UINT16;
            chassis->c_cap_enabled = PEEK_UINT16;
            break;

        case LLDP_TLV_MGMT_ADDR:
            CHECK_TLV_SIZE(1, "Management address");
            addr_str_length = PEEK_UINT8;
            CHECK_TLV_SIZE(1 + addr_str_length, "Management address");
            PEEK_BYTES(addr_str_buffer, addr_str_length);
            addr_length = addr_str_length - 1;
            addr_family = addr_str_buffer[0];
            addr_ptr = &addr_str_buffer[1];
            CHECK_TLV_SIZE(1 + addr_str_length + 5, "Management address");
            iface_subtype = PEEK_UINT8;
            iface_number = PEEK_UINT32;

            af = lldpd_af_from_lldp_proto(addr_family);
            if (af == LLDPD_AF_UNSPEC) {
                break;
            }
            iface = iface_subtype == LLDP_MGMT_IFACE_IFINDEX ?
                iface_number : 0;
            mgmt = lldpd_alloc_mgmt(af, addr_ptr, addr_length, iface);
            if (mgmt == NULL) {
                VLOG_WARN("unable to allocate memory for management address");
                goto malformed;
            }
            list_push_back(&chassis->c_mgmt.m_entries, &mgmt->m_entries);
            break;

        case LLDP_TLV_ORG:
            CHECK_TLV_SIZE(4, "Organisational");
            PEEK_BYTES(orgid, sizeof orgid);
            tlv_subtype = PEEK_UINT8;
            if (memcmp(dot1, orgid, sizeof orgid) == 0) {
                hardware->h_rx_unrecognized_cnt++;
            } else if (memcmp(dot3, orgid, sizeof orgid) == 0) {
                hardware->h_rx_unrecognized_cnt++;
            } else if (memcmp(med, orgid, sizeof orgid) == 0) {
                /* LLDP-MED */
                hardware->h_rx_unrecognized_cnt++;
            } else if (memcmp(avaya_oid, orgid, sizeof orgid) == 0) {
                u_int16_t aa_element_word;
                u_int16_t aa_status_vlan_word;
                u_int16_t aa_system_id_word;
                unsigned short num_mappings;

                switch(tlv_subtype) {
                case LLDP_TLV_AA_ELEMENT_SUBTYPE:
                    aa_element_word = PEEK_UINT16;

                    /* Type is first 4 most-significant bits */
                    port->p_element.type = aa_element_word >> 12;

                    /* mgmt_vlan is last 12 bits */
                    port->p_element.mgmt_vlan = aa_element_word & 0x0FFF;
                    VLOG_INFO("Element type: %X, Mgmt vlan: %X",
                              port->p_element.type,
                              port->p_element.mgmt_vlan);
                    PEEK_BYTES(&port->p_element.system_id.system_mac,
                               sizeof port->p_element.system_id.system_mac);
                    VLOG_INFO("System mac: 0x%.2X%.2X%.2X%.2X%.2X%.2X",
                              port->p_element.system_id.system_mac[0],
                              port->p_element.system_id.system_mac[1],
                              port->p_element.system_id.system_mac[2],
                              port->p_element.system_id.system_mac[3],
                              port->p_element.system_id.system_mac[4],
                              port->p_element.system_id.system_mac[5]);
                    aa_system_id_word = PEEK_UINT16;
                    port->p_element.system_id.conn_type =
                        aa_system_id_word >> 12;
                    port->p_element.system_id.smlt_id =
                        aa_system_id_word & 0x0FFF;
                    PEEK_BYTES(&port->p_element.system_id.mlt_id,
                               sizeof port->p_element.system_id.mlt_id);
                    break;

                case LLDP_TLV_AA_ISID_VLAN_ASGNS_SUBTYPE:
                    PEEK_BYTES(&msg_auth_digest, sizeof msg_auth_digest);

                    /* Subtract off tlv type and length (2Bytes) + OUI (3B) +
                     * Subtype (1B) + MSG DIGEST (32B).
                     */
                    num_mappings = tlv_size - 4 -
                        LLDP_TLV_AA_ISID_VLAN_DIGEST_LENGTH;
                    if ((num_mappings % 5) != 0) {
                        VLOG_INFO("malformed vlan-isid mappings tlv received");
                        goto malformed;
                    }

                    num_mappings /= 5; /* Each mapping is 5 Bytes */
                    for(; num_mappings > 0; num_mappings--) {
                        isid_vlan_map = (struct lldpd_aa_isid_vlan_maps_tlv *)
                            calloc(1, sizeof *isid_vlan_map);
                        if (!isid_vlan_map) {
                            VLOG_WARN("unable to allocate memory "
                                      "for aa_isid_vlan_maps_tlv struct");
                            goto malformed;
                        }
                        aa_status_vlan_word = PEEK_UINT16;

                        /* Status is first 4 most-significant bits. */
                        isid_vlan_map->isid_vlan_data.status =
                            aa_status_vlan_word >> 12;

                        /* Vlan is last 12 bits */
                        isid_vlan_map->isid_vlan_data.vlan =
                            aa_status_vlan_word & 0x0FFF;
                        PEEK_BYTES(&isid_vlan_map->isid_vlan_data.isid,
                            sizeof isid_vlan_map->isid_vlan_data.isid);
                        list_push_back(
                            (struct ovs_list *) &port->p_isid_vlan_maps,
                            (struct ovs_list *) isid_vlan_map);
                        isid_vlan_map = NULL;
                    }
                    break;

                default:
                    hardware->h_rx_unrecognized_cnt++;
                    VLOG_INFO("Unrecogised tlv subtype received");
                    break;
                }
            } else if (memcmp(dcbx, orgid, sizeof orgid) == 0) {
                VLOG_DBG("unsupported DCBX tlv received on %s "
                         "- ignore", hardware->h_ifname);
                hardware->h_rx_unrecognized_cnt++;
            } else {
                VLOG_INFO("unknown org tlv [%02x:%02x:%02x] received "
                          "on %s", orgid[0], orgid[1], orgid[2],
                          hardware->h_ifname);
                hardware->h_rx_unrecognized_cnt++;
            }
            break;
        default:
            VLOG_WARN("unknown tlv (%d) received on %s",
                      tlv_type,
                      hardware->h_ifname);
            goto malformed;
        }
        if (pos > tlv + tlv_size) {
            VLOG_WARN("BUG: already past TLV!");
            goto malformed;
        }
        PEEK_DISCARD(tlv + tlv_size - pos);
    }

    /* Some random check */
    if ((chassis->c_id == NULL) ||
        (port->p_id == NULL) ||
        (!ttl_received) ||
        (gotend == 0)) {
        VLOG_WARN("some mandatory tlv are missing for frame received "
                  "on %s", hardware->h_ifname);
        goto malformed;
    }
    *newchassis = chassis;
    *newport = port;
    return 1;

malformed:
    lldpd_chassis_cleanup(chassis, 1);
    lldpd_port_cleanup(port, 1);
    free(port);
    return -1;
}

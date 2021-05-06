/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2015 Nicira, Inc.
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

/* This set of macro are used to parse packets. The current position in buffer
 * is `pos'. The length of the remaining space in buffer is `length'.  There is
 * no check on boundaries.
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
#define PEEK_DISCARD_UINT32 PEEK_DISCARD(4)
#define PEEK_CMP(value, bytes) \
     (length -= (bytes),       \
     pos += (bytes),           \
     memcmp(pos-bytes, value, bytes))
#define CHECK_TLV_SIZE(x, name)                             \
    do {                                                    \
        if (tlv_size < (x)) {                               \
            VLOG_WARN(name " TLV too short received on %s", \
                      hardware->h_ifname);                  \
            goto malformed;                                 \
        }                                                   \
    } while (0)
#define PEEK_SAVE(where) (where = pos, 1)

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

static void
lldp_tlv_put_u8(struct dp_packet *p, uint8_t x)
{
    dp_packet_put(p, &x, sizeof x);
}

static void
lldp_tlv_put_u16(struct dp_packet *p, uint16_t x)
{
    ovs_be16 nx = htons(x);
    dp_packet_put(p, &nx, sizeof nx);
}

static void
lldp_tlv_put_u32(struct dp_packet *p, uint32_t x)
{
    ovs_be32 nx = htonl(x);
    dp_packet_put(p, &nx, sizeof nx);
}

static void
lldp_tlv_put_isid(struct dp_packet *p, uint32_t isid)
{
    uint8_t *data = dp_packet_put_uninit(p, 3);
    data[0] = isid >> 16;
    data[1] = isid >> 8;
    data[2] = isid;
}

static void
lldp_tlv_start(struct dp_packet *p, uint8_t tlv, unsigned int *start)
{
    *start = dp_packet_size(p);
    lldp_tlv_put_u16(p, tlv << 9);
}

static void
lldp_tlv_end(struct dp_packet *p, unsigned int start)
{
    ovs_be16 *tlv = dp_packet_at_assert(p, start, 2);
    *tlv |= htons((dp_packet_size(p) - (start + 2)) & 0x1ff);
}

int
lldp_send(struct lldpd *global OVS_UNUSED,
          struct lldpd_hardware *hardware,
          struct dp_packet *p)
{
    unsigned int orig_size = dp_packet_size(p);
    unsigned int start;

    struct lldpd_port *port;
    struct lldpd_chassis *chassis;
    struct lldpd_mgmt *mgmt;
    const uint8_t avaya[] = LLDP_TLV_ORG_AVAYA;
    struct lldpd_aa_isid_vlan_maps_tlv *vlan_isid_map;
    uint8_t msg_auth_digest[LLDP_TLV_AA_ISID_VLAN_DIGEST_LENGTH];

    port = &hardware->h_lport;
    chassis = port->p_chassis;

    /* The ethernet header is filled in elsewhere, we must save room for it. */
    VLOG_DBG("LLDP PDU send to %s mtu %d incoming",
              hardware->h_ifname, hardware->h_mtu);

    /* Chassis ID */
    lldp_tlv_start(p, LLDP_TLV_CHASSIS_ID, &start);
    lldp_tlv_put_u8(p, chassis->c_id_subtype);
    dp_packet_put(p, chassis->c_id, chassis->c_id_len);
    lldp_tlv_end(p, start);

    /* Port ID */
    lldp_tlv_start(p, LLDP_TLV_PORT_ID, &start);
    lldp_tlv_put_u8(p, port->p_id_subtype);
    dp_packet_put(p, port->p_id, port->p_id_len);
    lldp_tlv_end(p, start);

    /* Time to live */
    lldp_tlv_start(p, LLDP_TLV_TTL, &start);
    lldp_tlv_put_u16(p, chassis->c_ttl);
    lldp_tlv_end(p, start);

    /* System name */
    if (chassis->c_name && *chassis->c_name != '\0') {
        lldp_tlv_start(p, LLDP_TLV_SYSTEM_NAME, &start);
        dp_packet_put(p, chassis->c_name, strlen(chassis->c_name));
        lldp_tlv_end(p, start);
    }

    /* System description (skip it if empty) */
    if (chassis->c_descr && *chassis->c_descr != '\0') {
        lldp_tlv_start(p, LLDP_TLV_SYSTEM_DESCR, &start);
        dp_packet_put(p, chassis->c_descr, strlen(chassis->c_descr));
        lldp_tlv_end(p, start);
    }

    /* System capabilities */
    lldp_tlv_start(p, LLDP_TLV_SYSTEM_CAP, &start);
    lldp_tlv_put_u16(p, chassis->c_cap_available);
    lldp_tlv_put_u16(p, chassis->c_cap_enabled);
    lldp_tlv_end(p, start);

    LIST_FOR_EACH (mgmt, m_entries, &chassis->c_mgmt) {
        lldp_tlv_start(p, LLDP_TLV_MGMT_ADDR, &start);
        lldp_tlv_put_u8(p, mgmt->m_addrsize + 1);
        lldp_tlv_put_u8(p, lldpd_af_to_lldp_proto(mgmt->m_family));
        dp_packet_put(p, &mgmt->m_addr, mgmt->m_addrsize);

        /* Interface port type, OID */
        if (mgmt->m_iface == 0) {
            /* We don't know the management interface */
            lldp_tlv_put_u8(p, LLDP_MGMT_IFACE_UNKNOWN);
            lldp_tlv_put_u32(p, 0);
        } else {
            /* We have the index of the management interface */
            lldp_tlv_put_u8(p, LLDP_MGMT_IFACE_IFINDEX);
            lldp_tlv_put_u32(p, mgmt->m_iface);
        }
        lldp_tlv_put_u8(p, 0);
        lldp_tlv_end(p, start);
    }

    /* Port description */
    if (port->p_descr && *port->p_descr != '\0') {
        lldp_tlv_start(p, LLDP_TLV_PORT_DESCR, &start);
        dp_packet_put(p, port->p_descr, strlen(port->p_descr));
        lldp_tlv_end(p, start);
    }

    /* Add Auto Attach tlvs V3.1 to packet. LLDP FA element v3.1 format:
    TLV Type[127]   TLV Length[50 octets] Avaya OUI[00-04-0D] Subtype[11]
    7 bits                9 bits                3 octets      1 octet
    HMAC-SHA Digest  Element Type   State   Mgmt VLAN   Rsvd    System ID
      32 octets       6 bits        6 bits   12 bits    1 octet 10 octets
    */
    /* AA-ELEMENT */
    if (port->p_element.type != 0) {
        u_int16_t aa_element_first_word = 0;
        u_int16_t aa_element_second_word = 0;
        u_int16_t aa_element_state = 0;
        u_int8_t aa_elem_sys_id_first_byte;
        u_int8_t aa_elem_sys_id_second_byte;

        /* Link VLAN Tagging Requirements (bit 1),
         * Automatic Provisioning Mode (bit 2/3) (left to right, 1 based) */
        aa_element_state = ((port->p_element.vlan_tagging & 0x1) << 5) |
            ((port->p_element.auto_prov_mode & 0x3) << 3);

        /* Element first word should be first 6 most significant bits of
         * element type, bitwise OR that with the next 6 bits of the state,
         * bitwise OR with the first 4 bits of mgmt vlan id.
         * Element type should be LLDP_TLV_AA_ELEM_TYPE_VIRTUAL_SWITCH for
         * AA client */
        aa_element_first_word = (port->p_element.type << 10) |
            (aa_element_state << 4) |
            ((port->p_element.mgmt_vlan & 0x0F00)>> 8);

        /* Element second type should be the first 8 most significant bits
         * of the remaining 8 bits of mgmt vlan id. */
        aa_element_second_word = (port->p_element.mgmt_vlan & 0xFF) << 8;

        /* System id first byte should be first 3 most significant bits of
         * connecion type, bitwise OR that with the device state and bitwise
         * OR that with the first 2 most significant bitsof rsvd (10 bits). */
        aa_elem_sys_id_first_byte =
            ((port->p_element.system_id.conn_type & 0x7) << 5) |
            ((port->p_element.system_id.rsvd >> 8) & 0x3);

        /* Second byte should just be the remaining 8 bits of 10 bits rsvd */
        aa_elem_sys_id_second_byte =
            (port->p_element.system_id.rsvd & 0xFF);

        memset(msg_auth_digest, 0, sizeof msg_auth_digest);

        lldp_tlv_start(p, LLDP_TLV_ORG, &start);
        dp_packet_put(p, avaya, sizeof avaya);
        lldp_tlv_put_u8(p, LLDP_TLV_AA_ELEMENT_SUBTYPE);
        dp_packet_put(p, msg_auth_digest, sizeof msg_auth_digest);
        lldp_tlv_put_u16(p, aa_element_first_word);
        lldp_tlv_put_u16(p, aa_element_second_word);
        dp_packet_put(p, &port->p_element.system_id.system_mac,
                      sizeof port->p_element.system_id.system_mac);
        lldp_tlv_put_u8(p, aa_elem_sys_id_first_byte);
        lldp_tlv_put_u8(p, aa_elem_sys_id_second_byte);
        dp_packet_put(p, &port->p_element.system_id.rsvd2,
                      sizeof port->p_element.system_id.rsvd2);
        lldp_tlv_end(p, start);
    }

    if (!ovs_list_is_empty(&port->p_isid_vlan_maps)) {

        memset(msg_auth_digest, 0, sizeof msg_auth_digest);

        lldp_tlv_start(p, LLDP_TLV_ORG, &start);
        dp_packet_put(p, avaya, sizeof avaya);
        lldp_tlv_put_u8(p, LLDP_TLV_AA_ISID_VLAN_ASGNS_SUBTYPE);
        dp_packet_put(p, msg_auth_digest, sizeof msg_auth_digest);

        LIST_FOR_EACH (vlan_isid_map,
                       m_entries,
                       &hardware->h_lport.p_isid_vlan_maps) {
            u_int16_t status_vlan_word;
            status_vlan_word =
                (vlan_isid_map->isid_vlan_data.status << 12) |
                vlan_isid_map->isid_vlan_data.vlan;

            lldp_tlv_put_u16(p, status_vlan_word);
            lldp_tlv_put_isid(p, vlan_isid_map->isid_vlan_data.isid);
        }

        lldp_tlv_end(p, start);
    }

    /* END */
    lldp_tlv_start(p, LLDP_TLV_END, &start);
    lldp_tlv_end(p, start);

    hardware->h_tx_cnt++;

    const char *lldp = dp_packet_at_assert(p, orig_size, 0);
    unsigned int lldp_len = dp_packet_size(p) - orig_size;
    if (!hardware->h_lport.p_lastframe
        || hardware->h_lport.p_lastframe->size != lldp_len
        || memcmp(hardware->h_lport.p_lastframe->frame, lldp, lldp_len)) {

        struct lldpd_frame *frame = xmalloc(sizeof *frame + lldp_len);
        frame->size = lldp_len;
        memcpy(frame->frame, lldp, lldp_len);
        free(hardware->h_lport.p_lastframe);
        hardware->h_lport.p_lastframe = frame;
        hardware->h_lport.p_lastchange = time(NULL);
    }

    return dp_packet_size(p);
}
#define CHECK_TLV_MAX_SIZE(x, name)                                 \
    do { if (tlv_size > (x)) {                                      \
            VLOG_WARN(name " TLV too large received on %s",         \
                      hardware->h_ifname);                          \
            goto malformed;                                         \
        } } while (0)

int
lldp_decode(struct lldpd *cfg OVS_UNUSED, char *frame, int s,
            struct lldpd_hardware *hardware, struct lldpd_chassis **newchassis,
            struct lldpd_port **newport)
{
    struct lldpd_chassis *chassis;
    struct lldpd_port *port;
    const struct eth_addr lldpaddr = LLDP_MULTICAST_ADDR;
    const char dot1[] = LLDP_TLV_ORG_DOT1;
    const char dot3[] = LLDP_TLV_ORG_DOT3;
    const char med[] = LLDP_TLV_ORG_MED;
    const char avaya_oid[] = LLDP_TLV_ORG_AVAYA;
    const char dcbx[] = LLDP_TLV_ORG_DCBX;
    char orgid[3];
    int length, af;
    bool gotend = false;
    bool ttl_received = false;
    int tlv_size, tlv_type, tlv_subtype, tlv_count = 0;
    u_int8_t *pos, *tlv;
    void *b;
    struct lldpd_aa_isid_vlan_maps_tlv *isid_vlan_map = NULL;
    u_int8_t msg_auth_digest[LLDP_TLV_AA_ISID_VLAN_DIGEST_LENGTH];
    struct lldpd_mgmt *mgmt;
    u_int8_t addr_str_length, addr_str_buffer[32];
    u_int8_t addr_family, addr_length, *addr_ptr, iface_subtype;
    u_int32_t iface_number, iface;

    VLOG_DBG("receive LLDP PDU on %s", hardware->h_ifname);

    chassis = xzalloc(sizeof *chassis);
    ovs_list_init(&chassis->c_mgmt);

    port = xzalloc(sizeof *port);
    ovs_list_init(&port->p_isid_vlan_maps);

    length = s;
    pos = (u_int8_t*) frame;

    if (length < 2 * ETH_ADDR_LEN + sizeof(u_int16_t)) {
        VLOG_WARN("too short frame received on %s", hardware->h_ifname);
        goto malformed;
    }
    if (PEEK_CMP(&lldpaddr, ETH_ADDR_LEN) != 0) {
        VLOG_INFO("frame not targeted at LLDP multicast address "
                  "received on %s", hardware->h_ifname);
        goto malformed;
    }

    PEEK_DISCARD(ETH_ADDR_LEN); /* Skip source address */
    if (PEEK_UINT16 != ETHERTYPE_LLDP) {
        VLOG_INFO("non LLDP frame received on %s", hardware->h_ifname);
        goto malformed;
    }

    while (length && !gotend) {
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
        /* Check order for mandatory TLVs */
        tlv_count++;
        switch (tlv_type) {
        case LLDP_TLV_CHASSIS_ID:
            if (tlv_count != 1) {
                VLOG_WARN("first TLV should be a chassis ID on %s, not %d",
                          hardware->h_ifname, tlv_type);
                goto malformed;
            }
            break;
        case LLDP_TLV_PORT_ID:
            if (tlv_count != 2) {
                VLOG_WARN("second TLV should be a port ID on %s, not %d",
                          hardware->h_ifname, tlv_type);
                goto malformed;
            }
            break;
        case LLDP_TLV_TTL:
            if (tlv_count != 3) {
                VLOG_WARN("third TLV should be a TTL on %s, not %d",
                          hardware->h_ifname, tlv_type);
                goto malformed;
            }
            break;
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
            gotend = true;
            break;

        case LLDP_TLV_CHASSIS_ID:
        case LLDP_TLV_PORT_ID:
            CHECK_TLV_SIZE(2, "Port/Chassis Id");
            CHECK_TLV_MAX_SIZE(256, "Port/Chassis Id");
            tlv_subtype = PEEK_UINT8;
            if (tlv_subtype == 0 || tlv_subtype > 7) {
                VLOG_WARN("unknown subtype for tlv id received on %s",
                          hardware->h_ifname);
                goto malformed;
            }
            b = xzalloc(tlv_size - 1);
            PEEK_BYTES(b, tlv_size - 1);
            if (tlv_type == LLDP_TLV_PORT_ID) {
                if (port->p_id != NULL) {
                    VLOG_WARN("Port ID TLV received twice on %s",
                              hardware->h_ifname);
                    free(b);
                    goto malformed;
                }
                port->p_id_subtype = tlv_subtype;
                port->p_id = b;
                port->p_id_len = tlv_size - 1;
            } else {
                if (chassis->c_id != NULL) {
                    VLOG_WARN("Chassis ID TLV received twice on %s",
                              hardware->h_ifname);
                    free(b);
                    goto malformed;
                }
                chassis->c_id_subtype = tlv_subtype;
                chassis->c_id = b;
                chassis->c_id_len = tlv_size - 1;
            }
            break;

        case LLDP_TLV_TTL:
            if (ttl_received) {
                VLOG_WARN("TTL TLV received twice on %s",
                          hardware->h_ifname);
                goto malformed;
            }
            CHECK_TLV_SIZE(2, "TTL");
            chassis->c_ttl = PEEK_UINT16;
            ttl_received = true;
            break;

        case LLDP_TLV_PORT_DESCR:
        case LLDP_TLV_SYSTEM_NAME:
        case LLDP_TLV_SYSTEM_DESCR:
            if (tlv_size < 1) {
                VLOG_DBG("empty tlv received on %s", hardware->h_ifname);
                break;
            }
            b = xzalloc(tlv_size + 1);
            PEEK_BYTES(b, tlv_size);
            if (tlv_type == LLDP_TLV_PORT_DESCR) {
                free(port->p_descr);
                port->p_descr = b;
            } else if (tlv_type == LLDP_TLV_SYSTEM_NAME) {
                free(chassis->c_name);
                chassis->c_name = b;
            } else {
                free(chassis->c_descr);
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
            if (addr_str_length > sizeof(addr_str_buffer)) {
                VLOG_WARN("too large management address on %s",
                          hardware->h_ifname);
                goto malformed;
            }
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
            ovs_list_push_back(&chassis->c_mgmt, &mgmt->m_entries);
            break;

        case LLDP_TLV_ORG:
            CHECK_TLV_SIZE(1 + sizeof orgid, "Organisational");
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
                u_int32_t aa_element_dword;
                u_int16_t aa_system_id_word;
                u_int16_t aa_status_vlan_word;
                u_int8_t aa_element_state;
                unsigned short num_mappings;

                switch(tlv_subtype) {
                case LLDP_TLV_AA_ELEMENT_SUBTYPE:
                    PEEK_BYTES(&msg_auth_digest, sizeof msg_auth_digest);

                    aa_element_dword = PEEK_UINT32;

                    /* Type is first 6 most-significant bits of
                     * aa_element_dword */
                    port->p_element.type = aa_element_dword >> 26;

                    /* State is 6 most significant bits of aa_element_dword */
                    aa_element_state = (aa_element_dword >> 20) & 0x3F;

                    /* vlan tagging requirement is the bit 1(left to right)
                     * of the 6 bits state (1 based) */
                    port->p_element.vlan_tagging =
                        (aa_element_state >> 5) & 0x1;

                    /* Automatic provision mode is the bit 2/3(left to right)
                     * of the 6 bits state (1 based) */
                    port->p_element.auto_prov_mode =
                        (aa_element_state >> 3) & 0x3;

                    /* mgmt_vlan is the 12 bits of aa_element_dword from
                     * bit 12 */
                    port->p_element.mgmt_vlan =
                        (aa_element_dword >> 8) & 0xFFF;
                    VLOG_INFO("Element type: %X, vlan tagging %X, "
                              "auto prov mode %x, Mgmt vlan: %X",
                              port->p_element.type,
                              port->p_element.vlan_tagging,
                              port->p_element.auto_prov_mode,
                              port->p_element.mgmt_vlan);

                    PEEK_BYTES(&port->p_element.system_id.system_mac,
                               sizeof port->p_element.system_id.system_mac);
                    VLOG_INFO("System mac: "ETH_ADDR_FMT,
                        ETH_ADDR_ARGS(port->p_element.system_id.system_mac));
                    aa_system_id_word = PEEK_UINT16;
                    port->p_element.system_id.conn_type =
                        aa_system_id_word >> 13;
                    port->p_element.system_id.rsvd = aa_system_id_word &
                        0x03FF;
                    PEEK_BYTES(&port->p_element.system_id.rsvd2,
                               sizeof port->p_element.system_id.rsvd2);
                    break;

                case LLDP_TLV_AA_ISID_VLAN_ASGNS_SUBTYPE:
                    PEEK_BYTES(&msg_auth_digest, sizeof msg_auth_digest);

                    /* Subtract off tlv type and length (2Bytes) + OUI (3B) +
                     * Subtype (1B) + MSG DIGEST (32B).
                     */
                    num_mappings = tlv_size - 4 -
                        LLDP_TLV_AA_ISID_VLAN_DIGEST_LENGTH;
                    if (num_mappings % 5 != 0) {
                        VLOG_INFO("malformed vlan-isid mappings tlv received");
                        goto malformed;
                    }

                    num_mappings /= 5; /* Each mapping is 5 Bytes */
                    for(; num_mappings > 0; num_mappings--) {
                        uint8_t isid[3];

                        isid_vlan_map = xzalloc(sizeof *isid_vlan_map);
                        aa_status_vlan_word = PEEK_UINT16;

                        /* Status is first 4 most-significant bits. */
                        isid_vlan_map->isid_vlan_data.status =
                            aa_status_vlan_word >> 12;

                        /* Vlan is last 12 bits */
                        isid_vlan_map->isid_vlan_data.vlan =
                            aa_status_vlan_word & 0x0FFF;
                        PEEK_BYTES(isid, 3);
                        isid_vlan_map->isid_vlan_data.isid =
                            (isid[0] << 16) | (isid[1] << 8) | isid[2];
                        ovs_list_push_back(&port->p_isid_vlan_maps,
                                       &isid_vlan_map->m_entries);
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
            hardware->h_rx_unrecognized_cnt++;
            goto malformed;
        }
        if (pos > tlv + tlv_size) {
            VLOG_WARN("BUG: already past TLV!");
            goto malformed;
        }
        PEEK_DISCARD(tlv + tlv_size - pos);
    }

    /* Some random check */
    if (!chassis->c_id || !port->p_id || !ttl_received || !gotend) {
        VLOG_WARN("some mandatory tlv are missing for frame received "
                  "on %s", hardware->h_ifname);
        goto malformed;
    }
    *newchassis = chassis;
    *newport = port;
    return 1;

malformed:
    lldpd_chassis_cleanup(chassis, true);
    lldpd_port_cleanup(port, true);
    free(port);
    return -1;
}

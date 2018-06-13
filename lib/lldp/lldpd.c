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

#include <config.h>
#include "lldpd.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef _WIN32
#include <grp.h>
#include <libgen.h>
#include <pwd.h>
#include <sys/select.h>
#include <sys/utsname.h>
#endif
#include "compiler.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "packets.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(lldpd);

static struct protocol protos[] =
{
    { LLDPD_MODE_LLDP, 1, "LLDP", 'l', lldp_send, lldp_decode, NULL,
      LLDP_MULTICAST_ADDR },
    { 0, 0, "any", ' ', NULL, NULL, NULL,
      { { { 0,0,0,0,0,0 } } } }
};

void lldpd_assign_cfg_to_protocols(struct lldpd *cfg)
{
    cfg->g_protocols = protos;
}

struct lldpd_hardware *
lldpd_get_hardware(struct lldpd *cfg, char *name, int index,
                   struct lldpd_ops *ops)
{
    struct lldpd_hardware *hw;

    LIST_FOR_EACH (hw, h_entries, &cfg->g_hardware) {
        if (!strcmp(hw->h_ifname, name) && hw->h_ifindex == index
            && (!ops || ops == hw->h_ops)) {
            return hw;
        }
    }

    return NULL;
}

struct lldpd_hardware *
lldpd_alloc_hardware(struct lldpd *cfg, char *name, int index)
{
    struct lldpd_hardware *hw;

    VLOG_DBG("allocate a new local hardware interface (%s)", name);

    hw = xzalloc(sizeof *hw);
    hw->h_cfg = cfg;
    ovs_strlcpy(hw->h_ifname, name, sizeof hw->h_ifname);
    hw->h_ifindex = index;
    hw->h_lport.p_chassis = CONTAINER_OF(ovs_list_front(&cfg->g_chassis),
                                         struct lldpd_chassis, list);
    hw->h_lport.p_chassis->c_refcount++;
    ovs_list_init(&hw->h_rports);

    return hw;
}

struct lldpd_mgmt *
lldpd_alloc_mgmt(int family, void *addrptr, size_t addrsize, u_int32_t iface)
{
    struct lldpd_mgmt *mgmt;

    VLOG_DBG("allocate a new management address (family: %d)", family);

    if (family <= LLDPD_AF_UNSPEC || family >= LLDPD_AF_LAST) {
        errno = EAFNOSUPPORT;
        return NULL;
    }
    if (addrsize > LLDPD_MGMT_MAXADDRSIZE) {
        errno = EOVERFLOW;
        return NULL;
    }
    mgmt = xzalloc(sizeof *mgmt);
    mgmt->m_family = family;
    memcpy(&mgmt->m_addr, addrptr, addrsize);
    mgmt->m_addrsize = addrsize;
    mgmt->m_iface = iface;

    return mgmt;
}

void
lldpd_hardware_cleanup(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
    VLOG_DBG("cleanup hardware port %s", hardware->h_ifname);

    lldpd_port_cleanup(&hardware->h_lport, true);
    if (hardware->h_ops && hardware->h_ops->cleanup) {
        hardware->h_ops->cleanup(cfg, hardware);
    }
    free(hardware);
}

void
lldpd_cleanup(struct lldpd *cfg)
{
    struct lldpd_hardware *hw, *hw_next;
    struct lldpd_chassis *chassis, *chassis_next;

    VLOG_DBG("cleanup all ports");

    LIST_FOR_EACH_SAFE (hw, hw_next, h_entries, &cfg->g_hardware) {
        if (!hw->h_flags) {
            ovs_list_remove(&hw->h_entries);
            lldpd_remote_cleanup(hw, NULL, true);
            lldpd_hardware_cleanup(cfg, hw);
        } else {
            lldpd_remote_cleanup(hw, NULL, false);
        }
    }

    VLOG_DBG("cleanup all chassis");

    LIST_FOR_EACH_SAFE (chassis, chassis_next, list, &cfg->g_chassis) {
        if (chassis->c_refcount == 0) {
            ovs_list_remove(&chassis->list);
            lldpd_chassis_cleanup(chassis, 1);
        }
    }
}

/* Update chassis `ochassis' with values from `chassis'. The later one is not
 * expected to be part of a list! It will also be wiped from memory.
 */
static void
lldpd_move_chassis(struct lldpd_chassis *ochassis,
    struct lldpd_chassis *chassis)
{
    struct lldpd_mgmt *mgmt;
    int refcount = ochassis->c_refcount;
    int index = ochassis->c_index;
    struct ovs_list listcopy;

    /* We want to keep refcount, index and list stuff from the current chassis
     */
    memcpy(&listcopy, &ochassis->list, sizeof listcopy);
    lldpd_chassis_cleanup(ochassis, 0);

    /* Make the copy. */
    /* WARNING: this is a kludgy hack, we need in-place copy and cannot use
     * marshaling.
     */
    memcpy(ochassis, chassis, sizeof *ochassis);
    ovs_list_init(&ochassis->c_mgmt);

    /* Copy of management addresses */
    LIST_FOR_EACH_POP (mgmt, m_entries, &chassis->c_mgmt) {
        ovs_list_insert(&ochassis->c_mgmt, &mgmt->m_entries);
    }

    /* Restore saved values */
    ochassis->c_refcount = refcount;
    ochassis->c_index = index;
    memcpy(&ochassis->list, &listcopy, sizeof ochassis->list);

    /* Get rid of the new chassis */
    free(chassis);
}

static int
lldpd_guess_type(struct lldpd *cfg, char *frame, int s)
{
    int i;

    if (s < ETH_ADDR_LEN) {
        return -1;
    }

    for (i = 0; cfg->g_protocols[i].mode != 0; i++) {
        if (!cfg->g_protocols[i].enabled) {
            continue;
        }
        if (cfg->g_protocols[i].guess == NULL) {
            if (memcmp(frame, &cfg->g_protocols[i].mac, ETH_ADDR_LEN) == 0) {
                VLOG_DBG("guessed protocol is %s (from MAC address)",
                    cfg->g_protocols[i].name);
                return cfg->g_protocols[i].mode;
            }
        } else {
            if (cfg->g_protocols[i].guess(frame, s)) {
                VLOG_DBG("guessed protocol is %s (from detector function)",
                    cfg->g_protocols[i].name);
                return cfg->g_protocols[i].mode;
            }
        }
    }

    return -1;
}

static void
lldpd_decode(struct lldpd *cfg, char *frame, int s,
             struct lldpd_hardware *hw)
{
    size_t listsize, i;
    struct lldpd_chassis *chassis, *ochassis = NULL;
    struct lldpd_port *port, *oport;
    int guess = LLDPD_MODE_LLDP;
    struct eth_header eheader;
    int count = 0;
    bool found = false;

    VLOG_DBG("decode a received frame on %s size %d", hw->h_ifname,s);

    if (s < sizeof(struct eth_header) + 4) {
        /* Too short, just discard it */
        return;
    }

    /* Decapsulate VLAN frames */
    memcpy(&eheader, frame, sizeof eheader);
    if (eheader.eth_type == htons(ETH_TYPE_VLAN)) {
        /* VLAN decapsulation means to shift 4 bytes left the frame from
         * offset 2 * ETH_ADDR_LEN
         */
        memmove(frame + 2 * ETH_ADDR_LEN, frame + 2 * ETH_ADDR_LEN + 4,
                s - 2 * ETH_ADDR_LEN);
        s -= 4;
    }

    LIST_FOR_EACH (oport, p_entries, &hw->h_rports) {
        if (oport->p_lastframe &&
            oport->p_lastframe->size == s &&
            !memcmp(oport->p_lastframe->frame, frame, s)) {
            /* Already received the same frame */
            VLOG_DBG("duplicate frame, no need to decode");
            oport->p_lastupdate = time_now();
            return;
        }
    }

    guess = lldpd_guess_type(cfg, frame, s);
    VLOG_DBG("guessed %d enabled:%d", guess, cfg->g_protocols[0].enabled);

    for (i = 0; cfg->g_protocols[i].mode != 0; i++) {
        if (!cfg->g_protocols[i].enabled) {
            continue;
        }
        if (cfg->g_protocols[i].mode == guess) {
            VLOG_DBG("using decode function for %s protocol",
                cfg->g_protocols[i].name);
            if (cfg->g_protocols[i].decode(cfg, frame, s, hw, &chassis, &port)
                    == -1) {
                VLOG_DBG("function for %s protocol did not "
                         "decode this frame",
                         cfg->g_protocols[i].name);
                return;
            }
            chassis->c_protocol = port->p_protocol = cfg->g_protocols[i].mode;
            break;
      }
      VLOG_DBG(" %"PRIuSIZE "mode:%d enabled:%d",
               i, cfg->g_protocols[i].mode, cfg->g_protocols[i].enabled);
    }
    if (cfg->g_protocols[i].mode == 0) {
        VLOG_DBG("unable to guess frame type on %s", hw->h_ifname);
        return;
    }

    /* Do we already have the same MSAP somewhere? */
    VLOG_DBG("search for the same MSAP");

    LIST_FOR_EACH (oport, p_entries, &hw->h_rports) {
        if (port->p_protocol == oport->p_protocol) {
            count++;
            if (port->p_id_subtype == oport->p_id_subtype &&
                port->p_id_len == oport->p_id_len &&
                !memcmp(port->p_id, oport->p_id, port->p_id_len) &&
                chassis->c_id_subtype == oport->p_chassis->c_id_subtype &&
                chassis->c_id_len == oport->p_chassis->c_id_len &&
                !memcmp(chassis->c_id, oport->p_chassis->c_id,
                        chassis->c_id_len)) {
                ochassis = oport->p_chassis;
                VLOG_DBG("MSAP is already known");
                found = true;
                break;
            }
        }
    }

    if (!found) {
       oport = NULL;
    }

    /* Do we have room for a new MSAP? */
    if (!oport && cfg->g_config.c_max_neighbors) {
        if (count == (cfg->g_config.c_max_neighbors - 1)) {
            VLOG_DBG("max neighbors %d reached for port %s, "
                     "dropping any new ones silently",
                     cfg->g_config.c_max_neighbors,
                     hw->h_ifname);
        } else if (count > cfg->g_config.c_max_neighbors - 1) {
            VLOG_DBG("too many neighbors for port %s, drop this new one",
                     hw->h_ifname);
            lldpd_port_cleanup(port, true);
            lldpd_chassis_cleanup(chassis, true);
            free(port);
            return;
        }
    }

    /* No, but do we already know the system? */
    if (!oport) {
        found = false;
        VLOG_DBG("MSAP is unknown, search for the chassis");

        LIST_FOR_EACH (ochassis, list, &cfg->g_chassis) {
                if ((chassis->c_protocol == ochassis->c_protocol) &&
                    (chassis->c_id_subtype == ochassis->c_id_subtype) &&
                    (chassis->c_id_len == ochassis->c_id_len) &&
                    (memcmp(chassis->c_id, ochassis->c_id,
                    chassis->c_id_len) == 0)) {
                    found = true;
                    break;
                }
        }

        if (!found) {
            ochassis = NULL;
        }
    }

    if (oport) {
        /* The port is known, remove it before adding it back */
        ovs_list_remove(&oport->p_entries);
        lldpd_port_cleanup(oport, 1);
        free(oport);
    }

    if (ochassis) {
        lldpd_move_chassis(ochassis, chassis);
        chassis = ochassis;
    } else {
        /* Chassis not known, add it */
        VLOG_DBG("unknown chassis, add it to the list");
        chassis->c_index = ++cfg->g_lastrid;
        chassis->c_refcount = 0;
        ovs_list_push_back(&cfg->g_chassis, &chassis->list);
        listsize = ovs_list_size(&cfg->g_chassis);
        VLOG_DBG("%"PRIuSIZE " different systems are known", listsize);
    }

    /* Add port */
    port->p_lastchange = port->p_lastupdate = time_now();
    port->p_lastframe = xmalloc(s + sizeof(struct lldpd_frame));
    port->p_lastframe->size = s;
    memcpy(port->p_lastframe->frame, frame, s);
    ovs_list_insert(&hw->h_rports, &port->p_entries);

    port->p_chassis = chassis;
    port->p_chassis->c_refcount++;
    /* Several cases are possible :
     *   1. chassis is new, its refcount was 0. It is now attached
     *      to this port, its refcount is 1.
     *   2. chassis already exists and was attached to another
     *      port, we increase its refcount accordingly.
     *   3. chassis already exists and was attached to the same
     *      port, its refcount was decreased with
     *      lldpd_port_cleanup() and is now increased again.
     *
     * In all cases, if the port already existed, it has been
     * freed with lldpd_port_cleanup() and therefore, the refcount
     * of the chassis that was attached to it is decreased.
     */
    i = ovs_list_size(&hw->h_rports);
    VLOG_DBG("%"PRIuSIZE " neighbors for %s", i, hw->h_ifname);

    if (!oport)  {
        hw->h_insert_cnt++;
    }

    return;
}

static void
lldpd_hide_ports(struct lldpd *cfg,
                 struct lldpd_hardware *hw,
                 int mask) {
    struct lldpd_port *port;
    int protocols[LLDPD_MODE_MAX + 1];
    bool found = false;
    int i, j, k;
    unsigned int min;

    VLOG_DBG("apply smart filter for port %s", hw->h_ifname);

    /* Compute the number of occurrences of each protocol */
    for (i = 0; i <= LLDPD_MODE_MAX; i++) {
        protocols[i] = 0;
    }

    LIST_FOR_EACH (port, p_entries, &hw->h_rports) {
        protocols[port->p_protocol]++;
    }

    /* Turn the protocols[] array into an array of
     * enabled/disabled protocols. 1 means enabled, 0
     * means disabled.
     */
    min = (unsigned int) - 1;
    for (i = 0; i <= LLDPD_MODE_MAX; i++) {
        if (protocols[i] && (protocols[i] < min)) {
            min = protocols[i];
        }
    }
    for (i = 0; i <= LLDPD_MODE_MAX; i++) {
        if (protocols[i] == min && !found) {
            /* If we need a tie breaker, we take the first protocol only */
            if (cfg->g_config.c_smart & mask &
                (SMART_OUTGOING_ONE_PROTO | SMART_INCOMING_ONE_PROTO)) {
                found = true;
            }
            protocols[i] = 1;
        } else {
            protocols[i] = 0;
        }
    }

    /* We set the p_hidden flag to 1 if the protocol is disabled */
    LIST_FOR_EACH (port, p_entries, &hw->h_rports) {
        if (mask == SMART_OUTGOING) {
            port->p_hidden_out = protocols[port->p_protocol] ? false : true;
        } else {
            port->p_hidden_in = protocols[port->p_protocol] ? false : true;
        }
    }

    /* If we want only one neighbor, we take the first one */
    if (cfg->g_config.c_smart & mask &
        (SMART_OUTGOING_ONE_NEIGH | SMART_INCOMING_ONE_NEIGH)) {
        found = false;

        LIST_FOR_EACH (port, p_entries, &hw->h_rports) {
            if (mask == SMART_OUTGOING) {
                if (found) {
                    port->p_hidden_out = true;
                }
                if (!port->p_hidden_out) {
                    found = true;
                }
            }
            if (mask == SMART_INCOMING) {
                if (found) {
                    port->p_hidden_in = true;
                }
                if (!port->p_hidden_in) {
                    found = true;
                }
            }
        }
    }

    /* Print a debug message summarizing the operation */
    for (i = 0; i <= LLDPD_MODE_MAX; i++) {
        protocols[i] = 0;
    }

    k = j = 0;
    LIST_FOR_EACH (port, p_entries, &hw->h_rports) {
        if (!((mask == SMART_OUTGOING && port->p_hidden_out) ||
              (mask == SMART_INCOMING && port->p_hidden_in))) {
            k++;
            protocols[port->p_protocol] = 1;
        }
        j++;
    }

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds buffer = DS_EMPTY_INITIALIZER;
        for (struct protocol *p = cfg->g_protocols; p->mode; p++) {
            if (p->enabled && protocols[p->mode]) {
                if (buffer.length) {
                    ds_put_cstr(&buffer, ", ");
                }
                ds_put_cstr(&buffer, p->name);
            }
        }
        VLOG_DBG("%s: %s: %d visible neighbors (out of %d)",
                 hw->h_ifname,
                 (mask == SMART_OUTGOING) ? "out filter" : "in filter",
                 k, j);
        VLOG_DBG("%s: protocols: %s",
                 hw->h_ifname,
                 buffer.length ? ds_cstr(&buffer) : "(none)");
        ds_destroy(&buffer);
    }
}

/* Hide unwanted ports depending on smart mode set by the user */
static void
lldpd_hide_all(struct lldpd *cfg)
{
    struct lldpd_hardware *hw;

    if (!cfg->g_config.c_smart) {
        return;
    }

    VLOG_DBG("apply smart filter results on all ports");

    LIST_FOR_EACH (hw, h_entries, &cfg->g_hardware) {
        if (cfg->g_config.c_smart & SMART_INCOMING_FILTER) {
            lldpd_hide_ports(cfg, hw, SMART_INCOMING);
        }
        if (cfg->g_config.c_smart & SMART_OUTGOING_FILTER) {
            lldpd_hide_ports(cfg, hw, SMART_OUTGOING);
        }
    }
}

void
lldpd_recv(struct lldpd *cfg,
           struct lldpd_hardware *hw,
           char *buffer,
           size_t bufSize)
{
    int n = bufSize;

    VLOG_DBG("receive a frame on %s", hw->h_ifname);
    if (cfg->g_config.c_paused) {
        VLOG_DBG("paused, ignore the frame on %s", hw->h_ifname);
        return;
    }
    hw->h_rx_cnt++;
    VLOG_DBG("decode received frame on %s h_rx_cnt=%" PRIu64,
             hw->h_ifname, hw->h_rx_cnt);
    lldpd_decode(cfg, buffer, n, hw);
    lldpd_hide_all(cfg); /* Immediatly hide */
}

uint32_t
lldpd_send(struct lldpd_hardware *hw, struct dp_packet *p)
{
    struct lldpd *cfg = hw->h_cfg;
    struct lldpd_port *port;
    int i, sent = 0;
    int lldp_size = 0;

    if (cfg->g_config.c_receiveonly || cfg->g_config.c_paused) {
        return 0;
    }
#ifndef _WIN32
    if ((hw->h_flags & IFF_RUNNING) == 0) {
        return 0;
    }
#endif

    for (i = 0; cfg->g_protocols[i].mode != 0; i++) {
        if (!cfg->g_protocols[i].enabled) {
            continue;
        }

        /* We send only if we have at least one remote system
         * speaking this protocol or if the protocol is forced */
        if (cfg->g_protocols[i].enabled > 1) {
            if ((lldp_size = cfg->g_protocols[i].send(cfg, hw, p)) != -E2BIG) {
                sent++;
                continue;
            } else {
                VLOG_DBG("send PDU on %s failed E2BIG", hw->h_ifname);
                continue;
            }
        }

        LIST_FOR_EACH (port, p_entries, &hw->h_rports) {
            /* If this remote port is disabled, we don't consider it */
            if (port->p_hidden_out) {
                continue;
            }
            if (port->p_protocol == cfg->g_protocols[i].mode) {
                VLOG_DBG("send PDU on %s with protocol %s",
                         hw->h_ifname, cfg->g_protocols[i].name);
                lldp_size = cfg->g_protocols[i].send(cfg, hw, p);
                sent++;
                break;
            }
        }
    }

    if (!sent) {
        /* Nothing was sent for this port, let's speak the first
         * available protocol.
         */
        for (i = 0; cfg->g_protocols[i].mode != 0; i++) {
            if (!cfg->g_protocols[i].enabled) {
                continue;
            }
            VLOG_DBG("fallback to protocol %s for %s",
                     cfg->g_protocols[i].name, hw->h_ifname);
            lldp_size = cfg->g_protocols[i].send(cfg, hw, p);
            break;
        }
        if (cfg->g_protocols[i].mode == 0) {
            VLOG_WARN("no protocol enabled, dunno what to send");
        }
    }

    return lldp_size;
}

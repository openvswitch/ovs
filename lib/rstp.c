/*
 * Copyright (c) 2011-2015 M3S, Srl - Italy
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

/*
 * Rapid Spanning Tree Protocol (IEEE 802.1D-2004) public interface.
 *
 * Authors:
 *         Martino Fornasa <mf@fornasa.it>
 *         Daniele Venturino <daniele.venturino@m3s.it>
 *         Carlo Andreotti <c.andreotti@m3s.it>
 *
 * References to IEEE 802.1D-2004 standard are enclosed in square brackets.
 * E.g. [17.3], [Table 17-1], etc.
 *
 */

#include <config.h>

#include "rstp.h"
#include "rstp-common.h"
#include "rstp-state-machines.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdlib.h>
#include "byte-order.h"
#include "connectivity.h"
#include "openvswitch/ofpbuf.h"
#include "ofproto/ofproto.h"
#include "dp-packet.h"
#include "packets.h"
#include "seq.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(rstp);

struct ovs_mutex rstp_mutex = OVS_MUTEX_INITIALIZER;

static struct ovs_list all_rstps__ = OVS_LIST_INITIALIZER(&all_rstps__);
static struct ovs_list *const all_rstps OVS_GUARDED_BY(rstp_mutex) = &all_rstps__;

/* Internal use only. */
static void rstp_set_bridge_address__(struct rstp *, rstp_identifier)
    OVS_REQUIRES(rstp_mutex);
static void rstp_set_bridge_priority__(struct rstp *, int new_priority)
    OVS_REQUIRES(rstp_mutex);
static void rstp_set_bridge_ageing_time__(struct rstp *, int new_ageing_time)
    OVS_REQUIRES(rstp_mutex);
static void rstp_set_bridge_force_protocol_version__(struct rstp *,
                                                     enum rstp_force_protocol_version)
    OVS_REQUIRES(rstp_mutex);
static void rstp_set_bridge_hello_time__(struct rstp *)
    OVS_REQUIRES(rstp_mutex);
static void rstp_set_bridge_max_age__(struct rstp *, int new_max_age)
    OVS_REQUIRES(rstp_mutex);
static void rstp_set_bridge_forward_delay__(struct rstp *, int new_forward_delay)
    OVS_REQUIRES(rstp_mutex);
static void rstp_set_bridge_transmit_hold_count__(struct rstp *,
                                                  int new_transmit_hold_count)
    OVS_REQUIRES(rstp_mutex);
static void rstp_set_bridge_migrate_time__(struct rstp *)
    OVS_REQUIRES(rstp_mutex);
static void rstp_set_bridge_times__(struct rstp *, int new_forward_delay,
                                    int new_hello_time, int new_max_age,
                                    int new_message_age)
    OVS_REQUIRES(rstp_mutex);

static struct rstp_port *rstp_get_port__(struct rstp *rstp,
                                         uint16_t port_number)
    OVS_REQUIRES(rstp_mutex);
static void set_port_id__(struct rstp_port *)
    OVS_REQUIRES(rstp_mutex);
static void update_port_enabled__(struct rstp_port *)
    OVS_REQUIRES(rstp_mutex);
static void set_bridge_priority__(struct rstp *)
    OVS_REQUIRES(rstp_mutex);
static void reinitialize_rstp__(struct rstp *)
    OVS_REQUIRES(rstp_mutex);
static bool is_port_number_available__(struct rstp *, int, struct rstp_port *)
    OVS_REQUIRES(rstp_mutex);
static uint16_t rstp_first_free_number__(struct rstp *, struct rstp_port *)
    OVS_REQUIRES(rstp_mutex);
static void rstp_initialize_port_defaults__(struct rstp_port *)
    OVS_REQUIRES(rstp_mutex);
static void rstp_port_set_priority__(struct rstp_port *, int priority)
    OVS_REQUIRES(rstp_mutex);
static void rstp_port_set_port_number__(struct rstp_port *,
                                        uint16_t port_number)
    OVS_REQUIRES(rstp_mutex);
static void rstp_port_set_path_cost__(struct rstp_port *, uint32_t path_cost)
    OVS_REQUIRES(rstp_mutex);
static void rstp_port_set_administrative_bridge_port__(struct rstp_port *,
                                                       uint8_t admin_port_state,
                                                       bool initializing)
    OVS_REQUIRES(rstp_mutex);
static void rstp_port_set_admin_edge__(struct rstp_port *, bool admin_edge)
    OVS_REQUIRES(rstp_mutex);
static void rstp_port_set_auto_edge__(struct rstp_port *, bool auto_edge)
    OVS_REQUIRES(rstp_mutex);
static void rstp_port_set_admin_point_to_point_mac__(struct rstp_port *,
        enum rstp_admin_point_to_point_mac_state admin_p2p_mac_state)
    OVS_REQUIRES(rstp_mutex);
static void rstp_port_set_mcheck__(struct rstp_port *, bool mcheck)
    OVS_REQUIRES(rstp_mutex);
static void reinitialize_port__(struct rstp_port *p)
    OVS_REQUIRES(rstp_mutex);
static bool rstp_is_root_bridge__(const struct rstp *rstp)
    OVS_REQUIRES(rstp_mutex);
static uint32_t rstp_get_root_path_cost__(const struct rstp *rstp)
    OVS_REQUIRES(rstp_mutex);
static struct rstp_port *rstp_get_root_port__(const struct rstp *rstp)
    OVS_REQUIRES(rstp_mutex);
static rstp_identifier rstp_get_root_id__(const struct rstp *rstp)
    OVS_REQUIRES(rstp_mutex);
static void rstp_unixctl_tcn(struct unixctl_conn *, int argc,
                             const char *argv[], void *aux);
static void rstp_unixctl_show(struct unixctl_conn *, int argc,
                              const char *argv[], void *aux);

const char *
rstp_state_name(enum rstp_state state)
{
    switch (state) {
    case RSTP_DISABLED:
        return "Disabled";
    case RSTP_LEARNING:
        return "Learning";
    case RSTP_FORWARDING:
        return "Forwarding";
    case RSTP_DISCARDING:
        return "Discarding";
    default:
        return "Unknown";
    }
}

const char *
rstp_port_role_name(enum rstp_port_role role)
{
    switch (role) {
    case ROLE_ROOT:
        return "Root";
    case ROLE_DESIGNATED:
        return "Designated";
    case ROLE_ALTERNATE:
        return "Alternate";
    case ROLE_BACKUP:
        return "Backup";
    case ROLE_DISABLED:
        return "Disabled";
    default:
        return "Unknown";
    }
}

/* Caller has to hold a reference to prevent 'rstp' from being deleted
 * while taking a new reference. */
struct rstp *
rstp_ref(struct rstp *rstp)
    OVS_EXCLUDED(rstp_mutex)
{
    if (rstp) {
        ovs_refcount_ref(&rstp->ref_cnt);
    }
    return rstp;
}

/* Frees RSTP struct when reference count reaches zero. */
void
rstp_unref(struct rstp *rstp)
    OVS_EXCLUDED(rstp_mutex)
{
    if (rstp && ovs_refcount_unref_relaxed(&rstp->ref_cnt) == 1) {
        ovs_mutex_lock(&rstp_mutex);

        /* Each RSTP port points back to struct rstp without holding a
         * reference for that pointer.  This is OK as we never move
         * ports from one bridge to another, and holders always
         * release their ports before releasing the bridge.  This
         * means that there should be not ports at this time. */
        ovs_assert(hmap_is_empty(&rstp->ports));

        ovs_list_remove(&rstp->node);
        ovs_mutex_unlock(&rstp_mutex);
        hmap_destroy(&rstp->ports);
        free(rstp->name);
        free(rstp);
    }
}

/* Returns the port number.  Mutex is needed to guard against
 * concurrent reinitialization (which can temporarily clear the
 * port_number). */
int
rstp_port_get_number(const struct rstp_port *p)
    OVS_EXCLUDED(rstp_mutex)
{
    int number;

    ovs_mutex_lock(&rstp_mutex);
    number = p->port_number;
    ovs_mutex_unlock(&rstp_mutex);

    return number;
}

/* Decrements the State Machines' timers. */
void
rstp_tick_timers(struct rstp *rstp)
    OVS_EXCLUDED(rstp_mutex)
{
    ovs_mutex_lock(&rstp_mutex);
    decrease_rstp_port_timers__(rstp);
    ovs_mutex_unlock(&rstp_mutex);
}

/* Processes an incoming BPDU. */
void
rstp_port_received_bpdu(struct rstp_port *rp, const void *bpdu,
                        size_t bpdu_size)
    OVS_EXCLUDED(rstp_mutex)
{
    ovs_mutex_lock(&rstp_mutex);
    /* Only process packets on ports that have RSTP enabled. */
    if (rp && rp->rstp_state != RSTP_DISABLED) {
        process_received_bpdu__(rp, bpdu, bpdu_size);
    }
    ovs_mutex_unlock(&rstp_mutex);
}

void
rstp_init(void)
    OVS_EXCLUDED(rstp_mutex)
{
    unixctl_command_register("rstp/tcn", "[bridge]", 0, 1, rstp_unixctl_tcn,
                             NULL);
    unixctl_command_register("rstp/show", "[bridge]", 0, 1, rstp_unixctl_show,
                             NULL);
}

/* Creates and returns a new RSTP instance that initially has no ports. */
struct rstp *
rstp_create(const char *name, rstp_identifier bridge_address,
            void (*send_bpdu)(struct dp_packet *bpdu, void *port_aux,
                              void *rstp_aux),
            void *aux)
    OVS_EXCLUDED(rstp_mutex)
{
    struct rstp *rstp;

    VLOG_DBG("Creating RSTP instance");

    rstp = xzalloc(sizeof *rstp);
    rstp->name = xstrdup(name);

    /* Initialize the ports map before calling any setters,
     * so that the state machines will see an empty ports map. */
    hmap_init(&rstp->ports);

    ovs_mutex_lock(&rstp_mutex);
    /* Set bridge address. */
    rstp_set_bridge_address__(rstp, bridge_address);
    /* Set default parameters values. */
    rstp_set_bridge_priority__(rstp, RSTP_DEFAULT_PRIORITY);
    rstp_set_bridge_ageing_time__(rstp, RSTP_DEFAULT_AGEING_TIME);
    rstp_set_bridge_force_protocol_version__(rstp, FPV_DEFAULT);
    rstp_set_bridge_forward_delay__(rstp, RSTP_DEFAULT_BRIDGE_FORWARD_DELAY);
    rstp_set_bridge_hello_time__(rstp);
    rstp_set_bridge_max_age__(rstp, RSTP_DEFAULT_BRIDGE_MAX_AGE);
    rstp_set_bridge_migrate_time__(rstp);
    rstp_set_bridge_transmit_hold_count__(rstp,
                                          RSTP_DEFAULT_TRANSMIT_HOLD_COUNT);
    rstp_set_bridge_times__(rstp, RSTP_DEFAULT_BRIDGE_FORWARD_DELAY,
                            RSTP_BRIDGE_HELLO_TIME,
                            RSTP_DEFAULT_BRIDGE_MAX_AGE, 0);
    rstp->send_bpdu = send_bpdu;
    rstp->aux = aux;
    rstp->changes = false;
    rstp->begin = true;
    rstp->old_root_aux = NULL;
    rstp->new_root_aux = NULL;

    ovs_refcount_init(&rstp->ref_cnt);

    ovs_list_push_back(all_rstps, &rstp->node);
    ovs_mutex_unlock(&rstp_mutex);

    VLOG_DBG("RSTP instance creation done");
    return rstp;
}

/* Called by rstp_set_bridge_address() and rstp_set_bridge_priority(),
 * it updates the bridge priority vector according to the values passed by
 * those setters.
 */
static void
set_bridge_priority__(struct rstp *rstp)
    OVS_REQUIRES(rstp_mutex)
{
    struct rstp_port *p;

    rstp->bridge_priority.root_bridge_id = rstp->bridge_identifier;
    rstp->bridge_priority.designated_bridge_id = rstp->bridge_identifier;
    VLOG_DBG("%s: new bridge identifier: "RSTP_ID_FMT"", rstp->name,
             RSTP_ID_ARGS(rstp->bridge_identifier));

    /* [17.13] When the bridge address changes, recalculates all priority
     * vectors.
     */
    HMAP_FOR_EACH (p, node, &rstp->ports) {
        p->selected = false;
        p->reselect = true;
    }
    rstp->changes = true;
    updt_roles_tree__(rstp);
}

/* Sets the bridge address. */
static void
rstp_set_bridge_address__(struct rstp *rstp, rstp_identifier bridge_address)
    OVS_REQUIRES(rstp_mutex)
{
    VLOG_DBG("%s: set bridge address to: "RSTP_ID_FMT"", rstp->name,
             RSTP_ID_ARGS(bridge_address));
    if (rstp->address != bridge_address) {
        rstp->address = bridge_address;
        rstp->bridge_identifier &= 0xffff000000000000ULL;
        rstp->bridge_identifier |= bridge_address;
        set_bridge_priority__(rstp);
    }
}

/* Sets the bridge address. */
void
rstp_set_bridge_address(struct rstp *rstp, rstp_identifier bridge_address)
    OVS_EXCLUDED(rstp_mutex)
{
    ovs_mutex_lock(&rstp_mutex);
    rstp_set_bridge_address__(rstp, bridge_address);
    ovs_mutex_unlock(&rstp_mutex);
}

const char *
rstp_get_name(const struct rstp *rstp)
    OVS_EXCLUDED(rstp_mutex)
{
    char *name;

    ovs_mutex_lock(&rstp_mutex);
    name = rstp->name;
    ovs_mutex_unlock(&rstp_mutex);
    return name;
}

rstp_identifier
rstp_get_bridge_id(const struct rstp *rstp)
    OVS_EXCLUDED(rstp_mutex)
{
    rstp_identifier bridge_id;

    ovs_mutex_lock(&rstp_mutex);
    bridge_id = rstp->bridge_identifier;
    ovs_mutex_unlock(&rstp_mutex);

    return bridge_id;
}

/* Sets the bridge priority. */
static void
rstp_set_bridge_priority__(struct rstp *rstp, int new_priority)
    OVS_REQUIRES(rstp_mutex)
{
    new_priority = ROUND_DOWN(new_priority, RSTP_PRIORITY_STEP);

    if (rstp->priority != new_priority
        && new_priority >= RSTP_MIN_PRIORITY
        && new_priority <= RSTP_MAX_PRIORITY) {
        VLOG_DBG("%s: set bridge priority to %d", rstp->name, new_priority);

        rstp->priority = new_priority;
        rstp->bridge_identifier &= 0x0000ffffffffffffULL;
        rstp->bridge_identifier |= (uint64_t)new_priority << 48;
        set_bridge_priority__(rstp);
    }
}

void
rstp_set_bridge_priority(struct rstp *rstp, int new_priority)
    OVS_EXCLUDED(rstp_mutex)
{
    ovs_mutex_lock(&rstp_mutex);
    rstp_set_bridge_priority__(rstp, new_priority);
    ovs_mutex_unlock(&rstp_mutex);
}

/* Sets the bridge ageing time. */
static void
rstp_set_bridge_ageing_time__(struct rstp *rstp, int new_ageing_time)
    OVS_REQUIRES(rstp_mutex)
{
    if (new_ageing_time >= RSTP_MIN_AGEING_TIME
        && new_ageing_time <= RSTP_MAX_AGEING_TIME) {
        VLOG_DBG("%s: set ageing time to %d", rstp->name, new_ageing_time);

        rstp->ageing_time = new_ageing_time;
    }
}

void
rstp_set_bridge_ageing_time(struct rstp *rstp, int new_ageing_time)
    OVS_EXCLUDED(rstp_mutex)
{
    ovs_mutex_lock(&rstp_mutex);
    rstp_set_bridge_ageing_time__(rstp, new_ageing_time);
    ovs_mutex_unlock(&rstp_mutex);
}

/* Reinitializes RSTP when switching from RSTP mode to STP mode
 * or vice versa.
 */
static void
reinitialize_rstp__(struct rstp *rstp)
    OVS_REQUIRES(rstp_mutex)
{
    struct rstp temp;
    static struct hmap ports;
    struct rstp_port *p;

    /* Copy rstp in temp */
    temp = *rstp;
    ports = rstp->ports;

    /* stop and clear rstp */
    memset(rstp, 0, sizeof(struct rstp));

    /* Initialize rstp. */
    rstp->name = temp.name;

    /* Initialize the ports hmap before calling any setters,
     * so that the state machines will see an empty ports list. */
    hmap_init(&rstp->ports);

    /* Set bridge address. */
    rstp_set_bridge_address__(rstp, temp.address);
    /* Set default parameters values. */
    rstp_set_bridge_priority__(rstp, RSTP_DEFAULT_PRIORITY);
    rstp_set_bridge_ageing_time__(rstp, RSTP_DEFAULT_AGEING_TIME);
    rstp_set_bridge_forward_delay__(rstp, RSTP_DEFAULT_BRIDGE_FORWARD_DELAY);
    rstp_set_bridge_hello_time__(rstp);
    rstp_set_bridge_max_age__(rstp, RSTP_DEFAULT_BRIDGE_MAX_AGE);
    rstp_set_bridge_migrate_time__(rstp);
    rstp_set_bridge_transmit_hold_count__(rstp,
                                          RSTP_DEFAULT_TRANSMIT_HOLD_COUNT);
    rstp_set_bridge_times__(rstp, RSTP_DEFAULT_BRIDGE_FORWARD_DELAY,
                            RSTP_BRIDGE_HELLO_TIME,
                            RSTP_DEFAULT_BRIDGE_MAX_AGE, 0);

    rstp->send_bpdu = temp.send_bpdu;
    rstp->aux = temp.aux;
    rstp->node = temp.node;
    rstp->changes = false;
    rstp->begin = true;

    /* Restore ports. */
    rstp->ports = ports;

    HMAP_FOR_EACH (p, node, &rstp->ports) {
        reinitialize_port__(p);
    }

    rstp->ref_cnt = temp.ref_cnt;
}

/* Sets the force protocol version parameter. */
static void
rstp_set_bridge_force_protocol_version__(struct rstp *rstp,
                enum rstp_force_protocol_version new_force_protocol_version)
    OVS_REQUIRES(rstp_mutex)
{
    if (new_force_protocol_version != rstp->force_protocol_version &&
            (new_force_protocol_version == FPV_STP_COMPATIBILITY ||
             new_force_protocol_version == FPV_DEFAULT)) {
        VLOG_DBG("%s: set bridge Force Protocol Version to %d", rstp->name,
                 new_force_protocol_version);

        /* [17.13] The Spanning Tree Protocol Entity shall be reinitialized,
         * as specified by the assertion of BEGIN (17.18.1) in the state
         * machine specification.
         */
        reinitialize_rstp__(rstp);
        rstp->force_protocol_version = new_force_protocol_version;
        if (rstp->force_protocol_version < 2) {
            rstp->stp_version = true;
            rstp->rstp_version = false;
        } else {
            rstp->stp_version = false;
            rstp->rstp_version = true;
        }
        rstp->changes = true;
        move_rstp__(rstp);
    }
}

void
rstp_set_bridge_force_protocol_version(struct rstp *rstp,
                enum rstp_force_protocol_version new_force_protocol_version)
    OVS_EXCLUDED(rstp_mutex)
{
    ovs_mutex_lock(&rstp_mutex);
    rstp_set_bridge_force_protocol_version__(rstp, new_force_protocol_version);
    ovs_mutex_unlock(&rstp_mutex);
}

/* Sets the bridge Hello Time parameter. */
static void
rstp_set_bridge_hello_time__(struct rstp *rstp)
    OVS_REQUIRES(rstp_mutex)
{
    VLOG_DBG("%s: set RSTP Hello Time to %d", rstp->name,
             RSTP_BRIDGE_HELLO_TIME);
    /* 2 is the only acceptable value. */
    rstp->bridge_hello_time = RSTP_BRIDGE_HELLO_TIME;
}

/* Sets the bridge max age parameter. */
static void
rstp_set_bridge_max_age__(struct rstp *rstp, int new_max_age)
    OVS_REQUIRES(rstp_mutex)
{
    if (rstp->bridge_max_age != new_max_age
        && new_max_age >= RSTP_MIN_BRIDGE_MAX_AGE
        && new_max_age <= RSTP_MAX_BRIDGE_MAX_AGE) {
        /* [17.13] */
        if ((2 * (rstp->bridge_forward_delay - 1) >= new_max_age)
            && (new_max_age >= 2 * rstp->bridge_hello_time)) {
            VLOG_DBG("%s: set RSTP bridge Max Age to %d", rstp->name,
                     new_max_age);

            rstp->bridge_max_age = new_max_age;
            rstp->bridge_times.max_age = new_max_age;
            rstp->changes = true;
            updt_roles_tree__(rstp);
        }
    }
}

void
rstp_set_bridge_max_age(struct rstp *rstp, int new_max_age)
    OVS_EXCLUDED(rstp_mutex)
{
    ovs_mutex_lock(&rstp_mutex);
    rstp_set_bridge_max_age__(rstp, new_max_age);
    ovs_mutex_unlock(&rstp_mutex);
}

/* Sets the bridge forward delay parameter. */
static void
rstp_set_bridge_forward_delay__(struct rstp *rstp, int new_forward_delay)
    OVS_REQUIRES(rstp_mutex)
{
    if (rstp->bridge_forward_delay != new_forward_delay
            && new_forward_delay >= RSTP_MIN_BRIDGE_FORWARD_DELAY
            && new_forward_delay <= RSTP_MAX_BRIDGE_FORWARD_DELAY) {
        if (2 * (new_forward_delay - 1) >= rstp->bridge_max_age) {
            VLOG_DBG("%s: set RSTP Forward Delay to %d", rstp->name,
                     new_forward_delay);
            rstp->bridge_forward_delay = new_forward_delay;
            rstp->bridge_times.forward_delay = new_forward_delay;
            rstp->changes = true;
            updt_roles_tree__(rstp);
        }
    }
}

void
rstp_set_bridge_forward_delay(struct rstp *rstp, int new_forward_delay)
    OVS_EXCLUDED(rstp_mutex)
{
    ovs_mutex_lock(&rstp_mutex);
    rstp_set_bridge_forward_delay__(rstp, new_forward_delay);
    ovs_mutex_unlock(&rstp_mutex);
}

/* Sets the bridge transmit hold count parameter. */
static void
rstp_set_bridge_transmit_hold_count__(struct rstp *rstp,
                                      int new_transmit_hold_count)
    OVS_REQUIRES(rstp_mutex)
{
    if (rstp->transmit_hold_count != new_transmit_hold_count
        && new_transmit_hold_count >= RSTP_MIN_TRANSMIT_HOLD_COUNT
        && new_transmit_hold_count <= RSTP_MAX_TRANSMIT_HOLD_COUNT) {
        struct rstp_port *p;

        VLOG_DBG("%s: set RSTP Transmit Hold Count to %d", rstp->name,
                 new_transmit_hold_count);
        /* Resetting txCount on all ports [17.13]. */

        rstp->transmit_hold_count = new_transmit_hold_count;
        HMAP_FOR_EACH (p, node, &rstp->ports) {
            p->tx_count = 0;
        }
    }
}

void
rstp_set_bridge_transmit_hold_count(struct rstp *rstp,
                                    int new_transmit_hold_count)
    OVS_EXCLUDED(rstp_mutex)
{
    ovs_mutex_lock(&rstp_mutex);
    rstp_set_bridge_transmit_hold_count__(rstp, new_transmit_hold_count);
    ovs_mutex_unlock(&rstp_mutex);
}

/* Sets the bridge migrate time parameter. */
static void
rstp_set_bridge_migrate_time__(struct rstp *rstp)
    OVS_REQUIRES(rstp_mutex)
{
    VLOG_DBG("%s: set RSTP Migrate Time to %d", rstp->name,
             RSTP_MIGRATE_TIME);
    /* 3 is the only acceptable value */
    rstp->migrate_time = RSTP_MIGRATE_TIME;
}

/* Sets the bridge times. */
static void
rstp_set_bridge_times__(struct rstp *rstp, int new_forward_delay,
                        int new_hello_time, int new_max_age,
                        int new_message_age)
    OVS_REQUIRES(rstp_mutex)
{
    VLOG_DBG("%s: set RSTP times to (%d, %d, %d, %d)", rstp->name,
             new_forward_delay, new_hello_time, new_max_age, new_message_age);
    if (new_forward_delay >= RSTP_MIN_BRIDGE_FORWARD_DELAY
        && new_forward_delay <= RSTP_MAX_BRIDGE_FORWARD_DELAY) {
        rstp->bridge_times.forward_delay = new_forward_delay;
    }
    if (new_hello_time == RSTP_BRIDGE_HELLO_TIME) {
        rstp->bridge_times.hello_time = new_hello_time;
    }
    if (new_max_age >= RSTP_MIN_BRIDGE_MAX_AGE
        && new_max_age <= RSTP_MAX_BRIDGE_MAX_AGE) {
        rstp->bridge_times.max_age = new_max_age;
    }
    rstp->bridge_times.message_age = new_message_age;
}

/* Sets the port id, it is called by rstp_port_set_port_number__() or
 * rstp_port_set_priority__().
 */
static void
set_port_id__(struct rstp_port *p)
    OVS_REQUIRES(rstp_mutex)
{
    struct rstp *rstp;

    rstp = p->rstp;
    /* [9.2.7] Port identifier. */
    p->port_id = p->port_number | (p->priority << 8);
    VLOG_DBG("%s: new RSTP port id "RSTP_PORT_ID_FMT"", rstp->name,
             p->port_id);
}

/* Sets the port priority. */
static void
rstp_port_set_priority__(struct rstp_port *port, int priority)
    OVS_REQUIRES(rstp_mutex)
{
    if (port->priority != priority
        && priority >= RSTP_MIN_PORT_PRIORITY
        && priority <= RSTP_MAX_PORT_PRIORITY) {
        VLOG_DBG("%s, port %u: set RSTP port priority to %d", port->rstp->name,
                 port->port_number, priority);

        priority -= priority % RSTP_STEP_PORT_PRIORITY;
        port->priority = priority;
        set_port_id__(port);
        port->selected = false;
        port->reselect = true;
    }
}

/* Checks if a port number is available. */
static bool
is_port_number_available__(struct rstp *rstp, int n, struct rstp_port *port)
    OVS_REQUIRES(rstp_mutex)
{
    if (n >= 1 && n <= RSTP_MAX_PORTS) {
        struct rstp_port *p = rstp_get_port__(rstp, n);

        return p == NULL || p == port;
    }
    return false;
}

static uint16_t
rstp_first_free_number__(struct rstp *rstp, struct rstp_port *rstp_port)
    OVS_REQUIRES(rstp_mutex)
{
    int free_number = 1;

    while (free_number <= RSTP_MAX_PORTS) {
        if (is_port_number_available__(rstp, free_number, rstp_port)) {
            return free_number;
        }
        free_number++;
    }
    VLOG_DBG("%s, No free port number available.", rstp->name);
    return 0;
}

/* Sets the port number. */
static void
rstp_port_set_port_number__(struct rstp_port *port, uint16_t port_number)
    OVS_REQUIRES(rstp_mutex)
{
    int old_port_number = port->port_number;

    /* If new_port_number is available, use it, otherwise use the first free
     * available port number. */
    if (port->port_number != port_number || port_number == 0) {
        port->port_number =
            is_port_number_available__(port->rstp, port_number, port)
            ? port_number
            : rstp_first_free_number__(port->rstp, port);

        if (port->port_number != old_port_number) {
            set_port_id__(port);
            /* [17.13] is not clear. I suppose that a port number change
             * should trigger reselection like a port priority change. */
            port->selected = false;
            port->reselect = true;

            /* Adjust the ports hmap. */
            if (!hmap_node_is_null(&port->node)) {
                hmap_remove(&port->rstp->ports, &port->node);
            }
            hmap_insert(&port->rstp->ports, &port->node,
                        hash_int(port->port_number, 0));

            VLOG_DBG("%s: set new RSTP port number %d", port->rstp->name,
                     port->port_number);
        }
    }
}

static void
rstp_port_set_port_name__(struct rstp_port *port, const char *name)
    OVS_REQUIRES(rstp_mutex)
{
    free(port->port_name);
    port->port_name = xstrdup(name);
}

/* Converts the link speed to a port path cost [Table 17-3]. */
uint32_t
rstp_convert_speed_to_cost(unsigned int speed)
{
    uint32_t value;

    value = speed >= 10000000 ? 2 /* 10 Tb/s. */
          : speed >= 1000000 ? 20 /* 1 Tb/s. */
          : speed >= 100000 ? 200 /* 100 Gb/s. */
          : speed >= 10000 ? 2000 /* 10 Gb/s. */
          : speed >= 1000 ? 20000 /* 1 Gb/s. */
          : speed >= 100 ? 200000 /* 100 Mb/s. */
          : speed >= 10 ? 2000000 /* 10 Mb/s. */
          : speed >= 1 ? 20000000 /* 1 Mb/s. */
          : RSTP_DEFAULT_PORT_PATH_COST; /* 100 Mb/s. */

    return value;
}

/* Sets the port path cost. */
static void
rstp_port_set_path_cost__(struct rstp_port *port, uint32_t path_cost)
    OVS_REQUIRES(rstp_mutex)
{
    if (port->port_path_cost != path_cost
        && path_cost >= RSTP_MIN_PORT_PATH_COST
        && path_cost <= RSTP_MAX_PORT_PATH_COST) {
        VLOG_DBG("%s, port %u, set RSTP port path cost to %d",
                 port->rstp->name, port->port_number, path_cost);

        port->port_path_cost = path_cost;
        port->selected = false;
        port->reselect = true;
    }
}

/* Gets the root path cost. */
static uint32_t
rstp_get_root_path_cost__(const struct rstp *rstp)
    OVS_REQUIRES(rstp_mutex)
{
    return rstp->root_priority.root_path_cost;
}

uint32_t
rstp_get_root_path_cost(const struct rstp *rstp)
    OVS_EXCLUDED(rstp_mutex)
{
    uint32_t cost;

    ovs_mutex_lock(&rstp_mutex);
    cost = rstp_get_root_path_cost__(rstp);
    ovs_mutex_unlock(&rstp_mutex);
    return cost;
}

/* Finds a port which needs to flush its own MAC learning table.  A NULL
 * pointer is returned if no port needs to flush its MAC learning table.
 * '*port' needs to be NULL in the first call to start the iteration.  If
 * '*port' is passed as non-NULL, it must be the value set by the last
 * invocation of this function.
 *
 * This function may only be called by the thread that creates and deletes
 * ports.  Otherwise this function is not thread safe, as the returned
 * '*port' could become stale before it is used in the next invocation. */
void *
rstp_check_and_reset_fdb_flush(struct rstp *rstp, struct rstp_port **port)
    OVS_EXCLUDED(rstp_mutex)
{
    void *aux = NULL;

    ovs_mutex_lock(&rstp_mutex);
    if (*port == NULL) {
        struct rstp_port *p;

        HMAP_FOR_EACH (p, node, &rstp->ports) {
            if (p->fdb_flush) {
                aux = p->aux;
                *port = p;
                goto out;
            }
        }
    } else { /* continue */
        struct rstp_port *p = *port;

        HMAP_FOR_EACH_CONTINUE (p, node, &rstp->ports) {
            if (p->fdb_flush) {
                aux = p->aux;
                *port = p;
                goto out;
            }
        }
    }
    /* No port needs flushing. */
    *port = NULL;
out:
    /* fdb_flush should be reset by the filtering database
     * once the entries are removed if rstp_version is TRUE, and
     * immediately if stp_version is TRUE.*/
    if (*port != NULL) {
        (*port)->fdb_flush = false;
    }
    ovs_mutex_unlock(&rstp_mutex);

    return aux;
}

/* Finds a port whose state has changed, and returns the aux pointer set for
 * the port.  A NULL pointer is returned when no changed port is found.  On
 * return '*portp' contains the pointer to the rstp port that changed, or NULL
 * if no changed port can be found.
 *
 * If '*portp' is passed as non-NULL, it must be the value set by the last
 * invocation of this function.
 *
 * This function may only be called by the thread that creates and deletes
 * ports.  Otherwise this function is not thread safe, as the returned
 * '*portp' could become stale before it is used in the next invocation. */
void *
rstp_get_next_changed_port_aux(struct rstp *rstp, struct rstp_port **portp)
{
    void *aux = NULL;

    ovs_mutex_lock(&rstp_mutex);
    if (*portp == NULL) {
        struct rstp_port *p;

        HMAP_FOR_EACH (p, node, &rstp->ports) {
            if (p->state_changed) {
                p->state_changed = false;
                aux = p->aux;
                *portp = p;
                goto out;
            }
        }
    } else { /* continue */
        struct rstp_port *p = *portp;

        HMAP_FOR_EACH_CONTINUE (p, node, &rstp->ports) {
            if (p->state_changed) {
                p->state_changed = false;
                aux = p->aux;
                *portp = p;
                goto out;
            }
        }
    }
    /* No changed port found. */
    *portp = NULL;
out:
    ovs_mutex_unlock(&rstp_mutex);

    return aux;
}

bool
rstp_shift_root_learned_address(struct rstp *rstp)
{
    bool ret;

    ovs_mutex_lock(&rstp_mutex);
    ret = rstp->root_changed;
    ovs_mutex_unlock(&rstp_mutex);

    return ret;
}

void *
rstp_get_old_root_aux(struct rstp *rstp)
{
    void *aux;

    ovs_mutex_lock(&rstp_mutex);
    aux = rstp->old_root_aux;
    ovs_mutex_unlock(&rstp_mutex);

    return aux;
}

void *
rstp_get_new_root_aux(struct rstp *rstp)
{
    void *aux;

    ovs_mutex_lock(&rstp_mutex);
    aux = rstp->new_root_aux;
    ovs_mutex_unlock(&rstp_mutex);

    return aux;
}

void
rstp_reset_root_changed(struct rstp *rstp)
{
    ovs_mutex_lock(&rstp_mutex);
    rstp->root_changed = false;
    ovs_mutex_unlock(&rstp_mutex);
}

/* Returns the port in 'rstp' with number 'port_number'.
 *
 * XXX: May only be called while concurrent deletion of ports is excluded. */
static struct rstp_port *
rstp_get_port__(struct rstp *rstp, uint16_t port_number)
    OVS_REQUIRES(rstp_mutex)
{
    struct rstp_port *port;

    ovs_assert(rstp && port_number > 0 && port_number <= RSTP_MAX_PORTS);

    HMAP_FOR_EACH_WITH_HASH (port, node, hash_int(port_number, 0),
                             &rstp->ports) {
        if (port->port_number == port_number) {
            return port;
        }
    }
    return NULL;
}

struct rstp_port *
rstp_get_port(struct rstp *rstp, uint16_t port_number)
    OVS_EXCLUDED(rstp_mutex)
{
    struct rstp_port *p;

    ovs_mutex_lock(&rstp_mutex);
    p = rstp_get_port__(rstp, port_number);
    ovs_mutex_unlock(&rstp_mutex);
    return p;
}

void *
rstp_get_port_aux__(struct rstp *rstp, uint16_t port_number)
    OVS_REQUIRES(rstp_mutex)
{
    struct rstp_port *p;
    p = rstp_get_port__(rstp, port_number);
    if (p) {
        return p->aux;
    }
    return NULL;
}

/* Updates the port_enabled parameter. */
static void
update_port_enabled__(struct rstp_port *p)
    OVS_REQUIRES(rstp_mutex)
{
    if (p->mac_operational && p->is_administrative_bridge_port
        == RSTP_ADMIN_BRIDGE_PORT_STATE_ENABLED) {
        p->port_enabled = true;
    } else {
        p->port_enabled = false;
    }
}

/* Sets the port MAC_Operational parameter [6.4.2]. */
void
rstp_port_set_mac_operational(struct rstp_port *p, bool new_mac_operational)
    OVS_EXCLUDED(rstp_mutex)
{
    struct rstp *rstp;

    ovs_mutex_lock(&rstp_mutex);
    rstp = p->rstp;
    if (p->mac_operational != new_mac_operational) {
        p->mac_operational = new_mac_operational;
        update_port_enabled__(p);
        rstp->changes = true;
        move_rstp__(rstp);
    }
    ovs_mutex_unlock(&rstp_mutex);
}

/* Sets the port Administrative Bridge Port parameter. */
static void
rstp_port_set_administrative_bridge_port__(struct rstp_port *p,
                                           uint8_t admin_port_state,
                                           bool initializing)
    OVS_REQUIRES(rstp_mutex)
{
    VLOG_DBG("%s, port %u: set RSTP port admin-port-state to %d",
             p->rstp->name, p->port_number, admin_port_state);

    if (p->is_administrative_bridge_port != admin_port_state
        && (admin_port_state == RSTP_ADMIN_BRIDGE_PORT_STATE_DISABLED
            || admin_port_state == RSTP_ADMIN_BRIDGE_PORT_STATE_ENABLED)) {
        p->is_administrative_bridge_port = admin_port_state;
        update_port_enabled__(p);

        if (!initializing) {
            struct rstp *rstp = p->rstp;

            rstp->changes = true;
            move_rstp__(rstp);
        }
    }
}

/* Sets the port oper_point_to_point_mac parameter. */
static void
rstp_port_set_oper_point_to_point_mac__(struct rstp_port *p,
                                        uint8_t new_oper_p2p_mac)
    OVS_REQUIRES(rstp_mutex)
{
    if (p->oper_point_to_point_mac != new_oper_p2p_mac
        && (new_oper_p2p_mac == RSTP_OPER_P2P_MAC_STATE_DISABLED
            || new_oper_p2p_mac == RSTP_OPER_P2P_MAC_STATE_ENABLED)) {

        p->oper_point_to_point_mac = new_oper_p2p_mac;
        update_port_enabled__(p);
    }
}

/* Initializes a port with the defaults values for its parameters. */
static void
rstp_initialize_port_defaults__(struct rstp_port *p)
    OVS_REQUIRES(rstp_mutex)
{
    rstp_port_set_administrative_bridge_port__(p,
                                               RSTP_ADMIN_BRIDGE_PORT_STATE_ENABLED,
                                               true);
    rstp_port_set_oper_point_to_point_mac__(p,
                                         RSTP_OPER_P2P_MAC_STATE_ENABLED);
    rstp_port_set_path_cost__(p, RSTP_DEFAULT_PORT_PATH_COST);
    rstp_port_set_admin_edge__(p, false);
    rstp_port_set_auto_edge__(p, true);
    rstp_port_set_mcheck__(p, false);

    /* Initialize state machines. */
    p->port_receive_sm_state = PORT_RECEIVE_SM_INIT;
    p->port_protocol_migration_sm_state = PORT_PROTOCOL_MIGRATION_SM_INIT;
    p->bridge_detection_sm_state = BRIDGE_DETECTION_SM_INIT;
    p->port_transmit_sm_state = PORT_TRANSMIT_SM_INIT;
    p->port_information_sm_state = PORT_INFORMATION_SM_INIT;
    p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_INIT;
    p->port_state_transition_sm_state = PORT_STATE_TRANSITION_SM_INIT;
    p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_INIT;
    p->uptime = 0;

}

static void
reinitialize_port__(struct rstp_port *p)
    OVS_REQUIRES(rstp_mutex)
{
    struct rstp_port temp_port;
    struct rstp *rstp;

    rstp = p->rstp;
    temp_port = *p;
    memset(p, 0, sizeof(struct rstp_port));

    p->ref_cnt = temp_port.ref_cnt;
    p->rstp = rstp;
    p->node = temp_port.node;
    p->aux = temp_port.aux;
    p->port_number = temp_port.port_number;
    p->port_priority = temp_port.port_priority;
    p->port_id = temp_port.port_id;
    p->rstp_state = RSTP_DISCARDING;

    rstp_initialize_port_defaults__(p);

    VLOG_DBG("%s: RSTP port "RSTP_PORT_ID_FMT" reinitialized.", rstp->name,
             p->port_id);
}

void
reinitialize_port(struct rstp_port *p)
    OVS_EXCLUDED(rstp_mutex)
{
    ovs_mutex_lock(&rstp_mutex);
    reinitialize_port__(p);
    ovs_mutex_unlock(&rstp_mutex);
}

/* Sets the port state. */
void
rstp_port_set_state__(struct rstp_port *p, enum rstp_state state)
    OVS_REQUIRES(rstp_mutex)
{
    struct rstp *rstp;

    rstp = p->rstp;
    VLOG_DBG("%s, port %u: set RSTP port state %s -> %s", rstp->name,
             p->port_number,
             rstp_state_name(p->rstp_state), rstp_state_name(state));

    if (state != p->rstp_state && !p->state_changed) {
        p->state_changed = true;
        seq_change(connectivity_seq_get());
    }
    p->rstp_state = state;
}

void
rstp_port_set_state(struct rstp_port *p, enum rstp_state state)
    OVS_EXCLUDED(rstp_mutex)
{
    ovs_mutex_lock(&rstp_mutex);
    rstp_port_set_state__(p, state);
    ovs_mutex_unlock(&rstp_mutex);
}

/* Adds a RSTP port. */
struct rstp_port *
rstp_add_port(struct rstp *rstp)
    OVS_EXCLUDED(rstp_mutex)
{
    struct rstp_port *p = xzalloc(sizeof *p);

    ovs_refcount_init(&p->ref_cnt);
    hmap_node_nullify(&p->node);

    ovs_mutex_lock(&rstp_mutex);
    p->rstp = rstp;
    rstp_port_set_priority__(p, RSTP_DEFAULT_PORT_PRIORITY);
    rstp_port_set_port_number__(p, 0);
    p->aux = NULL;
    p->port_name = NULL;
    rstp_initialize_port_defaults__(p);
    VLOG_DBG("%s: RSTP port "RSTP_PORT_ID_FMT" initialized.", rstp->name,
             p->port_id);

    rstp_port_set_state__(p, RSTP_DISCARDING);
    rstp->changes = true;
    move_rstp__(rstp);
    VLOG_DBG("%s: added port "RSTP_PORT_ID_FMT"", rstp->name, p->port_id);
    ovs_mutex_unlock(&rstp_mutex);
    return p;
}

/* Caller has to hold a reference to prevent 'rstp_port' from being deleted
 * while taking a new reference. */
struct rstp_port *
rstp_port_ref(const struct rstp_port *rp_)
    OVS_EXCLUDED(rstp_mutex)
{
    struct rstp_port *rp = CONST_CAST(struct rstp_port *, rp_);

    if (rp) {
        ovs_refcount_ref(&rp->ref_cnt);
    }
    return rp;
}

/* Frees RSTP struct.  This can be caller by any thread. */
void
rstp_port_unref(struct rstp_port *rp)
    OVS_EXCLUDED(rstp_mutex)
{
    if (rp && ovs_refcount_unref_relaxed(&rp->ref_cnt) == 1) {
        struct rstp *rstp;

        ovs_mutex_lock(&rstp_mutex);
        rstp = rp->rstp;
        rstp_port_set_state__(rp, RSTP_DISABLED);
        free(rp->port_name);
        hmap_remove(&rstp->ports, &rp->node);
        VLOG_DBG("%s: removed port "RSTP_PORT_ID_FMT"", rstp->name,
                 rp->port_id);
        ovs_mutex_unlock(&rstp_mutex);
        free(rp);
    }
}

/* Sets the port Admin Edge parameter. */
static void
rstp_port_set_admin_edge__(struct rstp_port *port, bool admin_edge)
     OVS_REQUIRES(rstp_mutex)
{
    if (port->admin_edge != admin_edge) {
        VLOG_DBG("%s, port %u: set RSTP Admin Edge to %d", port->rstp->name,
                 port->port_number, admin_edge);

        port->admin_edge = admin_edge;
    }
}

/* Sets the port Auto Edge parameter. */
static void
rstp_port_set_auto_edge__(struct rstp_port *port, bool auto_edge)
    OVS_REQUIRES(rstp_mutex)
{
    if (port->auto_edge != auto_edge) {
        VLOG_DBG("%s, port %u: set RSTP Auto Edge to %d", port->rstp->name,
                 port->port_number, auto_edge);

        port->auto_edge = auto_edge;
    }
}

/* Sets the port admin_point_to_point_mac parameter. */
static void rstp_port_set_admin_point_to_point_mac__(struct rstp_port *port,
        enum rstp_admin_point_to_point_mac_state admin_p2p_mac_state)
    OVS_REQUIRES(rstp_mutex)
{
    VLOG_DBG("%s, port %u: set RSTP port admin-point-to-point-mac to %d",
            port->rstp->name, port->port_number, admin_p2p_mac_state);
    if (port->admin_point_to_point_mac != admin_p2p_mac_state) {
        if (admin_p2p_mac_state == RSTP_ADMIN_P2P_MAC_FORCE_TRUE) {
            port->admin_point_to_point_mac = admin_p2p_mac_state;
            rstp_port_set_oper_point_to_point_mac__(
                port, RSTP_OPER_P2P_MAC_STATE_ENABLED);
        } else if (admin_p2p_mac_state == RSTP_ADMIN_P2P_MAC_FORCE_FALSE) {
            port->admin_point_to_point_mac = admin_p2p_mac_state;
            rstp_port_set_oper_point_to_point_mac__(
                port, RSTP_OPER_P2P_MAC_STATE_DISABLED);
        } else if (admin_p2p_mac_state == RSTP_ADMIN_P2P_MAC_AUTO) {
            /* If adminPointToPointMAC is set to Auto, then the value of
             * operPointToPointMAC is determined in accordance with the
             * specific procedures defined for the MAC entity concerned, as
             * defined in 6.5. If these procedures determine that the MAC
             * entity is connected to a point-to-point LAN, then
             * operPointToPointMAC is set TRUE; otherwise it is set FALSE.
             * In the absence of a specific definition of how to determine
             * whether the MAC is connected to a point-to-point LAN or not,
             * the value of operPointToPointMAC shall be FALSE. */
            port->admin_point_to_point_mac = admin_p2p_mac_state;
            rstp_port_set_oper_point_to_point_mac__(
                port, RSTP_OPER_P2P_MAC_STATE_DISABLED);
        }
    }
}

/* Sets the port mcheck parameter.
 * [17.19.13] May be set by management to force the Port Protocol Migration
 * state machine to transmit RST BPDUs for a MigrateTime (17.13.9) period, to
 * test whether all STP Bridges (17.4) on the attached LAN have been removed
 * and the Port can continue to transmit RSTP BPDUs. Setting mcheck has no
 * effect if stpVersion (17.20.12) is TRUE, i.e., the Bridge is operating in
 * STP Compatibility mode.
 */
static void
rstp_port_set_mcheck__(struct rstp_port *port, bool mcheck)
    OVS_REQUIRES(rstp_mutex)
{
    if (mcheck == true && port->rstp->force_protocol_version >= 2) {
        port->mcheck = true;

        VLOG_DBG("%s, port %u: set RSTP mcheck to %d", port->rstp->name,
                 port->port_number, mcheck);
    }
}

/* Returns the designated bridge id. */
rstp_identifier
rstp_get_designated_id(const struct rstp *rstp)
    OVS_EXCLUDED(rstp_mutex)
{
    rstp_identifier designated_id;

    ovs_mutex_lock(&rstp_mutex);
    designated_id = rstp->root_priority.designated_bridge_id;
    ovs_mutex_unlock(&rstp_mutex);

    return designated_id;
}

/* Returns the root bridge id. */
static rstp_identifier
rstp_get_root_id__(const struct rstp *rstp)
    OVS_REQUIRES(rstp_mutex)
{
    return rstp->root_priority.root_bridge_id;
}

rstp_identifier
rstp_get_root_id(const struct rstp *rstp)
    OVS_EXCLUDED(rstp_mutex)
{
    rstp_identifier root_id;

    ovs_mutex_lock(&rstp_mutex);
    root_id = rstp_get_root_id__(rstp);
    ovs_mutex_unlock(&rstp_mutex);

    return root_id;
}

/* Returns the designated port id. */
uint16_t
rstp_get_designated_port_id(const struct rstp *rstp)
    OVS_EXCLUDED(rstp_mutex)
{
    uint16_t designated_port_id;

    ovs_mutex_lock(&rstp_mutex);
    designated_port_id = rstp->root_priority.designated_port_id;
    ovs_mutex_unlock(&rstp_mutex);

    return designated_port_id;
}

/* Return the bridge port id. */
uint16_t
rstp_get_bridge_port_id(const struct rstp *rstp)
    OVS_EXCLUDED(rstp_mutex)
{
    uint16_t bridge_port_id;

    ovs_mutex_lock(&rstp_mutex);
    bridge_port_id = rstp->root_priority.bridge_port_id;
    ovs_mutex_unlock(&rstp_mutex);

    return bridge_port_id;
}

/* Returns true if the bridge believes to the be root of the spanning tree,
 * false otherwise.
 */
static bool
rstp_is_root_bridge__(const struct rstp *rstp)
    OVS_REQUIRES(rstp_mutex)
{
    return rstp->bridge_identifier ==
        rstp->root_priority.designated_bridge_id;
}

bool
rstp_is_root_bridge(const struct rstp *rstp)
    OVS_EXCLUDED(rstp_mutex)
{
    bool is_root;

    ovs_mutex_lock(&rstp_mutex);
    is_root = rstp_is_root_bridge__(rstp);
    ovs_mutex_unlock(&rstp_mutex);

    return is_root;
}

/* Returns the bridge ID of the bridge currently believed to be the root. */
rstp_identifier
rstp_get_designated_root(const struct rstp *rstp)
    OVS_EXCLUDED(rstp_mutex)
{
    rstp_identifier designated_root;

    ovs_mutex_lock(&rstp_mutex);
    designated_root = rstp->root_priority.designated_bridge_id;
    ovs_mutex_unlock(&rstp_mutex);

    return designated_root;
}

/* Returns the port connecting 'rstp' to the root bridge, or a null pointer if
 * there is no such port.
 */
static struct rstp_port *
rstp_get_root_port__(const struct rstp *rstp)
    OVS_REQUIRES(rstp_mutex)
{
    struct rstp_port *p;

    HMAP_FOR_EACH (p, node, &rstp->ports) {
        if (p->port_id == rstp->root_port_id) {
            return p;
        }
    }
    return NULL;
}

struct rstp_port *
rstp_get_root_port(const struct rstp *rstp)
    OVS_EXCLUDED(rstp_mutex)
{
    ovs_mutex_lock(&rstp_mutex);
    struct rstp_port *p = rstp_get_root_port__(rstp);
    ovs_mutex_unlock(&rstp_mutex);
    return p;
}

/* Returns the state of port 'p'. */
enum rstp_state
rstp_port_get_state(const struct rstp_port *p)
    OVS_EXCLUDED(rstp_mutex)
{
    enum rstp_state state;

    ovs_mutex_lock(&rstp_mutex);
    state = p->rstp_state;
    ovs_mutex_unlock(&rstp_mutex);

    return state;
}

/* Retrieves port status. */
void
rstp_port_get_status(const struct rstp_port *p, uint16_t *id,
                     enum rstp_state *state, enum rstp_port_role *role,
                     rstp_identifier *designated_bridge_id,
                     uint16_t *designated_port_id,
                     uint32_t *designated_path_cost, int *tx_count,
                     int *rx_count, int *error_count, int *uptime)
    OVS_EXCLUDED(rstp_mutex)
{
    ovs_mutex_lock(&rstp_mutex);
    *id = p->port_id;
    *state = p->rstp_state;
    *role = p->role;

    *designated_bridge_id = p->port_priority.designated_bridge_id;
    *designated_port_id = p->port_priority.designated_port_id;
    *designated_path_cost = p->port_priority.root_path_cost;

    *tx_count = p->tx_count;
    *rx_count = p->rx_rstp_bpdu_cnt;
    *error_count = p->error_count;
    *uptime = p->uptime;
    ovs_mutex_unlock(&rstp_mutex);
}

void
rstp_port_set(struct rstp_port *port, uint16_t port_num, int priority,
              uint32_t path_cost, bool is_admin_edge, bool is_auto_edge,
              enum rstp_admin_point_to_point_mac_state admin_p2p_mac_state,
              bool admin_port_state, bool do_mcheck, void *aux,
              const char *name)
    OVS_EXCLUDED(rstp_mutex)
{
    ovs_mutex_lock(&rstp_mutex);
    port->aux = aux;
    rstp_port_set_priority__(port, priority);
    rstp_port_set_port_number__(port, port_num);
    rstp_port_set_port_name__(port, name);
    rstp_port_set_path_cost__(port, path_cost);
    rstp_port_set_admin_edge__(port, is_admin_edge);
    rstp_port_set_auto_edge__(port, is_auto_edge);
    rstp_port_set_admin_point_to_point_mac__(port, admin_p2p_mac_state);
    rstp_port_set_administrative_bridge_port__(port, admin_port_state, false);
    rstp_port_set_mcheck__(port, do_mcheck);
    ovs_mutex_unlock(&rstp_mutex);
}

/* Individual setters only used by test-rstp.c. */
void
rstp_port_set_priority(struct rstp_port *port, int priority)
    OVS_EXCLUDED(rstp_mutex)
{
    ovs_mutex_lock(&rstp_mutex);
    rstp_port_set_priority__(port, priority);
    ovs_mutex_unlock(&rstp_mutex);
}

void
rstp_port_set_path_cost(struct rstp_port *port, uint32_t path_cost)
    OVS_EXCLUDED(rstp_mutex)
{
    ovs_mutex_lock(&rstp_mutex);
    rstp_port_set_path_cost__(port, path_cost);
    ovs_mutex_unlock(&rstp_mutex);
}

void
rstp_port_set_aux(struct rstp_port *port, void *aux)
    OVS_EXCLUDED(rstp_mutex)
{
    ovs_mutex_lock(&rstp_mutex);
    port->aux = aux;
    ovs_mutex_unlock(&rstp_mutex);
}

/* Unixctl. */
static struct rstp *
rstp_find(const char *name)
    OVS_REQUIRES(rstp_mutex)
{
    struct rstp *rstp;

    LIST_FOR_EACH (rstp, node, all_rstps) {
        if (!strcmp(rstp->name, name)) {
            return rstp;
        }
    }
    return NULL;
}

static void
rstp_unixctl_tcn(struct unixctl_conn *conn, int argc,
                 const char *argv[], void *aux OVS_UNUSED)
    OVS_EXCLUDED(rstp_mutex)
{
    ovs_mutex_lock(&rstp_mutex);
    if (argc > 1) {
        struct rstp *rstp = rstp_find(argv[1]);
        if (!rstp) {
            unixctl_command_reply_error(conn, "No such RSTP object");
            goto out;
        }
        rstp->changes = true;
        move_rstp__(rstp);
    } else {
        struct rstp *rstp;
        LIST_FOR_EACH (rstp, node, all_rstps) {
            rstp->changes = true;
            move_rstp__(rstp);
        }
    }
    unixctl_command_reply(conn, "OK");

out:
    ovs_mutex_unlock(&rstp_mutex);
}

static void
rstp_bridge_id_details(struct ds *ds, const rstp_identifier bridge_id,
                       uint16_t hello_time, uint16_t max_age,
                       uint16_t forward_delay)
    OVS_REQUIRES(rstp_mutex)
{
    uint16_t priority = bridge_id >> 48;
    ds_put_format(ds, "  stp-priority    %"PRIu16"\n", priority);

    struct eth_addr mac;
    const uint64_t mac_bits = (UINT64_C(1) << 48) - 1;
    eth_addr_from_uint64(bridge_id & mac_bits, &mac);
    ds_put_format(ds, "  stp-system-id   "ETH_ADDR_FMT"\n", ETH_ADDR_ARGS(mac));
    ds_put_format(ds, "  stp-hello-time  %"PRIu16"s\n", hello_time);
    ds_put_format(ds, "  stp-max-age     %"PRIu16"s\n", max_age);
    ds_put_format(ds, "  stp-fwd-delay   %"PRIu16"s\n", forward_delay);
}

static void
rstp_print_details(struct ds *ds, const struct rstp *rstp)
    OVS_REQUIRES(rstp_mutex)
{
    ds_put_format(ds, "---- %s ----\n", rstp->name);

    ds_put_cstr(ds, "Root ID:\n");
    if (rstp_is_root_bridge__(rstp)) {
        rstp_bridge_id_details(ds, rstp->bridge_identifier,
                               rstp->bridge_hello_time,
                               rstp->bridge_max_age,
                               rstp->bridge_forward_delay);
        ds_put_cstr(ds, "  This bridge is the root\n");
    } else {
        struct rstp_port *root_port = rstp_get_root_port__(rstp);
        if (!root_port) {
            ds_put_cstr(ds, "unknown root port\n");
            return;
        }

        rstp_bridge_id_details(ds, rstp_get_root_id__(rstp),
                               root_port->designated_times.hello_time,
                               root_port->designated_times.max_age,
                               root_port->designated_times.forward_delay);
        ds_put_format(ds, "  root-port       %s\n", root_port->port_name);
        ds_put_format(ds, "  root-path-cost  %u\n",
                      rstp_get_root_path_cost__(rstp));
    }
    ds_put_cstr(ds, "\n");

    ds_put_cstr(ds, "Bridge ID:\n");
    rstp_bridge_id_details(ds, rstp->bridge_identifier,
                           rstp->bridge_hello_time,
                           rstp->bridge_max_age,
                           rstp->bridge_forward_delay);
    ds_put_cstr(ds, "\n");

    ds_put_format(ds, "  %-11.10s%-11.10s%-11.10s%-9.8s%-8.7s\n",
                  "Interface", "Role", "State", "Cost", "Pri.Nbr");
    ds_put_cstr(ds, "  ---------- ---------- ---------- -------- -------\n");

    struct rstp_port *p;
    HMAP_FOR_EACH (p, node, &rstp->ports) {
        if (p->rstp_state != RSTP_DISABLED) {
            ds_put_format(ds, "  %-11.10s",
                          p->port_name ? p->port_name : "null");
            ds_put_format(ds, "%-11.10s", rstp_port_role_name(p->role));
            ds_put_format(ds, "%-11.10s", rstp_state_name(p->rstp_state));
            ds_put_format(ds, "%-9d", p->port_path_cost);
            ds_put_format(ds, "%d.%d\n", p->priority, p->port_number);
        }
    }

    ds_put_cstr(ds, "\n");
}

static void
rstp_unixctl_show(struct unixctl_conn *conn, int argc,
                  const char *argv[], void *aux OVS_UNUSED)
    OVS_EXCLUDED(rstp_mutex)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    ovs_mutex_lock(&rstp_mutex);
    if (argc > 1) {
        struct rstp *rstp = rstp_find(argv[1]);

        if (!rstp) {
            unixctl_command_reply_error(conn, "No such RSTP object");
            goto out;
        }

        rstp_print_details(&ds, rstp);
    } else {
        struct rstp *rstp;

        LIST_FOR_EACH (rstp, node, all_rstps) {
            rstp_print_details(&ds, rstp);
        }
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);

out:
    ovs_mutex_unlock(&rstp_mutex);
}

/*
 * Copyright (c) 2011-2014 M3S, Srl - Italy
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
 *
 * References to IEEE 802.1D-2004 standard are enclosed in square brackets.
 * E.g. [17.3], [Table 17-1], etc.
 *
 */

#include <config.h>

#include "rstp.h"
#include "rstp-common.h"
#include "rstp-state-machines.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/types.h>
#include "byte-order.h"
#include "connectivity.h"
#include "ofpbuf.h"
#include "ofproto/ofproto.h"
#include "packets.h"
#include "seq.h"
#include "unixctl.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(rstp);

static struct ovs_mutex mutex;
static struct list all_rstps__ = LIST_INITIALIZER(&all_rstps__);
static struct list *const all_rstps OVS_GUARDED_BY(mutex) = &all_rstps__;

/* Internal use only */
static void set_port_id__(struct rstp_port *);
static void update_port_enabled__(struct rstp_port *);
static void set_bridge_priority__(struct rstp *);
static void reinitialize_rstp__(struct rstp *);
static bool is_port_number_available__(struct rstp *, int, struct rstp_port *);
static uint16_t rstp_first_free_number__(struct rstp *, struct rstp_port *);
static void rstp_initialize_port__(struct rstp_port *);

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
 * while we are taking a new reference. */
struct rstp *
rstp_ref(struct rstp *rstp)
{
    if (rstp) {
        ovs_refcount_ref(&rstp->ref_cnt);
    }
    return rstp;
}

/* Frees RSTP struct */
void
rstp_unref(struct rstp *rstp)
{
    if (rstp && ovs_refcount_unref(&rstp->ref_cnt) == 1) {
        ovs_mutex_lock(&mutex);
        if (rstp->ports_count > 0) {
            struct rstp_port *p;

            LIST_FOR_EACH (p, node, &rstp->ports) {
                rstp_delete_port(p);
            }
        }
        list_remove(&rstp->node);
        ovs_mutex_unlock(&mutex);
        free(rstp->name);
        free(rstp);
    }
}

/* Returns the port number.  Mutex is needed to guard against
 * concurrent reinitialization (which can temporarily clear the
 * port_number). */
int
rstp_port_number(const struct rstp_port *p)
{
    int number;

    ovs_mutex_lock(&mutex);
    number = p->port_number;
    ovs_mutex_unlock(&mutex);
    return number;
}

static void rstp_unixctl_tcn(struct unixctl_conn *, int argc,
                             const char *argv[], void *aux);

/* Decrements the State Machines' timers. */
void
rstp_tick_timers(struct rstp *rstp)
{
    ovs_mutex_lock(&mutex);
    decrease_rstp_port_timers(rstp);
    ovs_mutex_unlock(&mutex);
}

/* Processes an incoming BPDU. */
void
rstp_received_bpdu(struct rstp_port *p, const void *bpdu, size_t bpdu_size)
{
    ovs_mutex_lock(&mutex);
    process_received_bpdu(p, bpdu, bpdu_size);
    ovs_mutex_unlock(&mutex);
}

void
rstp_init(void)
{
    unixctl_command_register("rstp/tcn", "[bridge]", 0, 1, rstp_unixctl_tcn,
                             NULL);
}

/* Creates and returns a new RSTP instance that initially has no ports. */
struct rstp *
rstp_create(const char *name, rstp_identifier bridge_address,
            void (*send_bpdu)(struct ofpbuf *bpdu, int port_no, void *aux),
            void *aux)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    struct rstp *rstp;

    VLOG_DBG("Creating RSTP instance");
    if (ovsthread_once_start(&once)) {
        ovs_mutex_init_recursive(&mutex);
        ovsthread_once_done(&once);
    }

    rstp = xzalloc(sizeof *rstp);
    rstp->name = xstrdup(name);
    /* Set bridge address. */
    rstp_set_bridge_address(rstp, bridge_address);
    /* Set default parameters values. */
    rstp_set_bridge_priority(rstp, RSTP_DEFAULT_PRIORITY);
    rstp_set_bridge_ageing_time(rstp, RSTP_DEFAULT_AGEING_TIME);
    rstp_set_bridge_force_protocol_version(rstp, FPV_DEFAULT);
    rstp_set_bridge_forward_delay(rstp, RSTP_DEFAULT_BRIDGE_FORWARD_DELAY);
    rstp_set_bridge_hello_time(rstp);
    rstp_set_bridge_max_age(rstp, RSTP_DEFAULT_BRIDGE_MAX_AGE);
    rstp_set_bridge_migrate_time(rstp);
    rstp_set_bridge_transmit_hold_count(rstp,
                                        RSTP_DEFAULT_TRANSMIT_HOLD_COUNT);
    rstp_set_bridge_times(rstp, RSTP_DEFAULT_BRIDGE_FORWARD_DELAY,
                          RSTP_BRIDGE_HELLO_TIME, RSTP_DEFAULT_BRIDGE_MAX_AGE,
                          0);
    rstp->send_bpdu = send_bpdu;
    rstp->aux = aux;
    rstp->changes = false;
    rstp->begin = true;

    /* Initialize the ports list. */
    list_init(&rstp->ports);
    ovs_refcount_init(&rstp->ref_cnt);

    ovs_mutex_lock(&mutex);
    list_push_back(all_rstps, &rstp->node);
    ovs_mutex_unlock(&mutex);

    VLOG_DBG("RSTP instance creation done");
    return rstp;
}

/* Called by rstp_set_bridge_address() and rstp_set_bridge_priority(),
 * it updates the bridge priority vector according to the values passed by
 * those setters.
 */
static void
set_bridge_priority__(struct rstp *rstp)
    OVS_REQUIRES(mutex)
{
    rstp->bridge_priority.root_bridge_id = rstp->bridge_identifier;
    rstp->bridge_priority.designated_bridge_id = rstp->bridge_identifier;
    VLOG_DBG("%s: new bridge identifier: "RSTP_ID_FMT"", rstp->name,
             RSTP_ID_ARGS(rstp->bridge_identifier));

    /* [17.13] When the bridge address changes, recalculates all priority
     * vectors.
     */
    if (rstp->ports_count > 0) {
        struct rstp_port *p;

        LIST_FOR_EACH (p, node, &rstp->ports) {
            p->selected = false;
            p->reselect = true;
        }
    }
    rstp->changes = true;
    updt_roles_tree(rstp);
}

/* Sets the bridge address. */
void
rstp_set_bridge_address(struct rstp *rstp, rstp_identifier bridge_address)
{
    VLOG_DBG("%s: set bridge address to: "RSTP_ID_FMT"", rstp->name,
             RSTP_ID_ARGS(bridge_address));

    ovs_mutex_lock(&mutex);
    rstp->address = bridge_address;
    rstp->bridge_identifier = bridge_address;
    set_bridge_priority__(rstp);
    ovs_mutex_unlock(&mutex);
}

const char *
rstp_get_name(const struct rstp *rstp)
{
    char *name;

    ovs_mutex_lock(&mutex);
    name = rstp->name;
    ovs_mutex_unlock(&mutex);
    return name;
}

rstp_identifier
rstp_get_bridge_id(const struct rstp *rstp)
{
    rstp_identifier bridge_id;

    ovs_mutex_lock(&mutex);
    bridge_id = rstp->bridge_identifier;
    ovs_mutex_unlock(&mutex);
    return bridge_id;
}

/* Sets the bridge priority. */
void
rstp_set_bridge_priority(struct rstp *rstp, int new_priority)
{
    new_priority = ROUND_DOWN(new_priority, RSTP_PRIORITY_STEP);

    if (new_priority >= RSTP_MIN_PRIORITY
        && new_priority <= RSTP_MAX_PRIORITY) {
        VLOG_DBG("%s: set bridge priority to %d", rstp->name, new_priority);

        ovs_mutex_lock(&mutex);
        rstp->priority = new_priority;
        rstp->bridge_identifier &= 0x0000ffffffffffffULL;
        rstp->bridge_identifier |= (uint64_t)new_priority << 48;
        set_bridge_priority__(rstp);
        ovs_mutex_unlock(&mutex);
    }
}

/* Sets the bridge ageing time. */
void
rstp_set_bridge_ageing_time(struct rstp *rstp, int new_ageing_time)
{
    if (new_ageing_time >= RSTP_MIN_AGEING_TIME
        && new_ageing_time <= RSTP_MAX_AGEING_TIME) {
        VLOG_DBG("%s: set ageing time to %d", rstp->name, new_ageing_time);

        ovs_mutex_lock(&mutex);
        rstp->ageing_time = new_ageing_time;
        ovs_mutex_unlock(&mutex);
    }
}

/* Reinitializes RSTP when switching from RSTP mode to STP mode
 * or vice versa.
 */
static void
reinitialize_rstp__(struct rstp *rstp)
    OVS_REQUIRES(mutex)
{
    struct rstp temp;
    static struct list ports;

    /* Copy rstp in temp */
    temp = *rstp;
    ports = rstp->ports;

    /* stop and clear rstp */
    memset(rstp, 0, sizeof(struct rstp));

    /* Initialize rstp. */
    rstp->name = temp.name;
    /* Set bridge address. */
    rstp_set_bridge_address(rstp, temp.address);
    /* Set default parameters values. */
    rstp_set_bridge_priority(rstp, RSTP_DEFAULT_PRIORITY);
    rstp_set_bridge_ageing_time(rstp, RSTP_DEFAULT_AGEING_TIME);
    rstp_set_bridge_forward_delay(rstp, RSTP_DEFAULT_BRIDGE_FORWARD_DELAY);
    rstp_set_bridge_hello_time(rstp);
    rstp_set_bridge_max_age(rstp, RSTP_DEFAULT_BRIDGE_MAX_AGE);
    rstp_set_bridge_migrate_time(rstp);
    rstp_set_bridge_transmit_hold_count(rstp,
                                        RSTP_DEFAULT_TRANSMIT_HOLD_COUNT);
    rstp_set_bridge_times(rstp, RSTP_DEFAULT_BRIDGE_FORWARD_DELAY,
                          RSTP_BRIDGE_HELLO_TIME, RSTP_DEFAULT_BRIDGE_MAX_AGE,
                          0);

    rstp->send_bpdu = temp.send_bpdu;
    rstp->aux = temp.aux;
    rstp->node = temp.node;
    rstp->changes = false;
    rstp->begin = true;
    rstp->ports = ports;
    rstp->ports_count = temp.ports_count;

    if (rstp->ports_count > 0) {
        struct rstp_port *p, temp_port;

        LIST_FOR_EACH (p, node, &rstp->ports) {
            temp_port = *p;
            memset(p, 0, sizeof(struct rstp_port));
            p->rstp = rstp;
            p->node = temp_port.node;
            p->aux = temp_port.aux;
            p->port_number = temp_port.port_number;
            p->port_priority = temp_port.port_priority;
            p->port_id = temp_port.port_id;
            p->rstp_state = RSTP_DISCARDING;

            rstp_port_set_administrative_bridge_port(p,
                    RSTP_ADMIN_BRIDGE_PORT_STATE_ENABLED);
            rstp_port_set_oper_point_to_point_mac(p, 1);
            rstp_port_set_path_cost(p, RSTP_DEFAULT_PORT_PATH_COST);
            rstp_port_set_auto_edge(p, true);
            /* Initialize state machines. */
            p->port_receive_sm_state = PORT_RECEIVE_SM_INIT;
            p->port_protocol_migration_sm_state =
                PORT_PROTOCOL_MIGRATION_SM_INIT;
            p->bridge_detection_sm_state = BRIDGE_DETECTION_SM_INIT;
            p->port_transmit_sm_state = PORT_TRANSMIT_SM_INIT;
            p->port_information_sm_state = PORT_INFORMATION_SM_INIT;
            p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_INIT;
            p->port_state_transition_sm_state = PORT_STATE_TRANSITION_SM_INIT;
            p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_INIT;
            p->uptime = 0;
        }
    }
    rstp->ref_cnt = temp.ref_cnt;
}

/* Sets the force protocol version parameter. */
void
rstp_set_bridge_force_protocol_version(struct rstp *rstp,
                enum rstp_force_protocol_version new_force_protocol_version)
{
    if (new_force_protocol_version != rstp->force_protocol_version &&
            (new_force_protocol_version == FPV_STP_COMPATIBILITY ||
             new_force_protocol_version == FPV_DEFAULT)) {
        VLOG_DBG("%s: set bridge Force Protocol Version to %d", rstp->name,
                 new_force_protocol_version);
        ovs_mutex_lock(&mutex);
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
        move_rstp(rstp);
        ovs_mutex_unlock(&mutex);
    }
}

/* Sets the bridge Hello Time parameter. */
void
rstp_set_bridge_hello_time(struct rstp *rstp)
{
    VLOG_DBG("%s: set RSTP Hello Time to %d", rstp->name,
             RSTP_BRIDGE_HELLO_TIME);
    /* 2 is the only acceptable value. */
    ovs_mutex_lock(&mutex);
    rstp->bridge_hello_time = RSTP_BRIDGE_HELLO_TIME;
    ovs_mutex_unlock(&mutex);
}

/* Sets the bridge max age parameter. */
void
rstp_set_bridge_max_age(struct rstp *rstp, int new_max_age)
{
    if (new_max_age >= RSTP_MIN_BRIDGE_MAX_AGE &&
        new_max_age <= RSTP_MAX_BRIDGE_MAX_AGE) {
        /* [17.13] */
        if ((2 * (rstp->bridge_forward_delay - 1) >= new_max_age)
            && (new_max_age >= 2 * rstp->bridge_hello_time)) {
            VLOG_DBG("%s: set RSTP bridge Max Age to %d", rstp->name,
                     new_max_age);
            ovs_mutex_lock(&mutex);
            rstp->bridge_max_age = new_max_age;
            rstp->bridge_times.max_age = new_max_age;
            ovs_mutex_unlock(&mutex);
        }
    }
}

/* Sets the bridge forward delay parameter. */
void
rstp_set_bridge_forward_delay(struct rstp *rstp, int new_forward_delay)
{
    if (new_forward_delay >= RSTP_MIN_BRIDGE_FORWARD_DELAY
        && new_forward_delay <= RSTP_MAX_BRIDGE_FORWARD_DELAY) {
        if (2 * (new_forward_delay - 1) >= rstp->bridge_max_age) {
            VLOG_DBG("%s: set RSTP Forward Delay to %d", rstp->name,
                     new_forward_delay);
            ovs_mutex_lock(&mutex);
            rstp->bridge_forward_delay = new_forward_delay;
            rstp->bridge_times.forward_delay = new_forward_delay;
            ovs_mutex_unlock(&mutex);
        }
    }
}

/* Sets the bridge transmit hold count parameter. */
void
rstp_set_bridge_transmit_hold_count(struct rstp *rstp,
                                    int new_transmit_hold_count)
{
    struct rstp_port *p;

    if (new_transmit_hold_count >= RSTP_MIN_TRANSMIT_HOLD_COUNT
        && new_transmit_hold_count <= RSTP_MAX_TRANSMIT_HOLD_COUNT) {
        VLOG_DBG("%s: set RSTP Transmit Hold Count to %d", rstp->name,
                 new_transmit_hold_count);
        /* Resetting txCount on all ports [17.13]. */
        ovs_mutex_lock(&mutex);
        rstp->transmit_hold_count = new_transmit_hold_count;
        if (rstp->ports_count > 0) {
            LIST_FOR_EACH (p, node, &rstp->ports) {
                p->tx_count = 0;
            }
        }
        ovs_mutex_unlock(&mutex);
    }
}

/* Sets the bridge migrate time parameter. */
void
rstp_set_bridge_migrate_time(struct rstp *rstp)
{
    VLOG_DBG("%s: set RSTP Migrate Time to %d", rstp->name,
             RSTP_MIGRATE_TIME);
    /* 3 is the only acceptable value */
    ovs_mutex_lock(&mutex);
    rstp->migrate_time = RSTP_MIGRATE_TIME;
    ovs_mutex_unlock(&mutex);
}

/* Sets the bridge times. */
void
rstp_set_bridge_times(struct rstp *rstp, int new_forward_delay,
                      int new_hello_time, int new_max_age,
                      int new_message_age)
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

/* Sets the port id, it is called by rstp_port_set_port_number() or
 * rstp_port_set_priority().
 */
static void
set_port_id__(struct rstp_port *p)
{
    struct rstp *rstp;

    rstp = p->rstp;
    /* [9.2.7] Port identifier. */
    p->port_id = p->port_number | (p->priority << 8);
    VLOG_DBG("%s: new RSTP port id "RSTP_PORT_ID_FMT"", rstp->name,
             p->port_id);
}

/* Sets the port priority. */
void
rstp_port_set_priority(struct rstp_port *rstp_port, int new_port_priority)
{
    struct rstp *rstp;

    rstp = rstp_port->rstp;
    if (new_port_priority >= RSTP_MIN_PORT_PRIORITY
        && new_port_priority <= RSTP_MAX_PORT_PRIORITY) {
        VLOG_DBG("%s, port %u: set RSTP port priority to %d", rstp->name,
                 rstp_port->port_number, new_port_priority);
        ovs_mutex_lock(&mutex);
        new_port_priority -= new_port_priority % RSTP_STEP_PORT_PRIORITY;
        rstp_port->priority = new_port_priority;
        set_port_id__(rstp_port);
        rstp_port->selected = false;
        rstp_port->reselect = true;
        ovs_mutex_unlock(&mutex);
    }
}

/* Checks if a port number is available. */
static bool
is_port_number_available__(struct rstp *rstp, int n, struct rstp_port *port)
{
    if (n >= 1 && n <= RSTP_MAX_PORTS) {
        struct rstp_port *p = rstp_get_port(rstp, n);

        return p == NULL || p == port;
    }
    return false;
}

static uint16_t
rstp_first_free_number__(struct rstp *rstp, struct rstp_port *rstp_port)
{
    int free_number = 1;

    ovs_mutex_lock(&mutex);
    while (free_number <= RSTP_MAX_PORTS) {
        if (is_port_number_available__(rstp, free_number, rstp_port)) {
            ovs_mutex_unlock(&mutex);
            return free_number;
        }
        free_number++;
    }
    ovs_mutex_unlock(&mutex);
    VLOG_DBG("%s, No free port number available.", rstp->name);
    return 0;
}

/* Sets the port number. */
void
rstp_port_set_port_number(struct rstp_port *rstp_port,
                          uint16_t new_port_number)
{
    struct rstp *rstp;

    ovs_mutex_lock(&mutex);
    rstp = rstp_port->rstp;
    /* If new_port_number is available, use it, otherwise use the first free
     * available port number. */
    rstp_port->port_number =
        is_port_number_available__(rstp_port->rstp, new_port_number, rstp_port)
        ? new_port_number
        : rstp_first_free_number__(rstp, rstp_port);

    set_port_id__(rstp_port);
    /* [17.13] is not clear. I suppose that a port number change
     * should trigger reselection like a port priority change. */
    rstp_port->selected = false;
    rstp_port->reselect = true;
    ovs_mutex_unlock(&mutex);
    VLOG_DBG("%s: set new RSTP port number %d", rstp->name,
             rstp_port->port_number);
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
void
rstp_port_set_path_cost(struct rstp_port *rstp_port,
                        uint32_t new_port_path_cost)
{
    if (new_port_path_cost >= RSTP_MIN_PORT_PATH_COST &&
            new_port_path_cost <= RSTP_MAX_PORT_PATH_COST) {
        struct rstp *rstp;

        ovs_mutex_lock(&mutex);
        rstp = rstp_port->rstp;
        VLOG_DBG("%s, port %u, set RSTP port path cost to %d", rstp->name,
                 rstp_port->port_number, new_port_path_cost);
        rstp_port->port_path_cost = new_port_path_cost;
        rstp_port->selected = false;
        rstp_port->reselect = true;
        ovs_mutex_unlock(&mutex);
    }
}

/* Gets the root path cost. */
uint32_t
rstp_get_root_path_cost(const struct rstp *rstp)
{
    uint32_t cost;

    ovs_mutex_lock(&mutex);
    cost = rstp->root_priority.root_path_cost;
    ovs_mutex_unlock(&mutex);
    return cost;
}

/* Returns true if something has happened to 'rstp' which necessitates
 * flushing the client's MAC learning table.
 */
bool
rstp_check_and_reset_fdb_flush(struct rstp *rstp)
{
    bool needs_flush;
    struct rstp_port *p;

    needs_flush = false;

    ovs_mutex_lock(&mutex);
    if (rstp->ports_count > 0){
        LIST_FOR_EACH (p, node, &rstp->ports) {
            if (p->fdb_flush) {
                needs_flush = true;
                /* fdb_flush should be reset by the filtering database
                 * once the entries are removed if rstp_version is TRUE, and
                 * immediately if stp_version is TRUE.*/
                p->fdb_flush = false;
            }
        }
    }
    ovs_mutex_unlock(&mutex);
    return needs_flush;
}

/* Finds a port whose state has changed.  If successful, stores the port whose
 * state changed in '*portp' and returns true.  If no port has changed, stores
 * NULL in '*portp' and returns false.
 *
 * XXX: This function is only called by the main thread, which is also the one
 * that creates and deletes ports.  Otherwise this function is not thread safe,
 * as the returned '*portp' could become stale before it is referenced by the
 * caller. */
bool
rstp_get_changed_port(struct rstp *rstp, struct rstp_port **portp)
{
    bool changed = false;

    ovs_mutex_lock(&mutex);
    if (rstp->ports_count > 0) {
        struct rstp_port *p;

        LIST_FOR_EACH (p, node, &rstp->ports) {
            if (p->state_changed) {
                p->state_changed = false;
                *portp = p;
                changed = true;
                ovs_mutex_unlock(&mutex);
                return changed;
            }
        }
    }
    *portp = NULL;
    ovs_mutex_unlock(&mutex);
    return changed;
}

/* Returns the port in 'rstp' with number 'port_number'. */
struct rstp_port *
rstp_get_port(struct rstp *rstp, int port_number)
{
    struct rstp_port *port;

    ovs_mutex_lock(&mutex);
    if (rstp->ports_count > 0){
        LIST_FOR_EACH (port, node, &rstp->ports) {
            if (port->port_number == port_number) {
                ovs_mutex_unlock(&mutex);
                return port;
            }
        }
    }
    ovs_mutex_unlock(&mutex);
    return NULL;
}

/* Updates the port_enabled parameter. */
static void
update_port_enabled__(struct rstp_port *p)
{
    if (p->mac_operational && p->is_administrative_bridge_port ==
            RSTP_ADMIN_BRIDGE_PORT_STATE_ENABLED) {
        p->port_enabled = true;
    } else {
        p->port_enabled = false;
    }
}

/* Sets the port MAC_Operational parameter [6.4.2]. */
void
rstp_port_set_mac_operational(struct rstp_port *p, bool new_mac_operational)
{
    struct rstp *rstp;

    ovs_mutex_lock(&mutex);
    rstp = p->rstp;
    p->mac_operational = new_mac_operational;
    update_port_enabled__(p);
    rstp->changes = true;
    move_rstp(rstp);
    ovs_mutex_unlock(&mutex);
}

/* Gets the port MAC_Operational parameter [6.4.2]. */
bool
rstp_port_get_mac_operational(struct rstp_port *p)
{
    bool value;

    ovs_mutex_lock(&mutex);
    value = p->mac_operational;
    ovs_mutex_unlock(&mutex);
    return value;
}

/* Sets the port Administrative Bridge Port parameter. */
void
rstp_port_set_administrative_bridge_port(struct rstp_port *p,
                                         uint8_t new_admin_port_state)
{
    if (new_admin_port_state == RSTP_ADMIN_BRIDGE_PORT_STATE_DISABLED ||
            new_admin_port_state == RSTP_ADMIN_BRIDGE_PORT_STATE_ENABLED) {
        p->is_administrative_bridge_port = new_admin_port_state;
        update_port_enabled__(p);
    }
}

/* Sets the port oper_point_to_point_mac parameter. */
void
rstp_port_set_oper_point_to_point_mac(struct rstp_port *p,
                                      uint8_t new_oper_p2p_mac)
{
    if (new_oper_p2p_mac == RSTP_OPER_P2P_MAC_STATE_DISABLED ||
            new_oper_p2p_mac == RSTP_OPER_P2P_MAC_STATE_ENABLED) {
        p->oper_point_to_point_mac = new_oper_p2p_mac;
        update_port_enabled__(p);
    }
}

/* Initializes a port with the defaults values for its parameters. */
static void
rstp_initialize_port__(struct rstp_port *p)
    OVS_REQUIRES(mutex)
{
    struct rstp *rstp;

    rstp = p->rstp;
    rstp_port_set_administrative_bridge_port(p,
        RSTP_ADMIN_BRIDGE_PORT_STATE_ENABLED);
    rstp_port_set_oper_point_to_point_mac(p, 1);
    rstp_port_set_priority(p, RSTP_DEFAULT_PORT_PRIORITY);
    rstp_port_set_port_number(p, 0);
    rstp_port_set_path_cost(p, RSTP_DEFAULT_PORT_PATH_COST);
    rstp_port_set_auto_edge(p, true);

    p->port_receive_sm_state = PORT_RECEIVE_SM_INIT;
    p->port_protocol_migration_sm_state = PORT_PROTOCOL_MIGRATION_SM_INIT;
    p->bridge_detection_sm_state = BRIDGE_DETECTION_SM_INIT;
    p->port_transmit_sm_state = PORT_TRANSMIT_SM_INIT;
    p->port_information_sm_state = PORT_INFORMATION_SM_INIT;
    p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_INIT;
    p->port_state_transition_sm_state = PORT_STATE_TRANSITION_SM_INIT;
    p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_INIT;
    p->aux = NULL;
    p->uptime = 0;

    VLOG_DBG("%s: RSTP port "RSTP_PORT_ID_FMT" initialized.", rstp->name,
             p->port_id);
}

/* Reinitialization function used in tests. */
void
reinitialize_port(struct rstp_port *p)
{
    struct rstp_port temp_port;
    struct rstp *rstp;

    rstp = p->rstp;
    temp_port = *p;
    memset(p, 0, sizeof(struct rstp_port));
    p->rstp = rstp;
    p->node = temp_port.node;
    p->aux = temp_port.aux;
    p->port_number = temp_port.port_number;
    p->port_priority = temp_port.port_priority;
    p->port_id = temp_port.port_id;
    p->rstp_state = RSTP_DISCARDING;

    rstp_port_set_administrative_bridge_port(p,
            RSTP_ADMIN_BRIDGE_PORT_STATE_ENABLED);
    rstp_port_set_oper_point_to_point_mac(p, 1);
    rstp_port_set_path_cost(p, RSTP_DEFAULT_PORT_PATH_COST);
    rstp_port_set_auto_edge(p, true);
    /* Initialize state machines. */
    p->port_receive_sm_state = PORT_RECEIVE_SM_INIT;
    p->port_protocol_migration_sm_state =
        PORT_PROTOCOL_MIGRATION_SM_INIT;
    p->bridge_detection_sm_state = BRIDGE_DETECTION_SM_INIT;
    p->port_transmit_sm_state = PORT_TRANSMIT_SM_INIT;
    p->port_information_sm_state = PORT_INFORMATION_SM_INIT;
    p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_INIT;
    p->port_state_transition_sm_state = PORT_STATE_TRANSITION_SM_INIT;
    p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_INIT;
    p->uptime = 0;

    VLOG_DBG("%s: RSTP port "RSTP_PORT_ID_FMT" reinitialized.", rstp->name,
                 p->port_id);
}

/* Sets the port state. */
void
rstp_port_set_state(struct rstp_port *p, enum rstp_state state)
OVS_REQUIRES(mutex)
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

/* Adds a RSTP port. */
struct rstp_port *
rstp_add_port(struct rstp *rstp) {
    struct rstp_port *p = xzalloc(sizeof *p);

    ovs_mutex_lock(&mutex);
    p->rstp = rstp;
    rstp_initialize_port__(p);
    rstp_port_set_state(p, RSTP_DISCARDING);
    list_push_back(&rstp->ports, &p->node);
    rstp->ports_count++;
    rstp->changes = true;
    move_rstp(rstp);
    ovs_mutex_unlock(&mutex);
    VLOG_DBG("%s: added port "RSTP_PORT_ID_FMT"", rstp->name, p->port_id);
    return p;
}

/* Deletes a RSTP port. */
void
rstp_delete_port(struct rstp_port *p) {
    struct rstp *rstp;

    ovs_mutex_lock(&mutex);
    rstp = p->rstp;
    rstp_port_set_state(p, RSTP_DISABLED);
    list_remove(&p->node);
    rstp->ports_count--;
    VLOG_DBG("%s: removed port "RSTP_PORT_ID_FMT"", rstp->name, p->port_id);
    free(p);
    ovs_mutex_unlock(&mutex);
}

/* Sets the port Admin Edge parameter. */
void
rstp_port_set_admin_edge(struct rstp_port *rstp_port, bool new_admin_edge)
{
    struct rstp *rstp;

    rstp = rstp_port->rstp;
    if (rstp_port->admin_edge != new_admin_edge) {
        VLOG_DBG("%s, port %u: set RSTP Admin Edge to %d", rstp->name,
                 rstp_port->port_number, new_admin_edge);
        ovs_mutex_lock(&mutex);
        rstp_port->admin_edge = new_admin_edge;
        ovs_mutex_unlock(&mutex);
    }
}

/* Sets the port Auto Edge parameter. */
void
rstp_port_set_auto_edge(struct rstp_port *rstp_port, bool new_auto_edge)
{
    struct rstp *rstp;

    rstp = rstp_port->rstp;
    if (rstp_port->auto_edge != new_auto_edge) {
        VLOG_DBG("%s, port %u: set RSTP Auto Edge to %d", rstp->name,
                 rstp_port->port_number, new_auto_edge);
        ovs_mutex_lock(&mutex);
        rstp_port->auto_edge = new_auto_edge;
        ovs_mutex_unlock(&mutex);
    }
}

/* Sets the port mcheck parameter.
 * [17.19.13] May be set by management to force the Port Protocol Migration
 * state machine to transmit RST BPDUs for a MigrateTime (17.13.9) period, to
 * test whether all STP Bridges (17.4) on the attached LAN have been removed
 * and the Port can continue to transmit RSTP BPDUs. Setting mcheck has no
 * effect if stpVersion (17.20.12) is TRUE, i.e., the Bridge is operating in
 * STP Compatibility. mode.
 */
void
rstp_port_set_mcheck(struct rstp_port *rstp_port, bool new_mcheck)
{
    struct rstp *rstp;

    ovs_mutex_lock(&mutex);
    rstp = rstp_port->rstp;
    if (new_mcheck == true && rstp_port->rstp->force_protocol_version >= 2) {
        rstp_port->mcheck = true;
    }
    ovs_mutex_unlock(&mutex);
    VLOG_DBG("%s, port %u: set RSTP mcheck to %d", rstp->name,
             rstp_port->port_number, new_mcheck);
}

/* Returns the designated bridge id. */
rstp_identifier
rstp_get_designated_id(const struct rstp *rstp)
{
    rstp_identifier designated_id;

    ovs_mutex_lock(&mutex);
    designated_id = rstp->root_priority.designated_bridge_id;
    ovs_mutex_unlock(&mutex);
    return designated_id;
}

/* Returns the root bridge id. */
rstp_identifier
rstp_get_root_id(const struct rstp *rstp)
{
    rstp_identifier root_id;

    ovs_mutex_lock(&mutex);
    root_id = rstp->root_priority.root_bridge_id;
    ovs_mutex_unlock(&mutex);
    return root_id;
}

/* Returns the designated port id. */
uint16_t
rstp_get_designated_port_id(const struct rstp *rstp)
{
    uint16_t designated_port_id;

    ovs_mutex_lock(&mutex);
    designated_port_id = rstp->root_priority.designated_port_id;
    ovs_mutex_unlock(&mutex);
    return designated_port_id;
}

/* Return the bridge port id. */
uint16_t
rstp_get_bridge_port_id(const struct rstp *rstp)
{
    uint16_t bridge_port_id;

    ovs_mutex_lock(&mutex);
    bridge_port_id = rstp->root_priority.bridge_port_id;
    ovs_mutex_unlock(&mutex);
    return bridge_port_id;
}

/* Returns true if the bridge believes to the be root of the spanning tree,
 * false otherwise.
 */
bool
rstp_is_root_bridge(const struct rstp *rstp)
{
    bool is_root;

    ovs_mutex_lock(&mutex);
    is_root = rstp->bridge_identifier ==
                rstp->root_priority.designated_bridge_id;
    ovs_mutex_unlock(&mutex);
    return is_root;
}

/* Returns the bridge ID of the bridge currently believed to be the root. */
rstp_identifier
rstp_get_designated_root(const struct rstp *rstp)
{
    rstp_identifier designated_root;

    ovs_mutex_lock(&mutex);
    designated_root = rstp->root_priority.designated_bridge_id;
    ovs_mutex_unlock(&mutex);
    return designated_root;
}

/* Returns the port connecting 'rstp' to the root bridge, or a null pointer if
 * there is no such port.
 */
struct rstp_port *
rstp_get_root_port(struct rstp *rstp)
{
    struct rstp_port *p;

    ovs_mutex_lock(&mutex);
    if (rstp->ports_count > 0){
        LIST_FOR_EACH (p, node, &rstp->ports) {
            if (p->port_id == rstp->root_port_id) {
                ovs_mutex_unlock(&mutex);
                return p;
            }
        }
    }
    ovs_mutex_unlock(&mutex);
    return NULL;
}

/* Returns the port ID for 'p'. */
uint16_t
rstp_port_get_id(const struct rstp_port *p)
{
    uint16_t port_id;

    ovs_mutex_lock(&mutex);
    port_id = p->port_id;
    ovs_mutex_unlock(&mutex);
    return port_id;
}

/* Returns the state of port 'p'. */
enum rstp_state
rstp_port_get_state(const struct rstp_port *p)
{
    enum rstp_state state;

    ovs_mutex_lock(&mutex);
    state = p->rstp_state;
    ovs_mutex_unlock(&mutex);
    return state;
}

/* Returns the role of port 'p'. */
enum rstp_port_role
rstp_port_get_role(const struct rstp_port *p)
{
    enum rstp_port_role role;

    ovs_mutex_lock(&mutex);
    role = p->role;
    ovs_mutex_unlock(&mutex);
    return role;
}

/* Retrieves BPDU transmit and receive counts for 'p'. */
void
rstp_port_get_counts(const struct rstp_port *p,
        int *tx_count, int *rx_count, int *error_count, int *uptime)
{
    ovs_mutex_lock(&mutex);
    *tx_count = p->tx_count;
    *rx_count = p->rx_rstp_bpdu_cnt;
    *error_count = p->error_count;
    *uptime = p->uptime;
    ovs_mutex_unlock(&mutex);
}

void
rstp_port_set_aux(struct rstp_port *p, void *aux)
{
    ovs_mutex_lock(&mutex);
    p->aux = aux;
    ovs_mutex_unlock(&mutex);
}

void *
rstp_port_get_aux(struct rstp_port *p)
{
    void *aux;

    ovs_mutex_lock(&mutex);
    aux = p->aux;
    ovs_mutex_unlock(&mutex);
    return aux;
}

/* Returns true if 'state' is one in which BPDU packets should be received
 * and transmitted on a port, false otherwise.
 */
 bool
 rstp_should_manage_bpdu(enum rstp_state state)
 {
     return (state == RSTP_DISCARDING || state == RSTP_LEARNING ||
             state == RSTP_FORWARDING);
 }

/* Returns true if 'state' is one in which packets received on a port should
 * be forwarded, false otherwise.
 *
 * Returns true if 'state' is RSTP_DISABLED, since presumably in that case the
 * port should still work, just not have RSTP applied to it.
 */
bool
rstp_forward_in_state(enum rstp_state state)
{
    return (state == RSTP_DISABLED || state == RSTP_FORWARDING);
}

/* Returns true if 'state' is one in which MAC learning should be done on
 * packets received on a port, false otherwise.
 *
 * Returns true if 'state' is RSTP_DISABLED, since presumably in that case the
 * port should still work, just not have RSTP applied to it. */
bool
rstp_learn_in_state(enum rstp_state state)
{
    return (state == RSTP_DISABLED || state == RSTP_LEARNING ||
            state == RSTP_FORWARDING);
}

/* Unixctl. */
static struct rstp *
rstp_find(const char *name) OVS_REQUIRES(mutex)
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
{
    ovs_mutex_lock(&mutex);
    if (argc > 1) {
        struct rstp *rstp = rstp_find(argv[1]);
        if (!rstp) {
            unixctl_command_reply_error(conn, "No such RSTP object");
            goto out;
        }
        rstp->changes = true;
        move_rstp(rstp);
    } else {
        struct rstp *rstp;
        LIST_FOR_EACH (rstp, node, all_rstps) {
            rstp->changes = true;
            move_rstp(rstp);
        }
    }
    unixctl_command_reply(conn, "OK");

out:
    ovs_mutex_unlock(&mutex);
}

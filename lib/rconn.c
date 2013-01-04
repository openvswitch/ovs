/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include "rconn.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "coverage.h"
#include "ofp-msgs.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "sat-math.h"
#include "timeval.h"
#include "util.h"
#include "vconn.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(rconn);

COVERAGE_DEFINE(rconn_discarded);
COVERAGE_DEFINE(rconn_overflow);
COVERAGE_DEFINE(rconn_queued);
COVERAGE_DEFINE(rconn_sent);

#define STATES                                  \
    STATE(VOID, 1 << 0)                         \
    STATE(BACKOFF, 1 << 1)                      \
    STATE(CONNECTING, 1 << 2)                   \
    STATE(ACTIVE, 1 << 3)                       \
    STATE(IDLE, 1 << 4)
enum state {
#define STATE(NAME, VALUE) S_##NAME = VALUE,
    STATES
#undef STATE
};

static const char *
state_name(enum state state)
{
    switch (state) {
#define STATE(NAME, VALUE) case S_##NAME: return #NAME;
        STATES
#undef STATE
    }
    return "***ERROR***";
}

/* A reliable connection to an OpenFlow switch or controller.
 *
 * See the large comment in rconn.h for more information. */
struct rconn {
    enum state state;
    time_t state_entered;

    struct vconn *vconn;
    char *name;                 /* Human-readable descriptive name. */
    char *target;               /* vconn name, passed to vconn_open(). */
    bool reliable;

    struct list txq;            /* Contains "struct ofpbuf"s. */

    int backoff;
    int max_backoff;
    time_t backoff_deadline;
    time_t last_connected;
    time_t last_disconnected;
    unsigned int packets_sent;
    unsigned int seqno;
    int last_error;

    /* In S_ACTIVE and S_IDLE, probably_admitted reports whether we believe
     * that the peer has made a (positive) admission control decision on our
     * connection.  If we have not yet been (probably) admitted, then the
     * connection does not reset the timer used for deciding whether the switch
     * should go into fail-open mode.
     *
     * last_admitted reports the last time we believe such a positive admission
     * control decision was made. */
    bool probably_admitted;
    time_t last_admitted;

    /* These values are simply for statistics reporting, not used directly by
     * anything internal to the rconn (or ofproto for that matter). */
    unsigned int packets_received;
    unsigned int n_attempted_connections, n_successful_connections;
    time_t creation_time;
    unsigned long int total_time_connected;

    /* Throughout this file, "probe" is shorthand for "inactivity probe".  When
     * no activity has been observed from the peer for a while, we send out an
     * echo request as an inactivity probe packet.  We should receive back a
     * response.
     *
     * "Activity" is defined as either receiving an OpenFlow message from the
     * peer or successfully sending a message that had been in 'txq'. */
    int probe_interval;         /* Secs of inactivity before sending probe. */
    time_t last_activity;       /* Last time we saw some activity. */

    /* When we create a vconn we obtain these values, to save them past the end
     * of the vconn's lifetime.  Otherwise, in-band control will only allow
     * traffic when a vconn is actually open, but it is nice to allow ARP to
     * complete even between connection attempts, and it is also polite to
     * allow traffic from other switches to go through to the controller
     * whether or not we are connected.
     *
     * We don't cache the local port, because that changes from one connection
     * attempt to the next. */
    ovs_be32 local_ip, remote_ip;
    ovs_be16 remote_port;
    uint8_t dscp;

    /* Messages sent or received are copied to the monitor connections. */
#define MAX_MONITORS 8
    struct vconn *monitors[8];
    size_t n_monitors;
};

static unsigned int elapsed_in_this_state(const struct rconn *);
static unsigned int timeout(const struct rconn *);
static bool timed_out(const struct rconn *);
static void state_transition(struct rconn *, enum state);
static void rconn_set_target__(struct rconn *,
                               const char *target, const char *name);
static int try_send(struct rconn *);
static void reconnect(struct rconn *);
static void report_error(struct rconn *, int error);
static void disconnect(struct rconn *, int error);
static void flush_queue(struct rconn *);
static void copy_to_monitor(struct rconn *, const struct ofpbuf *);
static bool is_connected_state(enum state);
static bool is_admitted_msg(const struct ofpbuf *);
static bool rconn_logging_connection_attempts__(const struct rconn *);

/* Creates and returns a new rconn.
 *
 * 'probe_interval' is a number of seconds.  If the interval passes once
 * without an OpenFlow message being received from the peer, the rconn sends
 * out an "echo request" message.  If the interval passes again without a
 * message being received, the rconn disconnects and re-connects to the peer.
 * Setting 'probe_interval' to 0 disables this behavior.
 *
 * 'max_backoff' is the maximum number of seconds between attempts to connect
 * to the peer.  The actual interval starts at 1 second and doubles on each
 * failure until it reaches 'max_backoff'.  If 0 is specified, the default of
 * 8 seconds is used.
 *
 * The new rconn is initially unconnected.  Use rconn_connect() or
 * rconn_connect_unreliably() to connect it. */
struct rconn *
rconn_create(int probe_interval, int max_backoff, uint8_t dscp)
{
    struct rconn *rc = xzalloc(sizeof *rc);

    rc->state = S_VOID;
    rc->state_entered = time_now();

    rc->vconn = NULL;
    rc->name = xstrdup("void");
    rc->target = xstrdup("void");
    rc->reliable = false;

    list_init(&rc->txq);

    rc->backoff = 0;
    rc->max_backoff = max_backoff ? max_backoff : 8;
    rc->backoff_deadline = TIME_MIN;
    rc->last_connected = TIME_MIN;
    rc->last_disconnected = TIME_MIN;
    rc->seqno = 0;

    rc->packets_sent = 0;

    rc->probably_admitted = false;
    rc->last_admitted = time_now();

    rc->packets_received = 0;
    rc->n_attempted_connections = 0;
    rc->n_successful_connections = 0;
    rc->creation_time = time_now();
    rc->total_time_connected = 0;

    rc->last_activity = time_now();

    rconn_set_probe_interval(rc, probe_interval);
    rconn_set_dscp(rc, dscp);

    rc->n_monitors = 0;

    return rc;
}

void
rconn_set_max_backoff(struct rconn *rc, int max_backoff)
{
    rc->max_backoff = MAX(1, max_backoff);
    if (rc->state == S_BACKOFF && rc->backoff > max_backoff) {
        rc->backoff = max_backoff;
        if (rc->backoff_deadline > time_now() + max_backoff) {
            rc->backoff_deadline = time_now() + max_backoff;
        }
    }
}

int
rconn_get_max_backoff(const struct rconn *rc)
{
    return rc->max_backoff;
}

void
rconn_set_dscp(struct rconn *rc, uint8_t dscp)
{
    rc->dscp = dscp;
}

uint8_t
rconn_get_dscp(const struct rconn *rc)
{
    return rc->dscp;
}

void
rconn_set_probe_interval(struct rconn *rc, int probe_interval)
{
    rc->probe_interval = probe_interval ? MAX(5, probe_interval) : 0;
}

int
rconn_get_probe_interval(const struct rconn *rc)
{
    return rc->probe_interval;
}

/* Drops any existing connection on 'rc', then sets up 'rc' to connect to
 * 'target' and reconnect as needed.  'target' should be a remote OpenFlow
 * target in a form acceptable to vconn_open().
 *
 * If 'name' is nonnull, then it is used in log messages in place of 'target'.
 * It should presumably give more information to a human reader than 'target',
 * but it need not be acceptable to vconn_open(). */
void
rconn_connect(struct rconn *rc, const char *target, const char *name)
{
    rconn_disconnect(rc);
    rconn_set_target__(rc, target, name);
    rc->reliable = true;
    reconnect(rc);
}

/* Drops any existing connection on 'rc', then configures 'rc' to use
 * 'vconn'.  If the connection on 'vconn' drops, 'rc' will not reconnect on it
 * own.
 *
 * By default, the target obtained from vconn_get_name(vconn) is used in log
 * messages.  If 'name' is nonnull, then it is used instead.  It should
 * presumably give more information to a human reader than the target, but it
 * need not be acceptable to vconn_open(). */
void
rconn_connect_unreliably(struct rconn *rc,
                         struct vconn *vconn, const char *name)
{
    assert(vconn != NULL);
    rconn_disconnect(rc);
    rconn_set_target__(rc, vconn_get_name(vconn), name);
    rc->reliable = false;
    rc->vconn = vconn;
    rc->last_connected = time_now();
    state_transition(rc, S_ACTIVE);
}

/* If 'rc' is connected, forces it to drop the connection and reconnect. */
void
rconn_reconnect(struct rconn *rc)
{
    if (rc->state & (S_ACTIVE | S_IDLE)) {
        VLOG_INFO("%s: disconnecting", rc->name);
        disconnect(rc, 0);
    }
}

void
rconn_disconnect(struct rconn *rc)
{
    if (rc->state != S_VOID) {
        if (rc->vconn) {
            vconn_close(rc->vconn);
            rc->vconn = NULL;
        }
        rconn_set_target__(rc, "void", NULL);
        rc->reliable = false;

        rc->backoff = 0;
        rc->backoff_deadline = TIME_MIN;

        state_transition(rc, S_VOID);
    }
}

/* Disconnects 'rc' and frees the underlying storage. */
void
rconn_destroy(struct rconn *rc)
{
    if (rc) {
        size_t i;

        free(rc->name);
        free(rc->target);
        vconn_close(rc->vconn);
        flush_queue(rc);
        ofpbuf_list_delete(&rc->txq);
        for (i = 0; i < rc->n_monitors; i++) {
            vconn_close(rc->monitors[i]);
        }
        free(rc);
    }
}

static unsigned int
timeout_VOID(const struct rconn *rc OVS_UNUSED)
{
    return UINT_MAX;
}

static void
run_VOID(struct rconn *rc OVS_UNUSED)
{
    /* Nothing to do. */
}

static void
reconnect(struct rconn *rc)
{
    int retval;

    if (rconn_logging_connection_attempts__(rc)) {
        VLOG_INFO("%s: connecting...", rc->name);
    }
    rc->n_attempted_connections++;
    retval = vconn_open(rc->target, OFP10_VERSION, &rc->vconn, rc->dscp);
    if (!retval) {
        rc->remote_ip = vconn_get_remote_ip(rc->vconn);
        rc->local_ip = vconn_get_local_ip(rc->vconn);
        rc->remote_port = vconn_get_remote_port(rc->vconn);
        rc->backoff_deadline = time_now() + rc->backoff;
        state_transition(rc, S_CONNECTING);
    } else {
        VLOG_WARN("%s: connection failed (%s)", rc->name, strerror(retval));
        rc->backoff_deadline = TIME_MAX; /* Prevent resetting backoff. */
        disconnect(rc, retval);
    }
}

static unsigned int
timeout_BACKOFF(const struct rconn *rc)
{
    return rc->backoff;
}

static void
run_BACKOFF(struct rconn *rc)
{
    if (timed_out(rc)) {
        reconnect(rc);
    }
}

static unsigned int
timeout_CONNECTING(const struct rconn *rc)
{
    return MAX(1, rc->backoff);
}

static void
run_CONNECTING(struct rconn *rc)
{
    int retval = vconn_connect(rc->vconn);
    if (!retval) {
        VLOG_INFO("%s: connected", rc->name);
        rc->n_successful_connections++;
        state_transition(rc, S_ACTIVE);
        rc->last_connected = rc->state_entered;
    } else if (retval != EAGAIN) {
        if (rconn_logging_connection_attempts__(rc)) {
            VLOG_INFO("%s: connection failed (%s)",
                      rc->name, strerror(retval));
        }
        disconnect(rc, retval);
    } else if (timed_out(rc)) {
        if (rconn_logging_connection_attempts__(rc)) {
            VLOG_INFO("%s: connection timed out", rc->name);
        }
        rc->backoff_deadline = TIME_MAX; /* Prevent resetting backoff. */
        disconnect(rc, ETIMEDOUT);
    }
}

static void
do_tx_work(struct rconn *rc)
{
    if (list_is_empty(&rc->txq)) {
        return;
    }
    while (!list_is_empty(&rc->txq)) {
        int error = try_send(rc);
        if (error) {
            break;
        }
        rc->last_activity = time_now();
    }
    if (list_is_empty(&rc->txq)) {
        poll_immediate_wake();
    }
}

static unsigned int
timeout_ACTIVE(const struct rconn *rc)
{
    if (rc->probe_interval) {
        unsigned int base = MAX(rc->last_activity, rc->state_entered);
        unsigned int arg = base + rc->probe_interval - rc->state_entered;
        return arg;
    }
    return UINT_MAX;
}

static void
run_ACTIVE(struct rconn *rc)
{
    if (timed_out(rc)) {
        unsigned int base = MAX(rc->last_activity, rc->state_entered);
        int version;

        VLOG_DBG("%s: idle %u seconds, sending inactivity probe",
                 rc->name, (unsigned int) (time_now() - base));

        version = rconn_get_version(rc);
        assert(version >= 0 && version <= 0xff);

        /* Ordering is important here: rconn_send() can transition to BACKOFF,
         * and we don't want to transition back to IDLE if so, because then we
         * can end up queuing a packet with vconn == NULL and then *boom*. */
        state_transition(rc, S_IDLE);
        rconn_send(rc, make_echo_request(version), NULL);
        return;
    }

    do_tx_work(rc);
}

static unsigned int
timeout_IDLE(const struct rconn *rc)
{
    return rc->probe_interval;
}

static void
run_IDLE(struct rconn *rc)
{
    if (timed_out(rc)) {
        VLOG_ERR("%s: no response to inactivity probe after %u "
                 "seconds, disconnecting",
                 rc->name, elapsed_in_this_state(rc));
        disconnect(rc, ETIMEDOUT);
    } else {
        do_tx_work(rc);
    }
}

/* Performs whatever activities are necessary to maintain 'rc': if 'rc' is
 * disconnected, attempts to (re)connect, backing off as necessary; if 'rc' is
 * connected, attempts to send packets in the send queue, if any. */
void
rconn_run(struct rconn *rc)
{
    int old_state;
    size_t i;

    if (rc->vconn) {
        vconn_run(rc->vconn);
    }
    for (i = 0; i < rc->n_monitors; i++) {
        vconn_run(rc->monitors[i]);
    }

    do {
        old_state = rc->state;
        switch (rc->state) {
#define STATE(NAME, VALUE) case S_##NAME: run_##NAME(rc); break;
            STATES
#undef STATE
        default:
            NOT_REACHED();
        }
    } while (rc->state != old_state);
}

/* Causes the next call to poll_block() to wake up when rconn_run() should be
 * called on 'rc'. */
void
rconn_run_wait(struct rconn *rc)
{
    unsigned int timeo;
    size_t i;

    if (rc->vconn) {
        vconn_run_wait(rc->vconn);
        if ((rc->state & (S_ACTIVE | S_IDLE)) && !list_is_empty(&rc->txq)) {
            vconn_wait(rc->vconn, WAIT_SEND);
        }
    }
    for (i = 0; i < rc->n_monitors; i++) {
        vconn_run_wait(rc->monitors[i]);
    }

    timeo = timeout(rc);
    if (timeo != UINT_MAX) {
        long long int expires = sat_add(rc->state_entered, timeo);
        poll_timer_wait_until(expires * 1000);
    }
}

/* Attempts to receive a packet from 'rc'.  If successful, returns the packet;
 * otherwise, returns a null pointer.  The caller is responsible for freeing
 * the packet (with ofpbuf_delete()). */
struct ofpbuf *
rconn_recv(struct rconn *rc)
{
    if (rc->state & (S_ACTIVE | S_IDLE)) {
        struct ofpbuf *buffer;
        int error = vconn_recv(rc->vconn, &buffer);
        if (!error) {
            copy_to_monitor(rc, buffer);
            if (rc->probably_admitted || is_admitted_msg(buffer)
                || time_now() - rc->last_connected >= 30) {
                rc->probably_admitted = true;
                rc->last_admitted = time_now();
            }
            rc->last_activity = time_now();
            rc->packets_received++;
            if (rc->state == S_IDLE) {
                state_transition(rc, S_ACTIVE);
            }
            return buffer;
        } else if (error != EAGAIN) {
            report_error(rc, error);
            disconnect(rc, error);
        }
    }
    return NULL;
}

/* Causes the next call to poll_block() to wake up when a packet may be ready
 * to be received by vconn_recv() on 'rc'.  */
void
rconn_recv_wait(struct rconn *rc)
{
    if (rc->vconn) {
        vconn_wait(rc->vconn, WAIT_RECV);
    }
}

/* Sends 'b' on 'rc'.  Returns 0 if successful, or ENOTCONN if 'rc' is not
 * currently connected.  Takes ownership of 'b'.
 *
 * If 'counter' is non-null, then 'counter' will be incremented while the
 * packet is in flight, then decremented when it has been sent (or discarded
 * due to disconnection).  Because 'b' may be sent (or discarded) before this
 * function returns, the caller may not be able to observe any change in
 * 'counter'.
 *
 * There is no rconn_send_wait() function: an rconn has a send queue that it
 * takes care of sending if you call rconn_run(), which will have the side
 * effect of waking up poll_block(). */
int
rconn_send(struct rconn *rc, struct ofpbuf *b,
           struct rconn_packet_counter *counter)
{
    if (rconn_is_connected(rc)) {
        COVERAGE_INC(rconn_queued);
        copy_to_monitor(rc, b);
        b->private_p = counter;
        if (counter) {
            rconn_packet_counter_inc(counter, b->size);
        }
        list_push_back(&rc->txq, &b->list_node);

        /* If the queue was empty before we added 'b', try to send some
         * packets.  (But if the queue had packets in it, it's because the
         * vconn is backlogged and there's no point in stuffing more into it
         * now.  We'll get back to that in rconn_run().) */
        if (rc->txq.next == &b->list_node) {
            try_send(rc);
        }
        return 0;
    } else {
        ofpbuf_delete(b);
        return ENOTCONN;
    }
}

/* Sends 'b' on 'rc'.  Increments 'counter' while the packet is in flight; it
 * will be decremented when it has been sent (or discarded due to
 * disconnection).  Returns 0 if successful, EAGAIN if 'counter->n' is already
 * at least as large as 'queue_limit', or ENOTCONN if 'rc' is not currently
 * connected.  Regardless of return value, 'b' is destroyed.
 *
 * Because 'b' may be sent (or discarded) before this function returns, the
 * caller may not be able to observe any change in 'counter'.
 *
 * There is no rconn_send_wait() function: an rconn has a send queue that it
 * takes care of sending if you call rconn_run(), which will have the side
 * effect of waking up poll_block(). */
int
rconn_send_with_limit(struct rconn *rc, struct ofpbuf *b,
                      struct rconn_packet_counter *counter, int queue_limit)
{
    if (counter->n_packets < queue_limit) {
        return rconn_send(rc, b, counter);
    } else {
        COVERAGE_INC(rconn_overflow);
        ofpbuf_delete(b);
        return EAGAIN;
    }
}

/* Returns the total number of packets successfully sent on the underlying
 * vconn.  A packet is not counted as sent while it is still queued in the
 * rconn, only when it has been successfuly passed to the vconn.  */
unsigned int
rconn_packets_sent(const struct rconn *rc)
{
    return rc->packets_sent;
}

/* Adds 'vconn' to 'rc' as a monitoring connection, to which all messages sent
 * and received on 'rconn' will be copied.  'rc' takes ownership of 'vconn'. */
void
rconn_add_monitor(struct rconn *rc, struct vconn *vconn)
{
    if (rc->n_monitors < ARRAY_SIZE(rc->monitors)) {
        VLOG_INFO("new monitor connection from %s", vconn_get_name(vconn));
        rc->monitors[rc->n_monitors++] = vconn;
    } else {
        VLOG_DBG("too many monitor connections, discarding %s",
                 vconn_get_name(vconn));
        vconn_close(vconn);
    }
}

/* Returns 'rc''s name.  This is a name for human consumption, appropriate for
 * use in log messages.  It is not necessarily a name that may be passed
 * directly to, e.g., vconn_open(). */
const char *
rconn_get_name(const struct rconn *rc)
{
    return rc->name;
}

/* Sets 'rc''s name to 'new_name'. */
void
rconn_set_name(struct rconn *rc, const char *new_name)
{
    free(rc->name);
    rc->name = xstrdup(new_name);
}

/* Returns 'rc''s target.  This is intended to be a string that may be passed
 * directly to, e.g., vconn_open(). */
const char *
rconn_get_target(const struct rconn *rc)
{
    return rc->target;
}

/* Returns true if 'rconn' is connected or in the process of reconnecting,
 * false if 'rconn' is disconnected and will not reconnect on its own. */
bool
rconn_is_alive(const struct rconn *rconn)
{
    return rconn->state != S_VOID;
}

/* Returns true if 'rconn' is connected, false otherwise. */
bool
rconn_is_connected(const struct rconn *rconn)
{
    return is_connected_state(rconn->state);
}

/* Returns true if 'rconn' is connected and thought to have been accepted by
 * the peer's admission-control policy. */
bool
rconn_is_admitted(const struct rconn *rconn)
{
    return (rconn_is_connected(rconn)
            && rconn->last_admitted >= rconn->last_connected);
}

/* Returns 0 if 'rconn' is currently connected and considered to have been
 * accepted by the peer's admission-control policy, otherwise the number of
 * seconds since 'rconn' was last in such a state. */
int
rconn_failure_duration(const struct rconn *rconn)
{
    return rconn_is_admitted(rconn) ? 0 : time_now() - rconn->last_admitted;
}

/* Returns the IP address of the peer, or 0 if the peer's IP address is not
 * known. */
ovs_be32
rconn_get_remote_ip(const struct rconn *rconn)
{
    return rconn->remote_ip;
}

/* Returns the transport port of the peer, or 0 if the peer's port is not
 * known. */
ovs_be16
rconn_get_remote_port(const struct rconn *rconn)
{
    return rconn->remote_port;
}

/* Returns the IP address used to connect to the peer, or 0 if the
 * connection is not an IP-based protocol or if its IP address is not
 * known. */
ovs_be32
rconn_get_local_ip(const struct rconn *rconn)
{
    return rconn->local_ip;
}

/* Returns the transport port used to connect to the peer, or 0 if the
 * connection does not contain a port or if the port is not known. */
ovs_be16
rconn_get_local_port(const struct rconn *rconn)
{
    return rconn->vconn ? vconn_get_local_port(rconn->vconn) : 0;
}

/* Returns the OpenFlow version negotiated with the peer, or -1 if there is
 * currently no connection or if version negotiation is not yet complete. */
int
rconn_get_version(const struct rconn *rconn)
{
    return rconn->vconn ? vconn_get_version(rconn->vconn) : -1;
}

/* Returns the total number of packets successfully received by the underlying
 * vconn.  */
unsigned int
rconn_packets_received(const struct rconn *rc)
{
    return rc->packets_received;
}

/* Returns a string representing the internal state of 'rc'.  The caller must
 * not modify or free the string. */
const char *
rconn_get_state(const struct rconn *rc)
{
    return state_name(rc->state);
}

/* Returns the time at which the last successful connection was made by
 * 'rc'. Returns TIME_MIN if never connected. */
time_t
rconn_get_last_connection(const struct rconn *rc)
{
    return rc->last_connected;
}

/* Returns the time at which 'rc' was last disconnected. Returns TIME_MIN
 * if never disconnected. */
time_t
rconn_get_last_disconnect(const struct rconn *rc)
{
    return rc->last_disconnected;
}

/* Returns 'rc''s current connection sequence number, a number that changes
 * every time that 'rconn' connects or disconnects. */
unsigned int
rconn_get_connection_seqno(const struct rconn *rc)
{
    return rc->seqno;
}

/* Returns a value that explains why 'rc' last disconnected:
 *
 *   - 0 means that the last disconnection was caused by a call to
 *     rconn_disconnect(), or that 'rc' is new and has not yet completed its
 *     initial connection or connection attempt.
 *
 *   - EOF means that the connection was closed in the normal way by the peer.
 *
 *   - A positive integer is an errno value that represents the error.
 */
int
rconn_get_last_error(const struct rconn *rc)
{
    return rc->last_error;
}

/* Returns the number of messages queued for transmission on 'rc'. */
unsigned int
rconn_count_txqlen(const struct rconn *rc)
{
    return list_size(&rc->txq);
}

struct rconn_packet_counter *
rconn_packet_counter_create(void)
{
    struct rconn_packet_counter *c = xzalloc(sizeof *c);
    c->ref_cnt = 1;
    return c;
}

void
rconn_packet_counter_destroy(struct rconn_packet_counter *c)
{
    if (c) {
        assert(c->ref_cnt > 0);
        if (!--c->ref_cnt && !c->n_packets) {
            free(c);
        }
    }
}

void
rconn_packet_counter_inc(struct rconn_packet_counter *c, unsigned int n_bytes)
{
    c->n_packets++;
    c->n_bytes += n_bytes;
}

void
rconn_packet_counter_dec(struct rconn_packet_counter *c, unsigned int n_bytes)
{
    assert(c->n_packets > 0);
    assert(c->n_bytes >= n_bytes);

    c->n_bytes -= n_bytes;
    c->n_packets--;
    if (!c->n_packets) {
        assert(!c->n_bytes);
        if (!c->ref_cnt) {
            free(c);
        }
    }
}

/* Set rc->target and rc->name to 'target' and 'name', respectively.  If 'name'
 * is null, 'target' is used.
 *
 * Also, clear out the cached IP address and port information, since changing
 * the target also likely changes these values. */
static void
rconn_set_target__(struct rconn *rc, const char *target, const char *name)
{
    free(rc->name);
    rc->name = xstrdup(name ? name : target);
    free(rc->target);
    rc->target = xstrdup(target);
    rc->local_ip = 0;
    rc->remote_ip = 0;
    rc->remote_port = 0;
}

/* Tries to send a packet from 'rc''s send buffer.  Returns 0 if successful,
 * otherwise a positive errno value. */
static int
try_send(struct rconn *rc)
{
    struct ofpbuf *msg = ofpbuf_from_list(rc->txq.next);
    unsigned int n_bytes = msg->size;
    struct rconn_packet_counter *counter = msg->private_p;
    int retval;

    /* Eagerly remove 'msg' from the txq.  We can't remove it from the list
     * after sending, if sending is successful, because it is then owned by the
     * vconn, which might have freed it already. */
    list_remove(&msg->list_node);

    retval = vconn_send(rc->vconn, msg);
    if (retval) {
        list_push_front(&rc->txq, &msg->list_node);
        if (retval != EAGAIN) {
            report_error(rc, retval);
            disconnect(rc, retval);
        }
        return retval;
    }
    COVERAGE_INC(rconn_sent);
    rc->packets_sent++;
    if (counter) {
        rconn_packet_counter_dec(counter, n_bytes);
    }
    return 0;
}

/* Reports that 'error' caused 'rc' to disconnect.  'error' may be a positive
 * errno value, or it may be EOF to indicate that the connection was closed
 * normally. */
static void
report_error(struct rconn *rc, int error)
{
    if (error == EOF) {
        /* If 'rc' isn't reliable, then we don't really expect this connection
         * to last forever anyway (probably it's a connection that we received
         * via accept()), so use DBG level to avoid cluttering the logs. */
        enum vlog_level level = rc->reliable ? VLL_INFO : VLL_DBG;
        VLOG(level, "%s: connection closed by peer", rc->name);
    } else {
        VLOG_WARN("%s: connection dropped (%s)", rc->name, strerror(error));
    }
}

/* Disconnects 'rc' and records 'error' as the error that caused 'rc''s last
 * disconnection:
 *
 *   - 0 means that this disconnection is due to a request by 'rc''s client,
 *     not due to any kind of network error.
 *
 *   - EOF means that the connection was closed in the normal way by the peer.
 *
 *   - A positive integer is an errno value that represents the error.
 */
static void
disconnect(struct rconn *rc, int error)
{
    rc->last_error = error;
    if (rc->reliable) {
        time_t now = time_now();

        if (rc->state & (S_CONNECTING | S_ACTIVE | S_IDLE)) {
            rc->last_disconnected = now;
            vconn_close(rc->vconn);
            rc->vconn = NULL;
            flush_queue(rc);
        }

        if (now >= rc->backoff_deadline) {
            rc->backoff = 1;
        } else if (rc->backoff < rc->max_backoff / 2) {
            rc->backoff = MAX(1, 2 * rc->backoff);
            VLOG_INFO("%s: waiting %d seconds before reconnect",
                      rc->name, rc->backoff);
        } else {
            if (rconn_logging_connection_attempts__(rc)) {
                VLOG_INFO("%s: continuing to retry connections in the "
                          "background but suppressing further logging",
                          rc->name);
            }
            rc->backoff = rc->max_backoff;
        }
        rc->backoff_deadline = now + rc->backoff;
        state_transition(rc, S_BACKOFF);
    } else {
        rc->last_disconnected = time_now();
        rconn_disconnect(rc);
    }
}

/* Drops all the packets from 'rc''s send queue and decrements their queue
 * counts. */
static void
flush_queue(struct rconn *rc)
{
    if (list_is_empty(&rc->txq)) {
        return;
    }
    while (!list_is_empty(&rc->txq)) {
        struct ofpbuf *b = ofpbuf_from_list(list_pop_front(&rc->txq));
        struct rconn_packet_counter *counter = b->private_p;
        if (counter) {
            rconn_packet_counter_dec(counter, b->size);
        }
        COVERAGE_INC(rconn_discarded);
        ofpbuf_delete(b);
    }
    poll_immediate_wake();
}

static unsigned int
elapsed_in_this_state(const struct rconn *rc)
{
    return time_now() - rc->state_entered;
}

static unsigned int
timeout(const struct rconn *rc)
{
    switch (rc->state) {
#define STATE(NAME, VALUE) case S_##NAME: return timeout_##NAME(rc);
        STATES
#undef STATE
    default:
        NOT_REACHED();
    }
}

static bool
timed_out(const struct rconn *rc)
{
    return time_now() >= sat_add(rc->state_entered, timeout(rc));
}

static void
state_transition(struct rconn *rc, enum state state)
{
    rc->seqno += (rc->state == S_ACTIVE) != (state == S_ACTIVE);
    if (is_connected_state(state) && !is_connected_state(rc->state)) {
        rc->probably_admitted = false;
    }
    if (rconn_is_connected(rc)) {
        rc->total_time_connected += elapsed_in_this_state(rc);
    }
    VLOG_DBG("%s: entering %s", rc->name, state_name(state));
    rc->state = state;
    rc->state_entered = time_now();
}

static void
copy_to_monitor(struct rconn *rc, const struct ofpbuf *b)
{
    struct ofpbuf *clone = NULL;
    int retval;
    size_t i;

    for (i = 0; i < rc->n_monitors; ) {
        struct vconn *vconn = rc->monitors[i];

        if (!clone) {
            clone = ofpbuf_clone(b);
        }
        retval = vconn_send(vconn, clone);
        if (!retval) {
            clone = NULL;
        } else if (retval != EAGAIN) {
            VLOG_DBG("%s: closing monitor connection to %s: %s",
                     rconn_get_name(rc), vconn_get_name(vconn),
                     strerror(retval));
            rc->monitors[i] = rc->monitors[--rc->n_monitors];
            continue;
        }
        i++;
    }
    ofpbuf_delete(clone);
}

static bool
is_connected_state(enum state state)
{
    return (state & (S_ACTIVE | S_IDLE)) != 0;
}

static bool
is_admitted_msg(const struct ofpbuf *b)
{
    enum ofptype type;
    enum ofperr error;

    error = ofptype_decode(&type, b->data);
    if (error) {
        return false;
    }

    switch (type) {
    case OFPTYPE_HELLO:
    case OFPTYPE_ERROR:
    case OFPTYPE_ECHO_REQUEST:
    case OFPTYPE_ECHO_REPLY:
    case OFPTYPE_FEATURES_REQUEST:
    case OFPTYPE_FEATURES_REPLY:
    case OFPTYPE_GET_CONFIG_REQUEST:
    case OFPTYPE_GET_CONFIG_REPLY:
    case OFPTYPE_SET_CONFIG:
        return false;

    case OFPTYPE_PACKET_IN:
    case OFPTYPE_FLOW_REMOVED:
    case OFPTYPE_PORT_STATUS:
    case OFPTYPE_PACKET_OUT:
    case OFPTYPE_FLOW_MOD:
    case OFPTYPE_PORT_MOD:
    case OFPTYPE_BARRIER_REQUEST:
    case OFPTYPE_BARRIER_REPLY:
    case OFPTYPE_DESC_STATS_REQUEST:
    case OFPTYPE_DESC_STATS_REPLY:
    case OFPTYPE_FLOW_STATS_REQUEST:
    case OFPTYPE_FLOW_STATS_REPLY:
    case OFPTYPE_AGGREGATE_STATS_REQUEST:
    case OFPTYPE_AGGREGATE_STATS_REPLY:
    case OFPTYPE_TABLE_STATS_REQUEST:
    case OFPTYPE_TABLE_STATS_REPLY:
    case OFPTYPE_PORT_STATS_REQUEST:
    case OFPTYPE_PORT_STATS_REPLY:
    case OFPTYPE_QUEUE_STATS_REQUEST:
    case OFPTYPE_QUEUE_STATS_REPLY:
    case OFPTYPE_PORT_DESC_STATS_REQUEST:
    case OFPTYPE_PORT_DESC_STATS_REPLY:
    case OFPTYPE_ROLE_REQUEST:
    case OFPTYPE_ROLE_REPLY:
    case OFPTYPE_SET_FLOW_FORMAT:
    case OFPTYPE_FLOW_MOD_TABLE_ID:
    case OFPTYPE_SET_PACKET_IN_FORMAT:
    case OFPTYPE_FLOW_AGE:
    case OFPTYPE_SET_ASYNC_CONFIG:
    case OFPTYPE_SET_CONTROLLER_ID:
    case OFPTYPE_FLOW_MONITOR_STATS_REQUEST:
    case OFPTYPE_FLOW_MONITOR_STATS_REPLY:
    case OFPTYPE_FLOW_MONITOR_CANCEL:
    case OFPTYPE_FLOW_MONITOR_PAUSED:
    case OFPTYPE_FLOW_MONITOR_RESUMED:
    default:
        return true;
    }
}

/* Returns true if 'rc' is currently logging information about connection
 * attempts, false if logging should be suppressed because 'rc' hasn't
 * successuflly connected in too long. */
static bool
rconn_logging_connection_attempts__(const struct rconn *rc)
{
    return rc->backoff < rc->max_backoff;
}

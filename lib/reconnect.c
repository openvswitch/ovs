/*
 * Copyright (c) 2008, 2009, 2010, 2012, 2013 Nicira, Inc.
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
#include "reconnect.h"

#include <stdlib.h>

#include "openvswitch/poll-loop.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(reconnect);

#define STATES                                  \
    STATE(VOID, 1 << 0)                         \
    STATE(BACKOFF, 1 << 1)                      \
    STATE(CONNECTING, 1 << 3)          \
    STATE(ACTIVE, 1 << 4)                       \
    STATE(IDLE, 1 << 5)                         \
    STATE(RECONNECT, 1 << 6)                    \
    STATE(LISTENING, 1 << 7)
enum state {
#define STATE(NAME, VALUE) S_##NAME = VALUE,
    STATES
#undef STATE
};

static bool
is_connected_state(enum state state)
{
    return (state & (S_ACTIVE | S_IDLE)) != 0;
}

struct reconnect {
    /* Configuration. */
    char *name;
    int min_backoff;
    int max_backoff;
    int probe_interval;
    bool passive;
    enum vlog_level info;       /* Used for informational messages. */

    /* State. */
    enum state state;
    long long int state_entered;
    int backoff;
    long long int last_activity;
    long long int last_connected;
    long long int last_disconnected;
    unsigned int max_tries;
    unsigned int backoff_free_tries;

    /* These values are simply for statistics reporting, not otherwise used
     * directly by anything internal. */
    long long int creation_time;
    unsigned int n_attempted_connections, n_successful_connections;
    unsigned int total_connected_duration;
    unsigned int seqno;
};

static void reconnect_transition__(struct reconnect *, long long int now,
                                   enum state state);
static long long int reconnect_deadline__(const struct reconnect *);
static bool reconnect_may_retry(struct reconnect *);

static const char *
reconnect_state_name__(enum state state)
{
    switch (state) {
#define STATE(NAME, VALUE) case S_##NAME: return #NAME;
        STATES
#undef STATE
    }
    return "***ERROR***";
}

/* Creates and returns a new reconnect FSM with default settings.  The FSM is
 * initially disabled.  The caller will likely want to call reconnect_enable()
 * and reconnect_set_name() on the returned object. */
struct reconnect *
reconnect_create(long long int now)
{
    struct reconnect *fsm = xzalloc(sizeof *fsm);

    fsm->name = xstrdup("void");
    fsm->min_backoff = RECONNECT_DEFAULT_MIN_BACKOFF;
    fsm->max_backoff = RECONNECT_DEFAULT_MAX_BACKOFF;
    fsm->probe_interval = RECONNECT_DEFAULT_PROBE_INTERVAL;
    fsm->passive = false;
    fsm->info = VLL_INFO;

    fsm->state = S_VOID;
    fsm->state_entered = now;
    fsm->backoff = 0;
    fsm->last_activity = now;
    fsm->last_connected = LLONG_MAX;
    fsm->last_disconnected = LLONG_MAX;
    fsm->max_tries = UINT_MAX;
    fsm->creation_time = now;

    return fsm;
}

/* Frees 'fsm'. */
void
reconnect_destroy(struct reconnect *fsm)
{
    if (fsm) {
        free(fsm->name);
        free(fsm);
    }
}

/* If 'quiet' is true, 'fsm' will log informational messages at level VLL_DBG,
 * by default keeping them out of log files.  This is appropriate if the
 * connection is one that is expected to be short-lived, so that the log
 * messages are merely distracting.
 *
 * If 'quiet' is false, 'fsm' logs informational messages at level VLL_INFO.
 * This is the default.
 *
 * This setting has no effect on the log level of debugging, warning, or error
 * messages. */
void
reconnect_set_quiet(struct reconnect *fsm, bool quiet)
{
    fsm->info = quiet ? VLL_DBG : VLL_INFO;
}

/* Returns 'fsm''s name. */
const char *
reconnect_get_name(const struct reconnect *fsm)
{
    return fsm->name;
}

/* Sets 'fsm''s name to 'name'.  If 'name' is null, then "void" is used
 * instead.
 *
 * The name set for 'fsm' is used in log messages. */
void
reconnect_set_name(struct reconnect *fsm, const char *name)
{
    free(fsm->name);
    fsm->name = xstrdup(name ? name : "void");
}

/* Return the minimum number of milliseconds to back off between consecutive
 * connection attempts.  The default is RECONNECT_DEFAULT_MIN_BACKOFF. */
int
reconnect_get_min_backoff(const struct reconnect *fsm)
{
    return fsm->min_backoff;
}

/* Return the maximum number of milliseconds to back off between consecutive
 * connection attempts.  The default is RECONNECT_DEFAULT_MAX_BACKOFF. */
int
reconnect_get_max_backoff(const struct reconnect *fsm)
{
    return fsm->max_backoff;
}

/* Returns the "probe interval" for 'fsm' in milliseconds.  If this is zero, it
 * disables the connection keepalive feature.  If it is nonzero, then if the
 * interval passes while 'fsm' is connected and without reconnect_activity()
 * being called for 'fsm', reconnect_run() returns RECONNECT_PROBE.  If the
 * interval passes again without reconnect_activity() being called,
 * reconnect_run() returns RECONNECT_DISCONNECT for 'fsm'. */
int
reconnect_get_probe_interval(const struct reconnect *fsm)
{
    return fsm->probe_interval;
}

/* Limits the maximum number of times that 'fsm' will ask the client to try to
 * reconnect to 'max_tries'.  UINT_MAX (the default) means an unlimited number
 * of tries.
 *
 * After the number of tries has expired, the 'fsm' will disable itself
 * instead of backing off and retrying. */
void
reconnect_set_max_tries(struct reconnect *fsm, unsigned int max_tries)
{
    fsm->max_tries = max_tries;
}

/* Returns the current remaining number of connection attempts, UINT_MAX if
 * the number is unlimited.  */
unsigned int
reconnect_get_max_tries(struct reconnect *fsm)
{
    return fsm->max_tries;
}

/* Sets the number of connection attempts that will be made without backoff to
 * 'backoff_free_tries'.  Values 0 and 1 both represent a single attempt. */
void
reconnect_set_backoff_free_tries(struct reconnect *fsm,
                                 unsigned int backoff_free_tries)
{
    fsm->backoff_free_tries = backoff_free_tries;
}

/* Configures the backoff parameters for 'fsm'.  'min_backoff' is the minimum
 * number of milliseconds, and 'max_backoff' is the maximum, between connection
 * attempts.  The current backoff is also the duration that 'fsm' is willing to
 * wait for a given connection to succeed or fail.
 *
 * 'min_backoff' must be at least 1000, and 'max_backoff' must be greater than
 * or equal to 'min_backoff'.
 *
 * Pass 0 for 'min_backoff' or 'max_backoff' or both to use the defaults. */
void
reconnect_set_backoff(struct reconnect *fsm, int min_backoff, int max_backoff)
{
    fsm->min_backoff = MAX(min_backoff, 1000);
    fsm->max_backoff = (max_backoff
                        ? MAX(max_backoff, 1000)
                        : RECONNECT_DEFAULT_MAX_BACKOFF);
    if (fsm->min_backoff > fsm->max_backoff) {
        fsm->max_backoff = fsm->min_backoff;
    }

    if (fsm->state == S_BACKOFF && fsm->backoff > max_backoff) {
        fsm->backoff = max_backoff;
    }
}

/* Sets the "probe interval" for 'fsm' to 'probe_interval', in milliseconds.
 * If this is zero, it disables the connection keepalive feature.  If it is
 * nonzero, then if the interval passes while 'fsm' is connected and without
 * reconnect_activity() being called for 'fsm', reconnect_run() returns
 * RECONNECT_PROBE.  If the interval passes again without reconnect_activity()
 * being called, reconnect_run() returns RECONNECT_DISCONNECT for 'fsm'.
 *
 * If 'probe_interval' is nonzero, then it will be forced to a value of at
 * least 1000 ms. */
void
reconnect_set_probe_interval(struct reconnect *fsm, int probe_interval)
{
    fsm->probe_interval = probe_interval ? MAX(1000, probe_interval) : 0;
}

/* Returns true if 'fsm' is in passive mode, false if 'fsm' is in active mode
 * (the default). */
bool
reconnect_is_passive(const struct reconnect *fsm)
{
    return fsm->passive;
}

/* Configures 'fsm' for active or passive mode.  In active mode (the default),
 * the FSM is attempting to connect to a remote host.  In passive mode, the FSM
 * is listening for connections from a remote host. */
void
reconnect_set_passive(struct reconnect *fsm, bool passive, long long int now)
{
    if (fsm->passive != passive) {
        fsm->passive = passive;

        if (passive
            ? fsm->state & (S_CONNECTING | S_RECONNECT)
            : fsm->state == S_LISTENING && reconnect_may_retry(fsm)) {
            reconnect_transition__(fsm, now, S_BACKOFF);
            fsm->backoff = 0;
        }
    }
}

/* Returns true if 'fsm' has been enabled with reconnect_enable().  Calling
 * another function that indicates a change in connection state, such as
 * reconnect_disconnected() or reconnect_force_reconnect(), will also enable
 * a reconnect FSM. */
bool
reconnect_is_enabled(const struct reconnect *fsm)
{
    return fsm->state != S_VOID;
}

/* If 'fsm' is disabled (the default for newly created FSMs), enables it, so
 * that the next call to reconnect_run() for 'fsm' will return
 * RECONNECT_CONNECT.
 *
 * If 'fsm' is not disabled, this function has no effect. */
void
reconnect_enable(struct reconnect *fsm, long long int now)
{
    if (fsm->state == S_VOID && reconnect_may_retry(fsm)) {
        reconnect_transition__(fsm, now, S_BACKOFF);
        fsm->backoff = 0;
    }
}

/* Disables 'fsm'.  Until 'fsm' is enabled again, reconnect_run() will always
 * return 0. */
void
reconnect_disable(struct reconnect *fsm, long long int now)
{
    if (fsm->state != S_VOID) {
        reconnect_transition__(fsm, now, S_VOID);
    }
}

/* If 'fsm' is enabled and currently connected (or attempting to connect),
 * forces reconnect_run() for 'fsm' to return RECONNECT_DISCONNECT the next
 * time it is called, which should cause the client to drop the connection (or
 * attempt), back off, and then reconnect. */
void
reconnect_force_reconnect(struct reconnect *fsm, long long int now)
{
    if (fsm->state & (S_CONNECTING | S_ACTIVE | S_IDLE)) {
        reconnect_transition__(fsm, now, S_RECONNECT);
    }
}

/* Tell 'fsm' that the connection dropped or that a connection attempt failed.
 * 'error' specifies the reason: a positive value represents an errno value,
 * EOF indicates that the connection was closed by the peer (e.g. read()
 * returned 0), and 0 indicates no specific error.
 *
 * The FSM will back off, then reconnect. */
void
reconnect_disconnected(struct reconnect *fsm, long long int now, int error)
{
    if (!(fsm->state & (S_BACKOFF | S_VOID))) {
        /* Report what happened. */
        if (fsm->state & (S_ACTIVE | S_IDLE)) {
            if (error > 0) {
                VLOG_WARN("%s: connection dropped (%s)",
                          fsm->name, ovs_strerror(error));
            } else if (error == EOF) {
                VLOG(fsm->info, "%s: connection closed by peer", fsm->name);
            } else {
                VLOG(fsm->info, "%s: connection dropped", fsm->name);
            }
        } else if (fsm->state == S_LISTENING) {
            if (error > 0) {
                VLOG_WARN("%s: error listening for connections (%s)",
                          fsm->name, ovs_strerror(error));
            } else {
                VLOG(fsm->info, "%s: error listening for connections",
                     fsm->name);
            }
        } else if (fsm->backoff < fsm->max_backoff) {
            const char *type = fsm->passive ? "listen" : "connection";
            if (error > 0) {
                VLOG_INFO("%s: %s attempt failed (%s)",
                          fsm->name, type, ovs_strerror(error));
            } else {
                VLOG(fsm->info, "%s: %s attempt timed out", fsm->name, type);
            }
        } else {
            /* We have reached the maximum backoff, so suppress logging to
             * avoid wastefully filling the log.  (Previously we logged that we
             * were suppressing further logging, see below.) */
        }

        if (fsm->state & (S_ACTIVE | S_IDLE)) {
            fsm->last_disconnected = now;
        }

        if (!reconnect_may_retry(fsm)) {
            reconnect_transition__(fsm, now, S_VOID);
            return;
        }

        /* Back off. */
        if (fsm->backoff_free_tries > 1) {
            fsm->backoff_free_tries--;
            fsm->backoff = 0;
        } else if (fsm->state & (S_ACTIVE | S_IDLE)
                   && (fsm->last_activity - fsm->last_connected >= fsm->backoff
                       || fsm->passive)) {
            fsm->backoff = fsm->passive ? 0 : fsm->min_backoff;
        } else {
            if (fsm->backoff < fsm->min_backoff) {
                fsm->backoff = fsm->min_backoff;
            } else if (fsm->backoff < fsm->max_backoff / 2) {
                fsm->backoff *= 2;
                VLOG(fsm->info, "%s: waiting %.3g seconds before %s",
                     fsm->name, fsm->backoff / 1000.0,
                     fsm->passive ? "trying to listen again" : "reconnect");
            } else {
                if (fsm->backoff < fsm->max_backoff) {
                    VLOG_INFO("%s: continuing to %s in the background but "
                              "suppressing further logging", fsm->name,
                              fsm->passive ? "try to listen" : "reconnect");
                }
                fsm->backoff = fsm->max_backoff;
            }
        }
        reconnect_transition__(fsm, now, S_BACKOFF);
    }
}

/* Tell 'fsm' that a connection or listening attempt is in progress.
 *
 * The FSM will start a timer, after which the connection or listening attempt
 * will be aborted (by returning RECONNECT_DISCONNECT from
 * reconnect_run()).  */
void
reconnect_connecting(struct reconnect *fsm, long long int now)
{
    if (fsm->state != S_CONNECTING) {
        if (fsm->passive) {
            VLOG(fsm->info, "%s: listening...", fsm->name);
        } else if (fsm->backoff < fsm->max_backoff) {
            VLOG(fsm->info, "%s: connecting...", fsm->name);
        }
        reconnect_transition__(fsm, now, S_CONNECTING);
    }
}

/* Tell 'fsm' that the client is listening for connection attempts.  This state
 * last indefinitely until the client reports some change.
 *
 * The natural progression from this state is for the client to report that a
 * connection has been accepted or is in progress of being accepted, by calling
 * reconnect_connecting() or reconnect_connected().
 *
 * The client may also report that listening failed (e.g. accept() returned an
 * unexpected error such as ENOMEM) by calling reconnect_listen_error(), in
 * which case the FSM will back off and eventually return RECONNECT_CONNECT
 * from reconnect_run() to tell the client to try listening again. */
void
reconnect_listening(struct reconnect *fsm, long long int now)
{
    if (fsm->state != S_LISTENING) {
        VLOG(fsm->info, "%s: listening...", fsm->name);
        reconnect_transition__(fsm, now, S_LISTENING);
    }
}

/* Tell 'fsm' that the client's attempt to accept a connection failed
 * (e.g. accept() returned an unexpected error such as ENOMEM).
 *
 * If the FSM is currently listening (reconnect_listening() was called), it
 * will back off and eventually return RECONNECT_CONNECT from reconnect_run()
 * to tell the client to try listening again.  If there is an active
 * connection, this will be delayed until that connection drops. */
void
reconnect_listen_error(struct reconnect *fsm, long long int now, int error)
{
    if (fsm->state == S_LISTENING) {
        reconnect_disconnected(fsm, now, error);
    }
}

/* Tell 'fsm' that the connection was successful.
 *
 * The FSM will start the probe interval timer, which is reset by
 * reconnect_activity().  If the timer expires, a probe will be sent (by
 * returning RECONNECT_PROBE from reconnect_run()).  If the timer expires
 * again without being reset, the connection will be aborted (by returning
 * RECONNECT_DISCONNECT from reconnect_run()). */
void
reconnect_connected(struct reconnect *fsm, long long int now)
{
    if (!is_connected_state(fsm->state)) {
        reconnect_connecting(fsm, now);

        VLOG(fsm->info, "%s: connected", fsm->name);
        reconnect_transition__(fsm, now, S_ACTIVE);
        fsm->last_connected = now;
    }
}

/* Tell 'fsm' that the connection attempt failed.
 *
 * The FSM will back off and attempt to reconnect. */
void
reconnect_connect_failed(struct reconnect *fsm, long long int now, int error)
{
    reconnect_connecting(fsm, now);
    reconnect_disconnected(fsm, now, error);
}

/* Tell 'fsm' that some activity has occurred on the connection.  This resets
 * the probe interval timer, so that the connection is known not to be idle. */
void
reconnect_activity(struct reconnect *fsm, long long int now)
{
    if (fsm->state != S_ACTIVE) {
        reconnect_transition__(fsm, now, S_ACTIVE);
    }
    fsm->last_activity = now;
}

static void
reconnect_transition__(struct reconnect *fsm, long long int now,
                       enum state state)
{
    if (fsm->state == S_CONNECTING) {
        fsm->n_attempted_connections++;
        if (state == S_ACTIVE) {
            fsm->n_successful_connections++;
        }
    }
    if (is_connected_state(fsm->state) != is_connected_state(state)) {
        if (is_connected_state(fsm->state)) {
            fsm->total_connected_duration += now - fsm->last_connected;
        }
        fsm->seqno++;
    }

    VLOG_DBG("%s: entering %s", fsm->name, reconnect_state_name__(state));
    fsm->state = state;
    fsm->state_entered = now;
}

static long long int
reconnect_deadline__(const struct reconnect *fsm)
{
    ovs_assert(fsm->state_entered != LLONG_MIN);
    switch (fsm->state) {
    case S_VOID:
    case S_LISTENING:
        return LLONG_MAX;

    case S_BACKOFF:
        return fsm->state_entered + fsm->backoff;

    case S_CONNECTING:
        return fsm->state_entered + MAX(1000, fsm->backoff);

    case S_ACTIVE:
        if (fsm->probe_interval) {
            long long int base = MAX(fsm->last_activity, fsm->state_entered);
            return base + fsm->probe_interval;
        }
        return LLONG_MAX;

    case S_IDLE:
        if (fsm->probe_interval) {
            return fsm->state_entered + fsm->probe_interval;
        }
        return LLONG_MAX;

    case S_RECONNECT:
        return fsm->state_entered;
    }

    OVS_NOT_REACHED();
}

/* Assesses whether any action should be taken on 'fsm'.  The return value is
 * one of:
 *
 *     - 0: The client need not take any action.
 *
 *     - Active client, RECONNECT_CONNECT: The client should start a connection
 *       attempt and indicate this by calling reconnect_connecting().  If the
 *       connection attempt has definitely succeeded, it should call
 *       reconnect_connected().  If the connection attempt has definitely
 *       failed, it should call reconnect_connect_failed().
 *
 *       The FSM is smart enough to back off correctly after successful
 *       connections that quickly abort, so it is OK to call
 *       reconnect_connected() after a low-level successful connection
 *       (e.g. connect()) even if the connection might soon abort due to a
 *       failure at a high-level (e.g. SSL negotiation failure).
 *
 *     - Passive client, RECONNECT_CONNECT: The client should try to listen for
 *       a connection, if it is not already listening.  It should call
 *       reconnect_listening() if successful, otherwise reconnect_connecting()
 *       or reconnected_connect_failed() if the attempt is in progress or
 *       definitely failed, respectively.
 *
 *       A listening passive client should constantly attempt to accept a new
 *       connection and report an accepted connection with
 *       reconnect_connected().
 *
 *     - RECONNECT_DISCONNECT: The client should abort the current connection
 *       or connection attempt or listen attempt and call
 *       reconnect_disconnected() or reconnect_connect_failed() to indicate it.
 *
 *     - RECONNECT_PROBE: The client should send some kind of request to the
 *       peer that will elicit a response, to ensure that the connection is
 *       indeed in working order.  (This will only be returned if the "probe
 *       interval" is nonzero--see reconnect_set_probe_interval()).
 */
enum reconnect_action
reconnect_run(struct reconnect *fsm, long long int now)
{
    if (now >= reconnect_deadline__(fsm)) {
        switch (fsm->state) {
        case S_VOID:
            return 0;

        case S_BACKOFF:
            return RECONNECT_CONNECT;

        case S_CONNECTING:
            return RECONNECT_DISCONNECT;

        case S_ACTIVE:
            VLOG_DBG("%s: idle %lld ms, sending inactivity probe", fsm->name,
                     now - MAX(fsm->last_activity, fsm->state_entered));
            reconnect_transition__(fsm, now, S_IDLE);
            return RECONNECT_PROBE;

        case S_IDLE:
            VLOG_ERR("%s: no response to inactivity probe after %.3g "
                     "seconds, disconnecting",
                     fsm->name, (now - fsm->state_entered) / 1000.0);
            return RECONNECT_DISCONNECT;

        case S_RECONNECT:
            return RECONNECT_DISCONNECT;

        case S_LISTENING:
            return 0;
        }

        OVS_NOT_REACHED();
    } else {
        return 0;
    }
}

/* Causes the next call to poll_block() to wake up when reconnect_run() should
 * be called on 'fsm'. */
void
reconnect_wait(struct reconnect *fsm, long long int now)
{
    int timeout = reconnect_timeout(fsm, now);
    if (timeout >= 0) {
        poll_timer_wait(timeout);
    }
}

/* Returns the number of milliseconds after which reconnect_run() should be
 * called on 'fsm' if nothing else notable happens in the meantime, or a
 * negative number if this is currently unnecessary. */
int
reconnect_timeout(struct reconnect *fsm, long long int now)
{
    long long int deadline = reconnect_deadline__(fsm);
    if (deadline != LLONG_MAX) {
        long long int remaining = deadline - now;
        return MAX(0, MIN(INT_MAX, remaining));
    }
    return -1;
}

/* Returns true if 'fsm' is currently believed to be connected, that is, if
 * reconnect_connected() was called more recently than any call to
 * reconnect_connect_failed() or reconnect_disconnected() or
 * reconnect_disable(), and false otherwise.  */
bool
reconnect_is_connected(const struct reconnect *fsm)
{
    return is_connected_state(fsm->state);
}

/* Returns the number of milliseconds since 'fsm' last successfully connected
 * to its peer (even if it has since disconnected). Returns UINT_MAX if never
 * connected. */
unsigned int
reconnect_get_last_connect_elapsed(const struct reconnect *fsm,
                                   long long int now)
{
    return fsm->last_connected == LLONG_MAX ? UINT_MAX
        : now - fsm->last_connected;
}

/* Returns the number of milliseconds since 'fsm' last disconnected
 * from its peer (even if it has since reconnected). Returns UINT_MAX if never
 * disconnected. */
unsigned int
reconnect_get_last_disconnect_elapsed(const struct reconnect *fsm,
                                      long long int now)
{
    return fsm->last_disconnected == LLONG_MAX ? UINT_MAX
        : now - fsm->last_disconnected;
}

/* Copies various statistics for 'fsm' into '*stats'. */
void
reconnect_get_stats(const struct reconnect *fsm, long long int now,
                    struct reconnect_stats *stats)
{
    stats->creation_time = fsm->creation_time;
    stats->last_activity = fsm->last_activity;
    stats->last_connected = fsm->last_connected;
    stats->last_disconnected = fsm->last_disconnected;
    stats->backoff = fsm->backoff;
    stats->seqno = fsm->seqno;
    stats->is_connected = reconnect_is_connected(fsm);
    stats->msec_since_connect
        = reconnect_get_last_connect_elapsed(fsm, now);
    stats->msec_since_disconnect
        = reconnect_get_last_disconnect_elapsed(fsm, now);
    stats->total_connected_duration = fsm->total_connected_duration
        + (is_connected_state(fsm->state)
           ? reconnect_get_last_connect_elapsed(fsm, now) : 0);
    stats->n_attempted_connections = fsm->n_attempted_connections;
    stats->n_successful_connections = fsm->n_successful_connections;
    stats->state = reconnect_state_name__(fsm->state);
    stats->state_elapsed = now - fsm->state_entered;
}

static bool
reconnect_may_retry(struct reconnect *fsm)
{
    bool may_retry = fsm->max_tries > 0;
    if (may_retry && fsm->max_tries != UINT_MAX) {
        fsm->max_tries--;
    }
    return may_retry;
}

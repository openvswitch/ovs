/*
 * Copyright (c) 2009, 2010, 2012 Nicira, Inc.
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

#ifndef RECONNECT_H
#define RECONNECT_H 1

/* This library implements a finite-state machine for connecting and
 * reconnecting to a network resource with exponential backoff.  It also
 * provides optional support for detecting a connection on which the peer is no
 * longer responding.
 *
 * The library does not implement anything networking related, only an FSM for
 * networking code to use.
 *
 * Many "reconnect" functions take a "now" argument.  This makes testing easier
 * since there is no hidden state.  When not testing, just pass the return
 * value of time_msec() from timeval.h.  (Perhaps this design should be
 * revisited later.) */

#include <stdbool.h>

struct reconnect *reconnect_create(long long int now);
void reconnect_destroy(struct reconnect *);

void reconnect_set_quiet(struct reconnect *, bool quiet);

const char *reconnect_get_name(const struct reconnect *);
void reconnect_set_name(struct reconnect *, const char *name);

/* Defaults, all in msecs. */
#define RECONNECT_DEFAULT_MIN_BACKOFF 1000
#define RECONNECT_DEFAULT_MAX_BACKOFF 8000
#define RECONNECT_DEFAULT_PROBE_INTERVAL 5000

int reconnect_get_min_backoff(const struct reconnect *);
int reconnect_get_max_backoff(const struct reconnect *);
int reconnect_get_probe_interval(const struct reconnect *);

void reconnect_set_max_tries(struct reconnect *, unsigned int max_tries);
unsigned int reconnect_get_max_tries(struct reconnect *);
void reconnect_set_backoff_free_tries(struct reconnect *,
                                      unsigned int backoff_free_tries);

void reconnect_set_backoff(struct reconnect *,
                           int min_backoff, int max_backoff);
void reconnect_set_probe_interval(struct reconnect *, int probe_interval);

bool reconnect_is_passive(const struct reconnect *);
void reconnect_set_passive(struct reconnect *, bool passive,
                           long long int now);

bool reconnect_is_enabled(const struct reconnect *);
void reconnect_enable(struct reconnect *, long long int now);
void reconnect_disable(struct reconnect *, long long int now);

void reconnect_force_reconnect(struct reconnect *, long long int now);
void reconnect_skip_backoff(struct reconnect *);

bool reconnect_is_connected(const struct reconnect *);
unsigned int reconnect_get_last_connect_elapsed(const struct reconnect *,
                                                long long int now);
unsigned int reconnect_get_last_disconnect_elapsed(const struct reconnect *,
                                                   long long int now);

void reconnect_disconnected(struct reconnect *, long long int now, int error);
void reconnect_connecting(struct reconnect *, long long int now);
void reconnect_listening(struct reconnect *, long long int now);
void reconnect_listen_error(struct reconnect *, long long int now, int error);
void reconnect_connected(struct reconnect *, long long int now);
void reconnect_connect_failed(struct reconnect *, long long int now,
                              int error);
void reconnect_activity(struct reconnect *, long long int now);

enum reconnect_action {
    RECONNECT_CONNECT = 1,
    RECONNECT_DISCONNECT,
    RECONNECT_PROBE,
};
enum reconnect_action reconnect_run(struct reconnect *, long long int now);
void reconnect_wait(struct reconnect *, long long int now);
int reconnect_timeout(struct reconnect *, long long int now);

struct reconnect_stats {
    /* All times and durations in this structure are in milliseconds. */
    long long int creation_time;     /* Time reconnect_create() called. */
    long long int last_activity;     /* Last call to reconnect_activity(). */
    long long int last_connected;    /* Last call to reconnect_connected(). */
    long long int last_disconnected; /* Last call to reconnect_disconnected(). */
    int backoff;                     /* Current backoff duration.  */

    unsigned int seqno;              /* # of connections + # of disconnections. */

    bool is_connected;                     /* Currently connected? */
    unsigned int msec_since_connect;       /* Time since last connect. */
    unsigned int msec_since_disconnect;    /* Time since last disconnect. */
    unsigned int total_connected_duration; /* Sum of all connections. */
    unsigned int n_attempted_connections;
    unsigned int n_successful_connections;

    /* These should only be provided to a human user for debugging purposes.
     * The client should not attempt to interpret them. */
    const char *state;            /* FSM state. */
    unsigned int state_elapsed;   /* Time since FSM state entered. */
};

void reconnect_get_stats(const struct reconnect *, long long int now,
                         struct reconnect_stats *);

#endif /* reconnect.h */

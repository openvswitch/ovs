/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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
#include "fail-open.h"
#include <inttypes.h>
#include <stdlib.h>
#include "flow.h"
#include "mac-learning.h"
#include "odp-util.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "ofproto.h"
#include "pktbuf.h"
#include "poll-loop.h"
#include "rconn.h"
#include "status.h"
#include "timeval.h"
#include "vconn.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(fail_open)

/*
 * Fail-open mode.
 *
 * In fail-open mode, the switch detects when the controller cannot be
 * contacted or when the controller is dropping switch connections because the
 * switch does not pass its admission control policy.  In those situations the
 * switch sets up flows itself using the "normal" action.
 *
 * There is a little subtlety to implementation, to properly handle the case
 * where the controller allows switch connections but drops them a few seconds
 * later for admission control reasons.  Because of this case, we don't want to
 * just stop setting up flows when we connect to the controller: if we did,
 * then new flow setup and existing flows would stop during the duration of
 * connection to the controller, and thus the whole network would go down for
 * that period of time.
 *
 * So, instead, we add some special cases when we are connected to a
 * controller, but not yet sure that it has admitted us:
 *
 *     - We set up flows immediately ourselves, but simultaneously send out an
 *       OFPT_PACKET_IN to the controller.  We put a special bogus buffer-id in
 *       these OFPT_PACKET_IN messages so that duplicate packets don't get sent
 *       out to the network when the controller replies.
 *
 *     - We also send out OFPT_PACKET_IN messages for totally bogus packets
 *       every so often, in case no real new flows are arriving in the network.
 *
 *     - We don't flush the flow table at the time we connect, because this
 *       could cause network stuttering in a switch with lots of flows or very
 *       high-bandwidth flows by suddenly throwing lots of packets down to
 *       userspace.
 */

struct fail_open {
    struct ofproto *ofproto;
    struct rconn **controllers;
    size_t n_controllers;
    int last_disconn_secs;
    struct status_category *ss_cat;
    long long int next_bogus_packet_in;
    struct rconn_packet_counter *bogus_packet_counter;
};

static void fail_open_recover(struct fail_open *);

/* Returns the number of seconds of disconnection after which fail-open mode
 * should activate. */
static int
trigger_duration(const struct fail_open *fo)
{
    if (!fo->n_controllers) {
        /* Shouldn't ever arrive here, but if we do, never fail open. */
        return INT_MAX;
    } else {
        /* Otherwise, every controller must have a chance to send an
         * inactivity probe and reconnect before we fail open, so take the
         * maximum probe interval and multiply by 3:
         *
         *  - The first interval is the idle time before sending an inactivity
         *    probe.
         *
         *  - The second interval is the time allowed for a response to the
         *    inactivity probe.
         *
         *  - The third interval is the time allowed to reconnect after no
         *    response is received.
         */
        int max_probe_interval;
        size_t i;

        max_probe_interval = 0;
        for (i = 0; i < fo->n_controllers; i++) {
            int probe_interval = rconn_get_probe_interval(fo->controllers[i]);
            max_probe_interval = MAX(max_probe_interval, probe_interval);
        }
        return max_probe_interval * 3;
    }
}

/* Returns the number of seconds for which all controllers have been
 * disconnected.  */
static int
failure_duration(const struct fail_open *fo)
{
    int min_failure_duration;
    size_t i;

    if (!fo->n_controllers) {
        return 0;
    }

    min_failure_duration = INT_MAX;
    for (i = 0; i < fo->n_controllers; i++) {
        int failure_duration = rconn_failure_duration(fo->controllers[i]);
        min_failure_duration = MIN(min_failure_duration, failure_duration);
    }
    return min_failure_duration;
}

/* Returns true if 'fo' is currently in fail-open mode, otherwise false. */
bool
fail_open_is_active(const struct fail_open *fo)
{
    return fo->last_disconn_secs != 0;
}

/* Returns true if at least one controller is connected (regardless of whether
 * those controllers are believed to have authenticated and accepted this
 * switch), false if none of them are connected. */
static bool
any_controller_is_connected(const struct fail_open *fo)
{
    size_t i;

    for (i = 0; i < fo->n_controllers; i++) {
        if (rconn_is_connected(fo->controllers[i])) {
            return true;
        }
    }
    return false;
}

/* Returns true if at least one controller is believed to have authenticated
 * and accepted this switch, false otherwise. */
static bool
any_controller_is_admitted(const struct fail_open *fo)
{
    size_t i;

    for (i = 0; i < fo->n_controllers; i++) {
        if (rconn_is_admitted(fo->controllers[i])) {
            return true;
        }
    }
    return false;
}

static void
send_bogus_packet_in(struct fail_open *fo, struct rconn *rconn)
{
    uint8_t mac[ETH_ADDR_LEN];
    struct ofpbuf *opi;
    struct ofpbuf b;

    /* Compose ofp_packet_in. */
    ofpbuf_init(&b, 128);
    eth_addr_nicira_random(mac);
    compose_benign_packet(&b, "Open vSwitch Controller Probe", 0xa033, mac);
    opi = make_packet_in(pktbuf_get_null(), OFPP_LOCAL, OFPR_NO_MATCH, &b, 64);
    ofpbuf_uninit(&b);

    /* Send. */
    rconn_send_with_limit(rconn, opi, fo->bogus_packet_counter, 1);
}

static void
send_bogus_packet_ins(struct fail_open *fo)
{
    size_t i;

    for (i = 0; i < fo->n_controllers; i++) {
        if (rconn_is_connected(fo->controllers[i])) {
            send_bogus_packet_in(fo, fo->controllers[i]);
        }
    }
}

/* Enter fail-open mode if we should be in it. */
void
fail_open_run(struct fail_open *fo)
{
    int disconn_secs = failure_duration(fo);

    /* Enter fail-open mode if 'fo' is not in it but should be.  */
    if (disconn_secs >= trigger_duration(fo)) {
        if (!fail_open_is_active(fo)) {
            VLOG_WARN("Could not connect to controller (or switch failed "
                      "controller's post-connection admission control "
                      "policy) for %d seconds, failing open", disconn_secs);
            fo->last_disconn_secs = disconn_secs;

            /* Flush all OpenFlow and datapath flows.  We will set up our
             * fail-open rule from fail_open_flushed() when
             * ofproto_flush_flows() calls back to us. */
            ofproto_flush_flows(fo->ofproto);
        } else if (disconn_secs > fo->last_disconn_secs + 60) {
            VLOG_INFO("Still in fail-open mode after %d seconds disconnected "
                      "from controller", disconn_secs);
            fo->last_disconn_secs = disconn_secs;
        }
    }

    /* Schedule a bogus packet-in if we're connected and in fail-open. */
    if (fail_open_is_active(fo)) {
        if (any_controller_is_connected(fo)) {
            bool expired = time_msec() >= fo->next_bogus_packet_in;
            if (expired) {
                send_bogus_packet_ins(fo);
            }
            if (expired || fo->next_bogus_packet_in == LLONG_MAX) {
                fo->next_bogus_packet_in = time_msec() + 2000;
            }
        } else {
            fo->next_bogus_packet_in = LLONG_MAX;
        }
    }

}

/* If 'fo' is currently in fail-open mode and its rconn has connected to the
 * controller, exits fail open mode. */
void
fail_open_maybe_recover(struct fail_open *fo)
{
    if (any_controller_is_admitted(fo)) {
        fail_open_recover(fo);
    }
}

static void
fail_open_recover(struct fail_open *fo)
{
    if (fail_open_is_active(fo)) {
        flow_t flow;

        VLOG_WARN("No longer in fail-open mode");
        fo->last_disconn_secs = 0;
        fo->next_bogus_packet_in = LLONG_MAX;

        memset(&flow, 0, sizeof flow);
        ofproto_delete_flow(fo->ofproto, &flow, OVSFW_ALL, FAIL_OPEN_PRIORITY);
    }
}

void
fail_open_wait(struct fail_open *fo)
{
    if (fo->next_bogus_packet_in != LLONG_MAX) {
        poll_timer_wait_until(fo->next_bogus_packet_in);
    }
}

void
fail_open_flushed(struct fail_open *fo)
{
    int disconn_secs = failure_duration(fo);
    bool open = disconn_secs >= trigger_duration(fo);
    if (open) {
        union ofp_action action;
        flow_t flow;

        /* Set up a flow that matches every packet and directs them to
         * OFPP_NORMAL. */
        memset(&action, 0, sizeof action);
        action.type = htons(OFPAT_OUTPUT);
        action.output.len = htons(sizeof action);
        action.output.port = htons(OFPP_NORMAL);
        memset(&flow, 0, sizeof flow);
        ofproto_add_flow(fo->ofproto, &flow, OVSFW_ALL, FAIL_OPEN_PRIORITY,
                         &action, 1, 0);
    }
}

static void
fail_open_status_cb(struct status_reply *sr, void *fo_)
{
    struct fail_open *fo = fo_;
    int cur_duration = failure_duration(fo);
    int trigger = trigger_duration(fo);

    status_reply_put(sr, "trigger-duration=%d", trigger);
    status_reply_put(sr, "current-duration=%d", cur_duration);
    status_reply_put(sr, "triggered=%s",
                     cur_duration >= trigger ? "true" : "false");
}

/* Creates and returns a new struct fail_open for 'ofproto', registering switch
 * status with 'switch_status'.
 *
 * The caller should register its set of controllers with
 * fail_open_set_controllers().  (There should be at least one controller,
 * otherwise there isn't any point in having the struct fail_open around.) */
struct fail_open *
fail_open_create(struct ofproto *ofproto, struct switch_status *switch_status)
{
    struct fail_open *fo = xmalloc(sizeof *fo);
    fo->ofproto = ofproto;
    fo->controllers = NULL;
    fo->n_controllers = 0;
    fo->last_disconn_secs = 0;
    fo->ss_cat = switch_status_register(switch_status, "fail-open",
                                        fail_open_status_cb, fo);
    fo->next_bogus_packet_in = LLONG_MAX;
    fo->bogus_packet_counter = rconn_packet_counter_create();
    return fo;
}

/* Registers the 'n' rconns in 'rconns' as connections to the controller for
 * 'fo'.  The caller must ensure that all of the rconns remain valid until 'fo'
 * is destroyed or a new set is registered in a subsequent call.
 *
 * Takes ownership of the 'rconns' array, but not of the rconns that it points
 * to (of which the caller retains ownership). */
void
fail_open_set_controllers(struct fail_open *fo,
                          struct rconn **rconns, size_t n)
{
    free(fo->controllers);
    fo->controllers = rconns;
    fo->n_controllers = n;
}

/* Destroys 'fo'. */
void
fail_open_destroy(struct fail_open *fo)
{
    if (fo) {
        fail_open_recover(fo);
        free(fo->controllers);
        /* We don't own the rconns behind fo->controllers. */
        switch_status_unregister(fo->ss_cat);
        rconn_packet_counter_destroy(fo->bogus_packet_counter);
        free(fo);
    }
}

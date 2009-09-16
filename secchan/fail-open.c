/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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
#include "ofpbuf.h"
#include "ofproto.h"
#include "pktbuf.h"
#include "poll-loop.h"
#include "rconn.h"
#include "status.h"
#include "timeval.h"
#include "vconn.h"

#define THIS_MODULE VLM_fail_open
#include "vlog.h"

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
 * So, instead, we add some special caseswhen we are connected to a controller,
 * but not yet sure that it has admitted us:
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
    struct rconn *controller;
    int trigger_duration;
    int last_disconn_secs;
    struct status_category *ss_cat;
    long long int next_bogus_packet_in;
    struct rconn_packet_counter *bogus_packet_counter;
};

/* Returns true if 'fo' should be in fail-open mode, otherwise false. */
static inline bool
should_fail_open(const struct fail_open *fo)
{
    return rconn_failure_duration(fo->controller) >= fo->trigger_duration;
}

/* Returns true if 'fo' is currently in fail-open mode, otherwise false. */
bool
fail_open_is_active(const struct fail_open *fo)
{
    return fo->last_disconn_secs != 0;
}

static void
send_bogus_packet_in(struct fail_open *fo)
{
    uint8_t mac[ETH_ADDR_LEN];
    struct ofpbuf *opi;
    struct ofpbuf b;

    /* Compose ofp_packet_in. */
    ofpbuf_init(&b, 128);
    eth_addr_random(mac);
    compose_benign_packet(&b, "Open vSwitch Controller Probe", 0xa033, mac);
    opi = make_packet_in(pktbuf_get_null(), OFPP_LOCAL, OFPR_NO_MATCH, &b, 64);
    ofpbuf_uninit(&b);

    /* Send. */
    rconn_send_with_limit(fo->controller, opi, fo->bogus_packet_counter, 1);
}

/* Enter fail-open mode if we should be in it.  Handle reconnecting to a
 * controller from fail-open mode. */
void
fail_open_run(struct fail_open *fo)
{
    /* Enter fail-open mode if 'fo' is not in it but should be.  */
    if (should_fail_open(fo)) {
        int disconn_secs = rconn_failure_duration(fo->controller);
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
        if (rconn_is_connected(fo->controller)) {
            bool expired = time_msec() >= fo->next_bogus_packet_in;
            if (expired) {
                send_bogus_packet_in(fo);
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
    if (fail_open_is_active(fo) && rconn_is_admitted(fo->controller)) {
        flow_t flow;

        VLOG_WARN("No longer in fail-open mode");
        fo->last_disconn_secs = 0;
        fo->next_bogus_packet_in = LLONG_MAX;

        memset(&flow, 0, sizeof flow);
        ofproto_delete_flow(fo->ofproto, &flow, OFPFW_ALL, FAIL_OPEN_PRIORITY);
    }
}

void
fail_open_wait(struct fail_open *fo)
{
    if (fo->next_bogus_packet_in != LLONG_MAX) {
        poll_timer_wait(fo->next_bogus_packet_in - time_msec());
    }
}

void
fail_open_flushed(struct fail_open *fo)
{
    int disconn_secs = rconn_failure_duration(fo->controller);
    bool open = disconn_secs >= fo->trigger_duration;
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
        ofproto_add_flow(fo->ofproto, &flow, OFPFW_ALL, FAIL_OPEN_PRIORITY,
                         &action, 1, 0);
    }
}

static void
fail_open_status_cb(struct status_reply *sr, void *fo_)
{
    struct fail_open *fo = fo_;
    int cur_duration = rconn_failure_duration(fo->controller);

    status_reply_put(sr, "trigger-duration=%d", fo->trigger_duration);
    status_reply_put(sr, "current-duration=%d", cur_duration);
    status_reply_put(sr, "triggered=%s",
                     cur_duration >= fo->trigger_duration ? "true" : "false");
}

struct fail_open *
fail_open_create(struct ofproto *ofproto,
                 int trigger_duration, struct switch_status *switch_status,
                 struct rconn *controller)
{
    struct fail_open *fo = xmalloc(sizeof *fo);
    fo->ofproto = ofproto;
    fo->controller = controller;
    fo->trigger_duration = trigger_duration;
    fo->last_disconn_secs = 0;
    fo->ss_cat = switch_status_register(switch_status, "fail-open",
                                        fail_open_status_cb, fo);
    fo->next_bogus_packet_in = LLONG_MAX;
    fo->bogus_packet_counter = rconn_packet_counter_create();
    return fo;
}

void
fail_open_set_trigger_duration(struct fail_open *fo, int trigger_duration)
{
    fo->trigger_duration = trigger_duration;
}

void
fail_open_destroy(struct fail_open *fo)
{
    if (fo) {
        /* We don't own fo->controller. */
        switch_status_unregister(fo->ss_cat);
        rconn_packet_counter_destroy(fo->bogus_packet_counter);
        free(fo);
    }
}

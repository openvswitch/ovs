/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015, 2016 Nicira, Inc.
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
#include <inttypes.h>
#include <stdlib.h>
#include "classifier.h"
#include "connmgr.h"
#include "dp-packet.h"
#include "fail-open.h"
#include "flow.h"
#include "mac-learning.h"
#include "odp-util.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "ofproto.h"
#include "ofproto-provider.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/rconn.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(fail_open);

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
    struct connmgr *connmgr;
    int last_disconn_secs;
    long long int next_bogus_packet_in;
    struct rconn_packet_counter *bogus_packet_counter;
    bool fail_open_active;
};

static void fail_open_recover(struct fail_open *) OVS_REQUIRES(ofproto_mutex);

/* Returns the number of seconds of disconnection after which fail-open mode
 * should activate. */
static int
trigger_duration(const struct fail_open *fo)
{
    if (!connmgr_has_controllers(fo->connmgr)) {
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
        return connmgr_get_max_probe_interval(fo->connmgr) * 3;
    }
}

/* Returns true if 'fo' is currently in fail-open mode, otherwise false. */
bool
fail_open_is_active(const struct fail_open *fo)
{
    return fo->last_disconn_secs != 0;
}

static void
send_bogus_packet_ins(struct fail_open *fo)
{
    struct eth_addr mac;
    struct dp_packet b;

    dp_packet_init(&b, 128);
    eth_addr_nicira_random(&mac);
    compose_rarp(&b, mac);

    struct ofproto_async_msg am = {
        .oam = OAM_PACKET_IN,
        .pin = {
            .up = {
                .base = {
                    .packet = dp_packet_data(&b),
                    .packet_len = dp_packet_size(&b),
                    .flow_metadata.flow.in_port.ofp_port = OFPP_LOCAL,
                    .flow_metadata.wc.masks.in_port.ofp_port
                    = u16_to_ofp(UINT16_MAX),
                    .reason = OFPR_NO_MATCH,
                    .cookie = OVS_BE64_MAX,
                },
            },
            .max_len = UINT16_MAX,
        }
    };
    connmgr_send_async_msg(fo->connmgr, &am);

    dp_packet_uninit(&b);
}

/* Enter fail-open mode if we should be in it. */
void
fail_open_run(struct fail_open *fo)
{
    int disconn_secs = connmgr_failure_duration(fo->connmgr);

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
        if (connmgr_is_any_controller_connected(fo->connmgr)) {
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
    OVS_EXCLUDED(ofproto_mutex)
{
    if (fail_open_is_active(fo)
        && connmgr_is_any_controller_admitted(fo->connmgr)) {
        ovs_mutex_lock(&ofproto_mutex);
        fail_open_recover(fo);
        ovs_mutex_unlock(&ofproto_mutex);
    }
}

static void
fail_open_recover(struct fail_open *fo)
    OVS_REQUIRES(ofproto_mutex)
{
    struct match match;

    VLOG_WARN("No longer in fail-open mode");
    fo->last_disconn_secs = 0;
    fo->next_bogus_packet_in = LLONG_MAX;

    match_init_catchall(&match);
    ofproto_delete_flow(fo->ofproto, &match, FAIL_OPEN_PRIORITY);
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
    OVS_EXCLUDED(ofproto_mutex)
{
    int disconn_secs = connmgr_failure_duration(fo->connmgr);
    bool open = disconn_secs >= trigger_duration(fo);
    if (open) {
        struct ofpbuf ofpacts;
        struct match match;

        /* Set up a flow that matches every packet and directs them to
         * OFPP_NORMAL. */
        ofpbuf_init(&ofpacts, OFPACT_OUTPUT_SIZE);
        ofpact_put_OUTPUT(&ofpacts)->port = OFPP_NORMAL;

        match_init_catchall(&match);
        ofproto_add_flow(fo->ofproto, &match, FAIL_OPEN_PRIORITY,
                         ofpacts.data, ofpacts.size);

        ofpbuf_uninit(&ofpacts);
    }
    fo->fail_open_active = open;
}

/* Returns the number of fail-open rules currently installed in the flow
 * table. */
int
fail_open_count_rules(const struct fail_open *fo)
{
    return fo->fail_open_active != 0;
}

/* Creates and returns a new struct fail_open for 'ofproto' and 'mgr'. */
struct fail_open *
fail_open_create(struct ofproto *ofproto, struct connmgr *mgr)
{
    struct fail_open *fo = xmalloc(sizeof *fo);
    fo->ofproto = ofproto;
    fo->connmgr = mgr;
    fo->last_disconn_secs = 0;
    fo->next_bogus_packet_in = LLONG_MAX;
    fo->bogus_packet_counter = rconn_packet_counter_create();
    fo->fail_open_active = false;
    return fo;
}

/* Destroys 'fo'. */
void
fail_open_destroy(struct fail_open *fo)
    OVS_REQUIRES(ofproto_mutex)
{
    if (fo) {
        if (fail_open_is_active(fo)) {
            fail_open_recover(fo);
        }
        /* We don't own fo->connmgr. */
        rconn_packet_counter_destroy(fo->bogus_packet_counter);
        free(fo);
    }
}

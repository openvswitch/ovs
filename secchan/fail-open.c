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
#include "ofproto.h"
#include "rconn.h"
#include "status.h"
#include "timeval.h"

#define THIS_MODULE VLM_fail_open
#include "vlog.h"

struct fail_open {
    struct ofproto *ofproto;
    struct rconn *controller;
    int trigger_duration;
    int last_disconn_secs;
    struct status_category *ss_cat;
};

/* Causes the switch to enter or leave fail-open mode, if appropriate. */
void
fail_open_run(struct fail_open *fo)
{
    int disconn_secs = rconn_failure_duration(fo->controller);
    bool open = disconn_secs >= fo->trigger_duration;
    if (open != (fo->last_disconn_secs != 0)) {
        if (!open) {
            flow_t flow;

            VLOG_WARN("No longer in fail-open mode");
            fo->last_disconn_secs = 0;

            memset(&flow, 0, sizeof flow);
            ofproto_delete_flow(fo->ofproto, &flow, OFPFW_ALL, 70000);
        } else {
            VLOG_WARN("Could not connect to controller (or switch failed "
                      "controller's post-connection admission control "
                      "policy) for %d seconds, failing open", disconn_secs);
            fo->last_disconn_secs = disconn_secs;

            /* Flush all OpenFlow and datapath flows.  We will set up our
             * fail-open rule from fail_open_flushed() when
             * ofproto_flush_flows() calls back to us. */
            ofproto_flush_flows(fo->ofproto);
        }
    } else if (open && disconn_secs > fo->last_disconn_secs + 60) {
        VLOG_INFO("Still in fail-open mode after %d seconds disconnected "
                  "from controller", disconn_secs);
        fo->last_disconn_secs = disconn_secs;
    }
}

void
fail_open_wait(struct fail_open *fo UNUSED)
{
    /* Nothing to do. */
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
        ofproto_add_flow(fo->ofproto, &flow, OFPFW_ALL, 70000,
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
        free(fo);
    }
}

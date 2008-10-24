/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

#include <config.h>
#include "fail-open.h"
#include <arpa/inet.h>
#include <stddef.h>
#include <string.h>
#include "learning-switch.h"
#include "netdev.h"
#include "packets.h"
#include "port-watcher.h"
#include "rconn.h"
#include "secchan.h"
#include "status.h"
#include "stp-secchan.h"
#include "timeval.h"

#define THIS_MODULE VLM_fail_open
#include "vlog.h"

struct fail_open_data {
    const struct settings *s;
    struct rconn *local_rconn;
    struct rconn *remote_rconn;
    struct lswitch *lswitch;
    int last_disconn_secs;
    time_t boot_deadline;
};

/* Causes 'r' to enter or leave fail-open mode, if appropriate. */
static void
fail_open_periodic_cb(void *fail_open_)
{
    struct fail_open_data *fail_open = fail_open_;
    int disconn_secs;
    bool open;

    if (time_now() < fail_open->boot_deadline) {
        return;
    }
    disconn_secs = rconn_failure_duration(fail_open->remote_rconn);
    open = disconn_secs >= fail_open->s->probe_interval * 3;
    if (open != (fail_open->lswitch != NULL)) {
        if (!open) {
            VLOG_WARN("No longer in fail-open mode");
            lswitch_destroy(fail_open->lswitch);
            fail_open->lswitch = NULL;
        } else {
            VLOG_WARN("Could not connect to controller for %d seconds, "
                      "failing open", disconn_secs);
            fail_open->lswitch = lswitch_create(fail_open->local_rconn, true,
                                                fail_open->s->max_idle);
            fail_open->last_disconn_secs = disconn_secs;
        }
    } else if (open && disconn_secs > fail_open->last_disconn_secs + 60) {
        VLOG_WARN("Still in fail-open mode after %d seconds disconnected "
                  "from controller", disconn_secs);
        fail_open->last_disconn_secs = disconn_secs;
    }
    if (fail_open->lswitch) {
        lswitch_run(fail_open->lswitch, fail_open->local_rconn);
    }
}

static void
fail_open_wait_cb(void *fail_open_)
{
    struct fail_open_data *fail_open = fail_open_;
    if (fail_open->lswitch) {
        lswitch_wait(fail_open->lswitch);
    }
}

static bool
fail_open_local_packet_cb(struct relay *r, void *fail_open_)
{
    struct fail_open_data *fail_open = fail_open_;
    if (rconn_is_connected(fail_open->remote_rconn) || !fail_open->lswitch) {
        return false;
    } else {
        lswitch_process_packet(fail_open->lswitch, fail_open->local_rconn,
                               r->halves[HALF_LOCAL].rxbuf);
        rconn_run(fail_open->local_rconn);
        return true;
    }
}

static void
fail_open_status_cb(struct status_reply *sr, void *fail_open_)
{
    struct fail_open_data *fail_open = fail_open_;
    const struct settings *s = fail_open->s;
    int trigger_duration = s->probe_interval * 3;
    int cur_duration = rconn_failure_duration(fail_open->remote_rconn);

    status_reply_put(sr, "trigger-duration=%d", trigger_duration);
    status_reply_put(sr, "current-duration=%d", cur_duration);
    status_reply_put(sr, "triggered=%s",
                     cur_duration >= trigger_duration ? "true" : "false");
    status_reply_put(sr, "max-idle=%d", s->max_idle);
}

static struct hook_class fail_open_hook_class = {
    fail_open_local_packet_cb,  /* local_packet_cb */
    NULL,                       /* remote_packet_cb */
    fail_open_periodic_cb,      /* periodic_cb */
    fail_open_wait_cb,          /* wait_cb */
    NULL,                       /* closing_cb */
};

void
fail_open_start(struct secchan *secchan, const struct settings *s,
                struct switch_status *ss,
                struct rconn *local_rconn, struct rconn *remote_rconn)
{
    struct fail_open_data *fail_open = xmalloc(sizeof *fail_open);
    fail_open->s = s;
    fail_open->local_rconn = local_rconn;
    fail_open->remote_rconn = remote_rconn;
    fail_open->lswitch = NULL;
    fail_open->boot_deadline = time_now() + s->probe_interval * 3;
    if (s->enable_stp) {
        fail_open->boot_deadline += STP_EXTRA_BOOT_TIME;
    }
    switch_status_register_category(ss, "fail-open",
                                    fail_open_status_cb, fail_open);
    add_hook(secchan, &fail_open_hook_class, fail_open);
}

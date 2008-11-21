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
#include "status.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include "dynamic-string.h"
#include "openflow/nicira-ext.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "rconn.h"
#include "timeval.h"
#include "vconn.h"

#define THIS_MODULE VLM_status
#include "vlog.h"

struct switch_status_category {
    char *name;
    void (*cb)(struct status_reply *, void *aux);
    void *aux;
};

struct switch_status {
    const struct settings *s;
    time_t booted;
    struct switch_status_category *categories;
    int n_categories, allocated_categories;
};

struct status_reply {
    struct switch_status_category *category;
    struct ds request;
    struct ds output;
};

static bool
switch_status_remote_packet_cb(struct relay *r, void *ss_)
{
    struct switch_status *ss = ss_;
    struct rconn *rc = r->halves[HALF_REMOTE].rconn;
    struct ofpbuf *msg = r->halves[HALF_REMOTE].rxbuf;
    struct switch_status_category *c;
    struct nicira_header *request;
    struct nicira_header *reply;
    struct status_reply sr;
    struct ofpbuf *b;
    int retval;

    if (msg->size < sizeof(struct nicira_header)) {
        return false;
    }
    request = msg->data;
    if (request->header.type != OFPT_VENDOR
        || request->vendor != htonl(NX_VENDOR_ID)
        || request->subtype != htonl(NXT_STATUS_REQUEST)) {
        return false;
    }

    sr.request.string = (void *) (request + 1);
    sr.request.length = msg->size - sizeof *request;
    ds_init(&sr.output);
    for (c = ss->categories; c < &ss->categories[ss->n_categories]; c++) {
        if (!memcmp(c->name, sr.request.string,
                    MIN(strlen(c->name), sr.request.length))) {
            sr.category = c;
            c->cb(&sr, c->aux);
        }
    }
    reply = make_openflow_xid(sizeof *reply + sr.output.length,
                              OFPT_VENDOR, request->header.xid, &b);
    reply->vendor = htonl(NX_VENDOR_ID);
    reply->subtype = htonl(NXT_STATUS_REPLY);
    memcpy(reply + 1, sr.output.string, sr.output.length);
    retval = rconn_send(rc, b, NULL);
    if (retval && retval != EAGAIN) {
        VLOG_WARN("send failed (%s)", strerror(retval));
    }
    ds_destroy(&sr.output);
    return true;
}

void
rconn_status_cb(struct status_reply *sr, void *rconn_)
{
    struct rconn *rconn = rconn_;
    time_t now = time_now();

    status_reply_put(sr, "name=%s", rconn_get_name(rconn));
    status_reply_put(sr, "state=%s", rconn_get_state(rconn));
    status_reply_put(sr, "backoff=%d", rconn_get_backoff(rconn));
    status_reply_put(sr, "is-connected=%s",
                     rconn_is_connected(rconn) ? "true" : "false");
    status_reply_put(sr, "sent-msgs=%u", rconn_packets_sent(rconn));
    status_reply_put(sr, "received-msgs=%u", rconn_packets_received(rconn));
    status_reply_put(sr, "attempted-connections=%u",
                     rconn_get_attempted_connections(rconn));
    status_reply_put(sr, "successful-connections=%u",
                     rconn_get_successful_connections(rconn));
    status_reply_put(sr, "last-connection=%ld",
                     (long int) (now - rconn_get_last_connection(rconn)));
    status_reply_put(sr, "time-connected=%lu",
                     rconn_get_total_time_connected(rconn));
    status_reply_put(sr, "state-elapsed=%u", rconn_get_state_elapsed(rconn));
}

static void
config_status_cb(struct status_reply *sr, void *s_)
{
    const struct settings *s = s_;
    size_t i;

    for (i = 0; i < s->n_listeners; i++) {
        status_reply_put(sr, "management%zu=%s", i, s->listener_names[i]);
    }
    if (s->probe_interval) {
        status_reply_put(sr, "probe-interval=%d", s->probe_interval);
    }
    if (s->max_backoff) {
        status_reply_put(sr, "max-backoff=%d", s->max_backoff);
    }
}

static void
switch_status_cb(struct status_reply *sr, void *ss_)
{
    struct switch_status *ss = ss_;
    time_t now = time_now();

    status_reply_put(sr, "now=%ld", (long int) now);
    status_reply_put(sr, "uptime=%ld", (long int) (now - ss->booted));
    status_reply_put(sr, "pid=%ld", (long int) getpid());
}

static struct hook_class switch_status_hook_class = {
    NULL,                           /* local_packet_cb */
    switch_status_remote_packet_cb, /* remote_packet_cb */
    NULL,                           /* periodic_cb */
    NULL,                           /* wait_cb */
    NULL,                           /* closing_cb */
};

void
switch_status_start(struct secchan *secchan, const struct settings *s,
                    struct switch_status **ssp)
{
    struct switch_status *ss = xcalloc(1, sizeof *ss);
    ss->s = s;
    ss->booted = time_now();
    switch_status_register_category(ss, "config",
                                    config_status_cb, (void *) s);
    switch_status_register_category(ss, "switch", switch_status_cb, ss);
    *ssp = ss;
    add_hook(secchan, &switch_status_hook_class, ss);
}

void
switch_status_register_category(struct switch_status *ss,
                                const char *category,
                                void (*cb)(struct status_reply *, void *aux),
                                void *aux)
{
    struct switch_status_category *c;
    if (ss->n_categories >= ss->allocated_categories) {
        ss->allocated_categories = 1 + ss->allocated_categories * 2;
        ss->categories = xrealloc(ss->categories,
                                  (sizeof *ss->categories
                                   * ss->allocated_categories));
    }
    c = &ss->categories[ss->n_categories++];
    c->cb = cb;
    c->aux = aux;
    c->name = xstrdup(category);
}

void
status_reply_put(struct status_reply *sr, const char *content, ...)
{
    size_t old_length = sr->output.length;
    size_t added;
    va_list args;

    /* Append the status reply to the output. */
    ds_put_format(&sr->output, "%s.", sr->category->name);
    va_start(args, content);
    ds_put_format_valist(&sr->output, content, args);
    va_end(args);
    if (ds_last(&sr->output) != '\n') {
        ds_put_char(&sr->output, '\n');
    }

    /* Drop what we just added if it doesn't match the request. */
    added = sr->output.length - old_length;
    if (added < sr->request.length
        || memcmp(&sr->output.string[old_length],
                  sr->request.string, sr->request.length)) {
        ds_truncate(&sr->output, old_length);
    }
}

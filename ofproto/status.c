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
#include "status.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include "dynamic-string.h"
#include "list.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "ofproto.h"
#include "openflow/nicira-ext.h"
#include "packets.h"
#include "rconn.h"
#include "svec.h"
#include "timeval.h"
#include "vconn.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(status)

struct status_category {
    struct list node;
    char *name;
    void (*cb)(struct status_reply *, void *aux);
    void *aux;
};

struct switch_status {
    time_t booted;
    struct status_category *config_cat;
    struct status_category *switch_cat;
    struct list categories;
};

struct status_reply {
    struct status_category *category;
    struct ds request;
    struct ds output;
};

int
switch_status_handle_request(struct switch_status *ss, struct rconn *rconn,
                             struct nicira_header *request)
{
    struct status_category *c;
    struct nicira_header *reply;
    struct status_reply sr;
    struct ofpbuf *b;
    int retval;

    sr.request.string = (void *) (request + 1);
    sr.request.length = ntohs(request->header.length) - sizeof *request;
    ds_init(&sr.output);
    LIST_FOR_EACH (c, struct status_category, node, &ss->categories) {
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
    retval = rconn_send(rconn, b, NULL);
    if (retval && retval != EAGAIN) {
        VLOG_WARN("send failed (%s)", strerror(retval));
    }
    ds_destroy(&sr.output);
    return 0;
}

void
rconn_status_cb(struct status_reply *sr, void *rconn_)
{
    struct rconn *rconn = rconn_;
    time_t now = time_now();
    uint32_t remote_ip = rconn_get_remote_ip(rconn);
    uint32_t local_ip = rconn_get_local_ip(rconn);

    status_reply_put(sr, "name=%s", rconn_get_target(rconn));
    if (remote_ip) {
        status_reply_put(sr, "remote-ip="IP_FMT, IP_ARGS(&remote_ip));
        status_reply_put(sr, "remote-port=%d",
                         ntohs(rconn_get_remote_port(rconn)));
        status_reply_put(sr, "local-ip="IP_FMT, IP_ARGS(&local_ip));
        status_reply_put(sr, "local-port=%d",
                         ntohs(rconn_get_local_port(rconn)));
    }
    status_reply_put(sr, "state=%s", rconn_get_state(rconn));
    status_reply_put(sr, "backoff=%d", rconn_get_backoff(rconn));
    status_reply_put(sr, "probe-interval=%d", rconn_get_probe_interval(rconn));
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
    status_reply_put(sr, "last-received=%ld",
                     (long int) (now - rconn_get_last_received(rconn)));
    status_reply_put(sr, "time-connected=%lu",
                     rconn_get_total_time_connected(rconn));
    status_reply_put(sr, "state-elapsed=%u", rconn_get_state_elapsed(rconn));
}

static void
config_status_cb(struct status_reply *sr, void *ofproto_)
{
    const struct ofproto *ofproto = ofproto_;
    uint64_t datapath_id;

    datapath_id = ofproto_get_datapath_id(ofproto);
    if (datapath_id) {
        status_reply_put(sr, "datapath-id=%016"PRIx64, datapath_id);
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

struct switch_status *
switch_status_create(const struct ofproto *ofproto)
{
    struct switch_status *ss = xzalloc(sizeof *ss);
    ss->booted = time_now();
    list_init(&ss->categories);
    ss->config_cat = switch_status_register(ss, "config", config_status_cb,
                                            (void *) ofproto);
    ss->switch_cat = switch_status_register(ss, "switch", switch_status_cb,
                                            ss);
    return ss;
}

void
switch_status_destroy(struct switch_status *ss)
{
    if (ss) {
        /* Orphan any remaining categories, so that unregistering them later
         * won't write to bad memory. */
        struct status_category *c, *next;
        LIST_FOR_EACH_SAFE (c, next,
                            struct status_category, node, &ss->categories) {
            list_init(&c->node);
        }
        switch_status_unregister(ss->config_cat);
        switch_status_unregister(ss->switch_cat);
        free(ss);
    }
}

struct status_category *
switch_status_register(struct switch_status *ss,
                       const char *category,
                       status_cb_func *cb, void *aux)
{
    struct status_category *c = xmalloc(sizeof *c);
    c->cb = cb;
    c->aux = aux;
    c->name = xstrdup(category);
    list_push_back(&ss->categories, &c->node);
    return c;
}

void
switch_status_unregister(struct status_category *c)
{
    if (c) {
        if (!list_is_empty(&c->node)) {
            list_remove(&c->node);
        }
        free(c->name);
        free(c);
    }
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

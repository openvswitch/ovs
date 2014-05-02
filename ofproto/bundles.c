/*
 * Copyright (c) 2013, 2014 Alexandru Copot <alex.mihai.c@gmail.com>, with support from IXIA.
 * Copyright (c) 2013, 2014 Daniel Baluta <dbaluta@ixiacom.com>
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

#include "coverage.h"
#include "fail-open.h"
#include "in-band.h"
#include "odp-util.h"
#include "ofp-actions.h"
#include "ofp-msgs.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "ofproto-provider.h"
#include "pinsched.h"
#include "poll-loop.h"
#include "pktbuf.h"
#include "rconn.h"
#include "shash.h"
#include "simap.h"
#include "stream.h"
#include "timeval.h"
#include "vconn.h"
#include "vlog.h"

#include "bundles.h"

VLOG_DEFINE_THIS_MODULE(bundles);

enum bundle_state {
    BS_OPEN,
    BS_CLOSED
};

struct ofp_bundle {
    struct hmap_node  node;      /* In struct ofconn's "bundles" hmap. */
    uint32_t          id;
    uint16_t          flags;
    enum bundle_state state;

    /* List of 'struct bundle_message's */
    struct list       msg_list;
};

struct bundle_message {
    struct ofp_header *msg;
    struct list       node;  /* Element in 'struct ofp_bundles's msg_list */
};

static uint32_t
bundle_hash(uint32_t id)
{
    return hash_int(id, 0);
}

static struct ofp_bundle *
ofp_bundle_find(struct hmap *bundles, uint32_t id)
{
    struct ofp_bundle *bundle;

    HMAP_FOR_EACH_IN_BUCKET(bundle, node, bundle_hash(id), bundles) {
        if (bundle->id == id) {
            return bundle;
        }
    }

    return NULL;
}

static struct ofp_bundle *
ofp_bundle_create(uint32_t id, uint16_t flags)
{
    struct ofp_bundle *bundle;

    bundle = xmalloc(sizeof(*bundle));

    bundle->id = id;
    bundle->flags = flags;

    list_init(&bundle->msg_list);

    return bundle;
}

static void
ofp_bundle_remove(struct ofconn *ofconn, struct ofp_bundle *item)
{
    struct bundle_message *msg, *next;
    struct hmap *bundles;

    LIST_FOR_EACH_SAFE (msg, next, node, &item->msg_list) {
        list_remove(&msg->node);
        free(msg->msg);
        free(msg);
    }

    bundles = ofconn_get_bundles(ofconn);
    hmap_remove(bundles, &item->node);

    free(item);
}

void
ofp_bundle_remove_all(struct ofconn *ofconn)
{
    struct ofp_bundle *b, *next;
    struct hmap *bundles;

    bundles = ofconn_get_bundles(ofconn);

    HMAP_FOR_EACH_SAFE (b, next, node, bundles) {
        ofp_bundle_remove(ofconn, b);
    }
}

enum ofperr
ofp_bundle_open(struct ofconn *ofconn, uint32_t id, uint16_t flags)
{
    struct hmap *bundles;
    struct ofp_bundle *bundle;

    bundles = ofconn_get_bundles(ofconn);
    bundle = ofp_bundle_find(bundles, id);

    if (bundle) {
        VLOG_INFO("Bundle %x already exists.", id);
        ofp_bundle_remove(ofconn, bundle);

        return OFPERR_OFPBFC_BAD_ID;
    }

    /* TODO: Check the limit of open bundles */

    bundle = ofp_bundle_create(id, flags);
    bundle->state = BS_OPEN;

    bundles = ofconn_get_bundles(ofconn);
    hmap_insert(bundles, &bundle->node, bundle_hash(id));

    return 0;
}

enum ofperr
ofp_bundle_close(struct ofconn *ofconn, uint32_t id, uint16_t flags)
{
    struct hmap *bundles;
    struct ofp_bundle *bundle;

    bundles = ofconn_get_bundles(ofconn);
    bundle = ofp_bundle_find(bundles, id);

    if (!bundle) {
        return OFPERR_OFPBFC_BAD_ID;
    }

    if (bundle->state == BS_CLOSED) {
        ofp_bundle_remove(ofconn, bundle);
        return OFPERR_OFPBFC_BUNDLE_CLOSED;
    }

    if (bundle->flags != flags) {
        ofp_bundle_remove(ofconn, bundle);
        return OFPERR_OFPBFC_BAD_FLAGS;
    }

    bundle->state = BS_CLOSED;
    return 0;
}

enum ofperr
ofp_bundle_commit(struct ofconn *ofconn, uint32_t id, uint16_t flags)
{
    struct hmap *bundles;
    struct ofp_bundle *bundle;

    bundles = ofconn_get_bundles(ofconn);
    bundle = ofp_bundle_find(bundles, id);

    if (!bundle) {
        return OFPERR_OFPBFC_BAD_ID;
    }
    if (bundle->flags != flags) {
        ofp_bundle_remove(ofconn, bundle);
        return OFPERR_OFPBFC_BAD_FLAGS;
    }

    /* TODO: actual commit */

    return OFPERR_OFPBFC_MSG_UNSUP;
}

enum ofperr
ofp_bundle_discard(struct ofconn *ofconn, uint32_t id)
{
    struct hmap *bundles;
    struct ofp_bundle *bundle;

    bundles = ofconn_get_bundles(ofconn);
    bundle = ofp_bundle_find(bundles, id);

    if (!bundle) {
        return OFPERR_OFPBFC_BAD_ID;
    }

    ofp_bundle_remove(ofconn, bundle);

    return 0;
}

enum ofperr
ofp_bundle_add_message(struct ofconn *ofconn, struct ofputil_bundle_add_msg *badd)
{
    struct hmap *bundles;
    struct ofp_bundle *bundle;
    struct bundle_message *bmsg;

    bundles = ofconn_get_bundles(ofconn);
    bundle = ofp_bundle_find(bundles, badd->bundle_id);

    if (!bundle) {
        bundle = ofp_bundle_create(badd->bundle_id, badd->flags);
        bundle->state = BS_OPEN;

        bundles = ofconn_get_bundles(ofconn);
        hmap_insert(bundles, &bundle->node, bundle_hash(badd->bundle_id));
    }

    if (bundle->state == BS_CLOSED) {
        ofp_bundle_remove(ofconn, bundle);
        return OFPERR_OFPBFC_BUNDLE_CLOSED;
    }

    bmsg = xmalloc(sizeof *bmsg);
    bmsg->msg = xmemdup(badd->msg, ntohs(badd->msg->length));
    list_push_back(&bundle->msg_list, &bmsg->node);
    return 0;
}

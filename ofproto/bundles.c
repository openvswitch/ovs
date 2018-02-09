/*
 * Copyright (c) 2013, 2014 Alexandru Copot <alex.mihai.c@gmail.com>, with support from IXIA.
 * Copyright (c) 2013, 2014 Daniel Baluta <dbaluta@ixiacom.com>
 * Copyright (c) 2014, 2015, 2016 Nicira, Inc.
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

#include "bundles.h"
#include "coverage.h"
#include "fail-open.h"
#include "in-band.h"
#include "odp-util.h"
#include "ofproto-provider.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "pinsched.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/rconn.h"
#include "openvswitch/shash.h"
#include "simap.h"
#include "stream.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(bundles);

static struct ofp_bundle *
ofp_bundle_create(uint32_t id, uint16_t flags, const struct ofp_header *oh)
{
    struct ofp_bundle *bundle;

    bundle = xmalloc(sizeof(*bundle));

    bundle->used = time_msec();
    bundle->id = id;
    bundle->flags = flags;
    bundle->state = BS_OPEN;
    bundle->msg = xmemdup(oh, ntohs(oh->length));

    ovs_list_init(&bundle->msg_list);

    return bundle;
}

void
ofp_bundle_remove__(struct ofconn *ofconn, struct ofp_bundle *bundle)
{
    struct ofp_bundle_entry *msg;

    LIST_FOR_EACH_POP (msg, node, &bundle->msg_list) {
        ofp_bundle_entry_free(msg);
    }

    ofconn_remove_bundle(ofconn, bundle);
    free(bundle->msg);
    free(bundle);
}

enum ofperr
ofp_bundle_open(struct ofconn *ofconn, uint32_t id, uint16_t flags,
                const struct ofp_header *oh)
{
    struct ofp_bundle *bundle;

    bundle = ofconn_get_bundle(ofconn, id);

    if (bundle) {
        VLOG_INFO("Bundle %x already exists.", id);
        ofp_bundle_remove__(ofconn, bundle);

        return OFPERR_OFPBFC_BAD_ID;
    }

    bundle = ofp_bundle_create(id, flags, oh);
    ofconn_insert_bundle(ofconn, bundle);

    return 0;
}

enum ofperr
ofp_bundle_close(struct ofconn *ofconn, uint32_t id, uint16_t flags)
{
    struct ofp_bundle *bundle;

    bundle = ofconn_get_bundle(ofconn, id);

    if (!bundle) {
        return OFPERR_OFPBFC_BAD_ID;
    }

    if (bundle->state == BS_CLOSED) {
        ofp_bundle_remove__(ofconn, bundle);
        return OFPERR_OFPBFC_BUNDLE_CLOSED;
    }

    if (bundle->flags != flags) {
        ofp_bundle_remove__(ofconn, bundle);
        return OFPERR_OFPBFC_BAD_FLAGS;
    }

    bundle->used = time_msec();
    bundle->state = BS_CLOSED;
    return 0;
}

enum ofperr
ofp_bundle_discard(struct ofconn *ofconn, uint32_t id)
{
    struct ofp_bundle *bundle;

    bundle = ofconn_get_bundle(ofconn, id);

    if (!bundle) {
        return OFPERR_OFPBFC_BAD_ID;
    }

    ofp_bundle_remove__(ofconn, bundle);
    return 0;
}

enum ofperr
ofp_bundle_add_message(struct ofconn *ofconn, uint32_t id, uint16_t flags,
                       struct ofp_bundle_entry *bmsg,
                       const struct ofp_header *oh)
{
    struct ofp_bundle *bundle;

    bundle = ofconn_get_bundle(ofconn, id);

    if (!bundle) {
        bundle = ofp_bundle_create(id, flags, oh);
        ofconn_insert_bundle(ofconn, bundle);
    } else if (bundle->state == BS_CLOSED) {
        ofp_bundle_remove__(ofconn, bundle);
        return OFPERR_OFPBFC_BUNDLE_CLOSED;
    } else if (flags != bundle->flags) {
        ofp_bundle_remove__(ofconn, bundle);
        return OFPERR_OFPBFC_BAD_FLAGS;
    }

    bundle->used = time_msec();
    ovs_list_push_back(&bundle->msg_list, &bmsg->node);
    return 0;
}

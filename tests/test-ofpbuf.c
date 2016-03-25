/*
 * Copyright (c) 2015 Nicira, Inc.
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
#undef NDEBUG
#include <stdio.h>
#include "openvswitch/ofpbuf.h"
#include "ovstest.h"
#include "util.h"

#define BUF_SIZE 100
#define HDR_OFS 10
#define MSG_OFS 50

static void
test_ofpbuf_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ofpbuf *buf = ofpbuf_new(BUF_SIZE);
    int exit_code = 0;

    /* Init checks. */
    ovs_assert(!buf->size);
    ovs_assert(buf->allocated == BUF_SIZE);
    ovs_assert(buf->base == buf->data);

    /* Sets 'buf->header' and 'buf->msg'. */
    buf->header = (char *) buf->base + HDR_OFS;
    buf->msg = (char *) buf->base + MSG_OFS;

    /* Gets another 'BUF_SIZE' bytes headroom. */
    ofpbuf_prealloc_headroom(buf, BUF_SIZE);
    ovs_assert(!buf->size);
    ovs_assert(buf->allocated == 2 * BUF_SIZE);
    ovs_assert((char *) buf->base + BUF_SIZE == buf->data);
    /* Now 'buf->header' and 'buf->msg' must be BUF_SIZE away from
     * their original offsets. */
    ovs_assert(buf->header == (char *) buf->base + BUF_SIZE + HDR_OFS);
    ovs_assert(buf->msg == (char *) buf->base + BUF_SIZE + MSG_OFS);

    /* Gets another 'BUF_SIZE' bytes tailroom. */
    ofpbuf_prealloc_tailroom(buf, BUF_SIZE);
    /* Must remain unchanged. */
    ovs_assert(!buf->size);
    ovs_assert(buf->allocated == 2 * BUF_SIZE);
    ovs_assert((char *) buf->base + BUF_SIZE == buf->data);
    ovs_assert(buf->header == (char *) buf->base + BUF_SIZE + HDR_OFS);
    ovs_assert(buf->msg == (char *) buf->base + BUF_SIZE + MSG_OFS);

    ofpbuf_delete(buf);
    exit(exit_code);
}

OVSTEST_REGISTER("test-ofpbuf", test_ofpbuf_main);

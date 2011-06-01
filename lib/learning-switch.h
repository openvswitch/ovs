/*
 * Copyright (c) 2008, 2010, 2011 Nicira Networks.
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

#ifndef LEARNING_SWITCH_H
#define LEARNING_SWITCH_H 1

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

struct ofpbuf;
struct rconn;

enum lswitch_mode {
    LSW_NORMAL,                 /* Always use OFPP_NORMAL. */
    LSW_FLOOD,                  /* Always use OFPP_FLOOD. */
    LSW_LEARN                   /* Learn MACs at controller. */
};

struct lswitch_config {
    enum lswitch_mode mode;

    /* 0 to use exact-match flow entries,
     * a OFPFW_* bitmask to enable specific wildcards,
     * or UINT32_MAX to use the default wildcards (wildcarding as many fields
     * as possible.
     *
     * Ignored when max_idle < 0 (in which case no flows are set up). */
    uint32_t wildcards;

    /* <0: Process every packet at the controller.
     * >=0: Expire flows after they are unused for 'max_idle' seconds.
     * OFP_FLOW_PERMANENT: Set up permanent flows. */
    int max_idle;

    /* Optionally, a list of one or more "struct ofpbuf"s containing OpenFlow
     * messages to send to the switch at time of connection.  Presumably these
     * will be OFPT_FLOW_MOD requests to set up the flow table. */
    const struct list *default_flows;

    /* The OpenFlow queue to use by default.  Use UINT32_MAX to avoid
     * specifying a particular queue. */
    uint32_t default_queue;

    /* Maps from a port name to a queue_id (cast to void *). */
    const struct shash *port_queues;
};

struct lswitch *lswitch_create(struct rconn *, const struct lswitch_config *);
void lswitch_set_queue(struct lswitch *sw, uint32_t queue);
void lswitch_run(struct lswitch *);
void lswitch_wait(struct lswitch *);
void lswitch_destroy(struct lswitch *);
void lswitch_process_packet(struct lswitch *, struct rconn *,
                            const struct ofpbuf *);


#endif /* learning-switch.h */

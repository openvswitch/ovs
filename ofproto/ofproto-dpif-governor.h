/*
 * Copyright (c) 2012 Nicira, Inc.
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

#ifndef OFPROTO_DPIF_GOVERNOR_H
#define OFPROTO_DPIF_GOVERNOR_H 1

/* Flow setup rate limiter.
 *
 * A governor in an engine limits a vehicle's speed.  This governor limits the
 * rate at which flows are set up in the datapath.  The client provides as
 * input the hashes of observed packets.  The governor keeps track of hashes
 * seen multiple times.  When a given hash is seen often enough, the governor
 * indicates to its client that it should set up a facet and a subfacet and a
 * datapath flow for that flow.
 *
 * The same tracking could be done in terms of facets and subfacets directly,
 * but the governor code uses much less time and space to do the same job. */

#include <stdbool.h>
#include <stdint.h>

struct governor {
    char *name;                 /* Name, for log messages. */
    uint8_t *table;             /* Table of counters, two per byte. */
    unsigned int size;          /* Table size in bytes. */
    long long int start;        /* Time when the table was last cleared. */
    unsigned int n_packets;     /* Number of packets processed. */

    /* Statistics for skipping counters when most flows get set up. */
    unsigned int n_flows;       /* Number of unique flows seen. */
    unsigned int n_setups;      /* Number of flows set up based on counters. */
    unsigned int n_shortcuts;   /* Number of flows set up based on history. */
};

struct governor *governor_create(const char *name);
void governor_destroy(struct governor *);

void governor_run(struct governor *);
void governor_wait(struct governor *);

bool governor_is_idle(struct governor *);

bool governor_should_install_flow(struct governor *, uint32_t hash, int n);

#endif /* ofproto/ofproto-dpif-governor.h */

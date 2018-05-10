/*
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2016 Nicira, Inc.
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

#ifndef OX_STAT_H
#define OX_STAT_H 1

#include <stdint.h>

struct ofpbuf;

struct oxs_stats {
    uint32_t duration_sec;
    uint32_t duration_nsec;
    uint32_t idle_age;
    uint64_t packet_count;
    uint64_t byte_count;
    uint32_t flow_count;
};

void oxs_put_stats(struct ofpbuf *, const struct oxs_stats *);
enum ofperr oxs_pull_stat(struct ofpbuf *, struct oxs_stats *,
                          uint16_t *, uint8_t *);

#endif /* ox_stat.h */

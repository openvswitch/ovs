/*
 * Copyright (c) 2008-2017 Nicira, Inc.
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

#ifndef OPENVSWITCH_NAMEMAP_H
#define OPENVSWITCH_NAMEMAP_H 1

#include "openvswitch/hmap.h"

struct ds;

#ifdef __cplusplus
extern "C" {
#endif

/* Name-number mapping.
 *
 * This data structure tracks and manages a mapping between names and 32-bit
 * unsigned integers, with provision for detecting names that are used more
 * than once.
 *
 * This structure is suitable for tracking mappings between OpenFlow port names
 * and numbers.  OpenFlow doesn't require either these kinds of names to be
 * unique, and in OVS it's possible for two ports to appear to have the same
 * name if their names are longer than the maximum length supported by a given
 * version of OpenFlow.
 *
 * OpenFlow does require port numbers to be unique.  We check for duplicate
 * ports numbers just in case a switch has a bug.
 *
 * This structure is also suitable for tracking mappings between OpenFlow table
 * names and number.  OpenFlow doesn't require table names to be unique and
 * Open vSwitch doesn't try to make them unique. */
struct namemap_node {
    struct hmap_node name_node;
    struct hmap_node number_node;

    uint32_t number;
    char *name;

    bool duplicate;
};

struct namemap {
    struct hmap by_name;
    struct hmap by_number;
};
#define NAMEMAP_INITIALIZER(MAP) \
    { HMAP_INITIALIZER(&(MAP)->by_name), HMAP_INITIALIZER(&(MAP)->by_number) }

void namemap_init(struct namemap *);
struct namemap_node *namemap_find_by_name(const struct namemap *,
                                              const char *);
struct namemap_node *namemap_find_by_number(const struct namemap *, uint32_t);
void namemap_put(struct namemap *, uint32_t, const char *);
void namemap_destroy(struct namemap *);

void namemap_put_name(const char *, struct ds *);

#ifdef __cplusplus
}
#endif

#endif  /* namemap.h */



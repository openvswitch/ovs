/*
 * Copyright (c) 2024 Canonical Ltd.
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

#ifndef COOPERATIVE_MULTITASKING_PRIVATE_H
#define COOPERATIVE_MULTITASKING_PRIVATE_H 1

#include "openvswitch/hmap.h"

extern struct hmap cooperative_multitasking_callbacks;

struct cm_entry {
    struct hmap_node node;
    void (*cb)(void *);
    void *arg;
    long long int threshold;
    long long int last_run;
    const char *name;
};

#endif /* COOPERATIVE_MULTITASKING_PRIVATE_H */

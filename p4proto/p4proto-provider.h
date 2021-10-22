/*
* Copyright (c) 2021 Intel Corporation.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at:
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef P4PROTO_PROVIDER_H
#define P4PROTO_PROVIDER_H 1

#include "openvswitch/hmap.h"

/* Maximum number of P4 devices?? (Eg, PI = 256) */
// #define MAX_PROGS 256

struct p4proto {
    struct hmap_node node;      /* In global 'all_p4devices' hmap. */
    const struct p4proto_class *p4proto_class;

    char *type;                 /* Datapath type. */
    char *name;                 /* Datapath name. */

    // TODO: Placeholder - P4Info describing a P4 program.

    uint64_t dev_id;            /* Device ID used by P4Runtime. */
    char *config_file;          /* config file path. */

    struct hmap bridges;        /* "struct bridge"s indexed by name. */
};

/* TODO: Implement callbacks for P4runtime(grpc) and BfNode handling*/
struct p4proto_class {
};

#endif /* p4proto-provider.h */

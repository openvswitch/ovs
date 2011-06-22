/*
 * Copyright (c) 2010, 2011 Nicira Networks.
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

/* OpenFlow protocol string to flow parser. */

#ifndef OFP_PARSE_H
#define OFP_PARSE_H 1

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "openflow/nicira-ext.h"

struct flow_mod;
struct flow_stats_request;
struct list;
struct ofpbuf;

void parse_ofp_str(struct flow_mod *, int command, const char *str_,
                   bool verbose);

void parse_ofp_flow_mod_str(struct list *packets,
                            enum nx_flow_format *cur, bool *flow_mod_table_id,
                            char *string, uint16_t command, bool verbose);
bool parse_ofp_flow_mod_file(struct list *packets,
                             enum nx_flow_format *cur, bool *flow_mod_table_id,
                             FILE *, uint16_t command);

void parse_ofp_flow_stats_request_str(struct flow_stats_request *,
                                      bool aggregate, char *string);

#endif /* ofp-parse.h */

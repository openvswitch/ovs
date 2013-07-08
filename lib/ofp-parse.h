/*
 * Copyright (c) 2010, 2011, 2012, 2013 Nicira, Inc.
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
#include "compiler.h"

struct flow;
struct ofpbuf;
struct ofputil_flow_mod;
struct ofputil_flow_monitor_request;
struct ofputil_flow_stats_request;
struct ofputil_meter_mod;

char *parse_ofp_str(struct ofputil_flow_mod *, int command, const char *str_)
    WARN_UNUSED_RESULT;

char *parse_ofp_flow_mod_str(struct ofputil_flow_mod *, const char *string,
                            uint16_t command)
    WARN_UNUSED_RESULT;
char *parse_ofp_flow_mod_file(const char *file_name, uint16_t command,
                              struct ofputil_flow_mod **fms, size_t *n_fms)
    WARN_UNUSED_RESULT;

char *parse_ofp_flow_stats_request_str(struct ofputil_flow_stats_request *,
                                       bool aggregate, const char *string)
    WARN_UNUSED_RESULT;

char *parse_ofpacts(const char *, struct ofpbuf *ofpacts)
    WARN_UNUSED_RESULT;

char *parse_ofp_exact_flow(struct flow *, const char *);

char *parse_ofp_meter_mod_str(struct ofputil_meter_mod *, const char *string,
			      int command)
    WARN_UNUSED_RESULT;

char *parse_flow_monitor_request(struct ofputil_flow_monitor_request *,
                                const char *)
    WARN_UNUSED_RESULT;

#endif /* ofp-parse.h */

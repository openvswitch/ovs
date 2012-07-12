/*
 * Copyright (c) 2008, 2009, 2011, 2012 Nicira, Inc.
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

/* OpenFlow protocol pretty-printer. */

#ifndef OFP_PRINT_H
#define OFP_PRINT_H 1

#include <stdint.h>
#include <stdio.h>

struct ds;
struct ofp10_match;
struct ofp_flow_mod;
struct ofp_header;
struct ofputil_flow_stats;

#ifdef  __cplusplus
extern "C" {
#endif

void ofp_print(FILE *, const void *, size_t, int verbosity);
void ofp_print_packet(FILE *stream, const void *data, size_t len);

void ofp10_match_print(struct ds *, const struct ofp10_match *, int verbosity);

char *ofp_to_string(const void *, size_t, int verbosity);
char *ofp10_match_to_string(const struct ofp10_match *, int verbosity);
char *ofp_packet_to_string(const void *data, size_t len);

void ofp_print_flow_stats(struct ds *, struct ofputil_flow_stats *);
void ofp_print_version(const struct ofp_header *, struct ds *);

#ifdef  __cplusplus
}
#endif

#endif /* ofp-print.h */

/*
 * Copyright (c) 2010 Nicira Networks.
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

#include <stdint.h>

struct ofp_match;
struct ofpbuf;

void parse_ofp_str(char *string, struct ofp_match *match,
                   struct ofpbuf *actions, uint8_t *table_idx,
                   uint16_t *out_port, uint16_t *priority,
                   uint16_t *idle_timeout, uint16_t *hard_timeout,
                   uint64_t *cookie);

#endif /* ofp-parse.h */

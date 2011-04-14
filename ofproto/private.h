/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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

#ifndef OFPROTO_PRIVATE_H
#define OFPROTO_PRIVATE_H 1

/* Definitions for use within ofproto. */

#include "ofproto/ofproto.h"

void ofproto_add_flow(struct ofproto *, const struct cls_rule *,
                      const union ofp_action *, size_t n_actions);
void ofproto_delete_flow(struct ofproto *, const struct cls_rule *);
void ofproto_flush_flows(struct ofproto *);

#endif /* ofproto/private.h */

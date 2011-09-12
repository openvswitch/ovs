/*
 * Copyright (c) 2011 Nicira Networks.
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

#ifndef LEARN_H
#define LEARN_H 1

struct ds;
struct flow;
struct ofpbuf;
struct ofputil_flow_mod;
struct nx_action_learn;

/* NXAST_LEARN helper functions.
 *
 * See include/openflow/nicira-ext.h for NXAST_LEARN specification.
 */

int learn_check(const struct nx_action_learn *, const struct flow *);
void learn_execute(const struct nx_action_learn *, const struct flow *,
                   struct ofputil_flow_mod *);

void learn_parse(struct ofpbuf *, char *, const struct flow *);
void learn_format(const struct nx_action_learn *, struct ds *);

#endif /* learn.h */

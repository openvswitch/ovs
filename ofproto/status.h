/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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

#ifndef STATUS_H
#define STATUS_H 1

#include "compiler.h"

struct nicira_header;
struct rconn;
struct ofproto;
struct status_reply;

struct switch_status *switch_status_create(const struct ofproto *);
void switch_status_destroy(struct switch_status *);

int switch_status_handle_request(struct switch_status *, struct rconn *,
                                 struct nicira_header *);

typedef void status_cb_func(struct status_reply *, void *aux);
struct status_category *switch_status_register(struct switch_status *,
                                               const char *category,
                                               status_cb_func *, void *aux);
void switch_status_unregister(struct status_category *);

void status_reply_put(struct status_reply *, const char *, ...)
    PRINTF_FORMAT(2, 3);

void rconn_status_cb(struct status_reply *, void *rconn_);

#endif /* status.h */

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

#ifndef EXECUTER_H
#define EXECUTER_H 1

struct executer;
struct nicira_header;
struct rconn;

int executer_create(const char *acl, const char *dir, struct executer **);
void executer_set_acl(struct executer *, const char *acl, const char *dir);
void executer_destroy(struct executer *);
void executer_run(struct executer *);
void executer_wait(struct executer *);
void executer_rconn_closing(struct executer *, struct rconn *);
int executer_handle_request(struct executer *, struct rconn *,
                            struct nicira_header *);

#endif /* executer.h */

/* Copyright (c) 2017 Nicira, Inc.
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

#ifndef OVSDB_SESSION_H
#define OVSDB_SESSION_H 1

struct svec;
struct uuid;

void ovsdb_session_parse_remote(const char *s,
                                struct svec *remotes, struct uuid *cid);

#endif /* ovsdb-session.h */

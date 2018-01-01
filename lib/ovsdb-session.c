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

#include <config.h>
#include "ovsdb-session.h"
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "svec.h"
#include "util.h"
#include "uuid.h"

static const char *
next_remote(const char *s)
{
    for (const char *delimiter = strchr(s, ','); delimiter;
         delimiter = strchr(delimiter + 1, ',')) {
        const char *p = delimiter + 1;
        p += strspn(p, " \t");
        size_t n_letters = strspn(p, "abcdefghijklmnopqrstuvwxyz");
        if (n_letters && p[n_letters] == ':') {
            return delimiter;
        }
    }
    return NULL;
}

/* Parses string 's' into comma-delimited substrings and adds each of them into
 * 'remotes'.  If one of the substrings is of the form "cid:<uuid>", fills
 * '*cid' with the UUID (and omits it from 'remotes'), otherwise initializes
 * '*cid' to UUID_ZERO. */
void
ovsdb_session_parse_remote(const char *s,
                           struct svec *remotes, struct uuid *cid)
{
    *cid = UUID_ZERO;
    for (;;) {
        /* Skip white space. */
        s += strspn(s, " \t");
        if (*s == '\0') {
            break;
        }

        /* Find the start of the next remote  */
        const char *delimiter = next_remote(s);
        if (!delimiter) {
            svec_add(remotes, s);
            break;
        }
        svec_add_nocopy(remotes, xmemdup0(s, delimiter - s));
        s = delimiter + 1;
    }

    size_t i;
    for (i = 0; i < remotes->n; i++) {
        const char *name = remotes->names[i];
        struct uuid uuid;
        if (!strncmp(name, "cid:", 4) && uuid_from_string(&uuid, name + 4)) {
            *cid = uuid;
            svec_del(remotes, name);
            break;
        }
    }
}

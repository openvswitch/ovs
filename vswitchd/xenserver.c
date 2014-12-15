/* Copyright (c) 2009, 2010, 2013 Nicira, Inc.
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
#include "xenserver.h"
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dynamic-string.h"
#include "process.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(xenserver);

/* If running on a XenServer, the XenServer host UUID as a 36-character string,
 * otherwise null. */
static char *host_uuid;

static void
read_host_uuid(void)
{
    static const char filename[] = "/etc/xensource-inventory";
    char line[128];
    FILE *file;

    file = fopen(filename, "r");
    if (!file) {
        if (errno == ENOENT) {
            VLOG_DBG("not running on a XenServer");
        } else {
            VLOG_INFO("%s: open: %s", filename, ovs_strerror(errno));
        }
        return;
    }

    while (fgets(line, sizeof line, file)) {
        static const char leader[] = "INSTALLATION_UUID='";
        const int leader_len = strlen(leader);
        const int uuid_len = 36;
        static const char trailer[] = "'\n";
        const int trailer_len = strlen(trailer);

        if (strlen(line) == leader_len + uuid_len + trailer_len
            && !memcmp(line, leader, leader_len)
            && !memcmp(line + leader_len + uuid_len, trailer, trailer_len)) {
            host_uuid = xmemdup0(line + leader_len, uuid_len);
            VLOG_INFO("running on XenServer, host-uuid %s", host_uuid);
            fclose(file);
            return;
        }
    }
    fclose(file);
    VLOG_ERR("%s: INSTALLATION_UUID not found", filename);
}

const char *
xenserver_get_host_uuid(void)
{
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, read_host_uuid);
    return host_uuid;
}


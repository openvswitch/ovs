/* Copyright (c) 2009 Nicira Networks
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, Nicira Networks gives permission
 * to link the code of its release of vswitchd with the OpenSSL project's
 * "OpenSSL" library (or with modified versions of it that use the same
 * license as the "OpenSSL" library), and distribute the linked
 * executables.  You must obey the GNU General Public License in all
 * respects for all of the code used other than "OpenSSL".  If you modify
 * this file, you may extend this exception to your version of the file,
 * but you are not obligated to do so.  If you do not wish to do so,
 * delete this exception statement from your version.
 */

#include <config.h>
#include "xenserver.h"
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dynamic-string.h"
#include "process.h"

#include "vlog.h"
#define THIS_MODULE VLM_xenserver

static char *
read_host_uuid(void)
{
    static const char filename[] = "/etc/xensource-inventory";
    char line[128];
    FILE *file;

    file = fopen(filename, "r");
    if (!file) {
        if (errno == ENOENT) {
            VLOG_INFO("not running on a XenServer");
        } else {
            VLOG_INFO("%s: open: %s", filename, strerror(errno));
        }
        return NULL;
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
            char *host_uuid = xmemdup0(line + leader_len, uuid_len);
            VLOG_INFO("running on XenServer, host-uuid %s", host_uuid);
            fclose(file);
            return host_uuid;
        }
    }
    fclose(file);
    VLOG_ERR("%s: INSTALLATION_UUID not found", filename);
    return NULL;
}

const char *
xenserver_get_host_uuid(void)
{
    static char *host_uuid;
    static bool inited;

    if (!inited) {
        host_uuid = read_host_uuid();
        inited = true;
    }
    return host_uuid;
}


/*
 * Copyright (c) 2008, 2009, 2010, 2012, 2013, 2014, 2015 Nicira, Inc.
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
#include "stream.h"
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "openvswitch/dynamic-string.h"
#include "packets.h"
#include "socket-util.h"
#include "util.h"
#include "stream-provider.h"
#include "stream-fd.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(stream_tcp);

/* Active TCP. */

/* Takes ownership of 'name'. */
static int
new_tcp_stream(char *name, int fd, int connect_status, struct stream **streamp)
{
    if (connect_status == 0) {
        setsockopt_tcp_nodelay(fd);
    }

    return new_fd_stream(name, fd, connect_status, AF_INET, streamp);
}

static int
tcp_open(const char *name, char *suffix, struct stream **streamp, uint8_t dscp)
{
    int fd, error;

    error = inet_open_active(SOCK_STREAM, suffix, -1, NULL, &fd, dscp);
    if (fd >= 0) {
        return new_tcp_stream(xstrdup(name), fd, error, streamp);
    } else {
        VLOG_ERR("%s: connect: %s", name, ovs_strerror(error));
        return error;
    }
}

const struct stream_class tcp_stream_class = {
    "tcp",                      /* name */
    true,                       /* needs_probes */
    tcp_open,                   /* open */
    NULL,                       /* close */
    NULL,                       /* connect */
    NULL,                       /* recv */
    NULL,                       /* send */
    NULL,                       /* run */
    NULL,                       /* run_wait */
    NULL,                       /* wait */
};

/* Passive TCP. */

static int ptcp_accept(int fd, const struct sockaddr_storage *,
                       size_t, struct stream **streamp);

static int
new_pstream(char *suffix, const char *name, struct pstream **pstreamp,
            int dscp, char *unlink_path, bool kernel_print_port)
{
    struct sockaddr_storage ss;
    int error;
    int fd;

    fd = inet_open_passive(SOCK_STREAM, suffix, -1, &ss, dscp,
                           kernel_print_port);
    if (fd < 0) {
        return -fd;
    }

    struct ds bound_name = DS_EMPTY_INITIALIZER;
    if (!name) {
        ds_put_format(&bound_name, "ptcp:%"PRIu16":", ss_get_port(&ss));
        ss_format_address(&ss, &bound_name);
    } else {
        ds_put_cstr(&bound_name, name);
    }

    error = new_fd_pstream(ds_steal_cstr(&bound_name), fd,
                           ptcp_accept, unlink_path, pstreamp);
    if (!error) {
        pstream_set_bound_port(*pstreamp, htons(ss_get_port(&ss)));
    }
    return error;
}

static int
ptcp_open(const char *name OVS_UNUSED, char *suffix, struct pstream **pstreamp,
          uint8_t dscp)
{
    return new_pstream(suffix, NULL, pstreamp, dscp, NULL, true);
}

static int
ptcp_accept(int fd, const struct sockaddr_storage *ss,
            size_t ss_len OVS_UNUSED, struct stream **streamp)
{
    struct ds name = DS_EMPTY_INITIALIZER;
    ds_put_cstr(&name, "tcp:");
    ss_format_address(ss, &name);
    ds_put_format(&name, ":%"PRIu16, ss_get_port(ss));

    return new_tcp_stream(ds_steal_cstr(&name), fd, 0, streamp);
}

const struct pstream_class ptcp_pstream_class = {
    "ptcp",
    true,
    ptcp_open,
    NULL,
    NULL,
    NULL,
};

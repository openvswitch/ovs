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
#include "dynamic-string.h"
#include "packets.h"
#include "socket-util.h"
#include "util.h"
#include "stream-provider.h"
#include "stream-fd.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(stream_tcp);

/* Active TCP. */

static int
new_tcp_stream(const char *name, int fd, int connect_status,
               struct stream **streamp)
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

    error = inet_open_active(SOCK_STREAM, suffix, 0, NULL, &fd, dscp);
    if (fd >= 0) {
        return new_tcp_stream(name, fd, error, streamp);
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

#ifdef _WIN32
#include "dirs.h"

static int
windows_open(const char *name, char *suffix, struct stream **streamp,
             uint8_t dscp)
{
    int error, port;
    FILE *file;
    char *suffix_new, *path;

    /* If the path does not contain a ':', assume it is relative to
     * OVS_RUNDIR. */
    if (!strchr(suffix, ':')) {
        path = xasprintf("%s/%s", ovs_rundir(), suffix);
    } else {
        path = xstrdup(suffix);
    }

    file = fopen(path, "r");
    if (!file) {
        error = errno;
        VLOG_DBG("%s: could not open %s (%s)", name, suffix,
                 ovs_strerror(error));
        return error;
    }

    error = fscanf(file, "%d", &port);
    if (error != 1) {
        VLOG_ERR("failed to read port from %s", suffix);
        fclose(file);
        return EINVAL;
    }
    fclose(file);

    suffix_new = xasprintf("127.0.0.1:%d", port);

    error = tcp_open(name, suffix_new, streamp, dscp);

    free(suffix_new);
    free(path);
    return error;
}

const struct stream_class windows_stream_class = {
    "unix",                     /* name */
    false,                      /* needs_probes */
    windows_open,                  /* open */
    NULL,                       /* close */
    NULL,                       /* connect */
    NULL,                       /* recv */
    NULL,                       /* send */
    NULL,                       /* run */
    NULL,                       /* run_wait */
    NULL,                       /* wait */
};
#endif

/* Passive TCP. */

static int ptcp_accept(int fd, const struct sockaddr_storage *,
                       size_t, struct stream **streamp);

static int
new_pstream(char *suffix, const char *name, struct pstream **pstreamp,
            int dscp, char *unlink_path, bool kernel_print_port)
{
    char bound_name[SS_NTOP_BUFSIZE + 16];
    char addrbuf[SS_NTOP_BUFSIZE];
    struct sockaddr_storage ss;
    int error;
    uint16_t port;
    int fd;
    char *conn_name = CONST_CAST(char *, name);

    fd = inet_open_passive(SOCK_STREAM, suffix, -1, &ss, dscp,
                           kernel_print_port);
    if (fd < 0) {
        return -fd;
    }

    port = ss_get_port(&ss);
    if (!conn_name) {
        snprintf(bound_name, sizeof bound_name, "ptcp:%"PRIu16":%s",
                 port, ss_format_address(&ss, addrbuf, sizeof addrbuf));
        conn_name = bound_name;
    }

    error = new_fd_pstream(conn_name, fd, ptcp_accept, unlink_path, pstreamp);
    if (!error) {
        pstream_set_bound_port(*pstreamp, htons(port));
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
    char name[SS_NTOP_BUFSIZE + 16];
    char addrbuf[SS_NTOP_BUFSIZE];

    snprintf(name, sizeof name, "tcp:%s:%"PRIu16,
             ss_format_address(ss, addrbuf, sizeof addrbuf),
             ss_get_port(ss));
    return new_tcp_stream(name, fd, 0, streamp);
}

const struct pstream_class ptcp_pstream_class = {
    "ptcp",
    true,
    ptcp_open,
    NULL,
    NULL,
    NULL,
};

#ifdef _WIN32
static int
pwindows_open(const char *name, char *suffix, struct pstream **pstreamp,
              uint8_t dscp)
{
    int error;
    char *suffix_new, *path;
    FILE *file;
    struct pstream *listener;

    suffix_new = xstrdup("0:127.0.0.1");

    /* If the path does not contain a ':', assume it is relative to
     * OVS_RUNDIR. */
    if (!strchr(suffix, ':')) {
        path = xasprintf("%s/%s", ovs_rundir(), suffix);
    } else {
        path = xstrdup(suffix);
    }

    error = new_pstream(suffix_new, name, pstreamp, dscp, path, false);
    if (error) {
        goto exit;
    }
    listener = *pstreamp;

    file = fopen(path, "w");
    if (!file) {
        error = errno;
        VLOG_DBG("could not open %s (%s)", path, ovs_strerror(error));
        goto exit;
    }

    fprintf(file, "%d\n", ntohs(listener->bound_port));
    if (fflush(file) == EOF) {
        error = EIO;
        VLOG_ERR("write failed for %s", path);
        fclose(file);
        goto exit;
    }
    fclose(file);

exit:
    free(suffix_new);
    return error;
}

const struct pstream_class pwindows_pstream_class = {
    "punix",
    false,
    pwindows_open,
    NULL,
    NULL,
    NULL,
};
#endif

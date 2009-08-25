/*
 * Copyright (c) 2009 Nicira Networks.
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
#include "vconn.h"
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "poll-loop.h"
#include "socket-util.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

#undef NDEBUG
#include <assert.h>

struct fake_pvconn {
    const char *type;
    char *pvconn_name;
    char *vconn_name;
    int fd;
};

static void
fpv_create(const char *type, struct fake_pvconn *fpv)
{
    fpv->type = type;
    if (!strcmp(type, "unix")) {
        static int unix_count = 0;
        char *bind_path;
        int fd;

        bind_path = xasprintf("fake-pvconn.%d", unix_count++);
        fd = make_unix_socket(SOCK_STREAM, false, false, bind_path, NULL);
        if (fd < 0) {
            ovs_fatal(-fd, "%s: could not bind to Unix domain socket",
                      bind_path);
        }

        fpv->pvconn_name = xasprintf("punix:%s", bind_path);
        fpv->vconn_name = xasprintf("unix:%s", bind_path);
        fpv->fd = fd;
        free(bind_path);
    } else if (!strcmp(type, "tcp")) {
        struct sockaddr_in sin;
        socklen_t sin_len;
        int fd;

        /* Create TCP socket. */
        fd = socket(PF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            ovs_fatal(errno, "failed to create TCP socket");
        }

        /* Bind TCP socket to localhost on any available port. */
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_port = htons(0);
        if (bind(fd, (struct sockaddr *) &sin, sizeof sin) < 0) {
            ovs_fatal(errno, "failed to bind TCP socket");
        }

        /* Retrieve socket's port number. */
        sin_len = sizeof sin;
        if (getsockname(fd, (struct sockaddr *)&sin, &sin_len) < 0) {
            ovs_fatal(errno, "failed to read TCP socket name");
        }
        if (sin_len != sizeof sin || sin.sin_family != AF_INET) {
            ovs_fatal(errno, "bad TCP socket name");
        }

        /* Save info. */
        fpv->pvconn_name = xasprintf("ptcp:%"PRIu16":127.0.0.1",
                                    ntohs(sin.sin_port));
        fpv->vconn_name = xasprintf("tcp:127.0.0.1:%"PRIu16,
                                    ntohs(sin.sin_port));
        fpv->fd = fd;
    } else {
        abort();
    }

    /* Listen. */
    if (listen(fpv->fd, 0) < 0) {
        ovs_fatal(errno, "%s: listen failed", fpv->vconn_name);
    }
}

static int
fpv_accept(struct fake_pvconn *fpv)
{
    int fd;

    fd = accept(fpv->fd, NULL, NULL);
    if (fd < 0) {
        ovs_fatal(errno, "%s: accept failed", fpv->pvconn_name);
    }
    return fd;
}

static void
fpv_close(struct fake_pvconn *fpv)
{
    if (fpv->fd >= 0) {
        if (close(fpv->fd) < 0) {
            ovs_fatal(errno, "failed to close %s fake pvconn", fpv->type);
        }
        fpv->fd = -1;
    }
}

static void
fpv_destroy(struct fake_pvconn *fpv)
{
    fpv_close(fpv);
    free(fpv->pvconn_name);
    free(fpv->vconn_name);
}

/* Connects to a fake_pvconn with vconn_open(), then closes the listener and
 * verifies that vconn_connect() reports 'expected_error'. */
static void
test_refuse_connection(const char *type, int expected_error)
{
    struct fake_pvconn fpv;
    struct vconn *vconn;

    fpv_create(type, &fpv);
    assert(!vconn_open(fpv.vconn_name, OFP_VERSION, &vconn));
    fpv_close(&fpv);
    assert(vconn_connect(vconn) == expected_error);
    vconn_close(vconn);
    fpv_destroy(&fpv);
}

/* Connects to a fake_pvconn with vconn_open(), accepts that connection and
 * closes it immediately, and verifies that vconn_connect() reports
 * 'expected_error'. */
static void
test_accept_then_close(const char *type, int expected_error)
{
    struct fake_pvconn fpv;
    struct vconn *vconn;

    fpv_create(type, &fpv);
    assert(!vconn_open(fpv.vconn_name, OFP_VERSION, &vconn));
    close(fpv_accept(&fpv));
    fpv_close(&fpv);
    assert(vconn_connect(vconn) == expected_error);
    vconn_close(vconn);
    fpv_destroy(&fpv);
}

/* Connects to a fake_pvconn with vconn_open(), accepts that connection and
 * reads the hello message from it, then closes the connection and verifies
 * that vconn_connect() reports 'expected_error'. */
static void
test_read_hello(const char *type, int expected_error)
{
    struct fake_pvconn fpv;
    struct vconn *vconn;
    int fd;

    fpv_create(type, &fpv);
    assert(!vconn_open(fpv.vconn_name, OFP_VERSION, &vconn));
    fd = fpv_accept(&fpv);
    fpv_destroy(&fpv);
    assert(!set_nonblocking(fd));
    for (;;) {
       struct ofp_header hello;
       int retval;

       retval = read(fd, &hello, sizeof hello);
       if (retval == sizeof hello) {
           assert(hello.version == OFP_VERSION);
           assert(hello.type == OFPT_HELLO);
           assert(hello.length == htons(sizeof hello));
           break;
       } else {
           assert(errno == EAGAIN);
       }

       assert(vconn_connect(vconn) == EAGAIN);
       vconn_connect_wait(vconn);
       poll_fd_wait(fd, POLLIN);
       poll_block();
    }
    close(fd);
    assert(vconn_connect(vconn) == expected_error);
    vconn_close(vconn);
}

/* Connects to a fake_pvconn with vconn_open(), accepts that connection and
 * sends the 'out' bytes in 'out_size' to it (presumably an OFPT_HELLO
 * message), then verifies that vconn_connect() reports
 * 'expect_connect_error'. */
static void
test_send_hello(const char *type, const void *out, size_t out_size,
                int expect_connect_error)
{
    struct fake_pvconn fpv;
    struct vconn *vconn;
    bool read_hello, connected;
    struct ofpbuf *msg;
    int fd;

    fpv_create(type, &fpv);
    assert(!vconn_open(fpv.vconn_name, OFP_VERSION, &vconn));
    fd = fpv_accept(&fpv);
    fpv_destroy(&fpv);

    write(fd, out, out_size);

    assert(!set_nonblocking(fd));

    read_hello = connected = false;
    for (;;) {
       if (!read_hello) {
           struct ofp_header hello;
           int retval = read(fd, &hello, sizeof hello);
           if (retval == sizeof hello) {
               assert(hello.version == OFP_VERSION);
               assert(hello.type == OFPT_HELLO);
               assert(hello.length == htons(sizeof hello));
               read_hello = true;
           } else {
               assert(errno == EAGAIN);
           }
       }

       if (!connected) {
           int error = vconn_connect(vconn);
           if (error == expect_connect_error) {
               if (!error) {
                   connected = true;
               } else {
                   close(fd);
                   vconn_close(vconn);
                   return;
               }
           } else {
               assert(error == EAGAIN);
           }
       }

       if (read_hello && connected) {
           break;
       }

       if (!connected) {
           vconn_connect_wait(vconn);
       }
       if (!read_hello) {
           poll_fd_wait(fd, POLLIN);
       }
       poll_block();
    }
    close(fd);
    assert(vconn_recv(vconn, &msg) == EOF);
    vconn_close(vconn);
}

/* Try connecting and sending a normal hello, which should succeed. */
static void
test_send_plain_hello(const char *type)
{
    struct ofp_header hello;

    hello.version = OFP_VERSION;
    hello.type = OFPT_HELLO;
    hello.length = htons(sizeof hello);
    hello.xid = htonl(0x12345678);
    test_send_hello(type, &hello, sizeof hello, 0);
}

/* Try connecting and sending an extra-long hello, which should succeed (since
 * the specification says that implementations must accept and ignore extra
 * data). */
static void
test_send_long_hello(const char *type)
{
    struct ofp_header hello;
    char buffer[sizeof hello * 2];

    hello.version = OFP_VERSION;
    hello.type = OFPT_HELLO;
    hello.length = htons(sizeof buffer);
    hello.xid = htonl(0x12345678);
    memset(buffer, 0, sizeof buffer);
    memcpy(buffer, &hello, sizeof hello);
    test_send_hello(type, buffer, sizeof buffer, 0);
}

/* Try connecting and sending an echo request instead of a hello, which should
 * fail with EPROTO. */
static void
test_send_echo_hello(const char *type)
{
    struct ofp_header echo;

    echo.version = OFP_VERSION;
    echo.type = OFPT_ECHO_REQUEST;
    echo.length = htons(sizeof echo);
    echo.xid = htonl(0x89abcdef);
    test_send_hello(type, &echo, sizeof echo, EPROTO);
}

/* Try connecting and sending a hello packet that has its length field as 0,
 * which should fail with EPROTO. */
static void
test_send_short_hello(const char *type)
{
    struct ofp_header hello;

    memset(&hello, 0, sizeof hello);
    test_send_hello(type, &hello, sizeof hello, EPROTO);
}

/* Try connecting and sending a hello packet that has a bad version, which
 * should fail with EPROTO. */
static void
test_send_invalid_version_hello(const char *type)
{
    struct ofp_header hello;

    hello.version = OFP_VERSION - 1;
    hello.type = OFPT_HELLO;
    hello.length = htons(sizeof hello);
    hello.xid = htonl(0x12345678);
    test_send_hello(type, &hello, sizeof hello, EPROTO);
}

int
main(int argc UNUSED, char *argv[])
{
    set_program_name(argv[0]);
    time_init();
    vlog_init();
    signal(SIGPIPE, SIG_IGN);
    vlog_set_levels(VLM_ANY_MODULE, VLF_ANY_FACILITY, VLL_EMER);

    time_alarm(10);

    test_refuse_connection("unix", EPIPE);
    test_refuse_connection("tcp", ECONNRESET);

    test_accept_then_close("unix", EPIPE);
    test_accept_then_close("tcp", ECONNRESET);

    test_read_hello("unix", ECONNRESET);
    test_read_hello("tcp", ECONNRESET);

    test_send_plain_hello("unix");
    test_send_plain_hello("tcp");

    test_send_long_hello("unix");
    test_send_long_hello("tcp");

    test_send_echo_hello("unix");
    test_send_echo_hello("tcp");

    test_send_short_hello("unix");
    test_send_short_hello("tcp");

    test_send_invalid_version_hello("unix");
    test_send_invalid_version_hello("tcp");

    return 0;
}

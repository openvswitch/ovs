/*
 * Copyright (c) 2010, 2012, 2014 Nicira, Inc.
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
#undef NDEBUG
#include "socket-util.h"
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include "ovstest.h"
#include "util.h"

static void
test_unix_socket_main(int argc, char *argv[])
{
    const char *sockname1;
    const char *sockname2;
    int sock1, sock2;

    set_program_name(argv[0]);

    if (argc != 2 && argc != 3) {
        ovs_fatal(0, "usage: %s SOCKETNAME1 [SOCKETNAME2]", argv[0]);
    }
    sockname1 = argv[1];
    sockname2 = argc > 2 ? argv[2] : sockname1;

    signal(SIGALRM, SIG_DFL);
    alarm(5);

    /* Create a listening socket under name 'sockname1'. */
    sock1 = make_unix_socket(SOCK_STREAM, false, sockname1, NULL);
    if (sock1 < 0) {
        ovs_fatal(-sock1, "%s: bind failed", sockname1);
    }
    if (listen(sock1, 1)) {
        ovs_fatal(errno, "%s: listen failed", sockname1);
    }

    /* Connect to 'sockname2' (which should be the same file, perhaps under a
     * different name). */
    sock2 = make_unix_socket(SOCK_STREAM, false, NULL, sockname2);
    if (sock2 < 0) {
        ovs_fatal(-sock2, "%s: connect failed", sockname2);
    }

    close(sock1);
    close(sock2);
}

OVSTEST_REGISTER("test-unix-socket", test_unix_socket_main);

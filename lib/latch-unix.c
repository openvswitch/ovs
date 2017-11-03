/*
 * Copyright (c) 2013 Nicira, Inc.
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

#include "latch.h"
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include "openvswitch/poll-loop.h"
#include "socket-util.h"

/* Initializes 'latch' as initially unset. */
void
latch_init(struct latch *latch)
{
    xpipe_nonblocking(latch->fds);
}

/* Destroys 'latch'. */
void
latch_destroy(struct latch *latch)
{
    close(latch->fds[0]);
    close(latch->fds[1]);
}

/* Resets 'latch' to the unset state.  Returns true if 'latch' was previously
 * set, false otherwise. */
bool
latch_poll(struct latch *latch)
{
    char buffer[_POSIX_PIPE_BUF];

    return read(latch->fds[0], buffer, sizeof buffer) > 0;
}

/* Sets 'latch'.
 *
 * Calls are not additive: a single latch_poll() clears out any number of
 * latch_set(). */
void
latch_set(struct latch *latch)
{
    ignore(write(latch->fds[1], "", 1));
}

/* Returns true if 'latch' is set, false otherwise.  Does not reset 'latch'
 * to the unset state. */
bool
latch_is_set(const struct latch *latch)
{
    struct pollfd pfd;
    int retval;

    pfd.fd = latch->fds[0];
    pfd.events = POLLIN;
    do {
        retval = poll(&pfd, 1, 0);
    } while (retval < 0 && errno == EINTR);

    return pfd.revents & POLLIN;
}

/* Causes the next poll_block() to wake up when 'latch' is set.
 *
 * ('where' is used in debug logging.  Commonly one would use latch_wait() to
 * automatically provide the caller's source file and line number for
 * 'where'.) */
void
latch_wait_at(const struct latch *latch, const char *where)
{
    poll_fd_wait_at(latch->fds[0], POLLIN, where);
}

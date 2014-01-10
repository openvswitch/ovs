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
#include "poll-loop.h"
#include "socket-util.h"

/* Initializes 'latch' as initially unset. */
void
latch_init(struct latch *latch)
{
    latch->is_set = FALSE;
    latch->wevent = CreateEvent(NULL, TRUE, FALSE, NULL);
}

/* Destroys 'latch'. */
void
latch_destroy(struct latch *latch)
{
    latch->is_set = FALSE;
    CloseHandle(latch->wevent);
}

/* Resets 'latch' to the unset state.  Returns true if 'latch' was previously
 * set, false otherwise. */
bool
latch_poll(struct latch *latch)
{
    bool is_set;

    is_set = latch->is_set;
    latch->is_set = FALSE;
    ResetEvent(latch->wevent);
    return is_set;
}

/* Sets 'latch'.
 *
 * Calls are not additive: a single latch_poll() clears out any number of
 * latch_set(). */
void
latch_set(struct latch *latch)
{
    latch->is_set = TRUE;
    SetEvent(latch->wevent);
}

/* Returns true if 'latch' is set, false otherwise.  Does not reset 'latch'
 * to the unset state. */
bool
latch_is_set(const struct latch *latch)
{
    return latch->is_set;
}

/* Causes the next poll_block() to wake up when 'latch' is set.
 *
 * ('where' is used in debug logging.  Commonly one would use latch_wait() to
 * automatically provide the caller's source file and line number for
 * 'where'.) */
void
latch_wait_at(const struct latch *latch, const char *where)
{
    poll_fd_wait_at(0, latch->wevent, POLLIN, where);
}

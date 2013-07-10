/* Copyright (c) 2013 Nicira, Inc.
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

/* This implementation of the async-append.h interface uses ordinary
 * synchronous I/O, so it should be portable everywhere. */

#include "async-append.h"

#include <stdlib.h>
#include <unistd.h>

#include "util.h"

struct async_append {
    int fd;
};

void
async_append_enable(void)
{
    /* Nothing to do. */
}

struct async_append *
async_append_create(int fd)
{
    struct async_append *ap = xmalloc(sizeof *ap);
    ap->fd = fd;
    return ap;
}

void
async_append_destroy(struct async_append *ap)
{
    free(ap);
}

void
async_append_write(struct async_append *ap, const void *data, size_t size)
{
    ignore(write(ap->fd, data, size));
}

void
async_append_flush(struct async_append *ap OVS_UNUSED)
{
    /* Nothing to do. */
}

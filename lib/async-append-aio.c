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

/* This implementation of the async-append.h interface uses the POSIX
 * asynchronous I/O interface.  */

#include "async-append.h"

#include <aio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "byteq.h"
#include "ovs-thread.h"
#include "util.h"

/* Maximum number of bytes of buffered data. */
enum { BUFFER_SIZE = 65536 };

/* Maximum number of aiocbs to use.
 *
 * aiocbs are big (144 bytes with glibc 2.11 on i386) so we try to allow for a
 * reasonable number by basing the number we allocate on the amount of buffer
 * space. */
enum { MAX_CBS = ROUND_DOWN_POW2(BUFFER_SIZE / sizeof(struct aiocb)) };
BUILD_ASSERT_DECL(IS_POW2(MAX_CBS));

struct async_append {
    int fd;

    struct aiocb *aiocbs;
    unsigned int aiocb_head, aiocb_tail;

    uint8_t *buffer;
    struct byteq byteq;
};

struct async_append *
async_append_create(int fd)
{
    struct async_append *ap;

    ap = xmalloc(sizeof *ap);
    ap->fd = fd;
    ap->aiocbs = xmalloc(MAX_CBS * sizeof *ap->aiocbs);
    ap->aiocb_head = ap->aiocb_tail = 0;
    ap->buffer = xmalloc(BUFFER_SIZE);
    byteq_init(&ap->byteq, ap->buffer, BUFFER_SIZE);

    return ap;
}

void
async_append_destroy(struct async_append *ap)
{
    if (ap) {
        async_append_flush(ap);
        free(ap->aiocbs);
        free(ap->buffer);
        free(ap);
    }
}

static bool
async_append_is_full(const struct async_append *ap)
{
    return (ap->aiocb_head - ap->aiocb_tail >= MAX_CBS
            || byteq_is_full(&ap->byteq));
}

static bool
async_append_is_empty(const struct async_append *ap)
{
    return byteq_is_empty(&ap->byteq);
}

static void
async_append_wait(struct async_append *ap)
{
    int n = 0;

    while (!async_append_is_empty(ap)) {
        struct aiocb *aiocb = &ap->aiocbs[ap->aiocb_tail & (MAX_CBS - 1)];
        int error = aio_error(aiocb);

        if (error == EINPROGRESS) {
            const struct aiocb *p = aiocb;
            if (n > 0) {
                return;
            }
            aio_suspend(&p, 1, NULL);
        } else {
            ignore(aio_return(aiocb));
            ap->aiocb_tail++;
            byteq_advance_tail(&ap->byteq, aiocb->aio_nbytes);
            n++;
        }
    }
}

void
async_append_write(struct async_append *ap, const void *data_, size_t size)
{
    const uint8_t *data = data_;

    while (size > 0) {
        struct aiocb *aiocb;
        size_t chunk_size;
        void *chunk;

        while (async_append_is_full(ap)) {
            async_append_wait(ap);
        }

        chunk = byteq_head(&ap->byteq);
        chunk_size = byteq_headroom(&ap->byteq);
        if (chunk_size > size) {
            chunk_size = size;
        }
        memcpy(chunk, data, chunk_size);

        aiocb = &ap->aiocbs[ap->aiocb_head & (MAX_CBS - 1)];
        memset(aiocb, 0, sizeof *aiocb);
        aiocb->aio_fildes = ap->fd;
        aiocb->aio_offset = 0;
        aiocb->aio_buf = chunk;
        aiocb->aio_nbytes = chunk_size;
        aiocb->aio_sigevent.sigev_notify = SIGEV_NONE;
        if (aio_write(aiocb) == -1) {
            async_append_flush(ap);
            ignore(write(ap->fd, data, size));
            return;
        }

        data += chunk_size;
        size -= chunk_size;
        byteq_advance_head(&ap->byteq, chunk_size);
        ap->aiocb_head++;
    }
}

void
async_append_flush(struct async_append *ap)
{
    while (!async_append_is_empty(ap)) {
        async_append_wait(ap);
    }
}

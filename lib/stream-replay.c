/*
 * Copyright (c) 2021, Red Hat, Inc.
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
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "ovs-atomic.h"
#include "ovs-replay.h"
#include "util.h"
#include "stream-provider.h"
#include "stream.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(stream_replay);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 25);

/* Active replay stream. */

struct stream_replay {
    struct stream stream;
    replay_file_t f;
    int seqno;
};

const struct stream_class replay_stream_class;

/* Creates a new stream named 'name' that will emulate sending and receiving
 * data using replay file and stores a pointer to the stream in '*streamp'.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
static int
new_replay_stream(const char *name, struct stream **streamp)
{
    struct stream_replay *s;
    int seqno = 0, error = 0, open_result;
    replay_file_t f;

    ovs_replay_lock();
    error = ovs_replay_file_open(name, &f, &seqno);
    if (error) {
        VLOG_ERR_RL(&rl, "%s: failed to open stream.", name);
        goto unlock;
    }

    error = ovs_replay_read(f, NULL, 0, &open_result, &seqno, true);
    if (error) {
        VLOG_ERR_RL(&rl, "%s: failed to read 'open' record.", name);
        ovs_replay_file_close(f);
        goto unlock;
    }

    if (open_result) {
        error = -open_result;
        ovs_replay_file_close(f);
        goto unlock;
    }

    s = xmalloc(sizeof *s);
    stream_init(&s->stream, &replay_stream_class, 0, xstrdup(name));
    s->f = f;
    s->seqno = seqno;
    *streamp = &s->stream;
unlock:
    ovs_replay_unlock();
    return error;
}

static struct stream_replay *
stream_replay_cast(struct stream *stream)
{
    stream_assert_class(stream, &replay_stream_class);
    return CONTAINER_OF(stream, struct stream_replay, stream);
}

void
stream_replay_open_wfd(struct stream *s, int open_result, const char *name)
{
    int state = ovs_replay_get_state();
    int error = 0;
    replay_file_t f;

    if (OVS_LIKELY(state != OVS_REPLAY_WRITE)) {
        return;
    }

    ovs_replay_lock();
    error = ovs_replay_file_open(name, &f, NULL);
    if (error) {
        VLOG_ERR_RL(&rl, "%s: failed to open replay file for stream.", name);
        ovs_replay_unlock();
        return;
    }
    ovs_replay_unlock();

    if (ovs_replay_write(f, NULL, -open_result, true)) {
        VLOG_ERR_RL(&rl, "%s: failed to write 'open' failure: %d",
                    s->name, open_result);
    }
    if (open_result) {
        /* We recorded failure to open the stream. */
        ovs_replay_file_close(f);
    } else {
        s->replay_wfd = f;
    }
}

void
stream_replay_write(struct stream *s, const void *buffer, int n, bool is_read)
{
    int state = ovs_replay_get_state();

    if (OVS_LIKELY(state != OVS_REPLAY_WRITE)) {
        return;
    }

    if (ovs_replay_write(s->replay_wfd, buffer, n, is_read)) {
        VLOG_ERR_RL(&rl, "%s: failed to write buffer.", s->name);
    }
}

void
stream_replay_close_wfd(struct stream *s)
{
    if (s->replay_wfd) {
        ovs_replay_file_close(s->replay_wfd);
    }
}

static int
stream_replay_open(const char *name, char *suffix OVS_UNUSED,
                   struct stream **streamp, uint8_t dscp OVS_UNUSED)
{
    return new_replay_stream(name, streamp);
}

static void
stream_replay_close(struct stream *stream)
{
    struct stream_replay *s = stream_replay_cast(stream);
    ovs_replay_file_close(s->f);
    free(s);
}

static ssize_t
stream_replay_recv(struct stream *stream, void *buffer, size_t n)
{
    struct stream_replay *s = stream_replay_cast(stream);
    int norm_seqno = ovs_replay_normalized_seqno(s->seqno);
    int error, len;

    ovs_replay_lock();
    ovs_assert(norm_seqno >= ovs_replay_seqno());

    if (norm_seqno != ovs_replay_seqno()
        || !ovs_replay_seqno_is_read(s->seqno)) {
        error = EAGAIN;
        goto unlock;
    }

    error = ovs_replay_read(s->f, buffer, n, &len, &s->seqno, true);
    if (error) {
        VLOG_ERR_RL(&rl, "%s: failed to read from replay file.", stream->name);
        goto unlock;
    }

unlock:
    ovs_replay_unlock();
    return error ? -error : len;
}

static ssize_t
stream_replay_send(struct stream *stream OVS_UNUSED,
                   const void *buffer OVS_UNUSED, size_t n)
{
    struct stream_replay *s = stream_replay_cast(stream);
    int norm_seqno = ovs_replay_normalized_seqno(s->seqno);
    int error, len;

    ovs_replay_lock();
    ovs_assert(norm_seqno >= ovs_replay_seqno());

    if (norm_seqno != ovs_replay_seqno()
        || ovs_replay_seqno_is_read(s->seqno)) {
        error = EAGAIN;
        goto unlock;
    }

    error = ovs_replay_read(s->f, NULL, 0, &len, &s->seqno, false);
    if (error) {
        VLOG_ERR_RL(&rl, "%s: failed to read from replay file.", stream->name);
        goto unlock;
    }
    ovs_assert(len < 0 || len <= n);

unlock:
    ovs_replay_unlock();
    return error ? -error : len;
}

static void
stream_replay_wait(struct stream *stream, enum stream_wait_type wait)
{
    struct stream_replay *s = stream_replay_cast(stream);
    switch (wait) {
    case STREAM_CONNECT:
        /* Connect does nothing and always available. */
        poll_immediate_wake();
        break;

    case STREAM_SEND:
        if (s->seqno != INT_MAX && !ovs_replay_seqno_is_read(s->seqno)) {
            /* Stream waits for write. */
            poll_immediate_wake();
        }
        break;

    case STREAM_RECV:
        if (s->seqno != INT_MAX && ovs_replay_seqno_is_read(s->seqno)) {
            /* We still have something to read. */
            poll_immediate_wake();
        }
        break;

    default:
        OVS_NOT_REACHED();
    }
}

const struct stream_class replay_stream_class = {
    "replay",                   /* name */
    false,                      /* needs_probes */
    stream_replay_open,         /* open */
    stream_replay_close,        /* close */
    NULL,                       /* connect */
    stream_replay_recv,         /* recv */
    stream_replay_send,         /* send */
    NULL,                       /* run */
    NULL,                       /* run_wait */
    stream_replay_wait,         /* wait */
};

/* Passive replay stream. */

struct replay_pstream
{
    struct pstream pstream;
    replay_file_t f;
    int seqno;
};

const struct pstream_class preplay_pstream_class;

static struct replay_pstream *
replay_pstream_cast(struct pstream *pstream)
{
    pstream_assert_class(pstream, &preplay_pstream_class);
    return CONTAINER_OF(pstream, struct replay_pstream, pstream);
}

/* Creates a new pstream named 'name' that will accept new replay connections
 * reading them from the replay file and stores a pointer to the stream in
 * '*pstreamp'.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
static int
pstream_replay_listen(const char *name, char *suffix OVS_UNUSED,
                      struct pstream **pstreamp, uint8_t dscp OVS_UNUSED)
{
    int seqno = 0, error = 0, listen_result;
    replay_file_t f;

    ovs_replay_lock();
    error = ovs_replay_file_open(name, &f, &seqno);
    if (error) {
        VLOG_ERR_RL(&rl, "%s: failed to open pstream.", name);
        goto unlock;
    }

    error = ovs_replay_read(f, NULL, 0, &listen_result, &seqno, true);
    if (error) {
        VLOG_ERR_RL(&rl, "%s: failed to read 'listen' record.", name);
        ovs_replay_file_close(f);
        goto unlock;
    }

    if (listen_result) {
        error = -listen_result;
        ovs_replay_file_close(f);
        goto unlock;
    }

    struct replay_pstream *ps = xmalloc(sizeof *ps);
    pstream_init(&ps->pstream, &preplay_pstream_class, xstrdup(name));
    ps->f = f;
    ps->seqno = seqno;
    *pstreamp = &ps->pstream;
unlock:
    ovs_replay_unlock();
    return error;
}

void
pstream_replay_open_wfd(struct pstream *ps, int listen_result,
                        const char *name)
{
    int state = ovs_replay_get_state();
    int error = 0;
    replay_file_t f;

    if (OVS_LIKELY(state != OVS_REPLAY_WRITE)) {
        return;
    }

    ovs_replay_lock();
    error = ovs_replay_file_open(name, &f, NULL);
    if (error) {
        VLOG_ERR_RL(&rl, "%s: failed to open replay file for pstream.", name);
        ovs_replay_unlock();
        return;
    }
    ovs_replay_unlock();

    if (ovs_replay_write(f, NULL, -listen_result, true)) {
        VLOG_ERR_RL(&rl, "%s: failed to write 'listen' result: %d",
                    ps->name, listen_result);
    }

    if (listen_result) {
        /* We recorded failure to open the stream. */
        ovs_replay_file_close(f);
    } else {
        ps->replay_wfd = f;
    }
}

void
pstream_replay_write_accept(struct pstream *ps, const struct stream *s,
                            int accept_result)
{
    int state = ovs_replay_get_state();
    int len;

    if (OVS_LIKELY(state != OVS_REPLAY_WRITE)) {
        return;
    }

    if (!accept_result) {
        len = strlen(s->name);
        if (ovs_replay_write(ps->replay_wfd, s->name, len, true)) {
            VLOG_ERR_RL(&rl, "%s: failed to write accept name: %s",
                        ps->name, s->name);
        }
    } else if (ovs_replay_write(ps->replay_wfd, NULL, -accept_result, true)) {
        VLOG_ERR_RL(&rl, "%s: failed to write 'accept' failure: %d",
                    ps->name, accept_result);
    }
}

void
pstream_replay_close_wfd(struct pstream *ps)
{
    if (ps->replay_wfd) {
        ovs_replay_file_close(ps->replay_wfd);
    }
}

static void
pstream_replay_close(struct pstream *pstream)
{
    struct replay_pstream *ps = replay_pstream_cast(pstream);

    ovs_replay_file_close(ps->f);
    free(ps);
}

#define MAX_NAME_LEN 65536

static int
pstream_replay_accept(struct pstream *pstream, struct stream **new_streamp)
{
    struct replay_pstream *ps = replay_pstream_cast(pstream);
    int norm_seqno = ovs_replay_normalized_seqno(ps->seqno);
    int retval, len;
    char name[MAX_NAME_LEN];

    ovs_replay_lock();
    ovs_assert(norm_seqno >= ovs_replay_seqno());

    if (norm_seqno != ovs_replay_seqno()
        || !ovs_replay_seqno_is_read(ps->seqno)) {
        retval = EAGAIN;
        ovs_replay_unlock();
        goto exit;
    }

    retval = ovs_replay_read(ps->f, name, MAX_NAME_LEN - 1,
                             &len, &ps->seqno, true);
    if (retval) {
        VLOG_ERR_RL(&rl, "%s: failed to read from replay file.",
                    pstream->name);
        ovs_replay_unlock();
        goto exit;
    }

    ovs_replay_unlock();

    if (len > 0) {
        name[len] = 0;
        retval = new_replay_stream(name, new_streamp);
    } else {
        retval = -len;
    }
exit:
    return retval;
}

static void
pstream_replay_wait(struct pstream *pstream)
{
    struct replay_pstream *ps = replay_pstream_cast(pstream);

    if (ps->seqno != INT_MAX) {
        /* Replay always has something to say. */
        poll_immediate_wake();
    }
}

const struct pstream_class preplay_pstream_class = {
    "preplay",
    false,
    pstream_replay_listen,
    pstream_replay_close,
    pstream_replay_accept,
    pstream_replay_wait,
};

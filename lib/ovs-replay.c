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
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "dirs.h"
#include "ovs-atomic.h"
#include "ovs-replay.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovs_replay);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 25);

static struct ovs_mutex replay_mutex = OVS_MUTEX_INITIALIZER;
static int replay_seqno OVS_GUARDED_BY(replay_mutex) = 0;
static atomic_int replay_state = ATOMIC_VAR_INIT(OVS_REPLAY_NONE);

static char *dirname = NULL;

void
ovs_replay_set_state(enum ovs_replay_state state)
{
    atomic_store_relaxed(&replay_state, state);
}

enum ovs_replay_state
ovs_replay_get_state(void)
{
    int state;

    atomic_read_relaxed(&replay_state, &state);
    return state;
}

void
ovs_replay_set_dirname(const char *new_dirname)
{
    if (new_dirname) {
        free(dirname);
        dirname = xstrdup(new_dirname);
    }
}

void
ovs_replay_lock(void)
    OVS_ACQUIRES(replay_mutex)
{
    ovs_mutex_lock(&replay_mutex);
}

void
ovs_replay_unlock(void)
    OVS_RELEASES(replay_mutex)
{
    ovs_mutex_unlock(&replay_mutex);
}

int
ovs_replay_seqno(void)
    OVS_REQUIRES(replay_mutex)
{
    return replay_seqno;
}

static char *
ovs_replay_file_name(const char *name, int seqno)
{
    char *local_name = xstrdup(name);
    char *filename, *p, *c;
    bool skip = false;

    /* Replace all the numbers and special symbols with single underscore.
     * Numbers might be PIDs or port numbers that could change between record
     * and replay phases, special symbols might be not good as a filename.
     * We have a unique seuqence number as part of the name, so we don't care
     * keeping too much information. */
    for (c = p = local_name; *p; p++) {
         if (!isalpha((unsigned char) *p)) {
             if (!skip) {
                *c++ = '_';
                skip = true;
             }
         } else {
             *c++ = *p;
             skip = false;
         }
    }
    if (skip) {
        c--;
    }
    *c = '\0';
    filename = xasprintf("%s/replay_%s_%d", dirname ? dirname : "",
                                            local_name, seqno);
    VLOG_DBG("Constructing replay filename: '%s' --> '%s' --> '%s'.",
             name, local_name, filename);
    free(local_name);

    return filename;
}

int
ovs_replay_file_open(const char *name, replay_file_t *f, int *seqno)
    OVS_REQUIRES(replay_mutex)
{
    char *file_path, *filename;
    int state = ovs_replay_get_state();

    ovs_assert(state != OVS_REPLAY_NONE);

    filename = ovs_replay_file_name(name, replay_seqno);
    if (filename[0] != '/') {
        file_path = abs_file_name(ovs_rundir(), filename);
        free(filename);
    } else {
        file_path = filename;
    }

    *f = fopen(file_path, state == OVS_REPLAY_WRITE ? "wb" : "rb");
    if (!*f) {
        VLOG_ERR_RL(&rl, "%s: fopen failed: %s",
                    file_path, ovs_strerror(errno));
        free(file_path);
        return errno;
    }
    free(file_path);

    if (state == OVS_REPLAY_READ
        && fread(seqno, sizeof *seqno, 1, *f) != 1) {
        VLOG_INFO("%s: failed to read seqno: replay might be empty.", name);
        *seqno = INT_MAX;
    }
    replay_seqno++;  /* New file opened. */
    return 0;
}

void
ovs_replay_file_close(replay_file_t f)
{
    fclose(f);
}

int
ovs_replay_write(replay_file_t f, const void *buffer, int n, bool is_read)
    OVS_EXCLUDED(replay_mutex)
{
    int state = ovs_replay_get_state();
    int seqno_to_write;
    int retval = 0;

    if (OVS_LIKELY(state != OVS_REPLAY_WRITE)) {
        return 0;
    }

    ovs_replay_lock();

    seqno_to_write = is_read ? replay_seqno : -replay_seqno;
    if (fwrite(&seqno_to_write, sizeof seqno_to_write, 1, f) != 1) {
        VLOG_ERR_RL(&rl, "Failed to write seqno.");
        retval = -1;
        goto out;
    }
    if (fwrite(&n, sizeof n, 1, f) != 1) {
        VLOG_ERR_RL(&rl, "Failed to write length.");
        retval = -1;
        goto out;
    }
    if (n > 0 && is_read && fwrite(buffer, 1, n, f) != n) {
        VLOG_ERR_RL(&rl, "Failed to write data.");
        retval = -1;
    }
out:
    replay_seqno++; /* Write completed. */
    ovs_replay_unlock();
    fflush(f);
    return retval;
}

int
ovs_replay_read(replay_file_t f, void *buffer, int buffer_size,
                int *len, int *seqno, bool is_read)
    OVS_REQUIRES(replay_mutex)
{
    int retval = EINVAL;

    if (fread(len, sizeof *len, 1, f) != 1) {
        VLOG_ERR_RL(&rl, "Failed to read replay length.");
        goto out;
    }

    if (is_read && *len > buffer_size) {
        VLOG_ERR_RL(&rl, "Failed to read replay buffer: "
                    "insufficient buffer size: provided %d, needed %d.",
                    buffer_size, *len);
        goto out;
    }

    if (*len > 0 && is_read && fread(buffer, 1, *len, f) != *len) {
        VLOG_ERR_RL(&rl, "Failed to read replay buffer.");
        goto out;
    }

    if (fread(seqno, sizeof *seqno, 1, f) != 1) {
        *seqno = INT_MAX;  /* Most likely EOF. */
        if (ferror(f)) {
            VLOG_INFO("Failed to read replay seqno.");
            goto out;
        }
    }

    retval = 0;
out:
    replay_seqno++;  /* Read completed. */
    return retval;
}

void
ovs_replay_usage(void)
{
    printf("\nReplay options:\n"
           "  --record[=DIR]            turn on writing replay files\n"
           "  --replay[=DIR]            run from replay files\n");
}

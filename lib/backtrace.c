/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013 Nicira, Inc.
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
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include "backtrace.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(backtrace);

#ifdef HAVE_BACKTRACE
#include <execinfo.h>
void
backtrace_capture(struct backtrace *b)
{
    b->n_frames = backtrace(b->frames, BACKTRACE_MAX_FRAMES);
}

void
backtrace_format(struct ds *ds, const struct backtrace *bt,
                 const char *delimiter)
{
    if (bt->n_frames) {
        char **symbols = backtrace_symbols(bt->frames, bt->n_frames);

        if (!symbols) {
            return;
        }

        for (int i = 0; i < bt->n_frames - 1; i++) {
            ds_put_format(ds, "%s%s", symbols[i], delimiter);
        }

        ds_put_format(ds, "%s", symbols[bt->n_frames - 1]);

        free(symbols);
    }
}

#else
void
backtrace_capture(struct backtrace *backtrace)
{
    backtrace->n_frames = 0;
}

void
backtrace_format(struct ds *ds, const struct backtrace *bt OVS_UNUSED,
                 const char *delimiter OVS_UNUSED)
{
    ds_put_cstr(ds, "backtrace() is not supported!\n");
}
#endif

void
log_backtrace_at(const char *msg, const char *where)
{
    struct backtrace b;
    struct ds ds = DS_EMPTY_INITIALIZER;

    backtrace_capture(&b);
    if (msg) {
        ds_put_format(&ds, "%s ", msg);
    }

    ds_put_cstr(&ds, where);
    ds_put_cstr(&ds, " backtrace:\n");
    backtrace_format(&ds, &b, "\n");
    VLOG_ERR("%s", ds_cstr_ro(&ds));

    ds_destroy(&ds);
}

#if defined(HAVE_UNWIND) || defined(HAVE_BACKTRACE)
static bool
read_received_backtrace(int fd, void *dest, size_t len)
{
    VLOG_DBG("%s fd %d", __func__, fd);
    fcntl(fd, F_SETFL, O_NONBLOCK);
    memset(dest, 0, len);

    int byte_read = read(fd, dest, len);
    if (byte_read < 0) {
        VLOG_ERR("Read fd %d failed: %s", fd, ovs_strerror(errno));
    }

    return byte_read > 0;;
}
#else
static bool
read_received_backtrace(int fd OVS_UNUSED, void *dest OVS_UNUSED,
                        size_t len OVS_UNUSED)
{
    return false;
}
#endif

#ifdef HAVE_UNWIND
void
log_received_backtrace(int fd)
{
    struct unw_backtrace backtrace[UNW_MAX_DEPTH];

    if (read_received_backtrace(fd, backtrace, UNW_MAX_BUF)) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        ds_put_cstr(&ds, BACKTRACE_DUMP_MSG);

        for (int i = 0; i < UNW_MAX_DEPTH; i++) {
            if (backtrace[i].func[0] == 0) {
                break;
            }
            ds_put_format(&ds, "0x%016"PRIxPTR" <%s+0x%"PRIxPTR">\n",
                          backtrace[i].ip,
                          backtrace[i].func,
                          backtrace[i].offset);
        }

        VLOG_WARN("%s", ds_cstr_ro(&ds));

        ds_destroy(&ds);
    }
}
#elif HAVE_BACKTRACE
void
log_received_backtrace(int fd)
{
    struct backtrace bt;

    if (read_received_backtrace(fd, &bt, sizeof bt)) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        bt.n_frames = MIN(bt.n_frames, BACKTRACE_MAX_FRAMES);

        ds_put_cstr(&ds, BACKTRACE_DUMP_MSG);
        backtrace_format(&ds, &bt, "\n");
        VLOG_WARN("%s", ds_cstr_ro(&ds));

        ds_destroy(&ds);
    }
}
#else
void
log_received_backtrace(int daemonize_fd OVS_UNUSED)
{
    VLOG_WARN("Backtrace using libunwind or backtrace() is not supported.");
}
#endif

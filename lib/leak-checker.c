/*
 * Copyright (c) 2008, 2009, 2010 Nicira, Inc.
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
#include "leak-checker.h"
#include <inttypes.h>
#include "backtrace.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(leak_checker);

#ifndef HAVE_MALLOC_HOOKS
void
leak_checker_start(const char *file_name OVS_UNUSED)
{
    VLOG_WARN("not enabling leak checker because the libc in use does not "
              "have the required hooks");
}

void
leak_checker_set_limit(off_t max_size OVS_UNUSED)
{
}

void
leak_checker_claim(const void *p OVS_UNUSED)
{
}

void
leak_checker_usage(void)
{
    printf("  --check-leaks=FILE      (accepted but ignored in this build)\n");
}
#else /* HAVE_MALLOC_HOOKS */
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <sys/stat.h>

typedef void *malloc_hook_type(size_t, const void *);
typedef void *realloc_hook_type(void *, size_t, const void *);
typedef void free_hook_type(void *, const void *);

struct hooks {
    malloc_hook_type *malloc_hook_func;
    realloc_hook_type *realloc_hook_func;
    free_hook_type *free_hook_func;
};

static malloc_hook_type hook_malloc;
static realloc_hook_type hook_realloc;
static free_hook_type hook_free;

static struct hooks libc_hooks;
static const struct hooks our_hooks = { hook_malloc, hook_realloc, hook_free };

static FILE *file;
static off_t limit = 10 * 1000 * 1000;

static void
get_hooks(struct hooks *hooks)
{
    hooks->malloc_hook_func = __malloc_hook;
    hooks->realloc_hook_func = __realloc_hook;
    hooks->free_hook_func = __free_hook;
}

static void
set_hooks(const struct hooks *hooks)
{
    __malloc_hook = hooks->malloc_hook_func;
    __realloc_hook = hooks->realloc_hook_func;
    __free_hook = hooks->free_hook_func;
}

void
leak_checker_start(const char *file_name)
{
    if (!file) {
        file = fopen(file_name, "w");
        if (!file) {
            VLOG_WARN("failed to create \"%s\": %s",
                      file_name, strerror(errno));
            return;
        }
        setvbuf(file, NULL, _IOLBF, 0);
        VLOG_WARN("enabled memory leak logging to \"%s\"", file_name);
        get_hooks(&libc_hooks);
        set_hooks(&our_hooks);
    }
}

void
leak_checker_stop(void)
{
    if (file) {
        fclose(file);
        file = NULL;
        set_hooks(&libc_hooks);
        VLOG_WARN("disabled memory leak logging");
    }
}

void
leak_checker_set_limit(off_t limit_)
{
    limit = limit_;
}

void
leak_checker_usage(void)
{
    printf("  --check-leaks=FILE      log malloc and free calls to FILE\n");
}

static void PRINTF_FORMAT(1, 2)
log_callers(const char *format, ...)
{
    struct backtrace backtrace;
    va_list args;
    int i;

    va_start(args, format);
    vfprintf(file, format, args);
    va_end(args);

    putc(':', file);
    backtrace_capture(&backtrace);
    for (i = 0; i < backtrace.n_frames; i++) {
        fprintf(file, " 0x%"PRIxPTR, backtrace.frames[i]);
    }
    putc('\n', file);
}

static void
reset_hooks(void)
{
    static int count;

    if (file) {
        if (ferror(file)) {
            VLOG_WARN("error writing leak checker log file");
            leak_checker_stop();
            return;
        }

        if (count++ >= 100 && limit) {
            struct stat s;
            count = 0;
            if (fstat(fileno(file), &s) < 0) {
                VLOG_WARN("cannot fstat leak checker log file: %s",
                          strerror(errno));
                leak_checker_stop();
                return;
            }
            if (s.st_size > limit) {
                VLOG_WARN("leak checker log file size exceeded limit");
                leak_checker_stop();
                return;
            }
        }
    }
    if (file) {
        set_hooks(&our_hooks);
    }
}

static void *
hook_malloc(size_t size, const void *caller OVS_UNUSED)
{
    void *p;

    set_hooks(&libc_hooks);
    p = malloc(size);
    get_hooks(&libc_hooks);

    log_callers("malloc(%zu) -> %p", size, p);

    reset_hooks();
    return p;
}

void
leak_checker_claim(const void *p)
{
    if (!file) {
        return;
    }

    if (p) {
        set_hooks(&libc_hooks);
        log_callers("claim(%p)", p);
        reset_hooks();
    }
}

static void
hook_free(void *p, const void *caller OVS_UNUSED)
{
    if (!p) {
        return;
    }

    set_hooks(&libc_hooks);
    log_callers("free(%p)", p);
    free(p);
    get_hooks(&libc_hooks);

    reset_hooks();
}

static void *
hook_realloc(void *p, size_t size, const void *caller OVS_UNUSED)
{
    void *q;

    set_hooks(&libc_hooks);
    q = realloc(p, size);
    get_hooks(&libc_hooks);

    if (p != q) {
        log_callers("realloc(%p, %zu) -> %p", p, size, q);
    }

    reset_hooks();

    return q;
}
#endif /* HAVE_MALLOC_HOOKS */

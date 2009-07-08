/*
 * Copyright (c) 2008 Nicira Networks.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef DAEMON_H
#define DAEMON_H 1

#include <stdbool.h>
#include <sys/types.h>

#define DAEMON_LONG_OPTIONS                         \
        {"detach",      no_argument, 0, 'D'},       \
        {"force",       no_argument, 0, 'f'},       \
        {"pidfile",     optional_argument, 0, 'P'}

#define DAEMON_OPTION_HANDLERS                  \
        case 'D':                               \
            set_detach();                       \
            break;                              \
                                                \
        case 'P':                               \
            set_pidfile(optarg);                \
            break;                              \
                                                \
        case 'f':                               \
            ignore_existing_pidfile();          \
            break;

char *make_pidfile_name(const char *name);
void set_pidfile(const char *name);
const char *get_pidfile(void);
void set_detach(void);
void daemonize(void);
void die_if_already_running(void);
void ignore_existing_pidfile(void);
void daemon_usage(void);
pid_t read_pidfile(const char *name);

#endif /* daemon.h */

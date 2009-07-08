/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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

#ifndef LEAK_CHECKER_H
#define LEAK_CHECKER_H 1

#include <sys/types.h>

#define LEAK_CHECKER_OPTION_ENUMS               \
    OPT_CHECK_LEAKS,                            \
    OPT_LEAK_LIMIT
#define LEAK_CHECKER_LONG_OPTIONS                           \
    {"check-leaks", required_argument, 0, OPT_CHECK_LEAKS}, \
    {"leak-limit", required_argument, 0, OPT_LEAK_LIMIT}
#define LEAK_CHECKER_OPTION_HANDLERS                \
        case OPT_CHECK_LEAKS:                       \
            leak_checker_start(optarg);             \
            break;                                  \
        case OPT_LEAK_LIMIT:                        \
            leak_checker_set_limit(atol(optarg));   \
            break;
void leak_checker_start(const char *file_name);
void leak_checker_set_limit(off_t limit);
void leak_checker_stop(void);
void leak_checker_claim(const void *);
void leak_checker_usage(void);

#endif /* leak-checker.h */

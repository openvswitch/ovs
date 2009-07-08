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

#ifndef FATAL_SIGNAL_H
#define FATAL_SIGNAL_H 1

#include <stdbool.h>

/* Basic interface. */
void fatal_signal_add_hook(void (*)(void *aux), void *aux, bool run_at_exit);
void fatal_signal_block(void);
void fatal_signal_unblock(void);
void fatal_signal_fork(void);

/* Convenience functions for unlinking files upon termination.
 *
 * These functions also unlink the files upon normal process termination via
 * exit(). */
void fatal_signal_add_file_to_unlink(const char *);
void fatal_signal_remove_file_to_unlink(const char *);

/* Interface for other code that catches one of our signals and needs to pass
 * it through. */
void fatal_signal_handler(int sig_nr);

#endif /* fatal-signal.h */

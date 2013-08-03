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

#ifndef ASYNC_APPEND_H
#define ASYNC_APPEND_H 1

#include <stddef.h>

/* This module defines a simple, abstract interface to asynchronous file I/O.
 * It is currently used only for logging.  Thus, for now the interface only
 * supports appending to a file.  Multiple implementations are possible
 * depending on the operating system's degree and form of support for
 * asynchronous I/O.
 *
 * The comments below document the requirements on any implementation.
 *
 * Thread-safety
 * =============
 *
 * Only a single thread may use a given 'struct async_append' at one time.
 */

/* Creates and returns a new asynchronous appender for file descriptor 'fd',
 * which the caller must have opened in append mode (O_APPEND).  If the system
 * is for some reason unable to support asynchronous I/O on 'fd' this function
 * may return NULL. */
struct async_append *async_append_create(int fd);

/* Destroys 'ap', without closing its underlying file descriptor. */
void async_append_destroy(struct async_append *ap);

/* Appends the 'size' bytes of 'data' to 'ap', asynchronously if possible. */
void async_append_write(struct async_append *ap,
                        const void *data, size_t size);

/* Blocks until all data asynchronously written to 'ap' with
 * async_append_write() has been committed to the point that it will be written
 * to disk barring an operating system or hardware failure. */
void async_append_flush(struct async_append *ap);

#endif /* async-append.h */

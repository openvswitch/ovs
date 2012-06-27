/* Copyright (c) 2012 Nicira, Inc.
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

#ifndef WORKER_H
#define WORKER_H 1

/* Worker processes.
 *
 * Thes functions allow an OVS daemon to fork off a "worker process" to do
 * tasks that may unavoidably block in the kernel.  The worker executes remote
 * procedure calls on behalf of the main process.
 *
 * Tasks that may unavoidably block in the kernel include writes to regular
 * files, sends to Generic Netlink sockets (which as of this writing use a
 * global lock), and other unusual operations.
 *
 * The worker functions *will* block if the finite buffer between a main
 * process and its worker process fills up.
 */

#include <stdbool.h>
#include <stddef.h>
#include "compiler.h"

struct iovec;
struct ofpbuf;

/* The main process calls this function to start a worker. */
void worker_start(void);

/* Interface for main process to interact with the worker. */
typedef void worker_request_func(struct ofpbuf *request,
                                 const int fds[], size_t n_fds);
typedef void worker_reply_func(struct ofpbuf *reply,
                               const int fds[], size_t n_fds, void *aux);

bool worker_is_running(void);
void worker_run(void);
void worker_wait(void);

void worker_request(const void *data, size_t size,
                    const int fds[], size_t n_fds,
                    worker_request_func *request_cb,
                    worker_reply_func *reply_cb, void *aux);
void worker_request_iovec(const struct iovec *iovs, size_t n_iovs,
                          const int fds[], size_t n_fds,
                          worker_request_func *request_cb,
                          worker_reply_func *reply_cb, void *aux);

/* Interfaces for RPC implementations (running in the worker process). */
void worker_reply(const void *data, size_t size,
                  const int fds[], size_t n_fds);
void worker_reply_iovec(const struct iovec *iovs, size_t n_iovs,
                        const int fds[], size_t n_fds);

#endif /* worker.h */

/* Copyright (c) 2012, 2013 Nicira, Inc.
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

#include "worker.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "command-line.h"
#include "daemon.h"
#include "ofpbuf.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(worker);

/* Header for an RPC request. */
struct worker_request {
    size_t request_len;              /* Length of the payload in bytes. */
    worker_request_func *request_cb; /* Function to call in worker process. */
    worker_reply_func *reply_cb;     /* Function to call in main process. */
    void *reply_aux;                 /* Auxiliary data for 'reply_cb'. */
};

/* Header for an RPC reply. */
struct worker_reply {
    size_t reply_len;            /* Length of the payload in bytes. */
    worker_reply_func *reply_cb; /* Function to call in main process. */
    void *reply_aux;             /* Auxiliary data for 'reply_cb'. */
};

/* Receive buffer for a RPC request or reply. */
struct rxbuf {
    /* Header. */
    struct ofpbuf header;       /* Header data. */
    int fds[SOUTIL_MAX_FDS];    /* File descriptors. */
    size_t n_fds;

    /* Payload. */
    struct ofpbuf payload;      /* Payload data. */
};

static int client_sock = -1;
static struct rxbuf client_rx;

static void rxbuf_init(struct rxbuf *);
static void rxbuf_clear(struct rxbuf *);
static int rxbuf_run(struct rxbuf *, int sock, size_t header_len);

static struct iovec *prefix_iov(void *data, size_t len,
                                const struct iovec *iovs, size_t n_iovs);

static void worker_broke(void);

static void worker_main(int fd) NO_RETURN;

/* Starts a worker process as a subprocess of the current process.  Currently
 * only a single worker process is supported, so this function may only be
 * called once.
 *
 * The client should call worker_run() and worker_wait() from its main loop.
 *
 * Call this function between daemonize_start() and daemonize_complete(). */
void
worker_start(void)
{
    int work_fds[2];

    assert(client_sock < 0);

    /* Create non-blocking socket pair. */
    xsocketpair(AF_UNIX, SOCK_STREAM, 0, work_fds);
    xset_nonblocking(work_fds[0]);
    xset_nonblocking(work_fds[1]);

    if (!fork_and_clean_up()) {
        /* In child (worker) process. */
        daemonize_post_detach();
        close(work_fds[0]);
        worker_main(work_fds[1]);
        NOT_REACHED();
    }

    /* In parent (main) process. */
    close(work_fds[1]);
    client_sock = work_fds[0];
    rxbuf_init(&client_rx);
}

/* Returns true if this process has started a worker and the worker is not
 * known to have malfunctioned. */
bool
worker_is_running(void)
{
    return client_sock >= 0;
}

/* If a worker process was started, processes RPC replies from it, calling the
 * registered 'reply_cb' callbacks.
 *
 * If the worker process died or malfunctioned, aborts. */
void
worker_run(void)
{
    if (worker_is_running()) {
        int error;

        error = rxbuf_run(&client_rx, client_sock,
                          sizeof(struct worker_reply));
        if (!error) {
            struct worker_reply *reply = client_rx.header.data;
            reply->reply_cb(&client_rx.payload, client_rx.fds,
                            client_rx.n_fds, reply->reply_aux);
            rxbuf_clear(&client_rx);
        } else if (error != EAGAIN) {
            worker_broke();
            VLOG_ABORT("receive from worker failed (%s)",
                       ovs_retval_to_string(error));
        }
    }
}

/* Causes the poll loop to wake up if we need to process RPC replies. */
void
worker_wait(void)
{
    if (worker_is_running()) {
        poll_fd_wait(client_sock, POLLIN);
    }
}

/* Interface for main process to interact with the worker. */

/* Sends an RPC request to the worker process.  The worker process will call
 * 'request_cb' passing the 'size' (zero or more) bytes of data in 'data' as
 * arguments as well as the 'n_fds' (SOUTIL_MAX_FDS or fewer) file descriptors
 * in 'fds'.
 *
 * If and only if 'reply_cb' is nonnull, 'request_cb' must call worker_reply()
 * or worker_reply_iovec() with a reply.  The main process will later call
 * 'reply_cb' with the reply data (if any) and file descriptors (if any).
 *
 * 'request_cb' receives copies (as if by dup()) of the file descriptors in
 * fds[].  'request_cb' takes ownership of these copies, and the caller of
 * worker_request() retains its ownership of the originals.
 *
 * This function may block until the RPC request has been sent (if the socket
 * buffer fills up) but it does not wait for the reply (if any).  If this
 * function blocks, it may invoke reply callbacks for previous requests.
 *
 * The worker process executes RPC requests in strict order of submission and
 * runs each request to completion before beginning the next request.  The main
 * process invokes reply callbacks in strict order of request submission. */
void
worker_request(const void *data, size_t size,
               const int fds[], size_t n_fds,
               worker_request_func *request_cb,
               worker_reply_func *reply_cb, void *aux)
{
    if (size > 0) {
        struct iovec iov;

        iov.iov_base = (void *) data;
        iov.iov_len = size;
        worker_request_iovec(&iov, 1, fds, n_fds, request_cb, reply_cb, aux);
    } else {
        worker_request_iovec(NULL, 0, fds, n_fds, request_cb, reply_cb, aux);
    }
}

static int
worker_send_iovec(const struct iovec iovs[], size_t n_iovs,
                  const int fds[], size_t n_fds)
{
    size_t sent = 0;

    for (;;) {
        struct pollfd pfd;
        int error;

        /* Try to send the rest of the request. */
        error = send_iovec_and_fds_fully(client_sock, iovs, n_iovs,
                                         fds, n_fds, sent, &sent);
        if (error != EAGAIN) {
            return error;
        }

        /* Process replies to avoid deadlock. */
        worker_run();

        /* Wait for 'client_sock' to become ready before trying again.  We
         * can't use poll_block() because it sometimes calls into vlog, which
         * calls indirectly into worker_send_iovec().  To be usable here,
         * poll_block() would therefore need to be reentrant, but it isn't
         * (calling it recursively causes memory corruption and an eventual
         * crash). */
        pfd.fd = client_sock;
        pfd.events = POLLIN | POLLOUT;
        do {
            error = poll(&pfd, 1, -1) < 0 ? errno : 0;
        } while (error == EINTR);
        if (error) {
            worker_broke();
            VLOG_ABORT("poll failed (%s)", strerror(error));
        }
    }
}

/* Same as worker_request() except that the data to send is specified as an
 * array of iovecs. */
void
worker_request_iovec(const struct iovec iovs[], size_t n_iovs,
                     const int fds[], size_t n_fds,
                     worker_request_func *request_cb,
                     worker_reply_func *reply_cb, void *aux)
{
    struct worker_request rq;
    struct iovec *all_iovs;
    int error;

    assert(worker_is_running());

    rq.request_len = iovec_len(iovs, n_iovs);
    rq.request_cb = request_cb;
    rq.reply_cb = reply_cb;
    rq.reply_aux = aux;

    all_iovs = prefix_iov(&rq, sizeof rq, iovs, n_iovs);
    error = worker_send_iovec(all_iovs, n_iovs + 1, fds, n_fds);
    if (error) {
        worker_broke();
        VLOG_ABORT("send failed (%s)", strerror(error));
    }
    free(all_iovs);
}

/* Closes the client socket, if any, so that worker_is_running() will return
 * false.
 *
 * The client does this just before aborting if the worker process dies or
 * malfunctions, to prevent the logging subsystem from trying to use the
 * worker to log the failure. */
static void
worker_broke(void)
{
    if (client_sock >= 0) {
        close(client_sock);
        client_sock = -1;
    }
}

/* Interfaces for RPC implementations (running in the worker process). */

static int server_sock = -1;
static bool expect_reply;
static struct worker_request request;

/* When a call to worker_request() or worker_request_iovec() provides a
 * 'reply_cb' callback, the 'request_cb' implementation must call this function
 * to send its reply.  The main process will call 'reply_cb' passing the
 * 'size' (zero or more) bytes of data in 'data' as arguments as well as the
 * 'n_fds' (SOUTIL_MAX_FDS or fewer) file descriptors in 'fds'.
 *
 * If a call to worker_request() or worker_request_iovec() provides no
 * 'reply_cb' callback, the 'request_cb' implementation must not call this
 * function.
 *
 * 'reply_cb' receives copies (as if by dup()) of the file descriptors in
 * fds[].  'reply_cb' takes ownership of these copies, and the caller of
 * worker_reply() retains its ownership of the originals.
 *
 * This function blocks until the RPC reply has been sent (if the socket buffer
 * fills up) but it does not wait for the main process to receive or to process
 * the reply. */
void
worker_reply(const void *data, size_t size, const int fds[], size_t n_fds)
{
    if (size > 0) {
        struct iovec iov;

        iov.iov_base = (void *) data;
        iov.iov_len = size;
        worker_reply_iovec(&iov, 1, fds, n_fds);
    } else {
        worker_reply_iovec(NULL, 0, fds, n_fds);
    }
}

/* Same as worker_reply() except that the data to send is specified as an array
 * of iovecs. */
void
worker_reply_iovec(const struct iovec *iovs, size_t n_iovs,
                       const int fds[], size_t n_fds)
{
    struct worker_reply reply;
    struct iovec *all_iovs;
    int error;

    assert(expect_reply);
    expect_reply = false;

    reply.reply_len = iovec_len(iovs, n_iovs);
    reply.reply_cb = request.reply_cb;
    reply.reply_aux = request.reply_aux;

    all_iovs = prefix_iov(&reply, sizeof reply, iovs, n_iovs);

    error = send_iovec_and_fds_fully_block(server_sock, all_iovs, n_iovs + 1,
                                           fds, n_fds);
    if (error == EPIPE) {
        /* Parent probably died.  Continue processing any RPCs still buffered,
         * to avoid missing log messages. */
        VLOG_INFO("send failed (%s)", strerror(error));
    } else if (error) {
        VLOG_FATAL("send failed (%s)", strerror(error));
    }

    free(all_iovs);
}

static void
worker_main(int fd)
{
    struct rxbuf rx;

    server_sock = fd;

    subprogram_name = "worker";
    proctitle_set("worker process for pid %lu", (unsigned long int) getppid());
    VLOG_INFO("worker process started");

    rxbuf_init(&rx);
    for (;;) {
        int error;

        error = rxbuf_run(&rx, server_sock, sizeof(struct worker_request));
        if (!error) {
            request = *(struct worker_request *) rx.header.data;

            expect_reply = request.reply_cb != NULL;
            request.request_cb(&rx.payload, rx.fds, rx.n_fds);
            assert(!expect_reply);

            rxbuf_clear(&rx);
        } else if (error == EOF && !rx.header.size) {
            /* Main process closed the IPC socket.  Exit cleanly. */
            break;
        } else if (error != EAGAIN) {
            VLOG_FATAL("RPC receive failed (%s)", strerror(error));
        }

        poll_fd_wait(server_sock, POLLIN);
        poll_block();
    }

    VLOG_INFO("worker process exiting");
    exit(0);
}

static void
rxbuf_init(struct rxbuf *rx)
{
    ofpbuf_init(&rx->header, 0);
    rx->n_fds = 0;
    ofpbuf_init(&rx->payload, 0);
}

static void
rxbuf_clear(struct rxbuf *rx)
{
    ofpbuf_clear(&rx->header);
    rx->n_fds = 0;
    ofpbuf_clear(&rx->payload);
}

static int
rxbuf_run(struct rxbuf *rx, int sock, size_t header_len)
{
    for (;;) {
        if (!rx->header.size) {
            int retval;

            ofpbuf_clear(&rx->header);
            ofpbuf_prealloc_tailroom(&rx->header, header_len);

            retval = recv_data_and_fds(sock, rx->header.data, header_len,
                                       rx->fds, &rx->n_fds);
            if (retval <= 0) {
                return retval ? -retval : EOF;
            }
            rx->header.size += retval;
        } else if (rx->header.size < header_len) {
            size_t bytes_read;
            int error;

            error = read_fully(sock, ofpbuf_tail(&rx->header),
                               header_len - rx->header.size, &bytes_read);
            rx->header.size += bytes_read;
            if (error) {
                return error;
            }
        } else {
            size_t payload_len = *(size_t *) rx->header.data;

            if (rx->payload.size < payload_len) {
                size_t left = payload_len - rx->payload.size;
                size_t bytes_read;
                int error;

                ofpbuf_prealloc_tailroom(&rx->payload, left);
                error = read_fully(sock, ofpbuf_tail(&rx->payload), left,
                                   &bytes_read);
                rx->payload.size += bytes_read;
                if (error) {
                    return error;
                }
            } else {
                return 0;
            }
        }
    }

    return EAGAIN;
}

static struct iovec *
prefix_iov(void *data, size_t len, const struct iovec *iovs, size_t n_iovs)
{
    struct iovec *dst;

    dst = xmalloc((n_iovs + 1) * sizeof *dst);
    dst[0].iov_base = data;
    dst[0].iov_len = len;
    memcpy(dst + 1, iovs, n_iovs * sizeof *iovs);

    return dst;
}

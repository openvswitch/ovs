/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

#include <config.h>
#include "executer.h"
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "openflow/nicira-ext.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "rconn.h"
#include "secchan.h"
#include "socket-util.h"
#include "util.h"
#include "vconn.h"

#define THIS_MODULE VLM_executer
#include "vlog.h"

#define MAX_CHILDREN 8

struct child {
    /* Information about child process. */
    char *name;                 /* argv[0] passed to child. */
    pid_t pid;                  /* Child's process ID. */

    /* For sending a reply to the controller when the child dies. */
    struct relay *relay;
    uint32_t xid;               /* Transaction ID used by controller. */

    /* We read up to MAX_OUTPUT bytes of output and send them back to the
     * controller when the child dies. */
#define MAX_OUTPUT 4096
    int output_fd;              /* FD from which to read child's output. */
    uint8_t *output;            /* Output data. */
    size_t output_size;         /* Number of bytes of output data so far. */
};

struct executer {
    const struct settings *s;

    /* Children. */
    struct child children[MAX_CHILDREN];
    size_t n_children;

    /* File descriptors. */
    int wait_fd;                /* Pipe FD for wakeup when on SIGCHLD. */
    int null_fd;                /* FD for /dev/null. */
};

static void send_child_status(struct relay *, uint32_t xid, uint32_t status,
                              const void *data, size_t size);
static void send_child_message(struct relay *, uint32_t xid, uint32_t status,
                               const char *message);

/* Returns true if 'cmd' is allowed by 'acl', which is a command-separated
 * access control list in the format described for --command-acl in
 * secchan(8). */
static bool
executer_is_permitted(const char *acl_, const char *cmd)
{
    char *acl, *save_ptr, *pattern;
    bool allowed, denied;

    /* Verify that 'cmd' consists only of alphanumerics plus _ or -. */
    if (cmd[strspn(cmd, "abcdefghijklmnopqrstuvwxyz"
                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")] != '\0') {
        VLOG_WARN("rejecting command name \"%s\" that contain forbidden "
                  "characters", cmd);
        return false;
    }

    /* Check 'cmd' against 'acl'. */
    acl = xstrdup(acl_);
    save_ptr = acl;
    allowed = denied = false;
    while ((pattern = strsep(&save_ptr, ",")) != NULL && !denied) {
        if (pattern[0] != '!' && !fnmatch(pattern, cmd, 0)) {
            allowed = true;
        } else if (pattern[0] == '!' && !fnmatch(pattern + 1, cmd, 0)) {
            denied = true;
        }
    }
    free(acl);

    /* Check the command white/blacklisted state. */
    if (allowed && !denied) {
        VLOG_WARN("permitting command execution: \"%s\" is whitelisted", cmd);
    } else if (allowed && denied) {
        VLOG_WARN("denying command execution: \"%s\" is both blacklisted "
                  "and whitelisted", cmd);
    } else if (!allowed) {
        VLOG_WARN("denying command execution: \"%s\" is not whitelisted", cmd);
    } else if (denied) {
        VLOG_WARN("denying command execution: \"%s\" is blacklisted", cmd);
    }
    return allowed && !denied;
}

static bool
executer_remote_packet_cb(struct relay *r, void *e_)
{
    struct executer *e = e_;
    struct ofpbuf *msg = r->halves[HALF_REMOTE].rxbuf;
    struct nicira_header *request;
    char **argv;
    char *args;
    char *exec_file = NULL;
    int max_fds;
    struct stat s;
    size_t args_size;
    size_t argc;
    size_t i;
    pid_t pid;
    int output_fds[2];

    /* Check for NXT_COMMAND_REQUEST vendor extension. */
    if (msg->size < sizeof(struct nicira_header)) {
        return false;
    }
    request = msg->data;
    if (request->header.type != OFPT_VENDOR
        || request->vendor != htonl(NX_VENDOR_ID)
        || request->subtype != htonl(NXT_COMMAND_REQUEST)) {
        return false;
    }

    /* Verify limit on children not exceeded.
     * XXX should probably kill children when the connection drops? */
    if (e->n_children >= MAX_CHILDREN) {
        send_child_message(r, request->header.xid, NXT_STATUS_ERROR,
                           "too many child processes");
        VLOG_WARN("limit of %d child processes reached, dropping request",
                  MAX_CHILDREN);
        return false;
    }

    /* Copy argument buffer, adding a null terminator at the end.  Now every
     * argument is null-terminated, instead of being merely null-delimited. */
    args_size = msg->size - sizeof *request;
    args = xmemdup0((const void *) (request + 1), args_size);

    /* Count arguments. */
    argc = 0;
    for (i = 0; i <= args_size; i++) {
        argc += args[i] == '\0';
    }

    /* Set argv[*] to point to each argument. */
    argv = xmalloc((argc + 1) * sizeof *argv);
    argv[0] = args;
    for (i = 1; i < argc; i++) {
        argv[i] = strchr(argv[i - 1], '\0') + 1;
    }
    argv[argc] = NULL;

    /* Check permissions. */
    if (!executer_is_permitted(e->s->command_acl, argv[0])) {
        send_child_message(r, request->header.xid, NXT_STATUS_ERROR,
                           "command not allowed");
        goto done;
    }

    /* Find the executable. */
    exec_file = xasprintf("%s/%s", e->s->command_dir, argv[0]);
    if (stat(exec_file, &s)) {
        VLOG_WARN("failed to stat \"%s\": %s", exec_file, strerror(errno));
        send_child_message(r, request->header.xid, NXT_STATUS_ERROR,
                           "command not allowed");
        goto done;
    }
    if (!S_ISREG(s.st_mode)) {
        VLOG_WARN("\"%s\" is not a regular file", exec_file);
        send_child_message(r, request->header.xid, NXT_STATUS_ERROR,
                           "command not allowed");
        goto done;
    }
    argv[0] = exec_file;

    /* Arrange to capture output. */
    if (pipe(output_fds)) {
        VLOG_WARN("pipe failed: %s", strerror(errno));
        send_child_message(r, request->header.xid, NXT_STATUS_ERROR,
                           "internal error (pipe)");
        goto done;
    }

    pid = fork();
    if (!pid) {
        /* Running in child.
         * XXX should run in new process group so that we can signal all
         * subprocesses at once?  Would also want to catch fatal signals and
         * kill them at the same time though. */
        fatal_signal_fork();
        dup2(e->null_fd, 0);
        dup2(output_fds[1], 1);
        dup2(e->null_fd, 2);
        max_fds = get_max_fds();
        for (i = 3; i < max_fds; i++) {
            close(i);
        }
        if (chdir(e->s->command_dir)) {
            printf("could not change directory to \"%s\": %s",
                   e->s->command_dir, strerror(errno));
            exit(EXIT_FAILURE);
        }
        execv(argv[0], argv);
        printf("failed to start \"%s\": %s\n", argv[0], strerror(errno));
        exit(EXIT_FAILURE);
    } else if (pid > 0) {
        /* Running in parent. */
        struct child *child;

        VLOG_WARN("started \"%s\" subprocess", argv[0]);
        send_child_status(r, request->header.xid, NXT_STATUS_STARTED, NULL, 0);
        child = &e->children[e->n_children++];
        child->name = xstrdup(argv[0]);
        child->pid = pid;
        child->relay = r;
        child->xid = request->header.xid;
        child->output_fd = output_fds[0];
        child->output = xmalloc(MAX_OUTPUT);
        child->output_size = 0;
        set_nonblocking(output_fds[0]);
        close(output_fds[1]);
    } else {
        VLOG_WARN("fork failed: %s", strerror(errno));
        send_child_message(r, request->header.xid, NXT_STATUS_ERROR,
                           "internal error (fork)");
        close(output_fds[0]);
        close(output_fds[1]);
    }

done:
    free(exec_file);
    free(args);
    free(argv);
    return true;
}

static void
send_child_status(struct relay *relay, uint32_t xid, uint32_t status,
                  const void *data, size_t size)
{
    if (relay) {
        struct nx_command_reply *r;
        struct ofpbuf *buffer;

        r = make_openflow_xid(sizeof *r, OFPT_VENDOR, xid, &buffer);
        r->nxh.vendor = htonl(NX_VENDOR_ID);
        r->nxh.subtype = htonl(NXT_COMMAND_REPLY);
        r->status = htonl(status);
        ofpbuf_put(buffer, data, size);
        update_openflow_length(buffer);
        if (rconn_send(relay->halves[HALF_REMOTE].rconn, buffer, NULL)) {
            ofpbuf_delete(buffer);
        }
    }
}

static void
send_child_message(struct relay *relay, uint32_t xid, uint32_t status,
                   const char *message)
{
    send_child_status(relay, xid, status, message, strlen(message));
}

/* 'child' died with 'status' as its return code.  Deal with it. */
static void
child_terminated(struct child *child, int status)
{
    struct ds ds;
    uint32_t ofp_status;

    /* Log how it terminated. */
    ds_init(&ds);
    if (WIFEXITED(status)) {
        ds_put_format(&ds, "normally with status %d", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        const char *name = NULL;
#ifdef HAVE_STRSIGNAL
        name = strsignal(WTERMSIG(status));
#endif
        ds_put_format(&ds, "by signal %d", WTERMSIG(status));
        if (name) {
            ds_put_format(&ds, " (%s)", name);
        }
    }
    if (WCOREDUMP(status)) {
        ds_put_cstr(&ds, " (core dumped)");
    }
    VLOG_WARN("child process \"%s\" with pid %ld terminated %s",
              child->name, (long int) child->pid, ds_cstr(&ds));
    ds_destroy(&ds);

    /* Send a status message back to the controller that requested the
     * command. */
    if (WIFEXITED(status)) {
        ofp_status = WEXITSTATUS(status) | NXT_STATUS_EXITED;
    } else if (WIFSIGNALED(status)) {
        ofp_status = WTERMSIG(status) | NXT_STATUS_SIGNALED;
    } else {
        ofp_status = NXT_STATUS_UNKNOWN;
    }
    if (WCOREDUMP(status)) {
        ofp_status |= NXT_STATUS_COREDUMP;
    }
    send_child_status(child->relay, child->xid, ofp_status,
                      child->output, child->output_size);
}

/* Read output from 'child' and append it to its output buffer. */
static void
poll_child(struct child *child)
{
    ssize_t n;

    if (child->output_fd < 0) {
        return;
    }

    do {
        n = read(child->output_fd, child->output + child->output_size,
                 MAX_OUTPUT - child->output_size);
    } while (n < 0 && errno == EINTR);
    if (n > 0) {
        child->output_size += n;
        if (child->output_size < MAX_OUTPUT) {
            return;
        }
    } else if (n < 0 && errno == EAGAIN) {
        return;
    }
    close(child->output_fd);
    child->output_fd = -1;
}

static void
executer_periodic_cb(void *e_)
{
    struct executer *e = e_;
    char buffer[MAX_CHILDREN];
    size_t i;

    if (!e->n_children) {
        return;
    }

    /* Read output from children. */
    for (i = 0; i < e->n_children; i++) {
        struct child *child = &e->children[i];
        poll_child(child);
    }

    /* If SIGCHLD was received, reap dead children. */
    if (read(e->wait_fd, buffer, sizeof buffer) <= 0) {
        return;
    }
    for (;;) {
        int status;
        pid_t pid;

        /* Get dead child in 'pid' and its return code in 'status'. */
        pid = waitpid(WAIT_ANY, &status, WNOHANG);
        if (pid < 0 && errno == EINTR) {
            continue;
        } else if (pid <= 0) {
            return;
        }

        /* Find child with given 'pid' and drop it from the list. */
        for (i = 0; i < e->n_children; i++) {
            struct child *child = &e->children[i];
            if (child->pid == pid) {
                poll_child(child);
                child_terminated(child, status);
                free(child->name);
                free(child->output);
                *child = e->children[--e->n_children];
                goto found;
            }
        }
        VLOG_WARN("child with unknown pid %ld terminated", (long int) pid);
    found:;
    }

}

static void
executer_wait_cb(void *e_)
{
    struct executer *e = e_;
    if (e->n_children) {
        size_t i;

        /* Wake up on SIGCHLD. */
        poll_fd_wait(e->wait_fd, POLLIN);

        /* Wake up when we get output from a child. */
        for (i = 0; i < e->n_children; i++) {
            struct child *child = &e->children[i];
            if (child->output_fd >= 0) {
                poll_fd_wait(e->wait_fd, POLLIN);
            }
        }
    }
}

static void
executer_closing_cb(struct relay *r, void *e_)
{
    struct executer *e = e_;
    size_t i;

    /* If any of our children was connected to 'r', then disconnect it so we
     * don't try to reference a dead connection when the process terminates
     * later.
     * XXX kill the children started by 'r'? */
    for (i = 0; i < e->n_children; i++) {
        if (e->children[i].relay == r) {
            e->children[i].relay = NULL;
        }
    }
}

static int child_fd;

static void
sigchld_handler(int signr UNUSED)
{
    write(child_fd, "", 1);
}

static struct hook_class executer_hook_class = {
    NULL,                       /* local_packet_cb */
    executer_remote_packet_cb,  /* remote_packet_cb */
    executer_periodic_cb,       /* periodic_cb */
    executer_wait_cb,           /* wait_cb */
    executer_closing_cb,        /* closing_cb */
};

void
executer_start(struct secchan *secchan, const struct settings *settings)
{
    struct executer *e;
    struct sigaction sa;
    int fds[2], null_fd;

    /* Create pipe for notifying us that SIGCHLD was invoked. */
    if (pipe(fds)) {
        ofp_fatal(errno, "pipe failed");
    }
    set_nonblocking(fds[0]);
    set_nonblocking(fds[1]);
    child_fd = fds[1];

    /* Open /dev/null. */
    null_fd = open("/dev/null", O_RDWR);
    if (null_fd < 0) {
        ofp_fatal(errno, "could not open /dev/null");
    }

    /* Set up signal handler. */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NOCLDSTOP | SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL)) {
        ofp_fatal(errno, "sigaction(SIGCHLD) failed");
    }

    /* Add hook. */
    e = xcalloc(1, sizeof *e);
    e->s = settings;
    e->n_children = 0;
    e->wait_fd = fds[0];
    e->null_fd = null_fd;
    add_hook(secchan, &executer_hook_class, e);
}

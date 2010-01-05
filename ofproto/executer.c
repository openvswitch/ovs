/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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
#include "dirs.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "openflow/nicira-ext.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "rconn.h"
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
    struct rconn *rconn;
    uint32_t xid;               /* Transaction ID used by controller. */

    /* We read up to MAX_OUTPUT bytes of output and send them back to the
     * controller when the child dies. */
#define MAX_OUTPUT 4096
    int output_fd;              /* FD from which to read child's output. */
    uint8_t *output;            /* Output data. */
    size_t output_size;         /* Number of bytes of output data so far. */
};

struct executer {
    /* Settings. */
    char *command_acl;          /* Command white/blacklist, as shell globs. */
    char *command_dir;          /* Directory that contains commands. */

    /* Children. */
    struct child children[MAX_CHILDREN];
    size_t n_children;
};

/* File descriptors for waking up when a child dies. */
static int signal_fds[2] = {-1, -1};

static void send_child_status(struct rconn *, uint32_t xid, uint32_t status,
                              const void *data, size_t size);
static void send_child_message(struct rconn *, uint32_t xid, uint32_t status,
                               const char *message);

/* Returns true if 'cmd' is allowed by 'acl', which is a command-separated
 * access control list in the format described for --command-acl in
 * ovs-openflowd(8). */
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
        VLOG_INFO("permitting command execution: \"%s\" is whitelisted", cmd);
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

int
executer_handle_request(struct executer *e, struct rconn *rconn,
                        struct nicira_header *request)
{
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

    /* Verify limit on children not exceeded.
     * XXX should probably kill children when the connection drops? */
    if (e->n_children >= MAX_CHILDREN) {
        send_child_message(rconn, request->header.xid, NXT_STATUS_ERROR,
                           "too many child processes");
        return 0;
    }

    /* Copy argument buffer, adding a null terminator at the end.  Now every
     * argument is null-terminated, instead of being merely null-delimited. */
    args_size = ntohs(request->header.length) - sizeof *request;
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
    if (!executer_is_permitted(e->command_acl, argv[0])) {
        send_child_message(rconn, request->header.xid, NXT_STATUS_ERROR,
                           "command not allowed");
        goto done;
    }

    /* Find the executable. */
    exec_file = xasprintf("%s/%s", e->command_dir, argv[0]);
    if (stat(exec_file, &s)) {
        VLOG_WARN("failed to stat \"%s\": %s", exec_file, strerror(errno));
        send_child_message(rconn, request->header.xid, NXT_STATUS_ERROR,
                           "command not allowed");
        goto done;
    }
    if (!S_ISREG(s.st_mode)) {
        VLOG_WARN("\"%s\" is not a regular file", exec_file);
        send_child_message(rconn, request->header.xid, NXT_STATUS_ERROR,
                           "command not allowed");
        goto done;
    }
    argv[0] = exec_file;

    /* Arrange to capture output. */
    if (pipe(output_fds)) {
        VLOG_WARN("pipe failed: %s", strerror(errno));
        send_child_message(rconn, request->header.xid, NXT_STATUS_ERROR,
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
        dup2(get_null_fd(), 0);
        dup2(output_fds[1], 1);
        dup2(get_null_fd(), 2);
        max_fds = get_max_fds();
        for (i = 3; i < max_fds; i++) {
            close(i);
        }
        if (chdir(e->command_dir)) {
            printf("could not change directory to \"%s\": %s",
                   e->command_dir, strerror(errno));
            exit(EXIT_FAILURE);
        }
        execv(argv[0], argv);
        printf("failed to start \"%s\": %s\n", argv[0], strerror(errno));
        exit(EXIT_FAILURE);
    } else if (pid > 0) {
        /* Running in parent. */
        struct child *child;

        VLOG_INFO("started \"%s\" subprocess", argv[0]);
        send_child_status(rconn, request->header.xid, NXT_STATUS_STARTED,
                          NULL, 0);
        child = &e->children[e->n_children++];
        child->name = xstrdup(argv[0]);
        child->pid = pid;
        child->rconn = rconn;
        child->xid = request->header.xid;
        child->output_fd = output_fds[0];
        child->output = xmalloc(MAX_OUTPUT);
        child->output_size = 0;
        set_nonblocking(output_fds[0]);
        close(output_fds[1]);
    } else {
        VLOG_WARN("fork failed: %s", strerror(errno));
        send_child_message(rconn, request->header.xid, NXT_STATUS_ERROR,
                           "internal error (fork)");
        close(output_fds[0]);
        close(output_fds[1]);
    }

done:
    free(exec_file);
    free(args);
    free(argv);
    return 0;
}

static void
send_child_status(struct rconn *rconn, uint32_t xid, uint32_t status,
                  const void *data, size_t size)
{
    if (rconn) {
        struct nx_command_reply *r;
        struct ofpbuf *buffer;

        r = make_openflow_xid(sizeof *r, OFPT_VENDOR, xid, &buffer);
        r->nxh.vendor = htonl(NX_VENDOR_ID);
        r->nxh.subtype = htonl(NXT_COMMAND_REPLY);
        r->status = htonl(status);
        ofpbuf_put(buffer, data, size);
        update_openflow_length(buffer);
        if (rconn_send(rconn, buffer, NULL)) {
            ofpbuf_delete(buffer);
        }
    }
}

static void
send_child_message(struct rconn *rconn, uint32_t xid, uint32_t status,
                   const char *message)
{
    send_child_status(rconn, xid, status, message, strlen(message));
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
    VLOG_INFO("child process \"%s\" with pid %ld terminated %s",
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
    send_child_status(child->rconn, child->xid, ofp_status,
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

void
executer_run(struct executer *e)
{
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
    if (read(signal_fds[0], buffer, sizeof buffer) <= 0) {
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

void
executer_wait(struct executer *e)
{
    if (e->n_children) {
        size_t i;

        /* Wake up on SIGCHLD. */
        poll_fd_wait(signal_fds[0], POLLIN);

        /* Wake up when we get output from a child. */
        for (i = 0; i < e->n_children; i++) {
            struct child *child = &e->children[i];
            if (child->output_fd >= 0) {
                poll_fd_wait(child->output_fd, POLLIN);
            }
        }
    }
}

void
executer_rconn_closing(struct executer *e, struct rconn *rconn)
{
    size_t i;

    /* If any of our children was connected to 'r', then disconnect it so we
     * don't try to reference a dead connection when the process terminates
     * later.
     * XXX kill the children started by 'r'? */
    for (i = 0; i < e->n_children; i++) {
        if (e->children[i].rconn == rconn) {
            e->children[i].rconn = NULL;
        }
    }
}

static void
sigchld_handler(int signr UNUSED)
{
    write(signal_fds[1], "", 1);
}

int
executer_create(const char *command_acl, const char *command_dir,
                struct executer **executerp)
{
    struct executer *e;
    struct sigaction sa;

    *executerp = NULL;
    if (signal_fds[0] == -1) {
        /* Make sure we can get a fd for /dev/null. */
        int null_fd = get_null_fd();
        if (null_fd < 0) {
            return -null_fd;
        }

        /* Create pipe for notifying us that SIGCHLD was invoked. */
        if (pipe(signal_fds)) {
            VLOG_ERR("pipe failed: %s", strerror(errno));
            return errno;
        }
        set_nonblocking(signal_fds[0]);
        set_nonblocking(signal_fds[1]);
    }

    /* Set up signal handler. */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NOCLDSTOP | SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL)) {
        VLOG_ERR("sigaction(SIGCHLD) failed: %s", strerror(errno));
        return errno;
    }

    e = xcalloc(1, sizeof *e);
    e->command_acl = xstrdup(command_acl);
    e->command_dir = (command_dir
                      ? xstrdup(command_dir)
                      : xasprintf("%s/commands", ovs_pkgdatadir));
    e->n_children = 0;
    *executerp = e;
    return 0;
}

void
executer_destroy(struct executer *e)
{
    if (e) {
        size_t i;

        free(e->command_acl);
        free(e->command_dir);
        for (i = 0; i < e->n_children; i++) {
            struct child *child = &e->children[i];

            free(child->name);
            kill(child->pid, SIGHUP);
            /* We don't own child->rconn. */
            free(child->output);
            free(child);
        }
        free(e);
    }
}

void
executer_set_acl(struct executer *e, const char *acl, const char *dir)
{
    free(e->command_acl);
    e->command_acl = xstrdup(acl);
    free(e->command_dir);
    e->command_dir = (dir
                      ? xstrdup(dir)
                      : xasprintf("%s/commands", ovs_pkgdatadir));
}

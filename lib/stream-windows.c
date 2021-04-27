/*
 * Copyright (c) 2016, 2017 Cloudbase Solutions Srl
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "openvswitch/poll-loop.h"
#include "dirs.h"
#include "fatal-signal.h"
#include "util.h"
#include "stream-provider.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(stream_windows);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 25);

static void maybe_unlink_and_free(char *path);

/* Suggested buffer size at the creation of the named pipe for reading and
 * and writing operations. */
#define BUFSIZE 65000

/* Default prefix of a local named pipe. */
#define LOCAL_PREFIX "\\\\.\\pipe\\"

/* Size of the allowed PSIDs for securing Named Pipe. */
#define ALLOWED_PSIDS_SIZE 3

/* This function has the purpose to remove all the slashes received in s. */
static char *
remove_slashes(char *s)
{
    char *p1, *p2;
    p1 = p2 = s;

    while (*p1) {
        if ((*p1) == '\\' || (*p1) == '/') {
            p1++;
        } else {
            *p2 = *p1;
            p2++;
            p1++;
        }
    }
    *p2 = '\0';
    return s;
}

/* Active named pipe. */
struct windows_stream
{
    struct stream stream;
    HANDLE fd;
    /* Overlapped operations used for reading/writing. */
    OVERLAPPED read;
    OVERLAPPED write;
    /* Flag to check if a reading/writing operation is pending. */
    bool read_pending;
    bool write_pending;
    /* Flag to check if fd is a server HANDLE.  In the case of a server handle
     * we have to issue a disconnect before closing the actual handle. */
    bool server;
    bool retry_connect;
    char *pipe_path;
};

static struct windows_stream *
stream_windows_cast(struct stream *stream)
{
    stream_assert_class(stream, &windows_stream_class);
    return CONTAINER_OF(stream, struct windows_stream, stream);
}

static HANDLE
create_snpipe(char *path)
{
    return CreateFile(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                      OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED |
                      FILE_FLAG_NO_BUFFERING,
                      NULL);
}

/* Active named pipe open. */
static int
windows_open(const char *name, char *suffix, struct stream **streamp,
             uint8_t dscp OVS_UNUSED)
{
    char *connect_path;
    HANDLE npipe;
    DWORD mode = PIPE_READMODE_BYTE;
    char *path;
    FILE *file;
    bool retry = false;
    /* If the path does not contain a ':', assume it is relative to
     * OVS_RUNDIR. */
    if (!strchr(suffix, ':')) {
        path = xasprintf("%s/%s", ovs_rundir(), suffix);
    } else {
        path = xstrdup(suffix);
    }

    /* In case of "unix:" argument, the assumption is that there is a file
     * created in the path (name). */
    file = fopen(path, "r");
    if (!file) {
        free(path);
        VLOG_DBG_RL(&rl, "%s: could not open %s (%s)", name, suffix,
                    ovs_strerror(errno));
        return ENOENT;
    } else {
        fclose(file);
    }

    /* Valid pipe names do not have slashes.  The assumption is that the named
     * pipe was created with the name "path", with slashes removed and the
     * default prefix \\.\pipe\ appended.
     * Strip the slashes from the parameter name and append the default prefix.
     */
    connect_path = xasprintf("%s%s", LOCAL_PREFIX, remove_slashes(path));
    free(path);

    /* Try to connect to the named pipe.  In case all pipe instances are
     * busy we set the retry flag to true and retry again during the
     * connect function.  Use overlapped flag and file no buffering to ensure
     * asynchronous operations. */
    npipe = create_snpipe(connect_path);

    if (npipe == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY) {
        retry = true;
    }

    if (!retry && npipe == INVALID_HANDLE_VALUE) {
        VLOG_ERR_RL(&rl, "Could not connect to named pipe: %s",
                    ovs_lasterror_to_string());
        free(connect_path);
        return ENOENT;
    }
    if (!retry && !SetNamedPipeHandleState(npipe, &mode, NULL, NULL)) {
        VLOG_ERR_RL(&rl, "Could not set named pipe options: %s",
                    ovs_lasterror_to_string());
        free(connect_path);
        CloseHandle(npipe);
        return ENOENT;
    }
    struct windows_stream *s = xmalloc(sizeof *s);
    stream_init(&s->stream, &windows_stream_class, 0, xstrdup(name));
    s->pipe_path = connect_path;
    s->fd = npipe;
    /* This is an active stream. */
    s->server = false;
    /* Create events for reading and writing to be signaled later. */
    memset(&s->read, 0, sizeof(s->read));
    memset(&s->write, 0, sizeof(s->write));
    s->read.hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
    s->write.hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
    /* Initial read and write operations are not pending. */
    s->read_pending = false;
    s->write_pending = false;
    s->retry_connect = retry;
    *streamp = &s->stream;
    return 0;
}

/* Active named pipe close. */
static void
windows_close(struct stream *stream)
{
    struct windows_stream *s = stream_windows_cast(stream);
    /* Disconnect the named pipe in case it was created from a passive stream.
     */
    if (s->server) {
        /* Flush the pipe to allow the client to read the pipe's contents
         * before disconnecting. */
        FlushFileBuffers(s->fd);
        DisconnectNamedPipe(s->fd);
    }
    CloseHandle(s->fd);
    CloseHandle(s->read.hEvent);
    CloseHandle(s->write.hEvent);
    if (s->pipe_path) {
        free(s->pipe_path);
    }
    free(s);
}

/* Active named pipe connect. */
static int
windows_connect(struct stream *stream)
{
    struct windows_stream *s = stream_windows_cast(stream);

    if (!s->retry_connect) {
        return 0;
    } else {
        HANDLE npipe;
        npipe = create_snpipe(s->pipe_path);
        if (npipe == INVALID_HANDLE_VALUE) {
            if (GetLastError() == ERROR_PIPE_BUSY) {
                return EAGAIN;
            } else {
                s->retry_connect = false;
                return ENOENT;
            }
        }
        s->retry_connect = false;
        s->fd = npipe;
        return 0;
    }
}

/* Active named pipe receive. */
static ssize_t
windows_recv(struct stream *stream, void *buffer, size_t n)
{
    struct windows_stream *s = stream_windows_cast(stream);
    ssize_t retval = 0;
    boolean result = false;
    DWORD last_error = 0;
    LPOVERLAPPED  ov = NULL;
    ov = &s->read;

    /* If the read operation was pending, we verify its result. */
    if (s->read_pending) {
        if (!GetOverlappedResult(s->fd, ov, &(DWORD)retval, FALSE)) {
            last_error = GetLastError();
            if (last_error == ERROR_IO_INCOMPLETE) {
                /* If the operation is still pending, retry again. */
                s->read_pending = true;
                return -EAGAIN;
            } else if (last_error == ERROR_PIPE_NOT_CONNECTED
                       || last_error == ERROR_BAD_PIPE
                       || last_error == ERROR_NO_DATA
                       || last_error == ERROR_BROKEN_PIPE) {
                /* If the pipe was disconnected, return 0. */
                return 0;
            } else {
                VLOG_ERR_RL(&rl, "Could not receive data on named pipe. Last "
                            "error: %s", ovs_lasterror_to_string());
                return -EINVAL;
            }
        }
        s->read_pending = false;
        return retval;
    }

    result = ReadFile(s->fd, buffer, n, &(DWORD)retval, ov);

    if (!result && GetLastError() == ERROR_IO_PENDING) {
        /* Mark the read operation as pending. */
        s->read_pending = true;
        return -EAGAIN;
    } else if (!result) {
        last_error = GetLastError();
        if (last_error == ERROR_PIPE_NOT_CONNECTED
            || last_error == ERROR_BAD_PIPE
            || last_error == ERROR_NO_DATA
            || last_error == ERROR_BROKEN_PIPE) {
            /* If the pipe was disconnected, return 0. */
            return 0;
        }
        VLOG_ERR_RL(&rl, "Could not receive data synchronous on named pipe."
                    "Last error: %s", ovs_lasterror_to_string());
        return -EINVAL;
    }

    return retval;
}

/* Active named pipe send. */
static ssize_t
windows_send(struct stream *stream, const void *buffer, size_t n)
{
    struct windows_stream *s = stream_windows_cast(stream);
    ssize_t retval = 0;
    boolean result = false;
    DWORD last_error = 0;
    LPOVERLAPPED  ov = NULL;
    ov = &s->write;

    /* If the send operation was pending, we verify the result. */
    if (s->write_pending) {
        if (!GetOverlappedResult(s->fd, ov, &(DWORD)retval, FALSE)) {
            last_error = GetLastError();
            if (last_error == ERROR_IO_INCOMPLETE) {
                /* If the operation is still pending, retry again. */
                s->write_pending = true;
                return -EAGAIN;
            } else if (last_error == ERROR_PIPE_NOT_CONNECTED
                       || last_error == ERROR_BAD_PIPE
                       || last_error == ERROR_NO_DATA
                       || last_error == ERROR_BROKEN_PIPE) {
                /* If the pipe was disconnected, return connection reset. */
                return -EPIPE;
            } else {
                VLOG_ERR_RL(&rl, "Could not send data on named pipe. Last "
                            "error: %s", ovs_lasterror_to_string());
                return -EINVAL;
            }
        }
        s->write_pending = false;
        return retval;
    }

    result = WriteFile(s->fd, buffer, n, &(DWORD)retval, ov);
    last_error = GetLastError();
    if (!result && last_error == ERROR_IO_PENDING) {
        /* Mark the send operation as pending. */
        s->write_pending = true;
        return -EAGAIN;
    } else if (!result && (last_error == ERROR_PIPE_NOT_CONNECTED
                           || last_error == ERROR_BAD_PIPE
                           || last_error == ERROR_NO_DATA
                           || last_error == ERROR_BROKEN_PIPE)) {
        /* If the pipe was disconnected, return connection reset. */
        return -EPIPE;
    } else if (!result) {
        VLOG_ERR_RL(&rl, "Could not send data on synchronous named pipe. Last "
                    "error: %s", ovs_lasterror_to_string());
        return -EINVAL;
    }
    return (retval > 0 ? retval : -EAGAIN);
}

/* Active named pipe wait. */
static void
windows_wait(struct stream *stream, enum stream_wait_type wait)
{
    struct windows_stream *s = stream_windows_cast(stream);
    switch (wait) {
    case STREAM_SEND:
        poll_wevent_wait(s->write.hEvent);
        break;

    case STREAM_CONNECT:
        poll_immediate_wake();
        break;

    case STREAM_RECV:
        poll_wevent_wait(s->read.hEvent);
        break;

    default:
        OVS_NOT_REACHED();
    }
}

/* Passive named pipe. */
const struct stream_class windows_stream_class = {
    "unix",                     /* name */
    false,                      /* needs_probes */
    windows_open,               /* open */
    windows_close,              /* close */
    windows_connect,            /* connect */
    windows_recv,               /* recv */
    windows_send,               /* send */
    NULL,                       /* run */
    NULL,                       /* run_wait */
    windows_wait,               /* wait */
};

struct pwindows_pstream
{
    struct pstream pstream;
    HANDLE fd;
    /* Unlink path to be deleted during close. */
    char *unlink_path;
    /* Overlapped operation used for connect. */
    OVERLAPPED connect;
    /* Flag to check if an operation is pending. */
    bool pending;
    /* String used to create the named pipe. */
    char *pipe_path;
};

const struct pstream_class pwindows_pstream_class;

static struct pwindows_pstream *
pwindows_pstream_cast(struct pstream *pstream)
{
    pstream_assert_class(pstream, &pwindows_pstream_class);
    return CONTAINER_OF(pstream, struct pwindows_pstream, pstream);
}

/* Create a named pipe with read/write access, overlapped, message mode for
 * writing, byte mode for reading and with a maximum of 64 active instances. */
static HANDLE
create_pnpipe(char *name)
{
    SECURITY_ATTRIBUTES sa;
    SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
    DWORD aclSize;
    PSID allowedPsid[ALLOWED_PSIDS_SIZE];
    PSID remoteAccessSid;
    PACL acl = NULL;
    PSECURITY_DESCRIPTOR psd = NULL;
    HANDLE npipe;
    HANDLE hToken = NULL;
    DWORD dwBufSize = 0;
    PTOKEN_USER pTokenUsr = NULL;

    /* Disable access over network. */
    if (!AllocateAndInitializeSid(&sia, 1, SECURITY_NETWORK_RID,
                                  0, 0, 0, 0, 0, 0, 0, &remoteAccessSid)) {
        VLOG_ERR_RL(&rl, "Error creating Remote Access SID.");
        goto handle_error;
    }

    aclSize = sizeof(ACL) + sizeof(ACCESS_DENIED_ACE) +
              GetLengthSid(remoteAccessSid) - sizeof(DWORD);

    /* Allow Windows Services to access the Named Pipe. */
    if (!AllocateAndInitializeSid(&sia, 1, SECURITY_LOCAL_SYSTEM_RID,
                                  0, 0, 0, 0, 0, 0, 0, &allowedPsid[0])) {
        VLOG_ERR_RL(&rl, "Error creating Services SID.");
        goto handle_error;
    }

    /* Allow Administrators to access the Named Pipe. */
    if (!AllocateAndInitializeSid(&sia, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &allowedPsid[1])) {
        VLOG_ERR_RL(&rl, "Error creating Administrator SID.");
        goto handle_error;
    }

    /* Open the access token of calling process */
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        VLOG_ERR_RL(&rl, "Error opening access token of calling process.");
        goto handle_error;
    }

    /* get the buffer size buffer needed for SID */
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufSize);

    pTokenUsr = xmalloc(dwBufSize);
    memset(pTokenUsr, 0, dwBufSize);

    /* Retrieve the token information in a TOKEN_USER structure. */
    if (!GetTokenInformation(hToken, TokenUser, pTokenUsr, dwBufSize,
        &dwBufSize)) {
        VLOG_ERR_RL(&rl, "Error retrieving token information.");
        goto handle_error;
    }
    CloseHandle(hToken);

    if (!IsValidSid(pTokenUsr->User.Sid)) {
        VLOG_ERR_RL(&rl, "Invalid SID.");
        goto handle_error;
    }
    allowedPsid[2] = pTokenUsr->User.Sid;

    for (int i = 0; i < ALLOWED_PSIDS_SIZE; i++) {
        aclSize += sizeof(ACCESS_ALLOWED_ACE) +
                   GetLengthSid(allowedPsid[i]) -
                   sizeof(DWORD);
    }

    acl = xmalloc(aclSize);
    if (!InitializeAcl(acl, aclSize, ACL_REVISION)) {
        VLOG_ERR_RL(&rl, "Error initializing ACL.");
        goto handle_error;
    }

    /* Add denied ACL. */
    if (!AddAccessDeniedAce(acl, ACL_REVISION,
                            GENERIC_ALL, remoteAccessSid)) {
        VLOG_ERR_RL(&rl, "Error adding remote access ACE.");
        goto handle_error;
    }

    /* Add allowed ACLs. */
    for (int i = 0; i < ALLOWED_PSIDS_SIZE; i++) {
        if (!AddAccessAllowedAce(acl, ACL_REVISION,
                                 GENERIC_ALL, allowedPsid[i])) {
            VLOG_ERR_RL(&rl, "Error adding ACE.");
            goto handle_error;
        }
    }

    psd = xmalloc(SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (!InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION)) {
        VLOG_ERR_RL(&rl, "Error initializing Security Descriptor.");
        goto handle_error;
    }

    /* Set DACL. */
    if (!SetSecurityDescriptorDacl(psd, TRUE, acl, FALSE)) {
        VLOG_ERR_RL(&rl, "Error while setting DACL.");
        goto handle_error;
    }

    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = psd;

    if (strlen(name) > 256) {
        VLOG_ERR_RL(&rl, "Named pipe name too long.");
        goto handle_error;
    }

    npipe = CreateNamedPipe(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                            PIPE_TYPE_MESSAGE | PIPE_READMODE_BYTE | PIPE_WAIT,
                            64, BUFSIZE, BUFSIZE, 0, &sa);
    free(pTokenUsr);
    free(acl);
    free(psd);
    return npipe;

handle_error:
    free(pTokenUsr);
    free(acl);
    free(psd);
    return INVALID_HANDLE_VALUE;
}

/* Passive named pipe connect.  This function creates a new named pipe and
 * passes the old handle to the active stream. */
static int
pwindows_accept(struct pstream *pstream, struct stream **new_streamp)
{
    struct pwindows_pstream *p = pwindows_pstream_cast(pstream);
    DWORD last_error = 0;
    DWORD cbRet;
    HANDLE npipe;

    /* If the connect operation was pending, verify the result. */
    if (p->pending) {
        if (!GetOverlappedResult(p->fd, &p->connect, &cbRet, FALSE)) {
            last_error = GetLastError();
            if (last_error == ERROR_IO_INCOMPLETE) {
                /* If the operation is still pending, retry again. */
                p->pending = true;
                return EAGAIN;
            } else {
                VLOG_ERR_RL(&rl, "Could not connect named pipe. Last "
                            "error: %s", ovs_lasterror_to_string());
                DisconnectNamedPipe(p->fd);
                return EINVAL;
            }
        }
        p->pending = false;
    }

    if (!p->pending && !ConnectNamedPipe(p->fd, &p->connect)) {
        last_error = GetLastError();
        if (last_error == ERROR_IO_PENDING) {
            /* Mark the accept operation as pending. */
            p->pending = true;
            return EAGAIN;
        } else if (last_error != ERROR_PIPE_CONNECTED) {
            VLOG_ERR_RL(&rl, "Could not connect synchronous named pipe. Last "
                        "error: %s", ovs_lasterror_to_string());
            DisconnectNamedPipe(p->fd);
            return EINVAL;
        } else {
            /* If the pipe is connected, signal an event. */
            SetEvent(&p->connect.hEvent);
        }
    }

    npipe = create_pnpipe(p->pipe_path);
    if (npipe == INVALID_HANDLE_VALUE) {
        VLOG_ERR_RL(&rl, "Could not create a new named pipe after connect. ",
                    ovs_lasterror_to_string());
        return ENOENT;
    }

    /* Give the handle p->fd to the new created active stream and specify it
     * was created by an active stream. */
    struct windows_stream *p_temp = xmalloc(sizeof *p_temp);
    stream_init(&p_temp->stream, &windows_stream_class, 0, xstrdup("unix"));
    p_temp->fd = p->fd;
    /* Specify it was created by a passive stream. */
    p_temp->server = true;
    /* Create events for read/write operations. */
    memset(&p_temp->read, 0, sizeof(p_temp->read));
    memset(&p_temp->write, 0, sizeof(p_temp->write));
    p_temp->read.hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
    p_temp->write.hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
    p_temp->read_pending = false;
    p_temp->write_pending = false;
    p_temp->retry_connect = false;
    p_temp->pipe_path = NULL;
    *new_streamp = &p_temp->stream;

    /* The passive handle p->fd will be the new created handle. */
    p->fd = npipe;
    memset(&p->connect, 0, sizeof(p->connect));
    p->connect.hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
    p->pending = false;
    return 0;
}

/* Passive named pipe close. */
static void
pwindows_close(struct pstream *pstream)
{
    struct pwindows_pstream *p = pwindows_pstream_cast(pstream);
    DisconnectNamedPipe(p->fd);
    CloseHandle(p->fd);
    CloseHandle(p->connect.hEvent);
    maybe_unlink_and_free(p->unlink_path);
    free(p->pipe_path);
    free(p);
}

/* Passive named pipe wait. */
static void
pwindows_wait(struct pstream *pstream)
{
    struct pwindows_pstream *p = pwindows_pstream_cast(pstream);
    poll_wevent_wait(p->connect.hEvent);
}

/* Passive named pipe. */
static int
pwindows_open(const char *name OVS_UNUSED, char *suffix,
              struct pstream **pstreamp, uint8_t dscp OVS_UNUSED)
{
    char *bind_path;
    int error;
    HANDLE npipe;
    char *orig_path;

    char *path;
    if (!strchr(suffix, ':')) {
        path = xasprintf("%s/%s", ovs_rundir(), suffix);
    } else {
        path = xstrdup(suffix);
    }

    /* Try to create a file under the path location. */
    FILE *file = fopen(path, "w");
    if (!file) {
        free(path);
        error = errno;
        VLOG_DBG_RL(&rl, "could not open %s (%s)", path, ovs_strerror(error));
        return error;
    } else {
        fclose(file);
    }

    orig_path = xstrdup(path);
    /* Strip slashes from path and create a named pipe using that newly created
     * string. */
    bind_path = xasprintf("%s%s", LOCAL_PREFIX, remove_slashes(path));
    free(path);

    npipe = create_pnpipe(bind_path);

    if (npipe == INVALID_HANDLE_VALUE) {
        VLOG_ERR_RL(&rl, "Could not create named pipe. Last error: %s",
                    ovs_lasterror_to_string());
        return ENOENT;
    }

    struct pwindows_pstream *p = xmalloc(sizeof *p);
    pstream_init(&p->pstream, &pwindows_pstream_class, xstrdup(name));
    p->fd = npipe;
    p->unlink_path = orig_path;
    memset(&p->connect, 0, sizeof(p->connect));
    p->connect.hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
    p->pending = false;
    p->pipe_path = bind_path;
    *pstreamp = &p->pstream;
    return 0;
}

const struct pstream_class pwindows_pstream_class = {
    "punix",
    false,                   /* probes */
    pwindows_open,           /* open */
    pwindows_close,          /* close */
    pwindows_accept,         /* accept */
    pwindows_wait,           /* wait */
};

/* Helper functions. */
static void
maybe_unlink_and_free(char *path)
{
    if (path) {
        fatal_signal_unlink_file_now(path);
        free(path);
    }
}

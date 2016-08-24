/*
 * Copyright (c) 2015 Nicira, Inc.
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
#include "syslog-direct.h"

#include <config.h>

#include <string.h>
#include <unistd.h>

#include "compiler.h"
#include "openvswitch/dynamic-string.h"
#include "socket-util.h"
#include "syslog-provider.h"
#include "util.h"

#define FACILITY_MASK 0x03f8

static void syslog_direct_open(struct syslogger *this, int facility);
static void syslog_direct_log(struct syslogger *this, int pri,
                              const char *msg);

static struct syslog_class syslog_direct_class = {
    syslog_direct_open,
    syslog_direct_log,
};

struct syslog_direct {
    struct syslogger parent;
    int fd;  /* Negative number in error case.  Otherwise, socket. */
    int facility;
};


/* This function creates object that directly interacts with syslog over
 * UDP or Unix domain socket specified in 'method'. */
struct syslogger *
syslog_direct_create(const char *method)
{
    struct syslog_direct *this = xmalloc(sizeof *this);

    this->parent.class = &syslog_direct_class;
    this->parent.prefix = "<%B>";

    /* socket is created from here (opposed to syslog_direct_open())
     * so that deadlocks would be avoided.  The problem is that these
     * functions that create socket might call VLOG() */
    if (!strncmp(method, "udp:", 4)) {
        inet_open_active(SOCK_DGRAM, &method[4], 514, NULL, &this->fd, 0);
    } else if (!strncmp(method, "unix:", 5)) {
        this->fd = make_unix_socket(SOCK_DGRAM, true, NULL, &method[5]);
    } else {
        this->fd = -1;
    }

    return &this->parent;
}

static void
syslog_direct_open(struct syslogger *this, int facility)
{
    struct syslog_direct *this_ = (struct syslog_direct*) this;

    this_->facility = facility;
}

static void
syslog_direct_log(struct syslogger *this, int pri, const char *msg)
{
    static size_t max_len = SIZE_MAX; /* max message size we have discovered
                                       * to be able to send() without failing
                                       * with EMSGSIZE. */

    struct syslog_direct *this_ = (struct syslog_direct*) this;
    struct ds ds = DS_EMPTY_INITIALIZER;
    const char *wire_msg;
    size_t send_len;

    if (this_->fd < 0) {
        /* Failed to open socket for logging. */
        return;
    }

    if (!(pri & FACILITY_MASK)) {
        pri |= this_->facility;
    }
    ds_put_format(&ds, "<%u>%s", pri, msg);
    wire_msg = ds_cstr(&ds);
    send_len = MIN(strlen(wire_msg), max_len);
    while (send(this_->fd, wire_msg, send_len, 0) < 0 && errno == EMSGSIZE) {
        /* If message was too large for send() function then try to discover
         * max_len supported for this particular socket and retry sending a
         * truncated version of the same message. */
        send_len -= send_len / 20;
        max_len = send_len;
    }
    ds_destroy(&ds);
}

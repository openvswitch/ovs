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

#ifndef SYSLOG_PROVIDER_H
#define SYSLOG_PROVIDER_H 1


/* Open vSwitch interface to syslog daemon's interface.
 *
 * 'syslogger' is the base class that provides abstraction. */
struct syslogger {
    const struct syslog_class *class;  /* Virtual functions for concrete
                                        * syslogger implementations. */
    const char *prefix;                /* Prefix that is enforced by concrete
                                        * syslogger implementation.  Used
                                        * in vlog/list-pattern function. */
};

/* Each concrete syslogger implementation must define it's own table with
 * following functions.  These functions must never call any other VLOG_
 * function to prevent deadlocks. */
struct syslog_class {
    /* openlog() function should be called before syslog() function.  It
     * should initialize all system resources needed to perform logging. */
    void (*openlog)(struct syslogger *this, int facility);

    /* syslog() function sends message 'msg' to syslog daemon. */
    void (*syslog)(struct syslogger *this, int pri, const char *msg);
};

static inline const char *
syslog_get_prefix(struct syslogger *this)
{
    return this->prefix;
}

#endif /* syslog-provider.h */

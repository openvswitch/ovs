/*
 * Copyright (c) 2015, 2016 Nicira, Inc.
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
#include "syslog-null.h"

#include <config.h>

#include "compiler.h"
#include "syslog-provider.h"
#include "util.h"

static void syslog_null_open(struct syslogger *this, int facility);
static void syslog_null_log(struct syslogger *this, int pri, const char *msg);

static struct syslog_class syslog_null_class = {
    syslog_null_open,
    syslog_null_log,
};

struct syslog_null {
    struct syslogger parent;
};

/* This function  creates object that delegate all logging to null's
 * syslog implementation. */
struct syslogger *
syslog_null_create(void)
{
    struct syslog_null *this = xmalloc(sizeof *this);

    this->parent.class = &syslog_null_class;
    this->parent.prefix = "";

    return &this->parent;
}

static void
syslog_null_open(struct syslogger *this OVS_UNUSED, int facility OVS_UNUSED)
{
    /* Nothing to do. */
}

static void
syslog_null_log(struct syslogger *this OVS_UNUSED, int pri OVS_UNUSED,
                const char *msg OVS_UNUSED)
{
    /* Nothing to do. */
}

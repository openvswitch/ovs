/*
 * Copyright (c) 2017 Nicira, Inc.
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
#include "ovn/lib/acl-log.h"
#include <string.h>
#include "flow.h"
#include "openvswitch/json.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"


VLOG_DEFINE_THIS_MODULE(acl_log);

const char *
log_verdict_to_string(uint8_t verdict)
{
    if (verdict == LOG_VERDICT_ALLOW) {
        return "allow";
    } else if (verdict == LOG_VERDICT_DROP) {
        return "drop";
    } else if (verdict == LOG_VERDICT_REJECT) {
        return "reject";
    } else {
        return "<unknown>";
    }
}

const char *
log_severity_to_string(uint8_t severity)
{
    if (severity == LOG_SEVERITY_ALERT) {
        return "alert";
    } else if (severity == LOG_SEVERITY_WARNING) {
        return "warning";
    } else if (severity == LOG_SEVERITY_NOTICE) {
        return "notice";
    } else if (severity == LOG_SEVERITY_INFO) {
        return "info";
    } else if (severity == LOG_SEVERITY_DEBUG) {
        return "debug";
    } else {
        return "<unknown>";
    }
}

uint8_t
log_severity_from_string(const char *name)
{
    if (!strcmp(name, "alert")) {
        return LOG_SEVERITY_ALERT;
    } else if (!strcmp(name, "warning")) {
        return LOG_SEVERITY_WARNING;
    } else if (!strcmp(name, "notice")) {
        return LOG_SEVERITY_NOTICE;
    } else if (!strcmp(name, "info")) {
        return LOG_SEVERITY_INFO;
    } else if (!strcmp(name, "debug")) {
        return LOG_SEVERITY_DEBUG;
    } else {
        return UINT8_MAX;
    }
}

void
handle_acl_log(const struct flow *headers, struct ofpbuf *userdata)
{
    if (!VLOG_IS_INFO_ENABLED()) {
        return;
    }

    struct log_pin_header *lph = ofpbuf_try_pull(userdata, sizeof *lph);
    if (!lph) {
        VLOG_WARN("log data missing");
        return;
    }

    size_t name_len = userdata->size;
    char *name = name_len ? xmemdup0(userdata->data, name_len) : NULL;

    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_cstr(&ds, "name=");
    json_string_escape(name_len ? name : "<unnamed>", &ds);
    ds_put_format(&ds, ", verdict=%s, severity=%s: ",
                  log_verdict_to_string(lph->verdict),
                  log_severity_to_string(lph->severity));
    flow_format(&ds, headers, NULL);

    VLOG_INFO("%s", ds_cstr(&ds));
    ds_destroy(&ds);
    free(name);
}

/*
 * Copyright (c) 2017, 2018 Nicira, Inc.
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
#include "dns-resolve.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unbound.h>
#include "hash.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(dns_resolve);

/* Guard all_reqs__ and resolve_state of each request. */
static struct ovs_mutex dns_mutex__ = OVS_MUTEX_INITIALIZER;
static struct hmap all_reqs__;
static struct ub_ctx *ub_ctx__;

static bool thread_is_daemon;

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

enum resolve_state {
    RESOLVE_INVALID,
    RESOLVE_PENDING,
    RESOLVE_GOOD,
    RESOLVE_ERROR
};

struct resolve_request {
    struct hmap_node hmap_node;     /* node for all_reqs__ */
    char *name;                     /* the domain name to be resolved */
    char *addr;                     /* the resolved ip address */
    enum resolve_state state;       /* state of this request */
    time_t time;                    /* resolving time */
    struct ub_result *ub_result;    /* the stored unbound result */
};

static struct resolve_request *resolve_find_or_new__(const char *name)
    OVS_REQUIRES(dns_mutex__);
static bool resolve_check_expire__(struct resolve_request *req)
    OVS_REQUIRES(dns_mutex__);
static bool resolve_check_valid__(struct resolve_request *req)
    OVS_REQUIRES(dns_mutex__);
static bool resolve_async__(struct resolve_request *req, int qtype)
    OVS_REQUIRES(dns_mutex__);
static void resolve_callback__(void *req, int err, struct ub_result *)
    OVS_REQUIRES(dns_mutex__);
static bool resolve_result_to_addr__(struct ub_result *result, char **addr);
static bool dns_resolve_sync__(const char *name, char **addr);

/* Pass a true 'is_daemon' if you don't want the DNS-resolving to block the
 * running thread.
 */
void
dns_resolve_init(bool is_daemon)
{
    ub_ctx__ = ub_ctx_create();
    if (ub_ctx__ == NULL) {
        VLOG_ERR_RL(&rl, "Failed to create libunbound context, "
        "so asynchronous DNS resolving is disabled.");
        return;
    }

    const char *ub_conf_filename = getenv("OVS_UNBOUND_CONF");
    if (ub_conf_filename != NULL) {
        int retval = ub_ctx_config(ub_ctx__, ub_conf_filename);
        if (retval != 0) {
            VLOG_WARN_RL(&rl, "Failed to set libunbound context config: %s",
                         ub_strerror(retval));
            ub_ctx_delete(ub_ctx__);
            ub_ctx__ = NULL;
            return;
        }
    }

    const char *filename = getenv("OVS_RESOLV_CONF");
    if (!filename) {
#ifdef _WIN32
        /* On Windows, NULL means to use the system default nameserver. */
#else
        filename = "/etc/resolv.conf";
#endif
    }
    struct stat s;
    if (!filename || !stat(filename, &s) || errno != ENOENT) {
        int retval = ub_ctx_resolvconf(ub_ctx__, filename);
        if (retval != 0) {
            VLOG_WARN_RL(&rl, "Failed to read %s: %s",
                         filename ? filename : "system default nameserver",
                         ub_strerror(retval));
            ub_ctx_delete(ub_ctx__);
            ub_ctx__ = NULL;
            return;
        }
    } else {
        VLOG_WARN_RL(&rl, "Failed to read %s: %s",
                     filename, ovs_strerror(errno));
        ub_ctx_delete(ub_ctx__);
        ub_ctx__ = NULL;
        return;
    }

    /* Handles '/etc/hosts' on Linux and 'WINDIR/etc/hosts' on Windows. */
    int retval = ub_ctx_hosts(ub_ctx__, NULL);
    if (retval != 0) {
        VLOG_WARN_RL(&rl, "Failed to read etc/hosts: %s",
                     ub_strerror(retval));
    }

    ub_ctx_async(ub_ctx__, true);
    hmap_init(&all_reqs__);
    thread_is_daemon = is_daemon;
}

/* Returns true on success. Otherwise, returns false and the error information
 * can be found in logs. If there is no error information, then the resolving
 * is in process and the caller should call again later. The value of '*addr'
 * is always nullified if false is returned. If this function is called under
 * daemon-context, the resolving will undergo asynchronously. Otherwise, a
 * synchronouse resolving will take place.
 *
 * This function is thread-safe.
 *
 * The caller is responsible for freeing the returned '*addr'.
 */
bool
dns_resolve(const char *name, char **addr)
    OVS_EXCLUDED(dns_mutex__)
{
    bool success = false;

    if (!thread_is_daemon) {
        return dns_resolve_sync__(name, addr);
    }

    *addr = NULL;
    ovs_mutex_lock(&dns_mutex__);

    if (ub_ctx__ == NULL) {
        goto unlock;
    }

    /* ub_process is inside lock as it invokes resolve_callback__. */
    int retval = ub_process(ub_ctx__);
    if (retval != 0) {
        VLOG_ERR_RL(&rl, "dns-resolve error: %s", ub_strerror(retval));
        goto unlock;
    }

    struct resolve_request *req;
    req = resolve_find_or_new__(name);
    if (resolve_check_valid__(req)) {
        *addr = xstrdup(req->addr);
        success = true;
    } else if (req->state != RESOLVE_PENDING) {
        success = resolve_async__(req, ns_t_a);
    }
unlock:
    ovs_mutex_unlock(&dns_mutex__);
    return success;
}

void
dns_resolve_destroy(void)
{
    if (ub_ctx__ != NULL) {
        /* Outstanding requests will be killed. */
        ub_ctx_delete(ub_ctx__);
        ub_ctx__ = NULL;

        struct resolve_request *req, *next;
        HMAP_FOR_EACH_SAFE (req, next, hmap_node, &all_reqs__) {
            ub_resolve_free(req->ub_result);
            free(req->addr);
            free(req->name);
            free(req);
        }
        hmap_destroy(&all_reqs__);
    }
}

static struct resolve_request *
resolve_find_or_new__(const char *name)
    OVS_REQUIRES(dns_mutex__)
{
    struct resolve_request *req;

    HMAP_FOR_EACH_IN_BUCKET(req, hmap_node, hash_string(name, 0),
                            &all_reqs__) {
        if (!strcmp(name, req->name)) {
            return req;
        }
    }

    req = xzalloc(sizeof *req);
    req->name = xstrdup(name);
    req->state = RESOLVE_INVALID;
    hmap_insert(&all_reqs__, &req->hmap_node, hash_string(req->name, 0));
    return req;
}

static bool
resolve_check_expire__(struct resolve_request *req)
    OVS_REQUIRES(dns_mutex__)
{
    return time_now() > req->time + req->ub_result->ttl;
}

static bool
resolve_check_valid__(struct resolve_request *req)
    OVS_REQUIRES(dns_mutex__)
{
    return (req != NULL
        && req->state == RESOLVE_GOOD
        && !resolve_check_expire__(req));
}

static bool
resolve_async__(struct resolve_request *req, int qtype)
    OVS_REQUIRES(dns_mutex__)
{
    if (qtype == ns_t_a || qtype == ns_t_aaaa) {
        int retval;
        retval = ub_resolve_async(ub_ctx__, req->name,
                                  qtype, ns_c_in, req,
                                  resolve_callback__, NULL);
        if (retval != 0) {
            req->state = RESOLVE_ERROR;
            return false;
        } else {
            req->state = RESOLVE_PENDING;
            return true;
        }
    }
    return false;
}

static void
resolve_callback__(void *req_, int err, struct ub_result *result)
    OVS_REQUIRES(dns_mutex__)
{
    struct resolve_request *req = req_;

    if (err != 0 || (result->qtype == ns_t_aaaa && !result->havedata)) {
        ub_resolve_free(result);
        req->state = RESOLVE_ERROR;
        VLOG_ERR_RL(&rl, "%s: failed to resolve", req->name);
        return;
    }

    /* IPv4 address is empty, try IPv6. */
    if (result->qtype == ns_t_a && !result->havedata) {
        ub_resolve_free(result);
        resolve_async__(req, ns_t_aaaa);
        return;
    }

    char *addr;
    if (!resolve_result_to_addr__(result, &addr)) {
        ub_resolve_free(result);
        req->state = RESOLVE_ERROR;
        VLOG_ERR_RL(&rl, "%s: failed to resolve", req->name);
        return;
    }

    ub_resolve_free(req->ub_result);
    free(req->addr);

    req->ub_result = result;
    req->addr = addr;
    req->state = RESOLVE_GOOD;
    req->time = time_now();
}

static bool
resolve_result_to_addr__(struct ub_result *result, char **addr)
{
    int af = result->qtype == ns_t_a ? AF_INET : AF_INET6;
    char buffer[INET6_ADDRSTRLEN];

    /* XXX: only the first returned IP is used. */
    if (inet_ntop(af, result->data[0], buffer, sizeof buffer)) {
        *addr = xstrdup(buffer);
    } else {
        *addr = NULL;
    }

    return (*addr != NULL);
}

static bool
dns_resolve_sync__(const char *name, char **addr)
{
    *addr = NULL;

    if (ub_ctx__ == NULL) {
        dns_resolve_init(false);
        if (ub_ctx__ == NULL) {
            return false;
        }
    }

    struct ub_result *result;
    int retval = ub_resolve(ub_ctx__, name, ns_t_a, ns_c_in, &result);
    if (retval != 0) {
        return false;
    } else if (!result->havedata) {
        ub_resolve_free(result);

        retval = ub_resolve(ub_ctx__, name, ns_t_aaaa, ns_c_in, &result);
        if (retval != 0) {
            return false;
        } else if (!result->havedata) {
            ub_resolve_free(result);
            return false;
        }
    }

    bool success = resolve_result_to_addr__(result, addr);
    ub_resolve_free(result);
    return success;
}

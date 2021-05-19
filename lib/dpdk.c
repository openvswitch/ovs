/*
 * Copyright (c) 2014, 2015, 2016, 2017 Nicira, Inc.
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
#include "dpdk.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>

#include <rte_cpuflags.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_version.h>

#include "dirs.h"
#include "fatal-signal.h"
#include "netdev-dpdk.h"
#include "netdev-offload-provider.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "ovs-numa.h"
#include "smap.h"
#include "svec.h"
#include "unixctl.h"
#include "util.h"
#include "vswitch-idl.h"

VLOG_DEFINE_THIS_MODULE(dpdk);

static FILE *log_stream = NULL;       /* Stream for DPDK log redirection */

static char *vhost_sock_dir = NULL;   /* Location of vhost-user sockets */
static bool vhost_iommu_enabled = false; /* Status of vHost IOMMU support */
static bool vhost_postcopy_enabled = false; /* Status of vHost POSTCOPY
                                             * support. */
static bool dpdk_initialized = false; /* Indicates successful initialization
                                       * of DPDK. */
static bool per_port_memory = false; /* Status of per port memory support */

static int
process_vhost_flags(char *flag, const char *default_val, int size,
                    const struct smap *ovs_other_config,
                    char **new_val)
{
    const char *val;
    int changed = 0;

    val = smap_get(ovs_other_config, flag);

    /* Process the vhost-sock-dir flag if it is provided, otherwise resort to
     * default value.
     */
    if (val && (strlen(val) <= size)) {
        changed = 1;
        *new_val = xstrdup(val);
        VLOG_INFO("User-provided %s in use: %s", flag, *new_val);
    } else {
        VLOG_INFO("No %s provided - defaulting to %s", flag, default_val);
        *new_val = xstrdup(default_val);
    }

    return changed;
}

static bool
args_contains(const struct svec *args, const char *value)
{
    const char *arg;
    size_t i;

    /* We can't just use 'svec_contains' because args are not sorted. */
    SVEC_FOR_EACH (i, arg, args) {
        if (!strcmp(arg, value)) {
            return true;
        }
    }
    return false;
}

static void
construct_dpdk_options(const struct smap *ovs_other_config, struct svec *args)
{
    struct dpdk_options_map {
        const char *ovs_configuration;
        const char *dpdk_option;
        bool default_enabled;
        const char *default_value;
    } opts[] = {
        {"dpdk-lcore-mask",   "-c",             false, NULL},
        {"dpdk-hugepage-dir", "--huge-dir",     false, NULL},
        {"dpdk-socket-limit", "--socket-limit", false, NULL},
    };

    int i;

    /*First, construct from the flat-options (non-mutex)*/
    for (i = 0; i < ARRAY_SIZE(opts); ++i) {
        const char *value = smap_get(ovs_other_config,
                                     opts[i].ovs_configuration);
        if (!value && opts[i].default_enabled) {
            value = opts[i].default_value;
        }

        if (value) {
            if (!args_contains(args, opts[i].dpdk_option)) {
                svec_add(args, opts[i].dpdk_option);
                svec_add(args, value);
            } else {
                VLOG_WARN("Ignoring database defined option '%s' due to "
                          "dpdk-extra config", opts[i].dpdk_option);
            }
        }
    }
}

static char *
construct_dpdk_socket_mem(void)
{
    const char *def_value = "1024";
    int numa, numa_nodes = ovs_numa_get_n_numas();
    struct ds dpdk_socket_mem = DS_EMPTY_INITIALIZER;

    if (numa_nodes == 0 || numa_nodes == OVS_NUMA_UNSPEC) {
        numa_nodes = 1;
    }

    ds_put_cstr(&dpdk_socket_mem, def_value);
    for (numa = 1; numa < numa_nodes; ++numa) {
        ds_put_format(&dpdk_socket_mem, ",%s", def_value);
    }

    return ds_cstr(&dpdk_socket_mem);
}

#define MAX_DPDK_EXCL_OPTS 10

static void
construct_dpdk_mutex_options(const struct smap *ovs_other_config,
                             struct svec *args)
{
    char *default_dpdk_socket_mem = construct_dpdk_socket_mem();

    struct dpdk_exclusive_options_map {
        const char *category;
        const char *ovs_dpdk_options[MAX_DPDK_EXCL_OPTS];
        const char *eal_dpdk_options[MAX_DPDK_EXCL_OPTS];
        const char *default_value;
        int default_option;
    } excl_opts[] = {
        {"memory type",
         {"dpdk-alloc-mem", "dpdk-socket-mem", NULL,},
         {"-m",             "--socket-mem",    NULL,},
         default_dpdk_socket_mem, 1
        },
    };

    int i;
    for (i = 0; i < ARRAY_SIZE(excl_opts); ++i) {
        int found_opts = 0, scan, found_pos = -1;
        const char *found_value;
        struct dpdk_exclusive_options_map *popt = &excl_opts[i];

        for (scan = 0; scan < MAX_DPDK_EXCL_OPTS
                 && popt->ovs_dpdk_options[scan]; ++scan) {
            const char *value = smap_get(ovs_other_config,
                                         popt->ovs_dpdk_options[scan]);
            if (value && strlen(value)) {
                found_opts++;
                found_pos = scan;
                found_value = value;
            }
        }

        if (!found_opts) {
            if (popt->default_option) {
                found_pos = popt->default_option;
                found_value = popt->default_value;
            } else {
                continue;
            }
        }

        if (found_opts > 1) {
            VLOG_ERR("Multiple defined options for %s. Please check your"
                     " database settings and reconfigure if necessary.",
                     popt->category);
        }

        if (!args_contains(args, popt->eal_dpdk_options[found_pos])) {
            svec_add(args, popt->eal_dpdk_options[found_pos]);
            svec_add(args, found_value);
        } else {
            VLOG_WARN("Ignoring database defined option '%s' due to "
                      "dpdk-extra config", popt->eal_dpdk_options[found_pos]);
        }
    }

    free(default_dpdk_socket_mem);
}

static void
construct_dpdk_args(const struct smap *ovs_other_config, struct svec *args)
{
    const char *extra_configuration = smap_get(ovs_other_config, "dpdk-extra");

    if (extra_configuration) {
        svec_parse_words(args, extra_configuration);
    }

    construct_dpdk_options(ovs_other_config, args);
    construct_dpdk_mutex_options(ovs_other_config, args);
}

static ssize_t
dpdk_log_write(void *c OVS_UNUSED, const char *buf, size_t size)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(600, 600);
    static struct vlog_rate_limit dbg_rl = VLOG_RATE_LIMIT_INIT(600, 600);

    switch (rte_log_cur_msg_loglevel()) {
        case RTE_LOG_DEBUG:
            VLOG_DBG_RL(&dbg_rl, "%.*s", (int) size, buf);
            break;
        case RTE_LOG_INFO:
        case RTE_LOG_NOTICE:
            VLOG_INFO_RL(&rl, "%.*s", (int) size, buf);
            break;
        case RTE_LOG_WARNING:
            VLOG_WARN_RL(&rl, "%.*s", (int) size, buf);
            break;
        case RTE_LOG_ERR:
            VLOG_ERR_RL(&rl, "%.*s", (int) size, buf);
            break;
        case RTE_LOG_CRIT:
        case RTE_LOG_ALERT:
        case RTE_LOG_EMERG:
            VLOG_EMER("%.*s", (int) size, buf);
            break;
        default:
            OVS_NOT_REACHED();
    }

    return size;
}

static cookie_io_functions_t dpdk_log_func = {
    .write = dpdk_log_write,
};

static void
dpdk_unixctl_mem_stream(struct unixctl_conn *conn, int argc OVS_UNUSED,
                        const char *argv[] OVS_UNUSED, void *aux)
{
    void (*callback)(FILE *) = aux;
    char *response = NULL;
    FILE *stream;
    size_t size;

    stream = open_memstream(&response, &size);
    if (!stream) {
        response = xasprintf("Unable to open memstream: %s.",
                             ovs_strerror(errno));
        unixctl_command_reply_error(conn, response);
        goto out;
    }

    callback(stream);
    fclose(stream);
    unixctl_command_reply(conn, response);
out:
    free(response);
}

static int
dpdk_parse_log_level(const char *s)
{
    static const char * const levels[] = {
        [RTE_LOG_EMERG]   = "emergency",
        [RTE_LOG_ALERT]   = "alert",
        [RTE_LOG_CRIT]    = "critical",
        [RTE_LOG_ERR]     = "error",
        [RTE_LOG_WARNING] = "warning",
        [RTE_LOG_NOTICE]  = "notice",
        [RTE_LOG_INFO]    = "info",
        [RTE_LOG_DEBUG]   = "debug",
    };
    int i;

    for (i = 1; i < ARRAY_SIZE(levels); ++i) {
        if (!strcmp(s, levels[i])) {
            return i;
        }
    }
    return -1;
}

static void
dpdk_unixctl_log_set(struct unixctl_conn *conn, int argc, const char *argv[],
                     void *aux OVS_UNUSED)
{
    int i;

    /* With no argument, set all components level to 'debug'. */
    if (argc == 1) {
        rte_log_set_level_pattern("*", RTE_LOG_DEBUG);
    }
    for (i = 1; i < argc; i++) {
        char *err_msg = NULL;
        char *level_string;
        char *pattern;
        char *s;
        int level;

        s = xstrdup(argv[i]);
        level_string = strchr(s, ':');
        if (level_string == NULL) {
            pattern = "*";
            level_string = s;
        } else {
            pattern = s;
            level_string[0] = '\0';
            level_string++;
        }

        level = dpdk_parse_log_level(level_string);
        if (level == -1) {
            err_msg = xasprintf("invalid log level: '%s'", level_string);
        } else if (rte_log_set_level_pattern(pattern, level) < 0) {
            err_msg = xasprintf("cannot set log level for '%s'", argv[i]);
        }

        if (err_msg) {
            unixctl_command_reply_error(conn, err_msg);
            free(err_msg);
            free(s);
            return;
        }
        free(s);
    }
    unixctl_command_reply(conn, NULL);
}

static void
malloc_dump_stats_wrapper(FILE *stream)
{
    rte_malloc_dump_stats(stream, NULL);
}

static bool
dpdk_init__(const struct smap *ovs_other_config)
{
    char *sock_dir_subcomponent;
    char **argv = NULL;
    int result;
    bool auto_determine = true;
    int err = 0;
    struct ovs_numa_dump *affinity = NULL;
    struct svec args = SVEC_EMPTY_INITIALIZER;

    log_stream = fopencookie(NULL, "w+", dpdk_log_func);
    if (log_stream == NULL) {
        VLOG_ERR("Can't redirect DPDK log: %s.", ovs_strerror(errno));
    } else {
        setbuf(log_stream, NULL);
        rte_openlog_stream(log_stream);
    }

    if (process_vhost_flags("vhost-sock-dir", ovs_rundir(),
                            NAME_MAX, ovs_other_config,
                            &sock_dir_subcomponent)) {
        struct stat s;
        if (!strstr(sock_dir_subcomponent, "..")) {
            vhost_sock_dir = xasprintf("%s/%s", ovs_rundir(),
                                       sock_dir_subcomponent);

            err = stat(vhost_sock_dir, &s);
            if (err) {
                VLOG_ERR("vhost-user sock directory '%s' does not exist.",
                         vhost_sock_dir);
            }
        } else {
            vhost_sock_dir = xstrdup(ovs_rundir());
            VLOG_ERR("vhost-user sock directory request '%s/%s' has invalid"
                     "characters '..' - using %s instead.",
                     ovs_rundir(), sock_dir_subcomponent, ovs_rundir());
        }
        free(sock_dir_subcomponent);
    } else {
        vhost_sock_dir = sock_dir_subcomponent;
    }

    vhost_iommu_enabled = smap_get_bool(ovs_other_config,
                                        "vhost-iommu-support", false);
    VLOG_INFO("IOMMU support for vhost-user-client %s.",
               vhost_iommu_enabled ? "enabled" : "disabled");

    vhost_postcopy_enabled = smap_get_bool(ovs_other_config,
                                           "vhost-postcopy-support", false);
    if (vhost_postcopy_enabled && memory_locked()) {
        VLOG_WARN("vhost-postcopy-support and mlockall are not compatible.");
        vhost_postcopy_enabled = false;
    }
    VLOG_INFO("POSTCOPY support for vhost-user-client %s.",
              vhost_postcopy_enabled ? "enabled" : "disabled");

    per_port_memory = smap_get_bool(ovs_other_config,
                                    "per-port-memory", false);
    VLOG_INFO("Per port memory for DPDK devices %s.",
              per_port_memory ? "enabled" : "disabled");

    svec_add(&args, ovs_get_program_name());
    construct_dpdk_args(ovs_other_config, &args);

    if (!args_contains(&args, "--legacy-mem")
        && !args_contains(&args, "--socket-limit")) {
        const char *arg;
        size_t i;

        SVEC_FOR_EACH (i, arg, &args) {
            if (!strcmp(arg, "--socket-mem")) {
                break;
            }
        }
        if (i < args.n - 1) {
            svec_add(&args, "--socket-limit");
            svec_add(&args, args.names[i + 1]);
        }
    }

    if (args_contains(&args, "-c") || args_contains(&args, "-l")) {
        auto_determine = false;
    }

    /**
     * NOTE: This is an unsophisticated mechanism for determining the DPDK
     * main core.
     */
    if (auto_determine) {
        const struct ovs_numa_info_core *core;
        int cpu = 0;

        /* Get the main thread affinity */
        affinity = ovs_numa_thread_getaffinity_dump();
        if (affinity) {
            cpu = INT_MAX;
            FOR_EACH_CORE_ON_DUMP (core, affinity) {
                if (cpu > core->core_id) {
                    cpu = core->core_id;
                }
            }
        } else {
            /* User did not set dpdk-lcore-mask and unable to get current
             * thread affintity - default to core #0 */
            VLOG_ERR("Thread getaffinity failed. Using core #0");
        }
        svec_add(&args, "-l");
        svec_add_nocopy(&args, xasprintf("%d", cpu));
    }

    svec_terminate(&args);

    optind = 1;

    if (VLOG_IS_INFO_ENABLED()) {
        struct ds eal_args = DS_EMPTY_INITIALIZER;
        char *joined_args = svec_join(&args, " ", ".");

        ds_put_format(&eal_args, "EAL ARGS: %s", joined_args);
        VLOG_INFO("%s", ds_cstr_ro(&eal_args));
        ds_destroy(&eal_args);
        free(joined_args);
    }

    /* Copy because 'rte_eal_init' will change the argv, i.e. it will remove
     * some arguments from it. '+1' to copy the terminating NULL.  */
    argv = xmemdup(args.names, (args.n + 1) * sizeof args.names[0]);

    /* Make sure things are initialized ... */
    result = rte_eal_init(args.n, argv);

    free(argv);
    svec_destroy(&args);

    /* Set the main thread affinity back to pre rte_eal_init() value */
    if (affinity) {
        ovs_numa_thread_setaffinity_dump(affinity);
        ovs_numa_dump_destroy(affinity);
    }

    if (result < 0) {
        VLOG_EMER("Unable to initialize DPDK: %s", ovs_strerror(rte_errno));
        return false;
    }

    if (VLOG_IS_DBG_ENABLED()) {
        size_t size;
        char *response = NULL;
        FILE *stream = open_memstream(&response, &size);

        if (stream) {
            fprintf(stream, "rte_memzone_dump:\n");
            rte_memzone_dump(stream);
            fprintf(stream, "rte_log_dump:\n");
            rte_log_dump(stream);
            fclose(stream);
            VLOG_DBG("%s", response);
            free(response);
        } else {
            VLOG_DBG("Could not dump memzone and log levels. "
                     "Unable to open memstream: %s.", ovs_strerror(errno));
        }
    }

    unixctl_command_register("dpdk/log-list", "", 0, 0,
                             dpdk_unixctl_mem_stream, rte_log_dump);
    unixctl_command_register("dpdk/log-set", "{level | pattern:level}", 0,
                             INT_MAX, dpdk_unixctl_log_set, NULL);
    unixctl_command_register("dpdk/get-malloc-stats", "", 0, 0,
                             dpdk_unixctl_mem_stream,
                             malloc_dump_stats_wrapper);

    /* We are called from the main thread here */
    RTE_PER_LCORE(_lcore_id) = NON_PMD_CORE_ID;

    /* Finally, register the dpdk classes */
    netdev_dpdk_register();
    netdev_register_flow_api_provider(&netdev_offload_dpdk);
    return true;
}

void
dpdk_init(const struct smap *ovs_other_config)
{
    static bool enabled = false;

    if (enabled || !ovs_other_config) {
        return;
    }

    const char *dpdk_init_val = smap_get_def(ovs_other_config, "dpdk-init",
                                             "false");

    bool try_only = !strcasecmp(dpdk_init_val, "try");
    if (!strcasecmp(dpdk_init_val, "true") || try_only) {
        static struct ovsthread_once once_enable = OVSTHREAD_ONCE_INITIALIZER;

        if (ovsthread_once_start(&once_enable)) {
            VLOG_INFO("Using %s", rte_version());
            VLOG_INFO("DPDK Enabled - initializing...");
            enabled = dpdk_init__(ovs_other_config);
            if (enabled) {
                VLOG_INFO("DPDK Enabled - initialized");
            } else if (!try_only) {
                ovs_abort(rte_errno, "Cannot init EAL");
            }
            ovsthread_once_done(&once_enable);
        } else {
            VLOG_ERR_ONCE("DPDK Initialization Failed.");
        }
    } else {
        VLOG_INFO_ONCE("DPDK Disabled - Use other_config:dpdk-init to enable");
    }
    dpdk_initialized = enabled;
}

const char *
dpdk_get_vhost_sock_dir(void)
{
    return vhost_sock_dir;
}

bool
dpdk_vhost_iommu_enabled(void)
{
    return vhost_iommu_enabled;
}

bool
dpdk_vhost_postcopy_enabled(void)
{
    return vhost_postcopy_enabled;
}

bool
dpdk_per_port_memory(void)
{
    return per_port_memory;
}

bool
dpdk_available(void)
{
    return dpdk_initialized;
}

void
dpdk_set_lcore_id(unsigned cpu)
{
    /* NON_PMD_CORE_ID is reserved for use by non pmd threads. */
    ovs_assert(cpu != NON_PMD_CORE_ID);
    RTE_PER_LCORE(_lcore_id) = cpu;
}

void
print_dpdk_version(void)
{
    puts(rte_version());
}

#define CHECK_CPU_FEATURE(feature, name_str, RTE_CPUFLAG)               \
    do {                                                                \
        if (strncmp(feature, name_str, strlen(name_str)) == 0) {        \
            int has_isa = rte_cpu_get_flag_enabled(RTE_CPUFLAG);        \
            VLOG_DBG("CPU flag %s, available %s\n", name_str,           \
                      has_isa ? "yes" : "no");                          \
            return true;                                                \
        }                                                               \
    } while (0)

bool
dpdk_get_cpu_has_isa(const char *arch, const char *feature)
{
    /* Ensure Arch is x86_64. */
    if (strncmp(arch, "x86_64", 6) != 0) {
        return false;
    }

#if __x86_64__
    /* CPU flags only defined for the architecture that support it. */
    CHECK_CPU_FEATURE(feature, "avx512f", RTE_CPUFLAG_AVX512F);
    CHECK_CPU_FEATURE(feature, "bmi2", RTE_CPUFLAG_BMI2);
#endif

    VLOG_WARN("Unknown CPU arch,feature: %s,%s. Returning not supported.\n",
              arch, feature);
    return false;
}

void
dpdk_status(const struct ovsrec_open_vswitch *cfg)
{
    if (cfg) {
        ovsrec_open_vswitch_set_dpdk_initialized(cfg, dpdk_initialized);
        ovsrec_open_vswitch_set_dpdk_version(cfg, rte_version());
    }
}

/*
 * Copyright (c) 2015, 2016, 2019 Nicira, Inc.
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

/* This implementation only applies to the Linux platform.  */

#include <config.h>
#if defined(__linux__) && defined(HAVE_LINUX_PERF_EVENT_H) && !__CHECKER__

#include <stddef.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include "openvswitch/dynamic-string.h"
#include "perf-counter.h"
#include "openvswitch/shash.h"
#include "util.h"

static struct shash perf_counters = SHASH_INITIALIZER(&perf_counters);
static int fd__ = 0;

uint64_t
perf_counter_read(uint64_t *counter)
{
    int size = sizeof *counter;

    if (fd__ <= 0 || read(fd__, counter, size) < size) {
        *counter = 0;
    }

    return *counter;
}

static long
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                int cpu, int group_fd, unsigned long flags)
{
    int ret;

    ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
                  group_fd, flags);
    return ret;
}

/* Set up perf event counters to read user space instruction counters
 * only for this process, on all cpus.   */
static void
perf_event_setup(void)
{
    struct perf_event_attr pe;

    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_HW_INSTRUCTIONS;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    fd__ = perf_event_open(&pe, 0, -1, -1, 0);
    if (fd__ > 0) {
        ioctl(fd__, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd__, PERF_EVENT_IOC_ENABLE, 0);
    }
}

static void
perf_counter_init(struct perf_counter *counter)
{
    counter->once = true;
    shash_add_assert(&perf_counters, counter->name, counter);
}

void
perf_counter_accumulate(struct perf_counter *counter, uint64_t start_count)
{
    uint64_t end_count;

    if (!counter->once) {
        perf_counter_init(counter);
    }

    counter->n_events++;
    perf_counter_read(&end_count);
    counter->total_count += end_count - start_count;
}

static void
perf_counter_to_ds(struct ds *ds, struct perf_counter *pfc)
{
    double ratio;

    if (pfc->n_events) {
        ratio = (double)pfc->total_count / (double)pfc->n_events;
    } else {
        ratio = 0.0;
    }

    ds_put_format(ds, "%-40s %12"PRIu64" %12"PRIu64" %12.1f\n",
                  pfc->name, pfc->n_events, pfc->total_count, ratio);
}

static void
perf_counters_to_ds(struct ds *ds)
{
    const char *err_str;
    const struct shash_node **sorted;
    int i;

    err_str = NULL;
    if (fd__ == -1) {
        err_str = "performance counter is not supported on this platfrom";
    } else if (!shash_count(&perf_counters)) {
        err_str = "performance counter has never been hit";
    }

    if (err_str) {
        ds_put_format(ds, "%s\n", err_str);
        return;
    }

    /* Display counters in alphabetical order.  */
    sorted = shash_sort(&perf_counters);
    for (i = 0; i < shash_count(&perf_counters); i++) {
        perf_counter_to_ds(ds, sorted[i]->data);
    }
    free(sorted);
}

/*
 * Caller is responsible for free memory.
 */
char *
perf_counters_to_string(void)
{
    struct ds ds;

    ds_init(&ds);
    perf_counters_to_ds(&ds);
    return ds_steal_cstr(&ds);
}

void
perf_counters_init(void)
{
    shash_init(&perf_counters);
    perf_event_setup();
}

void
perf_counters_clear(void)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &perf_counters) {
        struct perf_counter *perf = node->data;

        perf->n_events = 0;
        perf->total_count = 0;
    }
}

void
perf_counters_destroy(void)
{
    struct shash_node *node, *next;

    if (fd__ != -1) {
        ioctl(fd__, PERF_EVENT_IOC_DISABLE, 0);
        close(fd__);
    }

    SHASH_FOR_EACH_SAFE (node, next, &perf_counters) {
        shash_delete(&perf_counters, node);
    }

    shash_destroy(&perf_counters);
}
#endif

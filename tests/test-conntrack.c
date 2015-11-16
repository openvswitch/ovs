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

#include <config.h>
#include "conntrack.h"

#include "dp-packet.h"
#include "fatal-signal.h"
#include "flow.h"
#include "netdev.h"
#include "ovs-thread.h"
#include "ovstest.h"
#include "timeval.h"

static const char payload[] = "50540000000a50540000000908004500001c00000000001100000a0101010a0101020001000200080000";

static struct dp_packet **
prepare_packets(size_t n, bool change, unsigned tid)
{
    struct dp_packet **pkts = xcalloc(n, sizeof *pkts);
    struct flow flow;
    size_t i;

    for (i = 0; i < n; i++) {
        struct udp_header *udp;

        pkts[i] = dp_packet_new(sizeof payload/2);
        dp_packet_put_hex(pkts[i], payload, NULL);
        flow_extract(pkts[i], &flow);

        udp = dp_packet_l4(pkts[i]);
        udp->udp_src = htons(ntohs(udp->udp_src) + tid);

        if (change) {
            udp->udp_dst = htons(ntohs(udp->udp_dst) + i);
        }
    }

    return pkts;
}

static void
destroy_packets(struct dp_packet **pkts, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        dp_packet_delete(pkts[i]);
    }

    free(pkts);
}

struct thread_aux {
    pthread_t thread;
    unsigned tid;
};

static struct conntrack ct;
static unsigned long n_threads, n_pkts, batch_size;
static bool change_conn = false;
static pthread_barrier_t barrier;

static void *
ct_thread_main(void *aux_)
{
    struct thread_aux *aux = aux_;
    struct dp_packet **pkts;
    size_t i;

    pkts = prepare_packets(batch_size, change_conn, aux->tid);
    pthread_barrier_wait(&barrier);
    for (i = 0; i < n_pkts; i += batch_size) {
        conntrack_execute(&ct, pkts, batch_size, true, 0, NULL, NULL, NULL);
    }
    pthread_barrier_wait(&barrier);
    destroy_packets(pkts, batch_size);

    return NULL;
}

static void
test_benchmark(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct thread_aux *threads;
    long long start;
    unsigned i;

    fatal_signal_init();

    /* Parse arguments */
    n_threads = strtoul(ctx->argv[1], NULL, 0);
    if (!n_threads) {
        ovs_fatal(0, "n_threads must be at least one");
    }
    n_pkts = strtoul(ctx->argv[2], NULL, 0);
    batch_size = strtoul(ctx->argv[3], NULL, 0);
    if (batch_size == 0 || batch_size > NETDEV_MAX_BURST) {
        ovs_fatal(0, "batch_size must be between 1 and NETDEV_MAX_BURST(%u)",
                  NETDEV_MAX_BURST);
    }
    if (ctx->argc > 4) {
        change_conn = strtoul(ctx->argv[4], NULL, 0);
    }

    threads = xcalloc(n_threads, sizeof *threads);
    pthread_barrier_init(&barrier, NULL, n_threads + 1);
    conntrack_init(&ct);

    /* Create threads */
    for (i = 0; i < n_threads; i++) {
        threads[i].tid = i;
        threads[i].thread = ovs_thread_create("ct_thread", ct_thread_main, &threads[i]);
    }
    /* Starts the work inside the threads */
    pthread_barrier_wait(&barrier);
    start = time_msec();

    /* Wait for the threads to finish the work */
    pthread_barrier_wait(&barrier);
    printf("conntrack:  %5lld ms\n", time_msec() - start);

    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i].thread, NULL);
    }

    conntrack_destroy(&ct);
    pthread_barrier_destroy(&barrier);
    free(threads);
}

static const struct ovs_cmdl_command commands[] = {
    /* Connection tracker tests. */
    /* Starts 'n_threads' threads. Each thread will send 'n_pkts' packets to
     * the connection tracker, 'batch_size' per call. If 'change_connection'
     * is '1', each packet in a batch will have a different source and
     * destination port */
    {"benchmark", "n_threads n_pkts batch_size [change_connection]", 3, 4, test_benchmark},

    {NULL, NULL, 0, 0, NULL},
};

static void
test_conntrack_main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = {
        .argc = argc - 1,
        .argv = argv + 1,
    };
    set_program_name(argv[0]);
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-conntrack", test_conntrack_main);

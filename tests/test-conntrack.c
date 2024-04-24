/*
 * Copyright (c) 2015, 2017 Nicira, Inc.
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
#include "pcap-file.h"
#include "timeval.h"
#include "stopwatch.h"

#define STOPWATCH_CT_EXECUTE_COMMIT "ct-execute-commit"
#define STOPWATCH_CT_EXECUTE_NO_COMMIT "ct-execute-no-commit"
#define STOPWATCH_FLUSH_FULL_ZONE "full-zone"
#define STOPWATCH_FLUSH_EMPTY_ZONE "empty-zone"

static const char payload[] = "50540000000a50540000000908004500001c0000000000"
                              "11a4cd0a0101010a0101020001000200080000";

static struct dp_packet *
build_packet(uint16_t udp_src, uint16_t udp_dst, ovs_be16 *dl_type)
{
    struct udp_header *udp;
    struct flow flow;
    struct dp_packet *pkt = dp_packet_new(sizeof payload / 2);

    dp_packet_put_hex(pkt, payload, NULL);
    flow_extract(pkt, &flow);

    udp = dp_packet_l4(pkt);
    udp->udp_src = htons(udp_src);
    udp->udp_dst = htons(udp_dst);

    *dl_type = flow.dl_type;

    return pkt;
}

static struct dp_packet_batch *
prepare_packets(size_t n, bool change, unsigned tid, ovs_be16 *dl_type)
{
    struct dp_packet_batch *pkt_batch = xzalloc(sizeof *pkt_batch);
    size_t i;

    ovs_assert(n <= ARRAY_SIZE(pkt_batch->packets));

    dp_packet_batch_init(pkt_batch);
    for (i = 0; i < n; i++) {
        uint16_t udp_dst = change ? 2+1 : 2;
        struct dp_packet *pkt = build_packet(1 + tid, udp_dst, dl_type);
        dp_packet_batch_add(pkt_batch, pkt);
    }

    return pkt_batch;
}

static void
destroy_packets(struct dp_packet_batch *pkt_batch)
{
    dp_packet_delete_batch(pkt_batch, true);
    free(pkt_batch);
}

struct thread_aux {
    pthread_t thread;
    unsigned tid;
};

static struct conntrack *ct;
static unsigned long n_threads, n_pkts, batch_size;
static bool change_conn = false;
static struct ovs_barrier barrier;

static void *
ct_thread_main(void *aux_)
{
    struct thread_aux *aux = aux_;
    struct dp_packet_batch *pkt_batch;
    struct dp_packet *pkt;
    ovs_be16 dl_type;
    size_t i;
    long long now = time_msec();

    pkt_batch = prepare_packets(batch_size, change_conn, aux->tid, &dl_type);
    ovs_barrier_block(&barrier);
    for (i = 0; i < n_pkts; i += batch_size) {
        conntrack_execute(ct, pkt_batch, dl_type, false, true, 0, NULL, NULL,
                          NULL, NULL, now, 0);
        DP_PACKET_BATCH_FOR_EACH (j, pkt, pkt_batch) {
            pkt_metadata_init_conn(&pkt->md);
        }
    }
    ovs_barrier_block(&barrier);
    destroy_packets(pkt_batch);

    return NULL;
}

static void
test_benchmark(struct ovs_cmdl_context *ctx)
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
    ovs_barrier_init(&barrier, n_threads + 1);
    ct = conntrack_init();

    /* Create threads */
    for (i = 0; i < n_threads; i++) {
        threads[i].tid = i;
        threads[i].thread = ovs_thread_create("ct_thread", ct_thread_main,
                                              &threads[i]);
    }
    /* Starts the work inside the threads */
    ovs_barrier_block(&barrier);
    start = time_msec();

    /* Wait for the threads to finish the work */
    ovs_barrier_block(&barrier);
    printf("conntrack:  %5lld ms\n", time_msec() - start);

    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i].thread, NULL);
    }

    conntrack_destroy(ct);
    ovs_barrier_destroy(&barrier);
    free(threads);
}

static void
test_benchmark_zones(struct ovs_cmdl_context *ctx)
{
    unsigned long n_conns, n_zones, iterations;
    long long start;
    unsigned i, j;
    ovs_be16 dl_type;
    long long now = time_msec();

    fatal_signal_init();

    /* Parse arguments */
    n_conns = strtoul(ctx->argv[1], NULL, 0);
    if (n_conns == 0 || n_conns >= UINT32_MAX) {
        ovs_fatal(0, "n_conns must be between 1 and 2^32");
    }
    n_zones = strtoul(ctx->argv[2], NULL, 0);
    if (n_zones == 0 || n_zones >= UINT16_MAX) {
        ovs_fatal(0, "n_zones must be between 1 and 2^16");
    }
    iterations = strtoul(ctx->argv[3], NULL, 0);
    if (iterations == 0) {
        ovs_fatal(0, "iterations must be greater than 0");
    }

    ct = conntrack_init();

    /* Create initial connection entries */
    start = time_msec();
    struct dp_packet_batch **pkt_batch = xzalloc(n_conns * sizeof *pkt_batch);
    for (i = 0; i < n_conns; i++) {
        pkt_batch[i] = xzalloc(sizeof(struct dp_packet_batch));
        dp_packet_batch_init(pkt_batch[i]);
        uint16_t udp_src = (i & 0xFFFF0000) >> 16;
        if (udp_src == 0) {
            udp_src = UINT16_MAX;
        }
        uint16_t udp_dst = i & 0xFFFF;
        if (udp_dst == 0) {
            udp_dst = UINT16_MAX;
        }
        struct dp_packet *pkt = build_packet(udp_src, udp_dst, &dl_type);
        dp_packet_batch_add(pkt_batch[i], pkt);
    }
    printf("initial packet generation time: %lld ms\n", time_msec() - start);

    /* Put initial entries to each zone */
    start = time_msec();
    for (i = 0; i < n_zones; i++) {
        for (j = 0; j < n_conns; j++) {
            conntrack_execute(ct, pkt_batch[j], dl_type, false, true, i,
                              NULL, NULL, NULL, NULL, now, 0);
            pkt_metadata_init_conn(&pkt_batch[j]->packets[0]->md);
        }
    }
    printf("initial insert time: %lld ms\n", time_msec() - start);

    /* Actually run the tests */
    stopwatch_create(STOPWATCH_CT_EXECUTE_COMMIT, SW_US);
    stopwatch_create(STOPWATCH_CT_EXECUTE_NO_COMMIT, SW_US);
    stopwatch_create(STOPWATCH_FLUSH_FULL_ZONE, SW_US);
    stopwatch_create(STOPWATCH_FLUSH_EMPTY_ZONE, SW_US);
    start = time_msec();
    for (i = 0; i < iterations; i++) {
        /* Testing flushing a full zone */
        stopwatch_start(STOPWATCH_FLUSH_FULL_ZONE, time_usec());
        uint16_t zone = 1;
        conntrack_flush(ct, &zone);
        stopwatch_stop(STOPWATCH_FLUSH_FULL_ZONE, time_usec());

        /* Now fill the zone again */
        stopwatch_start(STOPWATCH_CT_EXECUTE_COMMIT, time_usec());
        for (j = 0; j < n_conns; j++) {
            conntrack_execute(ct, pkt_batch[j], dl_type, false, true, zone,
                              NULL, NULL, NULL, NULL, now, 0);
            pkt_metadata_init_conn(&pkt_batch[j]->packets[0]->md);
        }
        stopwatch_stop(STOPWATCH_CT_EXECUTE_COMMIT, time_usec());

        /* Running conntrack_execute on the now existing connections  */
        stopwatch_start(STOPWATCH_CT_EXECUTE_NO_COMMIT, time_usec());
        for (j = 0; j < n_conns; j++) {
            conntrack_execute(ct, pkt_batch[j], dl_type, false, false, zone,
                              NULL, NULL, NULL, NULL, now, 0);
            pkt_metadata_init_conn(&pkt_batch[j]->packets[0]->md);
        }
        stopwatch_stop(STOPWATCH_CT_EXECUTE_NO_COMMIT, time_usec());

        /* Testing flushing an empty zone */
        stopwatch_start(STOPWATCH_FLUSH_EMPTY_ZONE, time_usec());
        zone = UINT16_MAX;
        conntrack_flush(ct, &zone);
        stopwatch_stop(STOPWATCH_FLUSH_EMPTY_ZONE, time_usec());
    }

    printf("flush run time: %lld ms\n", time_msec() - start);

    stopwatch_sync();
    struct stopwatch_stats stats_ct_execute_commit = { .unit = SW_US };
    stopwatch_get_stats(STOPWATCH_CT_EXECUTE_COMMIT, &stats_ct_execute_commit);
    struct stopwatch_stats stats_ct_execute_nocommit = { .unit = SW_US };
    stopwatch_get_stats(STOPWATCH_CT_EXECUTE_NO_COMMIT,
            &stats_ct_execute_nocommit);
    struct stopwatch_stats stats_flush_full = { .unit = SW_US };
    stopwatch_get_stats(STOPWATCH_FLUSH_FULL_ZONE, &stats_flush_full);
    struct stopwatch_stats stats_flush_empty = { .unit = SW_US };
    stopwatch_get_stats(STOPWATCH_FLUSH_EMPTY_ZONE, &stats_flush_empty);

    printf("results:\n");
    printf("         | ct execute (commit) | ct execute (no commit) |"
            " flush full zone | flush empty zone |\n");
    printf("+--------+---------------------+------------------------+"
            "-----------------+------------------+\n");
    printf("| Min    | %16llu us | %19llu us | %12llu us | %13llu us |\n",
            stats_ct_execute_commit.min, stats_ct_execute_nocommit.min,
            stats_flush_full.min, stats_flush_empty.min);
    printf("| Max    | %16llu us | %19llu us | %12llu us | %13llu us |\n",
            stats_ct_execute_commit.max, stats_ct_execute_nocommit.max,
            stats_flush_full.max, stats_flush_empty.max);
    printf("| 95%%ile | %16.2f us | %19.2f us | %12.2f us | %13.2f us |\n",
            stats_ct_execute_commit.pctl_95, stats_ct_execute_nocommit.pctl_95,
            stats_flush_full.pctl_95, stats_flush_empty.pctl_95);
    printf("| Avg    | %16.2f us | %19.2f us | %12.2f us | %13.2f us |\n",
            stats_ct_execute_commit.ewma_1, stats_ct_execute_nocommit.ewma_1,
            stats_flush_full.ewma_1, stats_flush_empty.ewma_1);

    conntrack_destroy(ct);
    for (i = 0; i < n_conns; i++) {
        dp_packet_delete_batch(pkt_batch[i], true);
        free(pkt_batch[i]);
    }
    free(pkt_batch);
}

static void
pcap_batch_execute_conntrack(struct conntrack *ct_,
                             struct dp_packet_batch *pkt_batch)
{
    struct dp_packet_batch new_batch;
    ovs_be16 dl_type = htons(0);
    long long now = time_msec();

    dp_packet_batch_init(&new_batch);

    /* pkt_batch contains packets with different 'dl_type'. We have to
     * call conntrack_execute() on packets with the same 'dl_type'. */
    struct dp_packet *packet;
    DP_PACKET_BATCH_FOR_EACH (i, packet, pkt_batch) {
        struct flow flow;

        /* This also initializes the l3 and l4 pointers. */
        flow_extract(packet, &flow);

        if (dp_packet_batch_is_empty(&new_batch)) {
            dl_type = flow.dl_type;
        }

        if (flow.dl_type != dl_type) {
            conntrack_execute(ct_, &new_batch, dl_type, false, true, 0,
                              NULL, NULL, NULL, NULL, now, 0);
            dp_packet_batch_init(&new_batch);
        }
        dp_packet_batch_add(&new_batch, packet);
    }

    if (!dp_packet_batch_is_empty(&new_batch)) {
        conntrack_execute(ct_, &new_batch, dl_type, false, true, 0, NULL, NULL,
                          NULL, NULL, now, 0);
    }

}

static void
test_pcap(struct ovs_cmdl_context *ctx)
{
    size_t total_count, batch_size_;
    struct pcap_file *pcap;
    int err = 0;

    pcap = ovs_pcap_open(ctx->argv[1], "rb");
    if (!pcap) {
        return;
    }

    batch_size_ = 1;
    if (ctx->argc > 2) {
        batch_size_ = strtoul(ctx->argv[2], NULL, 0);
        if (batch_size_ == 0 || batch_size_ > NETDEV_MAX_BURST) {
            ovs_fatal(0,
                      "batch_size must be between 1 and NETDEV_MAX_BURST(%u)",
                      NETDEV_MAX_BURST);
        }
    }

    fatal_signal_init();

    ct = conntrack_init();
    total_count = 0;
    for (;;) {
        struct dp_packet *packet;
        struct dp_packet_batch pkt_batch_;
        struct dp_packet_batch *batch = &pkt_batch_;

        dp_packet_batch_init(batch);
        for (int i = 0; i < batch_size_; i++) {
            err = ovs_pcap_read(pcap, &packet, NULL);
            if (err) {
                break;
            }
            dp_packet_batch_add(batch, packet);
        }
        if (dp_packet_batch_is_empty(batch)) {
            break;
        }
        pcap_batch_execute_conntrack(ct, batch);

        DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
            struct ds ds = DS_EMPTY_INITIALIZER;

            total_count++;

            format_flags(&ds, ct_state_to_string, packet->md.ct_state, '|');
            printf("%"PRIuSIZE": %s\n", total_count, ds_cstr(&ds));

            ds_destroy(&ds);
        }

        dp_packet_delete_batch(batch, true);
    }
    conntrack_destroy(ct);
    ovs_pcap_close(pcap);
}

static const struct ovs_cmdl_command commands[] = {
    /* Connection tracker tests. */
    /* Starts 'n_threads' threads. Each thread will send 'n_pkts' packets to
     * the connection tracker, 'batch_size' per call. If 'change_connection'
     * is '1', each packet in a batch will have a different source and
     * destination port */
    {"benchmark", "n_threads n_pkts batch_size [change_connection]", 3, 4,
     test_benchmark, OVS_RO},
    /* Reads packets from 'file' and sends them to the connection tracker,
     * 'batch_size' (1 by default) per call, with the commit flag set.
     * Prints the ct_state of each packet. */
    {"pcap", "file [batch_size]", 1, 2, test_pcap, OVS_RO},
    /* Creates 'n_conns' connections in 'n_zones' zones each.
     * Afterwards triggers flush requests repeadeatly for the last filled zone
     * and an empty zone. */
    {"benchmark-zones", "n_conns n_zones iterations", 3, 3,
        test_benchmark_zones, OVS_RO},

    {NULL, NULL, 0, 0, NULL, OVS_RO},
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

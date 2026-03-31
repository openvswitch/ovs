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

static const char payload[] = "50540000000a50540000000908004500001c0000000000"
                              "11a4cd0a0101010a0101020001000200080000";

/* Build an Ethernet + IPv4 packet.  If 'pkt' is NULL a new buffer is
 * allocated with 64 bytes of extra headroom so the FTP MTU guard passes.
 * The buffer is populated up through the IP header; l4 is set to point
 * directly after the IP header.  The caller is responsible for filling
 * the L4 header and payload that follow. */
static struct dp_packet *
build_eth_ip_packet(struct dp_packet *pkt, struct eth_addr eth_src,
                    struct eth_addr eth_dst, ovs_be32 ip_src, ovs_be32 ip_dst,
                    uint8_t proto, uint16_t payload_alloc)
{
    struct ip_header *iph;
    uint16_t proto_len;

    switch (proto) {
    case IPPROTO_TCP:  proto_len = TCP_HEADER_LEN;  break;
    case IPPROTO_UDP:  proto_len = UDP_HEADER_LEN;  break;
    case IPPROTO_ICMP: proto_len = ICMP_HEADER_LEN; break;
    default:           proto_len = 0;               break;
    }

    if (pkt == NULL) {
        /* 64-byte extra headroom keeps dp_packet_get_allocated() large enough
         * that the FTP V4 MTU guard (orig_used_size + 8 <= allocated) passes
         * even when the packet is near its maximum size. */
        pkt = dp_packet_new_with_headroom(ETH_HEADER_LEN + IP_HEADER_LEN
                                          + proto_len + payload_alloc, 64);
    }

    eth_compose(pkt, eth_src, eth_dst, ETH_TYPE_IP,
                IP_HEADER_LEN + proto_len + payload_alloc);
    iph = dp_packet_l3(pkt);
    iph->ip_ihl_ver = IP_IHL_VER(5, 4);
    iph->ip_tot_len = htons(IP_HEADER_LEN + proto_len + payload_alloc);
    iph->ip_ttl = 64;
    iph->ip_proto = proto;
    packet_set_ipv4_addr(pkt, &iph->ip_src, ip_src);
    packet_set_ipv4_addr(pkt, &iph->ip_dst, ip_dst);
    iph->ip_csum = csum(iph, IP_HEADER_LEN);
    dp_packet_set_l4(pkt, (char *) iph + IP_HEADER_LEN);
    return pkt;
}

/* Fill the TCP header and optional payload for a packet previously built with
 * build_eth_ip_packet().  The 'payload' buffer of 'payload_len' bytes is
 * appended after the TCP header if non-NULL.  IP total-length, IP checksum,
 * and TCP checksum are all updated to reflect the final packet contents. */
static struct dp_packet *
build_tcp_packet(struct dp_packet *pkt, uint16_t tcp_src, uint16_t tcp_dst,
                 uint16_t tcp_flags, const char *tcp_payload,
                 size_t payload_len)
{
    struct tcp_header *tcph;
    struct ip_header *iph;
    uint16_t ip_tot_len;
    uint32_t tcp_csum;
    struct flow flow;

    ovs_assert(pkt);
    tcph = dp_packet_l4(pkt);
    ovs_assert(tcph);

    tcph->tcp_src = htons(tcp_src);
    tcph->tcp_dst = htons(tcp_dst);
    put_16aligned_be32(&tcph->tcp_seq, 0);
    put_16aligned_be32(&tcph->tcp_ack, 0);
    tcph->tcp_ctl = TCP_CTL(tcp_flags, TCP_HEADER_LEN / 4);
    tcph->tcp_winsz = htons(65535);
    tcph->tcp_csum = 0;
    tcph->tcp_urg = 0;

    if (tcp_payload && payload_len > 0) {
        /* The caller must have pre-allocated space via build_eth_ip_packet's
         * payload_alloc argument.  Write directly to avoid a realloc that
         * would lose the extra headroom required by the FTP MTU guard. */
        memcpy((char *) tcph + TCP_HEADER_LEN, tcp_payload, payload_len);
    }

    /* Update IP total length and recompute IP checksum. */
    iph = dp_packet_l3(pkt);
    ip_tot_len = IP_HEADER_LEN + TCP_HEADER_LEN + payload_len;
    iph->ip_tot_len = htons(ip_tot_len);
    iph->ip_csum = 0;
    iph->ip_csum = csum(iph, IP_HEADER_LEN);

    /* Compute TCP checksum over pseudo-header + TCP segment. */
    tcp_csum = packet_csum_pseudoheader(iph);
    tcph->tcp_csum = csum_finish(
        csum_continue(tcp_csum, tcph, TCP_HEADER_LEN + payload_len));

    /* Set l3/l4 offsets so conntrack can extract a flow key. */
    flow_extract(pkt, &flow);
    return pkt;
}

static struct dp_packet_batch *
prepare_packets(size_t n, bool change, unsigned tid, ovs_be16 *dl_type)
{
    struct dp_packet_batch *pkt_batch = xzalloc(sizeof *pkt_batch);
    struct flow flow;
    size_t i;

    ovs_assert(n <= ARRAY_SIZE(pkt_batch->packets));

    dp_packet_batch_init(pkt_batch);
    for (i = 0; i < n; i++) {
        struct udp_header *udp;
        struct dp_packet *pkt = dp_packet_new(sizeof payload/2);

        dp_packet_put_hex(pkt, payload, NULL);
        flow_extract(pkt, &flow);

        udp = dp_packet_l4(pkt);
        udp->udp_src = htons(ntohs(udp->udp_src) + tid);

        if (change) {
            udp->udp_dst = htons(ntohs(udp->udp_dst) + i);
        }

        dp_packet_batch_add(pkt_batch, pkt);
        *dl_type = flow.dl_type;
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

/* ALG related testing. */

/* FTP IPv4 PORT payload for testing. */
#define FTP_PORT_CMD_STR  "PORT 192,168,123,2,113,42\r\n"
#define FTP_CMD_PAD       234
#define FTP_PAYLOAD_LEN   (sizeof FTP_PORT_CMD_STR - 1 + FTP_CMD_PAD)

/* Test modify_packet wrapping.
 *
 * The test builds a minimal FTP control-channel exchange:
 *   1. A TCP SYN that creates a conntrack entry with helper=ftp and SNAT.
 *   2. A PSH|ACK carrying "PORT 192,168,123,2,113,42\r\n" padded to exactly
 *      261 bytes of TCP payload, which makes total_size == 256.
 *
 * After the PORT packet is processed the address field in the payload must
 * read "192,168,1,1" (the SNAT address with dots replaced by commas). */
static void
test_ftp_alg_large_payload(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    /* Packet endpoints. */
    struct eth_addr eth_src = ETH_ADDR_C(00, 01, 02, 03, 04, 05);
    struct eth_addr eth_dst = ETH_ADDR_C(00, 06, 07, 08, 09, 0a);
    ovs_be32 ip_src = inet_addr("192.168.123.2"); /* FTP client. */
    ovs_be32 ip_dst = inet_addr("192.168.1.1");   /* FTP server / SNAT addr. */
    uint16_t sport = 12345;
    uint16_t dport = 21;                          /* FTP control port. */

    /* SNAT: rewrite client address to 192.168.1.1 in PORT commands. */
    struct nat_action_info_t nat_info;
    memset(&nat_info, 0, sizeof nat_info);
    nat_info.nat_action = NAT_ACTION_SRC;
    nat_info.min_addr.ipv4 = ip_dst;
    nat_info.max_addr.ipv4 = ip_dst;

    ct = conntrack_init();
    conntrack_set_tcp_seq_chk(ct, false);

    long long now = time_msec();

    struct dp_packet *syn = build_eth_ip_packet(NULL, eth_src, eth_dst,
                                                ip_src, ip_dst,
                                                IPPROTO_TCP, 0);
    build_tcp_packet(syn, sport, dport, TCP_SYN, NULL, 0);

    struct dp_packet_batch syn_batch;
    dp_packet_batch_init_packet(&syn_batch, syn);
    conntrack_execute(ct, &syn_batch, htons(ETH_TYPE_IP), false, true, 0,
                      NULL, NULL, "ftp", &nat_info, now, 0);
    dp_packet_delete_batch(&syn_batch, true);

    /* We get to skip some of the processing because the conntrack execute
     * above will create the required conntrack entries. */

    /* Build the large payload: PORT command followed by padding spaces
     * and a final "\r\n" to reach exactly FTP_PAYLOAD_LEN bytes.  The
     * FTP parser only looks at the first LARGEST_FTP_MSG_OF_INTEREST (128)
     * bytes, so the trailing spaces do not interfere with parsing. */
    char ftp_payload[FTP_PAYLOAD_LEN];
    memcpy(ftp_payload, FTP_PORT_CMD_STR, sizeof FTP_PORT_CMD_STR - 1);
    memset(ftp_payload + sizeof FTP_PORT_CMD_STR - 1, ' ', FTP_CMD_PAD);

    struct dp_packet *port_pkt =
        build_eth_ip_packet(NULL, eth_src, eth_dst, ip_src, ip_dst,
                            IPPROTO_TCP, FTP_PAYLOAD_LEN);
    build_tcp_packet(port_pkt, sport, dport, TCP_PSH | TCP_ACK,
                     ftp_payload, FTP_PAYLOAD_LEN);

    struct dp_packet_batch port_batch;
    dp_packet_batch_init_packet(&port_batch, port_pkt);
    conntrack_execute(ct, &port_batch, htons(ETH_TYPE_IP), false, true, 0,
                      NULL, NULL, "ftp", &nat_info, now, 0);

    struct tcp_header *th = dp_packet_l4(port_pkt);
    size_t tcp_hdr_len = TCP_OFFSET(th->tcp_ctl) * 4;
    const char *ftp_start = (const char *) th + tcp_hdr_len;
    ovs_assert(!strncmp(ftp_start, "PORT 192,168,1,1,", 17));
    dp_packet_delete_batch(&port_batch, true);
    conntrack_destroy(ct);
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
    /* Verifies that the FTP ALG replace_substring function correctly handles
     * a packet whose payload puts total_size at exactly 256 bytes.  The
     * original uint8_t parameter type truncated 256 to 0, leading to a
     * near-SIZE_MAX memmove (heap overflow).  The test confirms the address
     * is rewritten to the SNAT target rather than causing a crash. */
    {"ftp-alg-large-payload", "", 0, 0,
        test_ftp_alg_large_payload, OVS_RO},

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

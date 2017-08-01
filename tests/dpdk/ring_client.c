/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <getopt.h>

#include <config.h>
#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_string_fns.h>
#include <rte_ip.h>
#include <rte_byteorder.h>

#include "util.h"

/* Number of packets to attempt to read from queue. */
#define PKT_READ_SIZE  ((uint16_t)32)

/* Define common names for structures shared between ovs_dpdk and client. */
#define MP_CLIENT_RXQ_NAME "dpdkr%u_tx"
#define MP_CLIENT_TXQ_NAME "dpdkr%u_rx"

#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

/* Our client id number - tells us which rx queue to read, and tx
 * queue to write to.
 */
static unsigned int client_id;

/*
 * Given the rx queue name template above, get the queue name.
 */
static inline const char *
get_rx_queue_name(unsigned int id)
{
    /* Buffer for return value. */
    static char buffer[RTE_RING_NAMESIZE];

    snprintf(buffer, sizeof(buffer), MP_CLIENT_RXQ_NAME, id);
    return buffer;
}

/*
 * Given the tx queue name template above, get the queue name.
 */
static inline const char *
get_tx_queue_name(unsigned int id)
{
    /* Buffer for return value. */
    static char buffer[RTE_RING_NAMESIZE];

    snprintf(buffer, sizeof(buffer), MP_CLIENT_TXQ_NAME, id);
    return buffer;
}

/*
 * Print a usage message.
 */
static void
usage(const char *progname)
{
    printf("\nUsage: %s [EAL args] -- -n <client_id>\n", progname);
}

/*
 * Convert the client id number from a string to an usigned int.
 */
static int
parse_client_num(const char *client)
{
    if (str_to_uint(client, 10, &client_id)) {
        return 0;
    } else {
        return -1;
    }
}

/*
 * Parse the application arguments to the client app.
 */
static int
parse_app_args(int argc, char *argv[])
{
    int option_index = 0, opt = 0;
    char **argvopt = argv;
    const char *progname = NULL;
    static struct option lgopts[] = {
        {NULL, 0, NULL, 0 }
    };
    progname = argv[0];

    while ((opt = getopt_long(argc, argvopt, "n:", lgopts,
        &option_index)) != EOF) {
        switch (opt) {
            case 'n':
                if (parse_client_num(optarg) != 0) {
                    usage(progname);
                    return -1;
                }
                break;
            default:
                usage(progname);
                return -1;
        }
    }

    return 0;
}

/*
 * Application main function - loops through
 * receiving and processing packets. Never returns
 */
int
main(int argc, char *argv[])
{
    struct rte_ring *rx_ring = NULL;
    struct rte_ring *tx_ring = NULL;
    int retval = 0;
    void *pkts[PKT_READ_SIZE];
    int rslt = 0;

    if ((retval = rte_eal_init(argc, argv)) < 0) {
        return -1;
    }

    argc -= retval;
    argv += retval;

    if (parse_app_args(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
    }

    rx_ring = rte_ring_lookup(get_rx_queue_name(client_id));
    if (rx_ring == NULL) {
        rte_exit(EXIT_FAILURE,
            "Cannot get RX ring - is server process running?\n");
    }

    tx_ring = rte_ring_lookup(get_tx_queue_name(client_id));
    if (tx_ring == NULL) {
        rte_exit(EXIT_FAILURE,
            "Cannot get TX ring - is server process running?\n");
    }

    RTE_LOG(INFO, APP, "Finished Process Init.\n");

    printf("\nClient process %u handling packets\n", client_id);
    printf("[Press Ctrl-C to quit ...]\n");

    for (;;) {
        unsigned rx_pkts = PKT_READ_SIZE;

        /* Try dequeuing max possible packets first, if that fails, get the
         * most we can. Loop body should only execute once, maximum.
         */
        while (unlikely(rte_ring_dequeue_bulk(rx_ring, pkts,
                        rx_pkts, NULL) != 0) && rx_pkts > 0) {
            rx_pkts = (uint16_t)RTE_MIN(rte_ring_count(rx_ring), PKT_READ_SIZE);
        }

        if (rx_pkts > 0) {
            /* blocking enqueue */
            do {
                rslt = rte_ring_enqueue_bulk(tx_ring, pkts, rx_pkts, NULL);
            } while (rslt == -ENOBUFS);
        }
    }
}

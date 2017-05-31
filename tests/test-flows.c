/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2017 Nicira, Inc.
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
#undef NDEBUG
#include "flow.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "classifier.h"
#include "openflow/openflow.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "ovstest.h"
#include "dp-packet.h"
#include "pcap-file.h"
#include "timeval.h"
#include "util.h"

static void
test_flows_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ofp10_match expected_match;
    FILE *flows, *pcap;
    int retval;
    int n = 0, errors = 0;

    set_program_name(argv[0]);

    flows = fopen(argv[1], "rb");
    if (!flows) {
        ovs_fatal(errno, "failed to open %s", argv[1]);
    }
    pcap = fopen(argv[2], "rb");
    if (!pcap) {
        ovs_fatal(errno, "failed to open %s", argv[2]);
    }

    retval = ovs_pcap_read_header(pcap);
    if (retval) {
        ovs_fatal(retval > 0 ? retval : 0, "reading pcap header failed");
    }

    while (fread(&expected_match, sizeof expected_match, 1, flows)) {
        struct dp_packet *packet;
        struct ofp10_match extracted_match;
        struct match match;
        struct flow flow;
        n++;

        retval = ovs_pcap_read(pcap, &packet, NULL);
        if (retval == EOF) {
            ovs_fatal(0, "unexpected end of file reading pcap file");
        } else if (retval) {
            ovs_fatal(retval, "error reading pcap file");
        }

        flow_extract(packet, &flow);
        flow.in_port.ofp_port = u16_to_ofp(1);

        match_wc_init(&match, &flow);
        ofputil_match_to_ofp10_match(&match, &extracted_match);

        if (memcmp(&expected_match, &extracted_match, sizeof expected_match)) {
            char *exp_s = ofp10_match_to_string(&expected_match, NULL, 2);
            char *got_s = ofp10_match_to_string(&extracted_match, NULL, 2);
            errors++;
            printf("mismatch on packet #%d (1-based).\n", n);
            printf("Packet:\n");
            ofp_print_packet(stdout, dp_packet_data(packet), dp_packet_size(packet), htonl(PT_ETH));
            ovs_hex_dump(stdout, dp_packet_data(packet), dp_packet_size(packet), 0, true);
            match_print(&match, NULL);
            printf("Expected flow:\n%s\n", exp_s);
            printf("Actually extracted flow:\n%s\n", got_s);
            ovs_hex_dump(stdout, &expected_match, sizeof expected_match, 0, false);
            ovs_hex_dump(stdout, &extracted_match, sizeof extracted_match, 0, false);
            printf("\n");
            free(exp_s);
            free(got_s);
        }

        dp_packet_delete(packet);
    }
    printf("checked %d packets, %d errors\n", n, errors);
    exit(errors != 0);
}

OVSTEST_REGISTER("test-flows", test_flows_main);

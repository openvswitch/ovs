/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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
#include "flow.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "classifier.h"
#include "openflow/openflow.h"
#include "timeval.h"
#include "ofpbuf.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "pcap.h"
#include "util.h"
#include "vlog.h"

#undef NDEBUG
#include <assert.h>

int
main(int argc OVS_UNUSED, char *argv[])
{
    struct ofp_match expected_match;
    FILE *flows, *pcap;
    int retval;
    int n = 0, errors = 0;

    set_program_name(argv[0]);

    flows = stdin;
    pcap = fdopen(3, "rb");
    if (!pcap) {
        ovs_fatal(errno, "failed to open fd 3 for reading");
    }

    retval = pcap_read_header(pcap);
    if (retval) {
        ovs_fatal(retval > 0 ? retval : 0, "reading pcap header failed");
    }

    while (fread(&expected_match, sizeof expected_match, 1, flows)) {
        struct ofpbuf *packet;
        struct ofp_match extracted_match;
        struct cls_rule rule;
        struct flow flow;

        n++;

        retval = pcap_read(pcap, &packet);
        if (retval == EOF) {
            ovs_fatal(0, "unexpected end of file reading pcap file");
        } else if (retval) {
            ovs_fatal(retval, "error reading pcap file");
        }

        flow_extract(packet, 0, 1, &flow);
        cls_rule_init_exact(&flow, 0, &rule);
        ofputil_cls_rule_to_match(&rule, &extracted_match);

        if (memcmp(&expected_match, &extracted_match, sizeof expected_match)) {
            char *exp_s = ofp_match_to_string(&expected_match, 2);
            char *got_s = ofp_match_to_string(&extracted_match, 2);
            errors++;
            printf("mismatch on packet #%d (1-based).\n", n);
            printf("Packet:\n");
            ofp_print_packet(stdout, packet->data, packet->size, packet->size);
            ovs_hex_dump(stdout, packet->data, packet->size, 0, true);
            printf("Expected flow:\n%s\n", exp_s);
            printf("Actually extracted flow:\n%s\n", got_s);
            printf("\n");
            free(exp_s);
            free(got_s);
        }

        ofpbuf_delete(packet);
    }
    printf("checked %d packets, %d errors\n", n, errors);
    return errors != 0;
}


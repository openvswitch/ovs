/*
 * Copyright (c) 2009 Nicira Networks.
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
#include "packets.h"
#include <netinet/in.h>
#include <stdlib.h>
#include "ofpbuf.h"

bool
dpid_from_string(const char *s, uint64_t *dpidp)
{
    *dpidp = (strlen(s) == 16 && strspn(s, "0123456789abcdefABCDEF") == 16
              ? strtoll(s, NULL, 16)
              : 0);
    return *dpidp != 0;
}

bool
eth_addr_from_string(const char *s, uint8_t ea[ETH_ADDR_LEN])
{
    if (sscanf(s, ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(ea))
        == ETH_ADDR_SCAN_COUNT) {
        return true;
    } else {
        memset(ea, 0, ETH_ADDR_LEN);
        return false;
    }
}

/* Fills 'b' with an 802.2 SNAP packet with Ethernet source address 'eth_src',
 * the Nicira OUI as SNAP organization and 'snap_type' as SNAP type.  The text
 * string in 'tag' is enclosed as the packet payload.
 *
 * This function is used by Open vSwitch to compose packets in cases where
 * context is important but content doesn't (or shouldn't) matter.  For this
 * purpose, 'snap_type' should be a random number and 'tag' should be an
 * English phrase that explains the purpose of the packet.  (The English phrase
 * gives hapless admins running Wireshark the opportunity to figure out what's
 * going on.) */
void
compose_benign_packet(struct ofpbuf *b, const char *tag, uint16_t snap_type,
                      const uint8_t eth_src[ETH_ADDR_LEN])
{
    struct eth_header *eth;
    struct llc_snap_header *llc_snap;

    /* Compose basic packet structure.  (We need the payload size to stick into
     * the 802.2 header.) */
    ofpbuf_clear(b);
    eth = ofpbuf_put_zeros(b, ETH_HEADER_LEN);
    llc_snap = ofpbuf_put_zeros(b, LLC_SNAP_HEADER_LEN);
    ofpbuf_put(b, tag, strlen(tag) + 1); /* Includes null byte. */
    ofpbuf_put(b, eth_src, ETH_ADDR_LEN);

    /* Compose 802.2 header. */
    memcpy(eth->eth_dst, eth_addr_broadcast, ETH_ADDR_LEN);
    memcpy(eth->eth_src, eth_src, ETH_ADDR_LEN);
    eth->eth_type = htons(b->size - ETH_HEADER_LEN);

    /* Compose LLC, SNAP headers. */
    llc_snap->llc.llc_dsap = LLC_DSAP_SNAP;
    llc_snap->llc.llc_ssap = LLC_SSAP_SNAP;
    llc_snap->llc.llc_cntl = LLC_CNTL_SNAP;
    memcpy(llc_snap->snap.snap_org, "\x00\x23\x20", 3);
    llc_snap->snap.snap_type = htons(snap_type);
}

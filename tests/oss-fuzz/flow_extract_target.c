#include <config.h>
#include "classifier.h"
#include <assert.h>
#include "fuzzer.h"
#include "dp-packet.h"
#include "flow.h"
#include "openvswitch/ofp-match.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/match.h"
#include "classifier-private.h"

static void
test_flow_hash(const struct flow *flow)
{
    uint32_t hash = flow_hash_5tuple(flow, 0);
    hash = flow_hash_symmetric_l4(flow, 0);
    hash = flow_hash_symmetric_l2(flow, 0);
    hash = flow_hash_symmetric_l3l4(flow, 0, NULL);
    hash = flow_hash_symmetric_l3(flow, 0);
    hash = flow_hash_fields(flow, NX_HASH_FIELDS_ETH_SRC, hash);
    hash = flow_hash_fields(flow, NX_HASH_FIELDS_SYMMETRIC_L4, hash);
    hash = flow_hash_fields(flow, NX_HASH_FIELDS_SYMMETRIC_L3L4, hash);
    hash = flow_hash_fields(flow, NX_HASH_FIELDS_SYMMETRIC_L3L4_UDP, hash);
    hash = flow_hash_fields(flow, NX_HASH_FIELDS_NW_SRC, hash);
    hash = flow_hash_fields(flow, NX_HASH_FIELDS_NW_DST, hash);
    hash = flow_hash_fields(flow, NX_HASH_FIELDS_SYMMETRIC_L3, hash);
    ignore(hash);
}

static void
test_flow_mask(const struct flow *flow)
{
    struct flow_wildcards catchall;

    flow_wildcards_init_catchall(&catchall);
    flow_mask_hash_fields(flow, &catchall, NX_HASH_FIELDS_ETH_SRC);
    flow_mask_hash_fields(flow, &catchall, NX_HASH_FIELDS_SYMMETRIC_L4);
    flow_mask_hash_fields(flow, &catchall, NX_HASH_FIELDS_SYMMETRIC_L3L4);
    flow_mask_hash_fields(flow, &catchall, NX_HASH_FIELDS_SYMMETRIC_L3L4_UDP);
    flow_mask_hash_fields(flow, &catchall, NX_HASH_FIELDS_NW_SRC);
    flow_mask_hash_fields(flow, &catchall, NX_HASH_FIELDS_NW_DST);
    flow_mask_hash_fields(flow, &catchall, NX_HASH_FIELDS_SYMMETRIC_L3);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct dp_packet packet;
    struct flow flow;
    dp_packet_use_const(&packet, data, size);
    flow_extract(&packet, &flow);

    /* Extract flowmap. */
    struct flowmap fmap;
    flow_wc_map(&flow, &fmap);

    /* Parse TCP flags. */
    if (dp_packet_size(&packet) >= ETH_HEADER_LEN) {
        uint16_t tcp_flags = parse_tcp_flags(&packet);
        ignore(tcp_flags);
    }

    /* Count headers. */
    int count = flow_count_vlan_headers(&flow);
    ignore(count);

    /* Extract metadata. */
    struct match flow_metadata;
    flow_get_metadata(&flow, &flow_metadata);

    /* Hashing functions. */
    test_flow_hash(&flow);

    /* Masking functions. */
    test_flow_mask(&flow);

    /* Convert flow to match. */
    struct match match;
    match_wc_init(&match, &flow);

    struct ofp10_match ext_match;
    ofputil_match_to_ofp10_match(&match, &ext_match);

    /* Print match and packet. */
    ofp_print_packet(stdout, dp_packet_data(&packet), dp_packet_size(&packet),
                     htonl(PT_ETH));
    ovs_hex_dump(stdout, dp_packet_data(&packet), dp_packet_size(&packet), 0,
                 true);
    match_print(&match, NULL);

    ovs_hex_dump(stdout, &ext_match, sizeof ext_match, 0, false);

    return 0;
}

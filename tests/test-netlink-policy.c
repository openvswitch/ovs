/*
 * Copyright (c) 2021 Canonical
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

#include <string.h>

#include "netlink.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/types.h"
#include "ovstest.h"
#include "util.h"

/* nla_len is an inline function in the kernel net/netlink header, which we
 * don't necessarilly have at build time, so provide our own with
 * non-conflicting name. */
static int
_nla_len(const struct nlattr *nla) {
    return nla->nla_len - NLA_HDRLEN;
}

static void
test_nl_policy_parse_ll_addr(struct ovs_cmdl_context *ctx OVS_UNUSED) {
    struct nl_policy policy[] = {
        [42] = { .type = NL_A_LL_ADDR,
                 .optional = false, },
    };
    struct nlattr *attrs[ARRAY_SIZE(policy)];
    uint8_t fixture_nl_data_policy_short[] = {
        /* too short according to policy */
        0x04, 0x00, 0x2a, 0x00,
    };
    uint8_t fixture_nl_data_policy_long[] = {
        /* too long according to policy */
        0x19, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x67, 0xfe, 0x80, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xe4, 0x1d, 0x2d, 0x03, 0x00, 0xa5, 0xf0, 0x2f, 0x00,
        0x00,
    };
    uint8_t fixture_nl_data_eth[] = {
        /* valid policy and eth_addr length */
        0x0a, 0x00, 0x2a, 0x00, 0x00, 0x53, 0x00, 0x00, 0x00, 0x2a,
    };
    uint8_t fixture_nl_data_ib[] = {
        /* valid policy and ib_addr length */
        0x18, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x67, 0xfe, 0x80, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xe4, 0x1d, 0x2d, 0x03, 0x00, 0xa5, 0xf0, 0x2f,
    };
    uint8_t fixture_nl_data_invalid[] = {
        /* valid policy but data neither eth_addr nor ib_addr */
        0x0b, 0x00, 0x2a, 0x00, 0x00, 0x53, 0x00, 0x00, 0x00, 0x2a, 0x00,
    };
    struct ofpbuf *buf;

    /* confirm policy fails with too short data */
    buf = ofpbuf_clone_data(&fixture_nl_data_policy_short,
                            sizeof(fixture_nl_data_policy_short));
    ovs_assert(!nl_policy_parse(buf, 0, policy, attrs, ARRAY_SIZE(policy)));
    ofpbuf_delete(buf);
    memset(&attrs, 0, sizeof(*attrs));

    /* confirm policy fails with too long data */
    buf = ofpbuf_clone_data(&fixture_nl_data_policy_long,
                            sizeof(fixture_nl_data_policy_long));
    ovs_assert(!nl_policy_parse(buf, 0, policy, attrs, ARRAY_SIZE(policy)));
    ofpbuf_delete(buf);
    memset(&attrs, 0, sizeof(*attrs));

    /* confirm policy passes and interpret valid ethernet lladdr */
    buf = ofpbuf_clone_data(&fixture_nl_data_eth,
                            sizeof(fixture_nl_data_eth));
    ovs_assert(nl_policy_parse(buf, 0, policy, attrs, ARRAY_SIZE(policy)));
    ovs_assert((_nla_len(attrs[42]) == sizeof(struct eth_addr)));
    struct eth_addr eth_expect = ETH_ADDR_C(00,53,00,00,00,2a);
    struct eth_addr eth_parsed = nl_attr_get_eth_addr(attrs[42]);
    ovs_assert((!memcmp(&eth_expect, &eth_parsed, sizeof(struct eth_addr))));
    ofpbuf_delete(buf);
    memset(&attrs, 0, sizeof(*attrs));

    /* confirm policy passes and interpret valid infiniband lladdr */
    buf = ofpbuf_clone_data(&fixture_nl_data_ib,
                            sizeof(fixture_nl_data_ib));
    ovs_assert(nl_policy_parse(buf, 0, policy, attrs, ARRAY_SIZE(policy)));
    ovs_assert((_nla_len(attrs[42]) == sizeof(struct ib_addr)));
    struct ib_addr ib_expect = {
            .ia = {
                0x00, 0x00, 0x00, 0x67, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xe4, 0x1d, 0x2d, 0x03, 0x00, 0xa5, 0xf0, 0x2f,
            },
    };
    struct ib_addr ib_parsed = nl_attr_get_ib_addr(attrs[42]);
    ovs_assert((!memcmp(&ib_expect, &ib_parsed, sizeof(struct eth_addr))));
    ofpbuf_delete(buf);
    memset(&attrs, 0, sizeof(*attrs));

    /* confirm we're able to detect invalid data that passes policy check, this
     * can happen because the policy defines the data to be between the
     * currently known lladdr sizes of 6 (ETH_ALEN) and 20 (INFINIBAND_ALEN) */
    buf = ofpbuf_clone_data(&fixture_nl_data_invalid,
                            sizeof(fixture_nl_data_invalid));
    ovs_assert(nl_policy_parse(buf, 0, policy, attrs, ARRAY_SIZE(policy)));
    ovs_assert(_nla_len(attrs[42]) != sizeof(struct eth_addr)
               && _nla_len(attrs[42]) != sizeof(struct ib_addr));
    ofpbuf_delete(buf);
    memset(&attrs, 0, sizeof(*attrs));
}

static const struct ovs_cmdl_command commands[] = {
    {"ll_addr", "", 0, 0, test_nl_policy_parse_ll_addr, OVS_RO},
    {NULL, NULL, 0, 0, NULL, OVS_RO},
};

static void
test_netlink_policy(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = {
        .argc = argc - 1,
        .argv = argv + 1,
    };
    ovs_set_program_name(argv[0], OVS_PACKAGE_VERSION);
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-netlink-policy", test_netlink_policy);

/*
 * Copyright (c) 2009, 2010, 2011, 2014 Nicira, Inc.
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
#include "csum.h"
#include <assert.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crc32c.h"
#include "ovstest.h"
#include "packets.h"
#include "random.h"
#include "unaligned.h"
#include "util.h"

struct test_case {
    char *data;
    size_t size;                /* Test requires a multiple of 4. */
    uint16_t csum;
};

#define TEST_CASE(DATA, CSUM) { DATA, (sizeof DATA) - 1, CSUM }

static const struct test_case test_cases[] = {
    /* RFC 1071 section 3. */
    TEST_CASE("\x00\x01\xf2\x03"
              "\xf4\xf5\xf6\xf7",
              0xffff - 0xddf2 /* ~0xddf2 */),

    /* http://www.sbprojects.com/projects/tcpip/theory/theory14.htm */
    TEST_CASE("\x45\x00\x00\x28"
              "\x1F\xFD\x40\x00"
              "\x80\x06\x00\x00"
              "\xC0\xA8\x3B\x0A"
              "\xC0\xA8\x3B\x32",
              0xe345),

    /* http://mathforum.org/library/drmath/view/54379.html */
    TEST_CASE("\x86\x5e\xac\x60"
              "\x71\x2a\x81\xb5",
              0xda60),
};

static void
mark(char c)
{
    putchar(c);
    fflush(stdout);
}

#if 0
/* This code is useful for generating new test cases for RFC 1624 section 4. */
static void
generate_rfc1624_test_case(void)
{
    int i;

    for (i = 0; i < 10000000; i++) {
        uint32_t data[8];
        int j;

        for (j = 0; j < 8; j++) {
            data[j] = random_uint32();
        }
        data[7] &= 0x0000ffff;
        data[7] |= 0x55550000;
        if (ntohs(~csum(data, sizeof data - 2)) == 0xcd7a) {
            ovs_hex_dump(stdout, data, sizeof data, 0, false);
            exit(0);
        }
    }
}
#endif



/* Make sure we get the calculation in RFC 1624 section 4 correct. */
static void
test_rfc1624(void)
{
    /* "...an IP packet header in which a 16-bit field m = 0x5555..." */
    uint8_t data[32] = {
        0xfe, 0x8f, 0xc1, 0x14, 0x4b, 0x6f, 0x70, 0x2a,
        0x80, 0x29, 0x78, 0xc0, 0x58, 0x81, 0x77, 0xaa,
        0x66, 0x64, 0xfc, 0x96, 0x63, 0x97, 0x64, 0xee,
        0x12, 0x53, 0x1d, 0xa9, 0x2d, 0xa9, 0x55, 0x55
    };

    /* "...the one's complement sum of all other header octets is 0xCD7A." */
    assert(ntohs(csum(data, sizeof data - 2)) == 0xffff - 0xcd7a);

    /* "...the header checksum would be:

          HC = ~(0xCD7A + 0x5555)
             = ~0x22D0
             =  0xDD2F"
    */
    assert(ntohs(csum(data, sizeof data)) == 0xdd2f);

    /* "a 16-bit field m = 0x5555 changes to m' = 0x3285..." */
    data[30] = 0x32;
    data[31] = 0x85;

    /* "The new checksum via recomputation is:

          HC' = ~(0xCD7A + 0x3285)
              = ~0xFFFF
              =  0x0000"
    */
    assert(ntohs(csum(data, sizeof data)) == 0x0000);

    /* "Applying [Eqn. 3] to the example above, we get the correct result:

          HC' = ~(C + (-m) + m')
              = ~(0x22D0 + ~0x5555 + 0x3285)
              = ~0xFFFF
              =  0x0000" */
    assert(recalc_csum16(htons(0xdd2f), htons(0x5555), htons(0x3285))
           == htons(0x0000));

    mark('#');
}

/* CRC32C checksum tests, based on Intel IPPs, Chapter 13,
 * ippsCRC32C_8u() example, found at the following location:
 * http://software.intel.com/sites/products/documentation/hpc/ipp/ipps/ */
static void
test_crc32c(void)
{
    int i;
    uint8_t data[48] = {
        0x01, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x18,
        0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    /* iSCSI Read PDU */
    assert(ntohl(crc32c(data, 48)) == 0x563a96d9L);

    /* 32 bytes of all zeroes */
    for (i = 0; i < 32; i++) data[i] = 0x00;
    assert(ntohl(crc32c(data, 32)) == 0xaa36918aL);

    /* 32 bytes of all ones */
    for (i = 0; i < 32; i++) data[i] = 0xff;
    assert(ntohl(crc32c(data, 32)) == 0x43aba862L);

    /* 32 bytes of incrementing 00..1f */
    for (i = 0; i < 32; i++) data[i] = i;
    assert(ntohl(crc32c(data, 32)) == 0x4e79dd46L);

    /* 32 bytes of decrementing 1f..00 */
    for (i  = 0; i < 32; i++) data[i] = 31 - i;
    assert(ntohl(crc32c(data, 32)) == 0x5cdb3f11L);

    mark('#');
}

/* Check the IP pseudoheader calculation. */
static void
test_pseudo(void)
{
    ovs_be16 csum;
    /* Try an IP header similar to one that the tunnel code
     * might generate. */
    struct ip_header ip = {
        .ip_ihl_ver = IP_IHL_VER(5, 4),
        .ip_tos = 0,
        .ip_tot_len = htons(134),
        .ip_id = 0,
        .ip_frag_off = htons(IP_DF),
        .ip_ttl = 64,
        .ip_proto = IPPROTO_UDP,
        .ip_csum = htons(0x1265),
        .ip_src = { .hi = htons(0x1400), .lo = htons(0x0002) },
        .ip_dst = { .hi = htons(0x1400), .lo = htons(0x0001) }
    };

    csum = csum_finish(packet_csum_pseudoheader(&ip));
    assert(csum == htons(0xd779));

    /* And also test something totally different to check for
     * corner cases. */
    memset(&ip, 0xff, sizeof ip);
    csum = csum_finish(packet_csum_pseudoheader(&ip));
    assert(csum == htons(0xff3c));

    mark('#');
}

static void
test_csum_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    const struct test_case *tc;
    int i;

    for (tc = test_cases; tc < &test_cases[ARRAY_SIZE(test_cases)]; tc++) {
        const void *data = tc->data;
        const ovs_be16 *data16 = (OVS_FORCE const ovs_be16 *) data;
        const ovs_be32 *data32 = (OVS_FORCE const ovs_be32 *) data;
        uint32_t partial;

        /* Test csum(). */
        assert(ntohs(csum(tc->data, tc->size)) == tc->csum);
        mark('.');

        /* Test csum_add16(). */
        partial = 0;
        for (i = 0; i < tc->size / 2; i++) {
            partial = csum_add16(partial, get_unaligned_be16(&data16[i]));
        }
        assert(ntohs(csum_finish(partial)) == tc->csum);
        mark('.');

        /* Test csum_add32(). */
        partial = 0;
        for (i = 0; i < tc->size / 4; i++) {
            partial = csum_add32(partial, get_unaligned_be32(&data32[i]));
        }
        assert(ntohs(csum_finish(partial)) == tc->csum);
        mark('.');

        /* Test alternating csum_add16() and csum_add32(). */
        partial = 0;
        for (i = 0; i < tc->size / 4; i++) {
            if (i % 2) {
                partial = csum_add32(partial, get_unaligned_be32(&data32[i]));
            } else {
                ovs_be16 u0 = get_unaligned_be16(&data16[i * 2]);
                ovs_be16 u1 = get_unaligned_be16(&data16[i * 2 + 1]);
                partial = csum_add16(partial, u0);
                partial = csum_add16(partial, u1);
            }
        }
        assert(ntohs(csum_finish(partial)) == tc->csum);
        mark('.');

        /* Test csum_continue(). */
        partial = 0;
        for (i = 0; i < tc->size / 4; i++) {
            if (i) {
                partial = csum_continue(partial, &data32[i], 4);
            } else {
                partial = csum_continue(partial, &data16[i * 2], 2);
                partial = csum_continue(partial, &data16[i * 2 + 1], 2);
            }
        }
        assert(ntohs(csum_finish(partial)) == tc->csum);
        mark('#');
    }

    test_rfc1624();
    test_crc32c();
    test_pseudo();

    /* Test recalc_csum16(). */
    for (i = 0; i < 32; i++) {
        ovs_be16 old_u16, new_u16;
        ovs_be16 old_csum;
        ovs_be16 data[16];
        int j, index;

        for (j = 0; j < ARRAY_SIZE(data); j++) {
            data[j] = (OVS_FORCE ovs_be16) random_uint32();
        }
        old_csum = csum(data, sizeof data);
        index = random_range(ARRAY_SIZE(data));
        old_u16 = data[index];
        new_u16 = data[index] = (OVS_FORCE ovs_be16) random_uint32();
        assert(csum(data, sizeof data)
               == recalc_csum16(old_csum, old_u16, new_u16));
        mark('.');
    }
    mark('#');

    /* Test recalc_csum32(). */
    for (i = 0; i < 32; i++) {
        ovs_be32 old_u32, new_u32;
        ovs_be16 old_csum;
        ovs_be32 data[16];
        int j, index;

        for (j = 0; j < ARRAY_SIZE(data); j++) {
            data[j] = (OVS_FORCE ovs_be32) random_uint32();
        }
        old_csum = csum(data, sizeof data);
        index = random_range(ARRAY_SIZE(data));
        old_u32 = data[index];
        new_u32 = data[index] = (OVS_FORCE ovs_be32) random_uint32();
        assert(csum(data, sizeof data)
               == recalc_csum32(old_csum, old_u32, new_u32));
        mark('.');
    }
    mark('#');

    putchar('\n');
}

OVSTEST_REGISTER("test-csum", test_csum_main);

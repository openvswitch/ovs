/*
 * Copyright (c) 2011 Nicira, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef NDEBUG
#include <assert.h>


static void
test_ipv4_cidr(void)
{
    assert(ip_is_cidr(htonl(0x00000000)));
    assert(ip_is_cidr(htonl(0x80000000)));
    assert(ip_is_cidr(htonl(0xf0000000)));
    assert(ip_is_cidr(htonl(0xffffffe0)));
    assert(ip_is_cidr(htonl(0xffffffff)));

    assert(!ip_is_cidr(htonl(0x00000001)));
    assert(!ip_is_cidr(htonl(0x40000000)));
    assert(!ip_is_cidr(htonl(0x0fffffff)));
    assert(!ip_is_cidr(htonl(0xffffffd0)));
}

static void
test_ipv6_static_masks(void)
{
    /* The 'exact' and 'any' addresses should be identical to
     * 'in6addr_exact' and  'in6addr_any' definitions, but we redefine
     * them here since the pre-defined ones are used in the functions
     * we're testing. */
    struct in6_addr exact   = {{{ 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, \
                                  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff }}};

    struct in6_addr any     = {{{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, \
                                  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }}};

    struct in6_addr neither = {{{ 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef, \
                                  0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef }}};

    assert(ipv6_mask_is_exact(&exact));
    assert(!ipv6_mask_is_exact(&any));
    assert(!ipv6_mask_is_exact(&neither));

    assert(!ipv6_mask_is_any(&exact));
    assert(ipv6_mask_is_any(&any));
    assert(!ipv6_mask_is_any(&neither));

}

static void
test_ipv6_cidr(void)
{
    struct in6_addr dest;

    struct in6_addr src   = {{{ 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, \
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }}};

    dest = ipv6_create_mask(0);
    assert(ipv6_mask_is_any(&dest));
    assert(ipv6_count_cidr_bits(&dest) == 0);
    assert(ipv6_is_cidr(&dest));

    dest = ipv6_create_mask(128);
    assert(ipv6_mask_is_exact(&dest));
    assert(ipv6_count_cidr_bits(&dest) == 128);
    assert(ipv6_is_cidr(&dest));

    dest = ipv6_create_mask(1);
    assert(ipv6_count_cidr_bits(&dest) == 1);
    assert(ipv6_is_cidr(&dest));

    dest = ipv6_create_mask(13);
    assert(ipv6_count_cidr_bits(&dest) == 13);
    assert(ipv6_is_cidr(&dest));

    dest = ipv6_create_mask(64);
    assert(ipv6_count_cidr_bits(&dest) == 64);
    assert(ipv6_is_cidr(&dest));

    dest = ipv6_create_mask(95);
    assert(ipv6_count_cidr_bits(&dest) == 95);
    assert(ipv6_is_cidr(&dest));

    dest = ipv6_create_mask(96);
    assert(ipv6_count_cidr_bits(&dest) == 96);
    assert(ipv6_is_cidr(&dest));

    dest = ipv6_create_mask(97);
    assert(ipv6_count_cidr_bits(&dest) == 97);
    assert(ipv6_is_cidr(&dest));

    dest = ipv6_create_mask(127);
    assert(ipv6_count_cidr_bits(&dest) == 127);
    assert(ipv6_is_cidr(&dest));

    src.s6_addr[8] = 0xf0;
    assert(ipv6_is_cidr(&src));
    assert(ipv6_count_cidr_bits(&src) == 68);

    src.s6_addr[15] = 0x01;
    assert(!ipv6_is_cidr(&src));
    src.s6_addr[15] = 0x00;
    assert(ipv6_is_cidr(&src));

    src.s6_addr[8] = 0x0f;
    assert(!ipv6_is_cidr(&src));
}


static void
test_ipv6_masking(void)
{
    struct in6_addr dest;
    struct in6_addr mask;

    mask = ipv6_create_mask(0);
    dest = ipv6_addr_bitand(&in6addr_exact, &mask);
    assert(ipv6_count_cidr_bits(&dest) == 0);

    mask = ipv6_create_mask(1);
    dest = ipv6_addr_bitand(&in6addr_exact, &mask);
    assert(ipv6_count_cidr_bits(&dest) == 1);

    mask = ipv6_create_mask(13);
    dest = ipv6_addr_bitand(&in6addr_exact, &mask);
    assert(ipv6_count_cidr_bits(&dest) == 13);

    mask = ipv6_create_mask(127);
    dest = ipv6_addr_bitand(&in6addr_exact, &mask);
    assert(ipv6_count_cidr_bits(&dest) == 127);

    mask = ipv6_create_mask(128);
    dest = ipv6_addr_bitand(&in6addr_exact, &mask);
    assert(ipv6_count_cidr_bits(&dest) == 128);
}

int
main(void)
{
    test_ipv4_cidr();
    test_ipv6_static_masks();
    test_ipv6_cidr();
    test_ipv6_masking();

    return 0;
}

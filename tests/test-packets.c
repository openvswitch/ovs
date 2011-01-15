/*
 * Copyright (c) 2011 Nicira Networks.
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

int
main(void)
{
    test_ipv4_cidr();

    return 0;
}

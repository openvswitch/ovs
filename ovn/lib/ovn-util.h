/*
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


#ifndef OVN_UTIL_H
#define OVN_UTIL_H 1

#include "lib/packets.h"

struct sbrec_port_binding;

struct ipv4_netaddr {
    ovs_be32 addr;
    unsigned int plen;
};

struct ipv6_netaddr {
    struct in6_addr addr;
    unsigned int plen;
};

struct lport_addresses {
    struct eth_addr ea;
    size_t n_ipv4_addrs;
    struct ipv4_netaddr *ipv4_addrs;
    size_t n_ipv6_addrs;
    struct ipv6_netaddr *ipv6_addrs;
};

bool
extract_lsp_addresses(char *address, struct lport_addresses *laddrs,
                      bool store_ipv6);

char *
alloc_nat_zone_key(const char *key, const char *type);
#endif

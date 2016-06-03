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

#include <config.h>
#include "ovn-util.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"

VLOG_DEFINE_THIS_MODULE(ovn_util);

/*
 * Extracts the mac, ipv4 and ipv6 addresses from the input param 'address'
 * which should be of the format 'MAC [IP1 IP2 ..]" where IPn should be
 * a valid IPv4 or IPv6 address and stores them in the 'ipv4_addrs' and
 * 'ipv6_addrs' fields of input param 'laddrs'.
 *
 * Return true if at least 'MAC' is found in 'address', false otherwise.
 *
 * The caller must call destroy_lport_addresses().
 */
bool
extract_lsp_addresses(char *address, struct lport_addresses *laddrs)
{
    memset(laddrs, 0, sizeof *laddrs);

    char *buf = address;
    int buf_index = 0;
    char *buf_end = buf + strlen(address);
    if (!ovs_scan_len(buf, &buf_index, ETH_ADDR_SCAN_FMT,
                      ETH_ADDR_SCAN_ARGS(laddrs->ea))) {
        laddrs->ea = eth_addr_zero;
        return false;
    }

    laddrs->ea_s = xasprintf(ETH_ADDR_FMT, ETH_ADDR_ARGS(laddrs->ea));

    ovs_be32 ip4;
    struct in6_addr ip6;
    unsigned int plen;
    char *error;

    /* Loop through the buffer and extract the IPv4/IPv6 addresses
     * and store in the 'laddrs'. Break the loop if invalid data is found.
     */
    buf += buf_index;
    while (buf < buf_end) {
        buf_index = 0;
        error = ip_parse_cidr_len(buf, &buf_index, &ip4, &plen);
        if (!error) {
            laddrs->n_ipv4_addrs++;
            laddrs->ipv4_addrs = xrealloc(laddrs->ipv4_addrs,
                sizeof (struct ipv4_netaddr) * laddrs->n_ipv4_addrs);

            struct ipv4_netaddr *na
                = &laddrs->ipv4_addrs[laddrs->n_ipv4_addrs - 1];

            na->addr = ip4;
            na->mask = be32_prefix_mask(plen);
            na->network = ip4 & na->mask;
            na->plen = plen;

            na->addr_s = xasprintf(IP_FMT, IP_ARGS(ip4));
            na->network_s = xasprintf(IP_FMT, IP_ARGS(na->network));
            na->bcast_s = xasprintf(IP_FMT, IP_ARGS(ip4 | ~na->mask));

            buf += buf_index;
            continue;
        }
        free(error);
        error = ipv6_parse_cidr_len(buf, &buf_index, &ip6, &plen);
        if (!error) {
            laddrs->n_ipv6_addrs++;
            laddrs->ipv6_addrs = xrealloc(
                laddrs->ipv6_addrs,
                sizeof(struct ipv6_netaddr) * laddrs->n_ipv6_addrs);

            struct ipv6_netaddr *na
                = &laddrs->ipv6_addrs[laddrs->n_ipv6_addrs - 1];

            memcpy(&na->addr, &ip6, sizeof(struct in6_addr));
            na->mask = ipv6_create_mask(plen);
            na->network = ipv6_addr_bitand(&ip6, &na->mask);
            na->plen = plen;

            na->addr_s = xmalloc(INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &ip6, na->addr_s, INET6_ADDRSTRLEN);
            na->network_s = xmalloc(INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &na->network, na->network_s, INET6_ADDRSTRLEN);
        }

        if (error) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_INFO_RL(&rl, "invalid syntax '%s' in address", address);
            free(error);
            break;
        }
        buf += buf_index;
    }

    return true;
}

void
destroy_lport_addresses(struct lport_addresses *laddrs)
{
    free(laddrs->ea_s);

    for (int i = 0; i < laddrs->n_ipv4_addrs; i++) {
        free(laddrs->ipv4_addrs[i].addr_s);
        free(laddrs->ipv4_addrs[i].network_s);
        free(laddrs->ipv4_addrs[i].bcast_s);
    }
    free(laddrs->ipv4_addrs);

    for (int i = 0; i < laddrs->n_ipv6_addrs; i++) {
        free(laddrs->ipv6_addrs[i].addr_s);
        free(laddrs->ipv6_addrs[i].network_s);
    }
    free(laddrs->ipv6_addrs);
}

/* Allocates a key for NAT conntrack zone allocation for a provided
 * 'key' record and a 'type'.
 *
 * It is the caller's responsibility to free the allocated memory. */
char *
alloc_nat_zone_key(const char *key, const char *type)
{
    return xasprintf("%s_%s", key, type);
}

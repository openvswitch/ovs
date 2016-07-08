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
 * The caller has to free the 'ipv4_addrs' and 'ipv6_addrs' fields.
 * If input param 'store_ipv6' is true only then extracted ipv6 addresses
 * are stored in 'ipv6_addrs' fields.
 * Return true if at least 'MAC' is found in 'address', false otherwise.
 * Eg 1.
 * If 'address' = '00:00:00:00:00:01 10.0.0.4 fe80::ea2a:eaff:fe28:3390/64
 *                 30.0.0.3/23' and 'store_ipv6' = true
 * then returns true with laddrs->n_ipv4_addrs = 2, naddrs->n_ipv6_addrs = 1.
 *
 * Eg. 2
 * If 'address' = '00:00:00:00:00:01 10.0.0.4 fe80::ea2a:eaff:fe28:3390/64
 *                 30.0.0.3/23' and 'store_ipv6' = false
 * then returns true with laddrs->n_ipv4_addrs = 2, naddrs->n_ipv6_addrs = 0.
 *
 * Eg 3. If 'address' = '00:00:00:00:00:01 10.0.0.4 addr 30.0.0.4', then
 * returns true with laddrs->n_ipv4_addrs = 1 and laddrs->n_ipv6_addrs = 0.
 */
bool
extract_lsp_addresses(char *address, struct lport_addresses *laddrs,
                      bool store_ipv6)
{
    char *buf = address;
    int buf_index = 0;
    char *buf_end = buf + strlen(address);
    if (!ovs_scan_len(buf, &buf_index, ETH_ADDR_SCAN_FMT,
                      ETH_ADDR_SCAN_ARGS(laddrs->ea))) {
        return false;
    }

    ovs_be32 ip4;
    struct in6_addr ip6;
    unsigned int plen;
    char *error;

    laddrs->n_ipv4_addrs = 0;
    laddrs->n_ipv6_addrs = 0;
    laddrs->ipv4_addrs = NULL;
    laddrs->ipv6_addrs = NULL;

    /* Loop through the buffer and extract the IPv4/IPv6 addresses
     * and store in the 'laddrs'. Break the loop if invalid data is found.
     */
    buf += buf_index;
    while (buf < buf_end) {
        buf_index = 0;
        error = ip_parse_cidr_len(buf, &buf_index, &ip4, &plen);
        if (!error) {
            laddrs->n_ipv4_addrs++;
            laddrs->ipv4_addrs = xrealloc(
                laddrs->ipv4_addrs,
                sizeof (struct ipv4_netaddr) * laddrs->n_ipv4_addrs);
            laddrs->ipv4_addrs[laddrs->n_ipv4_addrs - 1].addr = ip4;
            laddrs->ipv4_addrs[laddrs->n_ipv4_addrs - 1].plen = plen;
            buf += buf_index;
            continue;
        }
        free(error);
        error = ipv6_parse_cidr_len(buf, &buf_index, &ip6, &plen);
        if (!error && store_ipv6) {
            laddrs->n_ipv6_addrs++;
            laddrs->ipv6_addrs = xrealloc(
                laddrs->ipv6_addrs,
                sizeof(struct ipv6_netaddr) * laddrs->n_ipv6_addrs);
            memcpy(&laddrs->ipv6_addrs[laddrs->n_ipv6_addrs - 1].addr, &ip6,
                   sizeof(struct in6_addr));
            laddrs->ipv6_addrs[laddrs->n_ipv6_addrs - 1].plen = plen;
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

/* Allocates a key for NAT conntrack zone allocation for a provided
 * 'key' record and a 'type'.
 *
 * It is the caller's responsibility to free the allocated memory. */
char *
alloc_nat_zone_key(const char *key, const char *type)
{
    return xasprintf("%s_%s", key, type);
}

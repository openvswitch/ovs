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
#include "dirs.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-nb-idl.h"
#include "ovn/lib/ovn-sb-idl.h"

VLOG_DEFINE_THIS_MODULE(ovn_util);

static void
add_ipv4_netaddr(struct lport_addresses *laddrs, ovs_be32 addr,
                 unsigned int plen)
{
    laddrs->n_ipv4_addrs++;
    laddrs->ipv4_addrs = xrealloc(laddrs->ipv4_addrs,
        laddrs->n_ipv4_addrs * sizeof *laddrs->ipv4_addrs);

    struct ipv4_netaddr *na = &laddrs->ipv4_addrs[laddrs->n_ipv4_addrs - 1];

    na->addr = addr;
    na->mask = be32_prefix_mask(plen);
    na->network = addr & na->mask;
    na->plen = plen;

    ovs_be32 bcast = addr | ~na->mask;
    inet_ntop(AF_INET, &addr, na->addr_s, sizeof na->addr_s);
    inet_ntop(AF_INET, &na->network, na->network_s, sizeof na->network_s);
    inet_ntop(AF_INET, &bcast, na->bcast_s, sizeof na->bcast_s);
}

static void
add_ipv6_netaddr(struct lport_addresses *laddrs, struct in6_addr addr,
                 unsigned int plen)
{
    laddrs->n_ipv6_addrs++;
    laddrs->ipv6_addrs = xrealloc(laddrs->ipv6_addrs,
        laddrs->n_ipv6_addrs * sizeof *laddrs->ipv6_addrs);

    struct ipv6_netaddr *na = &laddrs->ipv6_addrs[laddrs->n_ipv6_addrs - 1];

    memcpy(&na->addr, &addr, sizeof na->addr);
    na->mask = ipv6_create_mask(plen);
    na->network = ipv6_addr_bitand(&addr, &na->mask);
    na->plen = plen;
    in6_addr_solicited_node(&na->sn_addr, &addr);

    inet_ntop(AF_INET6, &addr, na->addr_s, sizeof na->addr_s);
    inet_ntop(AF_INET6, &na->sn_addr, na->sn_addr_s, sizeof na->sn_addr_s);
    inet_ntop(AF_INET6, &na->network, na->network_s, sizeof na->network_s);
}

/* Returns true if specified address specifies a dynamic address,
 * supporting the following formats:
 *
 *    "dynamic":
 *        Both MAC and IP are to be allocated dynamically.
 *
 *    "xx:xx:xx:xx:xx:xx dynamic":
 *        Use specified MAC address, but allocate an IP address
 *        dynamically.
 */
bool
is_dynamic_lsp_address(const char *address)
{
    struct eth_addr ea;
    int n;
    return (!strcmp(address, "dynamic")
            || (ovs_scan(address, ETH_ADDR_SCAN_FMT" dynamic%n",
                         ETH_ADDR_SCAN_ARGS(ea), &n) && address[n] == '\0'));
}

static bool
parse_and_store_addresses(const char *address, struct lport_addresses *laddrs,
                          int *ofs, bool extract_eth_addr)
{
    memset(laddrs, 0, sizeof *laddrs);

    const char *buf = address;
    const char *const start = buf;
    int buf_index = 0;
    const char *buf_end = buf + strlen(address);

    if (extract_eth_addr) {
        if (!ovs_scan_len(buf, &buf_index, ETH_ADDR_SCAN_FMT,
                          ETH_ADDR_SCAN_ARGS(laddrs->ea))) {
            laddrs->ea = eth_addr_zero;
            *ofs = 0;
            return false;
        }

        snprintf(laddrs->ea_s, sizeof laddrs->ea_s, ETH_ADDR_FMT,
                 ETH_ADDR_ARGS(laddrs->ea));
    }

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
            add_ipv4_netaddr(laddrs, ip4, plen);
            buf += buf_index;
            continue;
        }
        free(error);
        error = ipv6_parse_cidr_len(buf, &buf_index, &ip6, &plen);
        if (!error) {
            add_ipv6_netaddr(laddrs, ip6, plen);
        } else {
            free(error);
            break;
        }
        buf += buf_index;
    }

    *ofs = buf - start;
    return true;
}

/* Extracts the mac, IPv4 and IPv6 addresses from * 'address' which
 * should be of the format "MAC [IP1 IP2 ..] .." where IPn should be a
 * valid IPv4 or IPv6 address and stores them in the 'ipv4_addrs' and
 * 'ipv6_addrs' fields of 'laddrs'.  There may be additional content in
 * 'address' after "MAC [IP1 IP2 .. ]".  The value of 'ofs' that is
 * returned indicates the offset where that additional content begins.
 *
 * Returns true if at least 'MAC' is found in 'address', false otherwise.
 *
 * The caller must call destroy_lport_addresses(). */
bool
extract_addresses(const char *address, struct lport_addresses *laddrs,
                  int *ofs)
{
    return parse_and_store_addresses(address, laddrs, ofs, true);
}

/* Extracts the mac, IPv4 and IPv6 addresses from * 'address' which
 * should be of the format 'MAC [IP1 IP2 ..]" where IPn should be a
 * valid IPv4 or IPv6 address and stores them in the 'ipv4_addrs' and
 * 'ipv6_addrs' fields of 'laddrs'.
 *
 * Return true if at least 'MAC' is found in 'address', false otherwise.
 *
 * The caller must call destroy_lport_addresses(). */
bool
extract_lsp_addresses(const char *address, struct lport_addresses *laddrs)
{
    int ofs;
    bool success = extract_addresses(address, laddrs, &ofs);

    if (success && ofs < strlen(address)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_INFO_RL(&rl, "invalid syntax '%s' in address", address);
    }

    return success;
}

/* Extracts the IPv4 and IPv6 addresses from * 'address' which
 * should be of the format 'IP1 IP2 .." where IPn should be a
 * valid IPv4 or IPv6 address and stores them in the 'ipv4_addrs' and
 * 'ipv6_addrs' fields of 'laddrs'.
 *
 * Return true if at least one IP address is found in 'address',
 * false otherwise.
 *
 * The caller must call destroy_lport_addresses(). */
bool
extract_ip_addresses(const char *address, struct lport_addresses *laddrs)
{
    int ofs;
    if (parse_and_store_addresses(address, laddrs, &ofs, false)) {
        return (laddrs->n_ipv4_addrs || laddrs->n_ipv6_addrs);
    }

    return false;
}

/* Extracts the mac, IPv4 and IPv6 addresses from the
 * "nbrec_logical_router_port" parameter 'lrp'.  Stores the IPv4 and
 * IPv6 addresses in the 'ipv4_addrs' and 'ipv6_addrs' fields of
 * 'laddrs', respectively.  In addition, a link local IPv6 address
 * based on the 'mac' member of 'lrp' is added to the 'ipv6_addrs'
 * field.
 *
 * Return true if a valid 'mac' address is found in 'lrp', false otherwise.
 *
 * The caller must call destroy_lport_addresses(). */
bool
extract_lrp_networks(const struct nbrec_logical_router_port *lrp,
                     struct lport_addresses *laddrs)
{
    memset(laddrs, 0, sizeof *laddrs);

    if (!eth_addr_from_string(lrp->mac, &laddrs->ea)) {
        laddrs->ea = eth_addr_zero;
        return false;
    }
    snprintf(laddrs->ea_s, sizeof laddrs->ea_s, ETH_ADDR_FMT,
             ETH_ADDR_ARGS(laddrs->ea));

    for (int i = 0; i < lrp->n_networks; i++) {
        ovs_be32 ip4;
        struct in6_addr ip6;
        unsigned int plen;
        char *error;

        error = ip_parse_cidr(lrp->networks[i], &ip4, &plen);
        if (!error) {
            if (!ip4) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "bad 'networks' %s", lrp->networks[i]);
                continue;
            }

            add_ipv4_netaddr(laddrs, ip4, plen);
            continue;
        }
        free(error);

        error = ipv6_parse_cidr(lrp->networks[i], &ip6, &plen);
        if (!error) {
            add_ipv6_netaddr(laddrs, ip6, plen);
        } else {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_INFO_RL(&rl, "invalid syntax '%s' in networks",
                         lrp->networks[i]);
            free(error);
        }
    }

    /* Always add the IPv6 link local address. */
    struct in6_addr lla;
    in6_generate_lla(laddrs->ea, &lla);
    add_ipv6_netaddr(laddrs, lla, 64);

    return true;
}

void
destroy_lport_addresses(struct lport_addresses *laddrs)
{
    free(laddrs->ipv4_addrs);
    free(laddrs->ipv6_addrs);
}

/* Allocates a key for NAT conntrack zone allocation for a provided
 * 'key' record and a 'type'.
 *
 * It is the caller's responsibility to free the allocated memory. */
char *
alloc_nat_zone_key(const struct uuid *key, const char *type)
{
    return xasprintf(UUID_FMT"_%s", UUID_ARGS(key), type);
}

const char *
default_nb_db(void)
{
    static char *def;
    if (!def) {
        def = getenv("OVN_NB_DB");
        if (!def) {
            def = xasprintf("unix:%s/ovnnb_db.sock", ovs_rundir());
        }
    }
    return def;
}

const char *
default_sb_db(void)
{
    static char *def;
    if (!def) {
        def = getenv("OVN_SB_DB");
        if (!def) {
            def = xasprintf("unix:%s/ovnsb_db.sock", ovs_rundir());
        }
    }
    return def;
}

/* l3gateway, chassisredirect, and patch
 * are not in this list since they are
 * only set in the SB DB by northd
 */
static const char *OVN_NB_LSP_TYPES[] = {
    "l2gateway",
    "localnet",
    "localport",
    "router",
    "vtep",
};

bool
ovn_is_known_nb_lsp_type(const char *type)
{
    int i;

    if (!type || !type[0]) {
        return true;
    }

    for (i = 0; i < ARRAY_SIZE(OVN_NB_LSP_TYPES); ++i) {
        if (!strcmp(OVN_NB_LSP_TYPES[i], type)) {
            return true;
        }
    }

    return false;
}

uint32_t
sbrec_logical_flow_hash(const struct sbrec_logical_flow *lf)
{
    const struct sbrec_datapath_binding *ld = lf->logical_datapath;
    if (!ld) {
        return 0;
    }

    return ovn_logical_flow_hash(&ld->header_.uuid,
                                 lf->table_id, lf->pipeline,
                                 lf->priority, lf->match, lf->actions);
}

uint32_t
ovn_logical_flow_hash(const struct uuid *logical_datapath,
                      uint8_t table_id, const char *pipeline,
                      uint16_t priority,
                      const char *match, const char *actions)
{
    size_t hash = uuid_hash(logical_datapath);
    hash = hash_2words((table_id << 16) | priority, hash);
    hash = hash_string(pipeline, hash);
    hash = hash_string(match, hash);
    return hash_string(actions, hash);
}

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

#ifndef __CHECKER__
#error "Use this header only with sparse.  It is not a correct implementation."
#endif

#ifndef __NETINET_IP6_SPARSE
#define __NETINET_IP6_SPARSE 1

#include <netinet/in.h>

struct ip6_hdr {
    union {
        struct ip6_hdrctl {
            ovs_be32 ip6_un1_flow;
            ovs_be16 ip6_un1_plen;
            uint8_t ip6_un1_nxt;
            uint8_t ip6_un1_hlim;
        } ip6_un1;
        uint8_t ip6_un2_vfc;
    } ip6_ctlun;
    struct in6_addr ip6_src;
    struct in6_addr ip6_dst;
};

#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim

struct ip6_rthdr {
    uint8_t ip6r_nxt;
    uint8_t ip6r_len;
    uint8_t ip6r_type;
    uint8_t ip6r_segleft;
};

struct ip6_ext {
    uint8_t ip6e_nxt;
    uint8_t ip6e_len;
};

struct ip6_frag {
    uint8_t ip6f_nxt;
    uint8_t ip6f_reserved;
    ovs_be16 ip6f_offlg;
    ovs_be32 ip6f_ident;
};

#define IP6F_OFF_MASK ((OVS_FORCE ovs_be16) 0xfff8)

#endif /* netinet/ip6.h sparse */

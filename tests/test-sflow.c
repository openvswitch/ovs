/*
 * Copyright (c) 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
 * Copyright (c) 2013 InMon Corp.
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
#include "netflow.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <setjmp.h>
#include "command-line.h"
#include "daemon.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/ofpbuf.h"
#include "ovstest.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "socket-util.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"

OVS_NO_RETURN static void usage(void);
static void parse_options(int argc, char *argv[]);

static unixctl_cb_func test_sflow_exit;

/* Datagram. */
#define SFLOW_VERSION_5 5
#define SFLOW_MIN_LEN 36

/* Sample tag numbers. */
#define SFLOW_FLOW_SAMPLE 1
#define SFLOW_COUNTERS_SAMPLE 2
#define SFLOW_FLOW_SAMPLE_EXPANDED 3
#define SFLOW_COUNTERS_SAMPLE_EXPANDED 4

/* Structure element tag numbers. */
#define SFLOW_TAG_CTR_IFCOUNTERS 1
#define SFLOW_TAG_CTR_ETHCOUNTERS 2
#define SFLOW_TAG_CTR_LACPCOUNTERS 7
#define SFLOW_TAG_CTR_OPENFLOWPORT 1004
#define SFLOW_TAG_CTR_PORTNAME 1005
#define SFLOW_TAG_PKT_HEADER 1
#define SFLOW_TAG_PKT_SWITCH 1001
#define SFLOW_TAG_PKT_TUNNEL4_OUT 1023
#define SFLOW_TAG_PKT_TUNNEL4_IN 1024
#define SFLOW_TAG_PKT_TUNNEL_VNI_OUT 1029
#define SFLOW_TAG_PKT_TUNNEL_VNI_IN 1030
#define SFLOW_TAG_PKT_MPLS 1006

/* string sizes */
#define SFL_MAX_PORTNAME_LEN 255

struct sflow_addr {
    enum {
        SFLOW_ADDRTYPE_undefined = 0,
        SFLOW_ADDRTYPE_IP4,
        SFLOW_ADDRTYPE_IP6
    } type;

    union {
        ovs_be32 ip4;
        ovs_be32 ip6[4];
    } a;
};

struct sflow_xdr {
    /* Exceptions. */
    jmp_buf env;
    int errline;

    /* Cursor. */
    ovs_be32 *datap;
    uint32_t i;
    uint32_t quads;

    /* Agent. */
    struct sflow_addr agentAddr;
    char agentIPStr[INET6_ADDRSTRLEN + 2];
    uint32_t subAgentId;
    uint32_t uptime_mS;

    /* Datasource. */
    uint32_t dsClass;
    uint32_t dsIndex;

    /* Sequence numbers. */
    uint32_t dgramSeqNo;
    uint32_t fsSeqNo;
    uint32_t csSeqNo;

    /* Structure offsets. */
    struct {
        uint32_t HEADER;
        uint32_t SWITCH;
        uint32_t TUNNEL4_OUT;
        uint32_t TUNNEL4_IN;
        uint32_t TUNNEL_VNI_OUT;
        uint32_t TUNNEL_VNI_IN;
        uint32_t MPLS;
        uint32_t IFCOUNTERS;
        uint32_t ETHCOUNTERS;
        uint32_t LACPCOUNTERS;
        uint32_t OPENFLOWPORT;
        uint32_t PORTNAME;
    } offset;

    /* Flow sample fields. */
    uint32_t meanSkipCount;
    uint32_t samplePool;
    uint32_t dropEvents;
    uint32_t inputPortFormat;
    uint32_t inputPort;
    uint32_t outputPortFormat;
    uint32_t outputPort;
};

#define SFLOWXDR_try(x) ((x->errline = setjmp(x->env)) == 0)
#define SFLOWXDR_throw(x) longjmp(x->env, __LINE__)
#define SFLOWXDR_assert(x, t) if (!(t)) SFLOWXDR_throw(x)

static void
sflowxdr_init(struct sflow_xdr *x, void *buf, size_t len)
{
    x->datap = buf;
    x->quads = len >> 2;
}

static uint32_t
sflowxdr_next(struct sflow_xdr *x)
{
    return ntohl(x->datap[x->i++]);
}

static ovs_be32
sflowxdr_next_n(struct sflow_xdr *x)
{
    return x->datap[x->i++];
}

static bool
sflowxdr_more(const struct sflow_xdr *x, uint32_t q)
{
    return q + x->i <= x->quads;
}

static void
sflowxdr_skip(struct sflow_xdr *x, uint32_t q)
{
    x->i += q;
}

static uint32_t
sflowxdr_mark(const struct sflow_xdr *x, uint32_t q)
{
    return x->i + q;
}

static bool
sflowxdr_mark_ok(const struct sflow_xdr *x, uint32_t m)
{
    return m == x->i;
}

static void
sflowxdr_mark_unique(struct sflow_xdr *x, uint32_t *pi)
{
    if (*pi) {
        SFLOWXDR_throw(x);
    }
    *pi = x->i;
}

static void
sflowxdr_setc(struct sflow_xdr *x, uint32_t j)
{
    x->i = j;
}

static const char *
sflowxdr_str(const struct sflow_xdr *x)
{
    return (const char *) (x->datap + x->i);
}

static uint64_t
sflowxdr_next_int64(struct sflow_xdr *x)
{
    uint64_t scratch;
    scratch = sflowxdr_next(x);
    scratch <<= 32;
    scratch += sflowxdr_next(x);
    return scratch;
}

static void
process_counter_sample(struct sflow_xdr *x)
{
    if (x->offset.IFCOUNTERS) {
        sflowxdr_setc(x, x->offset.IFCOUNTERS);
        printf("IFCOUNTERS");
        printf(" dgramSeqNo=%"PRIu32, x->dgramSeqNo);
        printf(" ds=%s>%"PRIu32":%"PRIu32,
               x->agentIPStr, x->dsClass, x->dsIndex);
        printf(" csSeqNo=%"PRIu32, x->csSeqNo);
        printf(" ifindex=%"PRIu32, sflowxdr_next(x));
        printf(" type=%"PRIu32, sflowxdr_next(x));
        printf(" ifspeed=%"PRIu64, sflowxdr_next_int64(x));
        printf(" direction=%"PRIu32, sflowxdr_next(x));
        printf(" status=%"PRIu32, sflowxdr_next(x));
        printf(" in_octets=%"PRIu64, sflowxdr_next_int64(x));
        printf(" in_unicasts=%"PRIu32, sflowxdr_next(x));
        printf(" in_multicasts=%"PRIu32, sflowxdr_next(x));
        printf(" in_broadcasts=%"PRIu32, sflowxdr_next(x));
        printf(" in_discards=%"PRIu32, sflowxdr_next(x));
        printf(" in_errors=%"PRIu32, sflowxdr_next(x));
        printf(" in_unknownprotos=%"PRIu32, sflowxdr_next(x));
        printf(" out_octets=%"PRIu64, sflowxdr_next_int64(x));
        printf(" out_unicasts=%"PRIu32, sflowxdr_next(x));
        printf(" out_multicasts=%"PRIu32, sflowxdr_next(x));
        printf(" out_broadcasts=%"PRIu32, sflowxdr_next(x));
        printf(" out_discards=%"PRIu32, sflowxdr_next(x));
        printf(" out_errors=%"PRIu32, sflowxdr_next(x));
        printf(" promiscuous=%"PRIu32, sflowxdr_next(x));
        printf("\n");
    }
    if (x->offset.LACPCOUNTERS) {
        struct eth_addr *mac;
        union {
            ovs_be32 all;
            struct {
                uint8_t actorAdmin;
                uint8_t actorOper;
                uint8_t partnerAdmin;
                uint8_t partnerOper;
            } v;
        } state;

        sflowxdr_setc(x, x->offset.LACPCOUNTERS);
        printf("LACPCOUNTERS");
        mac = (void *)sflowxdr_str(x);
        printf(" sysID="ETH_ADDR_FMT, ETH_ADDR_ARGS(*mac));
        sflowxdr_skip(x, 2);
        mac = (void *)sflowxdr_str(x);
        printf(" partnerID="ETH_ADDR_FMT, ETH_ADDR_ARGS(*mac));
        sflowxdr_skip(x, 2);
        printf(" aggID=%"PRIu32, sflowxdr_next(x));
        state.all = sflowxdr_next_n(x);
        printf(" actorAdmin=0x%"PRIx32, state.v.actorAdmin);
        printf(" actorOper=0x%"PRIx32, state.v.actorOper);
        printf(" partnerAdmin=0x%"PRIx32, state.v.partnerAdmin);
        printf(" partnerOper=0x%"PRIx32, state.v.partnerOper);
        printf(" LACPDUsRx=%"PRIu32, sflowxdr_next(x));
        printf(" markerPDUsRx=%"PRIu32, sflowxdr_next(x));
        printf(" markerRespPDUsRx=%"PRIu32, sflowxdr_next(x));
        printf(" unknownRx=%"PRIu32, sflowxdr_next(x));
        printf(" illegalRx=%"PRIu32, sflowxdr_next(x));
        printf(" LACPDUsTx=%"PRIu32, sflowxdr_next(x));
        printf(" markerPDUsTx=%"PRIu32, sflowxdr_next(x));
        printf(" markerRespPDUsTx=%"PRIu32, sflowxdr_next(x));
        printf("\n");
    }
    if (x->offset.OPENFLOWPORT) {
        sflowxdr_setc(x, x->offset.OPENFLOWPORT);
        printf("OPENFLOWPORT");
        printf(" datapath_id=%"PRIu64, sflowxdr_next_int64(x));
        printf(" port_no=%"PRIu32, sflowxdr_next(x));
        printf("\n");
    }
    if (x->offset.PORTNAME) {
        uint32_t pnLen;
        const char *pnBytes;
        char portName[SFL_MAX_PORTNAME_LEN + 1];
        sflowxdr_setc(x, x->offset.PORTNAME);
        printf("PORTNAME");
        pnLen = sflowxdr_next(x);
        SFLOWXDR_assert(x, (pnLen <= SFL_MAX_PORTNAME_LEN));
        pnBytes = sflowxdr_str(x);
        memcpy(portName, pnBytes, pnLen);
        portName[pnLen] = '\0';
        printf(" portName=%s", portName);
        printf("\n");
    }
    if (x->offset.ETHCOUNTERS) {
        sflowxdr_setc(x, x->offset.ETHCOUNTERS);
        printf("ETHCOUNTERS");
        printf(" dot3StatsAlignmentErrors=%"PRIu32, sflowxdr_next(x));
        printf(" dot3StatsFCSErrors=%"PRIu32, sflowxdr_next(x));
        printf(" dot3StatsSingleCollisionFrames=%"PRIu32, sflowxdr_next(x));
        printf(" dot3StatsMultipleCollisionFrames=%"PRIu32, sflowxdr_next(x));
        printf(" dot3StatsSQETestErrors=%"PRIu32, sflowxdr_next(x));
        printf(" dot3StatsDeferredTransmissions=%"PRIu32, sflowxdr_next(x));
        printf(" dot3StatsLateCollisions=%"PRIu32, sflowxdr_next(x));
        printf(" dot3StatsExcessiveCollisions=%"PRIu32, sflowxdr_next(x));
        printf(" dot3StatsInternalMacTransmitErrors=%"PRIu32,
               sflowxdr_next(x));
        printf(" dot3StatsCarrierSenseErrors=%"PRIu32, sflowxdr_next(x));
        printf(" dot3StatsFrameTooLongs=%"PRIu32, sflowxdr_next(x));
        printf(" dot3StatsInternalMacReceiveErrors=%"PRIu32, sflowxdr_next(x));
        printf(" dot3StatsSymbolErrors=%"PRIu32, sflowxdr_next(x));
        printf("\n");
    }
}

static char
bin_to_hex(int hexit)
{
    return "0123456789ABCDEF"[hexit];
}

static int
print_hex(const char *a, int len, char *buf, int bufLen)
{
    unsigned char nextByte;
    int b = 0;
    int i;

    for (i = 0; i < len; i++) {
        if (b > bufLen - 10) {
            break;
        }
        nextByte = a[i];
        buf[b++] = bin_to_hex(nextByte >> 4);
        buf[b++] = bin_to_hex(nextByte & 0x0f);
        if (i < len - 1) {
            buf[b++] = '-';
        }
    }
    buf[b] = '\0';
    return b;
}

static void
print_struct_ipv4(struct sflow_xdr *x, const char *prefix)
{
    ovs_be32 src, dst;

    printf(" %s_length=%"PRIu32,    prefix, sflowxdr_next(x));
    printf(" %s_protocol=%"PRIu32,  prefix, sflowxdr_next(x));

    src = sflowxdr_next_n(x);
    dst = sflowxdr_next_n(x);
    printf(" %s_src="IP_FMT,        prefix, IP_ARGS(src));
    printf(" %s_dst="IP_FMT,        prefix, IP_ARGS(dst));

    printf(" %s_src_port=%"PRIu32,  prefix, sflowxdr_next(x));
    printf(" %s_dst_port=%"PRIu32,  prefix, sflowxdr_next(x));
    printf(" %s_tcp_flags=%"PRIu32, prefix, sflowxdr_next(x));
    printf(" %s_tos=%"PRIu32,       prefix, sflowxdr_next(x));
}

#define SFLOW_HEX_SCRATCH 1024

static void
process_flow_sample(struct sflow_xdr *x)
{
    if (x->offset.HEADER) {
        uint32_t headerLen;
        char scratch[SFLOW_HEX_SCRATCH];

        printf("HEADER");
        printf(" dgramSeqNo=%"PRIu32, x->dgramSeqNo);
        printf(" ds=%s>%"PRIu32":%"PRIu32,
               x->agentIPStr, x->dsClass, x->dsIndex);
        printf(" fsSeqNo=%"PRIu32, x->fsSeqNo);

        if (x->offset.TUNNEL4_IN) {
            sflowxdr_setc(x, x->offset.TUNNEL4_IN);
            print_struct_ipv4(x, "tunnel4_in");
        }

        if (x->offset.TUNNEL4_OUT) {
            sflowxdr_setc(x, x->offset.TUNNEL4_OUT);
            print_struct_ipv4(x, "tunnel4_out");
        }

        if (x->offset.TUNNEL_VNI_IN) {
            sflowxdr_setc(x, x->offset.TUNNEL_VNI_IN);
            printf( " tunnel_in_vni=%"PRIu32, sflowxdr_next(x));
        }

        if (x->offset.TUNNEL_VNI_OUT) {
            sflowxdr_setc(x, x->offset.TUNNEL_VNI_OUT);
            printf( " tunnel_out_vni=%"PRIu32, sflowxdr_next(x));
        }

        if (x->offset.MPLS) {
            uint32_t addr_type, stack_depth, ii;
            ovs_be32 mpls_lse;
            sflowxdr_setc(x, x->offset.MPLS);
            /* OVS only sets the out_stack. The rest will be blank. */
            /* skip next hop address */
            addr_type = sflowxdr_next(x);
            sflowxdr_skip(x, addr_type == SFLOW_ADDRTYPE_IP6 ? 4 : 1);
            /* skip in_stack */
            stack_depth = sflowxdr_next(x);
            sflowxdr_skip(x, stack_depth);
            /* print out_stack */
            stack_depth = sflowxdr_next(x);
            for(ii = 0; ii < stack_depth; ii++) {
                mpls_lse=sflowxdr_next_n(x);
                printf(" mpls_label_%"PRIu32"=%"PRIu32,
                       ii, mpls_lse_to_label(mpls_lse));
                printf(" mpls_tc_%"PRIu32"=%"PRIu32,
                       ii, mpls_lse_to_tc(mpls_lse));
                printf(" mpls_ttl_%"PRIu32"=%"PRIu32,
                       ii, mpls_lse_to_ttl(mpls_lse));
                printf(" mpls_bos_%"PRIu32"=%"PRIu32,
                       ii, mpls_lse_to_bos(mpls_lse));
            }
        }

        if (x->offset.SWITCH) {
            sflowxdr_setc(x, x->offset.SWITCH);
            printf(" in_vlan=%"PRIu32, sflowxdr_next(x));
            printf(" in_priority=%"PRIu32, sflowxdr_next(x));
            printf(" out_vlan=%"PRIu32, sflowxdr_next(x));
            printf(" out_priority=%"PRIu32, sflowxdr_next(x));
        }

        sflowxdr_setc(x, x->offset.HEADER);
        printf(" meanSkip=%"PRIu32, x->meanSkipCount);
        printf(" samplePool=%"PRIu32, x->samplePool);
        printf(" dropEvents=%"PRIu32, x->dropEvents);
        printf(" in_ifindex=%"PRIu32, x->inputPort);
        printf(" in_format=%"PRIu32, x->inputPortFormat);
        printf(" out_ifindex=%"PRIu32, x->outputPort);
        printf(" out_format=%"PRIu32, x->outputPortFormat);
        printf(" hdr_prot=%"PRIu32, sflowxdr_next(x));
        printf(" pkt_len=%"PRIu32, sflowxdr_next(x));
        printf(" stripped=%"PRIu32, sflowxdr_next(x));
        headerLen = sflowxdr_next(x);
        printf(" hdr_len=%"PRIu32, headerLen);
        print_hex(sflowxdr_str(x), headerLen, scratch, SFLOW_HEX_SCRATCH);
        printf(" hdr=%s", scratch);
        printf("\n");
    }
}

static void
process_datagram(struct sflow_xdr *x)
{
    uint32_t samples, s;

    SFLOWXDR_assert(x, (sflowxdr_next(x) == SFLOW_VERSION_5));

    /* Read the sFlow header. */
    x->agentAddr.type = sflowxdr_next(x);
    switch (x->agentAddr.type) {
    case SFLOW_ADDRTYPE_IP4:
        x->agentAddr.a.ip4 = sflowxdr_next_n(x);
        break;

    case SFLOW_ADDRTYPE_IP6:
        x->agentAddr.a.ip6[0] = sflowxdr_next_n(x);
        x->agentAddr.a.ip6[1] = sflowxdr_next_n(x);
        x->agentAddr.a.ip6[2] = sflowxdr_next_n(x);
        x->agentAddr.a.ip6[3] = sflowxdr_next_n(x);
        break;

    case SFLOW_ADDRTYPE_undefined:
    default:
        SFLOWXDR_throw(x);
        break;
    }
    x->subAgentId = sflowxdr_next(x);
    x->dgramSeqNo = sflowxdr_next(x);
    x->uptime_mS = sflowxdr_next(x);

    /* Store the agent address as a string. */
    if (x->agentAddr.type == SFLOW_ADDRTYPE_IP6) {
        char ipstr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, (const void *) &x->agentAddr.a.ip6,
                  ipstr, INET6_ADDRSTRLEN);
        snprintf(x->agentIPStr, sizeof x->agentIPStr, "[%s]", ipstr);
    } else {
        snprintf(x->agentIPStr, sizeof x->agentIPStr,
                 IP_FMT, IP_ARGS(x->agentAddr.a.ip4));
    }

    /* Array of flow/counter samples. */
    samples = sflowxdr_next(x);
    for (s = 0; s < samples; s++) {
        uint32_t sType = sflowxdr_next(x);
        uint32_t sQuads = sflowxdr_next(x) >> 2;
        uint32_t sMark = sflowxdr_mark(x, sQuads);
        SFLOWXDR_assert(x, sflowxdr_more(x, sQuads));

        switch (sType) {
        case SFLOW_COUNTERS_SAMPLE_EXPANDED:
        case SFLOW_COUNTERS_SAMPLE:
        {
            uint32_t csElements, e;
            uint32_t ceTag, ceQuads, ceMark, csEnd;

            x->csSeqNo = sflowxdr_next(x);
            if (sType == SFLOW_COUNTERS_SAMPLE_EXPANDED) {
                x->dsClass = sflowxdr_next(x);
                x->dsIndex = sflowxdr_next(x);
            } else {
                uint32_t dsCombined = sflowxdr_next(x);
                x->dsClass = dsCombined >> 24;
                x->dsIndex = dsCombined & 0x00FFFFFF;
            }

            csElements = sflowxdr_next(x);
            for (e = 0; e < csElements; e++) {
                SFLOWXDR_assert(x, sflowxdr_more(x,2));
                ceTag = sflowxdr_next(x);
                ceQuads = sflowxdr_next(x) >> 2;
                ceMark = sflowxdr_mark(x, ceQuads);
                SFLOWXDR_assert(x, sflowxdr_more(x,ceQuads));
                /* Only care about selected structures.  Just record their
                 * offsets here. We'll read the fields out later. */
                switch (ceTag) {
                case SFLOW_TAG_CTR_IFCOUNTERS:
                    sflowxdr_mark_unique(x, &x->offset.IFCOUNTERS);
                    break;
                case SFLOW_TAG_CTR_ETHCOUNTERS:
                    sflowxdr_mark_unique(x, &x->offset.ETHCOUNTERS);
                    break;
                case SFLOW_TAG_CTR_LACPCOUNTERS:
                    sflowxdr_mark_unique(x, &x->offset.LACPCOUNTERS);
                    break;
                case SFLOW_TAG_CTR_PORTNAME:
                    sflowxdr_mark_unique(x, &x->offset.PORTNAME);
                    break;
                case SFLOW_TAG_CTR_OPENFLOWPORT:
                    sflowxdr_mark_unique(x, &x->offset.OPENFLOWPORT);
                    break;

                    /* Add others here... */
                }

                sflowxdr_skip(x, ceQuads);
                SFLOWXDR_assert(x, sflowxdr_mark_ok(x, ceMark));
            }

            csEnd = sflowxdr_mark(x, 0);
            process_counter_sample(x);
            /* Make sure we pick up the decoding where we left off. */
            sflowxdr_setc(x, csEnd);

            /* Clear the offsets for the next sample. */
            memset(&x->offset, 0, sizeof x->offset);
        }
        break;

        case SFLOW_FLOW_SAMPLE:
        case SFLOW_FLOW_SAMPLE_EXPANDED:
        {
            uint32_t fsElements, e;
            uint32_t feTag, feQuads, feMark, fsEnd;
            x->fsSeqNo = sflowxdr_next(x);
            if (sType == SFLOW_FLOW_SAMPLE_EXPANDED) {
                x->dsClass = sflowxdr_next(x);
                x->dsIndex = sflowxdr_next(x);
            } else {
                uint32_t dsCombined = sflowxdr_next(x);
                x->dsClass = dsCombined >> 24;
                x->dsIndex = dsCombined & 0x00FFFFFF;
            }
            x->meanSkipCount = sflowxdr_next(x);
            x->samplePool = sflowxdr_next(x);
            x->dropEvents = sflowxdr_next(x);
            if (sType == SFLOW_FLOW_SAMPLE_EXPANDED) {
                x->inputPortFormat = sflowxdr_next(x);
                x->inputPort = sflowxdr_next(x);
                x->outputPortFormat = sflowxdr_next(x);
                x->outputPort = sflowxdr_next(x);
            } else {
                uint32_t inp, outp;

                inp = sflowxdr_next(x);
                outp = sflowxdr_next(x);
                x->inputPortFormat = inp >> 30;
                x->inputPort = inp & 0x3fffffff;
                x->outputPortFormat = outp >> 30;
                x->outputPort = outp & 0x3fffffff;
            }
            fsElements = sflowxdr_next(x);
            for (e = 0; e < fsElements; e++) {
                SFLOWXDR_assert(x, sflowxdr_more(x,2));
                feTag = sflowxdr_next(x);
                feQuads = sflowxdr_next(x) >> 2;
                feMark = sflowxdr_mark(x, feQuads);
                SFLOWXDR_assert(x, sflowxdr_more(x,feQuads));
                /* Only care about selected structures.  Just record their
                 * offsets here. We'll read the fields out below. */
                switch (feTag) {
                case SFLOW_TAG_PKT_HEADER:
                    sflowxdr_mark_unique(x, &x->offset.HEADER);
                    break;

                case SFLOW_TAG_PKT_SWITCH:
                    sflowxdr_mark_unique(x, &x->offset.SWITCH);
                    break;

                case SFLOW_TAG_PKT_TUNNEL4_OUT:
                    sflowxdr_mark_unique(x, &x->offset.TUNNEL4_OUT);
                    break;

                case SFLOW_TAG_PKT_TUNNEL4_IN:
                    sflowxdr_mark_unique(x, &x->offset.TUNNEL4_IN);
                    break;

                case SFLOW_TAG_PKT_TUNNEL_VNI_OUT:
                    sflowxdr_mark_unique(x, &x->offset.TUNNEL_VNI_OUT);
                    break;

                case SFLOW_TAG_PKT_TUNNEL_VNI_IN:
                    sflowxdr_mark_unique(x, &x->offset.TUNNEL_VNI_IN);
                    break;

                case SFLOW_TAG_PKT_MPLS:
                    sflowxdr_mark_unique(x, &x->offset.MPLS);
                    break;

                    /* Add others here... */
                }

                sflowxdr_skip(x, feQuads);
                SFLOWXDR_assert(x, sflowxdr_mark_ok(x, feMark));
            }

            fsEnd = sflowxdr_mark(x, 0);
            process_flow_sample(x);
            /* Make sure we pick up the decoding where we left off. */
            sflowxdr_setc(x, fsEnd);

            /* Clear the offsets for the next counter/flow sample. */
            memset(&x->offset, 0, sizeof x->offset);
        }
        break;

        default:
            /* Skip other sample types. */
            sflowxdr_skip(x, sQuads);
        }
        SFLOWXDR_assert(x, sflowxdr_mark_ok(x, sMark));
    }
}

static void
print_sflow(struct ofpbuf *buf)
{
    char *dgram_buf;
    int dgram_len = buf->size;
    struct sflow_xdr xdrDatagram;
    struct sflow_xdr *x = &xdrDatagram;

    memset(x, 0, sizeof *x);
    if (SFLOWXDR_try(x)) {
        SFLOWXDR_assert(x, (dgram_buf = ofpbuf_try_pull(buf, buf->size)));
        sflowxdr_init(x, dgram_buf, dgram_len);
        SFLOWXDR_assert(x, dgram_len >= SFLOW_MIN_LEN);
        process_datagram(x);
    } else {
        // CATCH
        printf("\n>>>>> ERROR in " __FILE__ " at line %d\n", x->errline);
    }
}

static void
test_sflow_main(int argc, char *argv[])
{
    struct unixctl_server *server;
    enum { MAX_RECV = 1500 };
    const char *target;
    struct ofpbuf buf;
    bool exiting = false;
    int error;
    int sock;

    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    parse_options(argc, argv);

    if (argc - optind != 1) {
        ovs_fatal(0, "exactly one non-option argument required "
                  "(use --help for help)");
    }
    target = argv[optind];

    sock = inet_open_passive(SOCK_DGRAM, target, 0, NULL, 0, true);
    if (sock < 0) {
        ovs_fatal(0, "%s: failed to open (%s)", target, ovs_strerror(-sock));
    }

    daemon_save_fd(STDOUT_FILENO);
    daemonize_start(false);

    error = unixctl_server_create(NULL, &server);
    if (error) {
        ovs_fatal(error, "failed to create unixctl server");
    }
    unixctl_command_register("exit", "", 0, 0, test_sflow_exit, &exiting);

    daemonize_complete();

    ofpbuf_init(&buf, MAX_RECV);
    for (;;) {
        int retval;

        unixctl_server_run(server);

        ofpbuf_clear(&buf);
        do {
            retval = recv(sock, buf.data, buf.allocated, 0);
        } while (retval < 0 && errno == EINTR);
        if (retval > 0) {
            ofpbuf_put_uninit(&buf, retval);
            print_sflow(&buf);
            fflush(stdout);
        }

        if (exiting) {
            break;
        }

        poll_fd_wait(sock, POLLIN);
        unixctl_server_wait(server);
        poll_block();
    }
    ofpbuf_uninit(&buf);
    unixctl_server_destroy(server);
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        DAEMON_OPTION_ENUMS,
        VLOG_OPTION_ENUMS
    };
    static const struct option long_options[] = {
        {"verbose", optional_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        DAEMON_OPTION_HANDLERS
        VLOG_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}

static void
usage(void)
{
    printf("%s: sflow collector test utility\n"
           "usage: %s [OPTIONS] PORT[:IP]\n"
           "where PORT is the UDP port to listen on and IP is optionally\n"
           "the IP address to listen on.\n",
           program_name, program_name);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help                  display this help message\n");
    exit(EXIT_SUCCESS);
}

static void
test_sflow_exit(struct unixctl_conn *conn,
                int argc OVS_UNUSED, const char *argv[] OVS_UNUSED,
                void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
}

OVSTEST_REGISTER("test-sflow", test_sflow_main);

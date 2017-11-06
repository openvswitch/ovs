/*
 * Copyright (c) 2014 VMware, Inc.
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

#include "PacketParser.h"

//XXX consider moving to NdisGetDataBuffer.
const VOID *
OvsGetPacketBytes(const NET_BUFFER_LIST *nbl,
                  UINT32 len,
                  UINT32 srcOffset,
                  VOID *storage)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    PNET_BUFFER netBuffer = NET_BUFFER_LIST_FIRST_NB(nbl);
    PMDL currentMdl;
    BOOLEAN firstMDL = TRUE;
    ULONG destOffset = 0;
    VOID *dest = storage;
    const UINT32 copyLen = len;
    ULONG packetLen;

    packetLen = NET_BUFFER_DATA_LENGTH(netBuffer);
    // Start copy from current MDL
    currentMdl = NET_BUFFER_CURRENT_MDL(netBuffer);

    // Data on current MDL may be offset from start of MDL
    while (destOffset < copyLen && currentMdl) {
        PUCHAR srcMemory = OvsGetMdlWithLowPriority(currentMdl);
        ULONG length = MmGetMdlByteCount(currentMdl);
        if (!srcMemory) {
            status = NDIS_STATUS_RESOURCES;
            break;
        }

        if (firstMDL) {
            ULONG mdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(netBuffer);
            srcMemory += mdlOffset;
            length -= mdlOffset;
            firstMDL = FALSE;
        }
        length = MIN(length, packetLen);
        packetLen -= length;
        ASSERT((INT)packetLen >= 0);

        if (srcOffset >= length) {
            currentMdl = NDIS_MDL_LINKAGE(currentMdl);
            srcOffset -= length;
            continue;
        } else {
            srcMemory += srcOffset;
            length -= srcOffset;
            srcOffset = 0;
        }

        length = min(length, copyLen-destOffset);

        NdisMoveMemory((PUCHAR)dest+destOffset, srcMemory, length);
        destOffset += length;

        currentMdl = NDIS_MDL_LINKAGE(currentMdl);
    }

    if (destOffset == copyLen) {
        ASSERT(status == NDIS_STATUS_SUCCESS);
        return storage;
    }

    return NULL;
}

NDIS_STATUS
OvsParseIPv6(const NET_BUFFER_LIST *packet,
             Ipv6Key *ipv6Key,
             POVS_PACKET_HDR_INFO layers)
{
    UINT16 ofs = layers->l3Offset;
    IPv6Hdr ipv6HdrStorage;
    const IPv6Hdr *nh;
    UINT32 nextHdr;

    nh = OvsGetPacketBytes(packet, sizeof *nh, ofs, &ipv6HdrStorage);
    if (!nh) {
        return NDIS_STATUS_FAILURE;
    }

    nextHdr = nh->nexthdr;
    RtlCopyMemory(&ipv6Key->ipv6Src, nh->saddr.s6_addr, 16);
    RtlCopyMemory(&ipv6Key->ipv6Dst, nh->daddr.s6_addr, 16);

    ipv6Key->nwTos = ((nh->flow_lbl[0] & 0xF0) >> 4) | (nh->priority << 4);
    ipv6Key->ipv6Label =
        ((nh->flow_lbl[0] & 0x0F) << 16) | (nh->flow_lbl[1] << 8) | nh->flow_lbl[2];
    ipv6Key->nwTtl = nh->hop_limit;
    ipv6Key->nwProto = SOCKET_IPPROTO_NONE;
    ipv6Key->nwFrag = OVS_FRAG_TYPE_NONE;

    // Parse extended headers and compute L4 offset
    ofs += sizeof(IPv6Hdr);
    for (;;) {
        if ((nextHdr != SOCKET_IPPROTO_HOPOPTS)
            && (nextHdr != SOCKET_IPPROTO_ROUTING)
            && (nextHdr != SOCKET_IPPROTO_DSTOPTS)
            && (nextHdr != SOCKET_IPPROTO_AH)
            && (nextHdr != SOCKET_IPPROTO_FRAGMENT)) {
             /*
              * It's either a terminal header (e.g., TCP, UDP) or one we
              * don't understand.  In either case, we're done with the
              * packet, so use it to fill in 'nw_proto'.
              */
            break;
        }

        if (nextHdr == SOCKET_IPPROTO_HOPOPTS
            || nextHdr == SOCKET_IPPROTO_ROUTING
            || nextHdr == SOCKET_IPPROTO_DSTOPTS
            || nextHdr == SOCKET_IPPROTO_AH) {
            IPv6ExtHdr extHdrStorage;
            const IPv6ExtHdr *extHdr;
            UINT8 len;

            extHdr = OvsGetPacketBytes(packet, sizeof *extHdr, ofs, &extHdrStorage);
            if (!extHdr) {
                return NDIS_STATUS_FAILURE;
            }

            len = extHdr->hdrExtLen;
            ofs += nextHdr == SOCKET_IPPROTO_AH ? (len + 2) * 4 : (len + 1) * 8;
            nextHdr = extHdr->nextHeader;
            if (OvsPacketLenNBL(packet) < ofs) {
                return NDIS_STATUS_FAILURE;
             }
        } else if (nextHdr == SOCKET_IPPROTO_FRAGMENT) {
            IPv6FragHdr fragHdrStorage;
            const IPv6FragHdr *fragHdr;

            fragHdr = OvsGetPacketBytes(packet, sizeof *fragHdr, ofs,
                                     &fragHdrStorage);
            if (!fragHdr) {
                return NDIS_STATUS_FAILURE;
            }

            nextHdr = fragHdr->nextHeader;
            ofs += sizeof *fragHdr;

            /* We only process the first fragment. */
            if (fragHdr->offlg != htons(0)) {
                if ((fragHdr->offlg & IP6F_OFF_HOST_ORDER_MASK) == htons(0)) {
                    ipv6Key->nwFrag = OVS_FRAG_TYPE_FIRST;
                } else {
                    ipv6Key->nwFrag = OVS_FRAG_TYPE_LATER;
                    nextHdr = SOCKET_IPPROTO_FRAGMENT;
                    break;
                }
            }
        }
    }

    ipv6Key->nwProto = (UINT8)nextHdr;
    layers->l4Offset = ofs;
    return NDIS_STATUS_SUCCESS;
}

VOID
OvsParseTcp(const NET_BUFFER_LIST *packet,
            L4Key *flow,
            POVS_PACKET_HDR_INFO layers)
{
    TCPHdr tcpStorage;
    const TCPHdr *tcp = OvsGetTcp(packet, layers->l4Offset, &tcpStorage);
    if (tcp) {
        if (flow) {
            flow->tpSrc = tcp->source;
            flow->tpDst = tcp->dest;
        }
        if (layers) {
            layers->isTcp = 1;
            layers->l7Offset = layers->l4Offset + 4 * tcp->doff;
        }
    }
}

VOID
OvsParseSctp(const NET_BUFFER_LIST *packet,
             L4Key *flow,
             POVS_PACKET_HDR_INFO layers)
{
    SCTPHdr sctpStorage;
    const SCTPHdr *sctp = OvsGetSctp(packet, layers->l4Offset, &sctpStorage);
    if (sctp) {
        if (flow) {
            flow->tpSrc = sctp->source;
            flow->tpDst = sctp->dest;
        }
        if (layers) {
            layers->isSctp = 1;
            layers->l7Offset = layers->l4Offset + sizeof *sctp;
        }
    }
}

VOID
OvsParseUdp(const NET_BUFFER_LIST *packet,
            L4Key *flow,
            POVS_PACKET_HDR_INFO layers)
{
    UDPHdr udpStorage;
    const UDPHdr *udp = OvsGetUdp(packet, layers->l4Offset, &udpStorage);
    if (udp) {
        if (flow) {
            flow->tpSrc = udp->source;
            flow->tpDst = udp->dest;
        }
        if (layers) {
            layers->isUdp = 1;
            if (udp->check == 0) {
                layers->udpCsumZero = 1;
            }
            layers->l7Offset = layers->l4Offset + sizeof *udp;
        }
    }
}

NDIS_STATUS
OvsParseIcmpV6(const NET_BUFFER_LIST *packet,
               Ipv6Key *ipv6Key,
               Icmp6Key *icmp6Key,
               POVS_PACKET_HDR_INFO layers)
{
    UINT16 ofs = layers->l4Offset;
    ICMPHdr icmpStorage;
    const ICMPHdr *icmp;

    memset(&icmp6Key->ndTarget, 0, sizeof(icmp6Key->ndTarget));
    memset(icmp6Key->arpSha, 0, sizeof(icmp6Key->arpSha));
    memset(icmp6Key->arpTha, 0, sizeof(icmp6Key->arpTha));

    icmp = OvsGetIcmp(packet, ofs, &icmpStorage);
    if (!icmp) {
        return NDIS_STATUS_FAILURE;
    }
    ofs += sizeof *icmp;

    /*
     * The ICMPv6 type and code fields use the 16-bit transport port
     * fields, so we need to store them in 16-bit network byte order.
     */
    if (ipv6Key) {
        ipv6Key->l4.tpSrc = htons(icmp->type);
        ipv6Key->l4.tpDst = htons(icmp->code);
    }

    if (icmp->code == 0 &&
        (icmp->type == ND_NEIGHBOR_SOLICIT ||
        icmp->type == ND_NEIGHBOR_ADVERT)) {
        struct in6_addr ndTargetStorage;
        const struct in6_addr *ndTarget;

        ndTarget = OvsGetPacketBytes(packet, sizeof *ndTarget, ofs,
                                  &ndTargetStorage);
        if (!ndTarget) {
            return NDIS_STATUS_FAILURE;
        }
        icmp6Key->ndTarget = *ndTarget;

        while ((UINT32)(ofs + 8) <= OvsPacketLenNBL(packet)) {
            /*
             * The minimum size of an option is 8 bytes, which also is
             * the size of Ethernet link-layer options.
             */
            IPv6NdOptHdr ndOptStorage;
            const IPv6NdOptHdr *ndOpt;
            UINT16 optLen;

            ndOpt = OvsGetPacketBytes(packet, sizeof *ndOpt, ofs, &ndOptStorage);
            if (!ndOpt) {
                return NDIS_STATUS_FAILURE;
            }

            optLen = ndOpt->len * 8;
            if (!optLen || (UINT32)(ofs + optLen) >  OvsPacketLenNBL(packet)) {
                goto invalid;
            }

            /*
             * Store the link layer address if the appropriate option is
             * provided.  It is considered an error if the same link
             * layer option is specified twice.
             */
            if (ndOpt->type == ND_OPT_SOURCE_LINKADDR && optLen == 8) {
                if (Eth_IsNullAddr(icmp6Key->arpSha)) {
                    memcpy(icmp6Key->arpSha, ndOpt + 1, ETH_ADDR_LENGTH);
                } else {
                    goto invalid;
                }
            } else if (ndOpt->type == ND_OPT_TARGET_LINKADDR && optLen == 8) {
                if (Eth_IsNullAddr(icmp6Key->arpTha)) {
                    memcpy(icmp6Key->arpTha, ndOpt + 1, ETH_ADDR_LENGTH);
                } else {
                    goto invalid;
                }
            }

            ofs += optLen;
        }
    }

    layers->l7Offset = ofs;
    return NDIS_STATUS_SUCCESS;

invalid:
    RtlZeroMemory(&icmp6Key->ndTarget, sizeof(icmp6Key->ndTarget));
    RtlZeroMemory(icmp6Key->arpSha, sizeof(icmp6Key->arpSha));
    RtlZeroMemory(icmp6Key->arpTha, sizeof(icmp6Key->arpTha));

    return NDIS_STATUS_FAILURE;
}

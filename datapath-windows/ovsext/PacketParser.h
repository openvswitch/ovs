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

#ifndef __PACKET_PARSER_H_
#define __PACKET_PARSER_H_ 1

#include "precomp.h"
#include "NetProto.h"

const VOID* OvsGetPacketBytes(const NET_BUFFER_LIST *_pNB, UINT32 len,
                              UINT32 SrcOffset, VOID *storage);
NDIS_STATUS OvsParseIPv6(const NET_BUFFER_LIST *packet, OvsFlowKey *key,
                        POVS_PACKET_HDR_INFO layers);
VOID OvsParseTcp(const NET_BUFFER_LIST *packet, L4Key *flow,
                 POVS_PACKET_HDR_INFO layers);
VOID OvsParseUdp(const NET_BUFFER_LIST *packet, L4Key *flow,
                 POVS_PACKET_HDR_INFO layers);
NDIS_STATUS OvsParseIcmpV6(const NET_BUFFER_LIST *packet, OvsFlowKey *key,
                            POVS_PACKET_HDR_INFO layers);

static __inline ULONG
OvsPacketLenNBL(const NET_BUFFER_LIST *_pNB)
{
    INT length = 0;
    NET_BUFFER *nb;

    nb = NET_BUFFER_LIST_FIRST_NB(_pNB);
    ASSERT(nb);
    while(nb) {
        length += NET_BUFFER_DATA_LENGTH(nb);
        nb = NET_BUFFER_NEXT_NB(nb);
    }

    return length;
}

/*
 * Returns the ctl field from the TCP header in 'packet', or 0 if the field
 * can't be read.  The caller must have ensured that 'packet' contains a TCP
 * header.
 *
 * We can't just use TCPHdr, from netProto.h, for this because that
 * breaks the flags down into individual bit-fields.  We can't even use
 * offsetof because that will try to take the address of a bit-field,
 * which C does not allow.
 */
static UINT16
OvsGetTcpCtl(const NET_BUFFER_LIST *packet, // IN
             const POVS_PACKET_HDR_INFO layers) // IN
{
#define TCP_CTL_OFS 12                // Offset of "ctl" field in TCP header.
#define TCP_FLAGS(CTL) ((CTL) & 0x3f) // Obtain TCP flags from CTL.

    const UINT16 *ctl;
    UINT16 storage;

    ctl = OvsGetPacketBytes(packet, sizeof *ctl, layers->l4Offset + TCP_CTL_OFS,
                         &storage);
    return ctl ? *ctl : 0;
}


static UINT8
OvsGetTcpFlags(const NET_BUFFER_LIST *packet,    // IN
               const OvsFlowKey *key,   // IN
               const POVS_PACKET_HDR_INFO layers) // IN
{
    UNREFERENCED_PARAMETER(key); // should be removed later

    if (layers->isTcp) {
        return TCP_FLAGS(OvsGetTcpCtl(packet, layers));
    } else {
        return 0;
    }
}

static const EtherArp *
OvsGetArp(const NET_BUFFER_LIST *packet,
          UINT32 ofs,
          EtherArp *storage)
{
    return OvsGetPacketBytes(packet, sizeof *storage, ofs, storage);
}

static const IPHdr *
OvsGetIp(const NET_BUFFER_LIST *packet,
         UINT32 ofs,
         IPHdr *storage)
{
    const IPHdr *ip = OvsGetPacketBytes(packet, sizeof *ip, ofs, storage);
    if (ip) {
        int ipLen = ip->ihl * 4;
        if (ipLen >= sizeof *ip && OvsPacketLenNBL(packet) >= ofs + ipLen) {
            return ip;
        }
    }
    return NULL;
}

static const TCPHdr *
OvsGetTcp(const NET_BUFFER_LIST *packet,
          UINT32 ofs,
          TCPHdr *storage)
{
    const TCPHdr *tcp = OvsGetPacketBytes(packet, sizeof *tcp, ofs, storage);
    if (tcp) {
        int tcpLen = tcp->doff * 4;
        if (tcpLen >= sizeof *tcp && OvsPacketLenNBL(packet) >= ofs + tcpLen) {
            return tcp;
        }
    }
    return NULL;
}

static const UDPHdr *
OvsGetUdp(const NET_BUFFER_LIST *packet,
          UINT32 ofs,
          UDPHdr *storage)
{
    return OvsGetPacketBytes(packet, sizeof *storage, ofs, storage);
}

static const ICMPHdr *
OvsGetIcmp(const NET_BUFFER_LIST *packet,
           UINT32 ofs,
           ICMPHdr *storage)
{
    return OvsGetPacketBytes(packet, sizeof *storage, ofs, storage);
}

#endif /* __PACKET_PARSER_H_ */

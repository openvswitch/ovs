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

#include "precomp.h"
#include "Checksum.h"
#include "Flow.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_CHECKSUM
#include "Debug.h"
#include "PacketParser.h"

#ifndef htons
#define htons(_x) (((UINT16)(_x) >> 8) + (((UINT16)(_x) << 8) & 0xff00))
#endif

#ifndef swap64
#define swap64(_x) ((((UINT64)(_x) >> 8) & 0x00ff00ff00ff00ff) + \
                   (((UINT64)(_x) << 8) & 0xff00ff00ff00ff00))
#endif

#define fold64(_x)                             \
     _x = ((_x) >> 32) + ((_x) & 0xffffffff);  \
     _x = (UINT32)(((_x) >> 32) + (_x));       \
     _x = ((_x) >> 16) + ((_x) & 0xffff);      \
     _x = (UINT16)(((_x) >> 16) + (_x))

#define fold32(_x)                             \
     _x = ((_x) >> 16) + ((_x) & 0xffff);      \
     _x = (UINT16)(((_x) >> 16) + (_x))


/*
 *----------------------------------------------------------------------------
 * CalculateOnesComplement --
 *
 *  Given the start address and buffer length, calculate the 1's complement
 *  This routine can be used when multiple buffers are used for a packets.
 *
 *  PLEASE NOTE, even though the last parameter is UINT64, but the assumption
 *  is it will not overflowed after adding the extra data.
 *     ------------------------------------------------
 *
 * Result:
 *    As name indicate, the final data is not 1's complemnent
 *----------------------------------------------------------------------------
 */
UINT64
CalculateOnesComplement(UINT8 *start,
                        UINT16 totalLength,
                        UINT64 initial,
                        BOOLEAN isEvenStart)
{
    UINT64  sum = 0, val;
    UINT64  *src = (UINT64 *)start;
    union {
        UINT32 val;
        UINT8  b8[4];
    } tmp;

    while (totalLength > 7) {
        val = *src;
        sum += (val >> 32) + (val & 0xffffffff);
        src++;
        totalLength -= 8;
    }
    if (totalLength > 3) {
        sum += *(UINT32 *)src;
        src = (UINT64 *)((UINT8 *)src + 4);
        totalLength -= 4;
    }
    start = (UINT8 *)src;
    tmp.val = 0;
    switch (totalLength) {
    case 3:
        tmp.b8[2] = start[2];
    case 2:
        tmp.b8[1] = start[1];
    case 1:
        tmp.b8[0] = start[0];
        sum += tmp.val;
    }
    sum = (isEvenStart ? sum : swap64(sum)) + initial;
    return sum;
}

/*
 *----------------------------------------------------------------------------
 * CalculateChecksum --
 *
 *   Given the start point, and length, calculate the checksum
 *   as 1's complement of 1's comlement.
 *
 *   This assume the checksum field is initailized properly.
 *
 * Input Parameter:
 *    ptr:  point to the data to be checksumed
 *    totalLength: total length of the data
 *    initial: inital value to remit the checksum. Please note this
 *             value should be network byte order value.
 *
 *    The last parameter may be useful where you don't want to set
 *    checksum field to zero, in that case you can pass ~checksum,
 *    this is equivalent of set checksum field to zero.
 *
 * Result:
 *    The result can be assigned to checksum field directly.
 *----------------------------------------------------------------------------
 */
UINT16
CalculateChecksum(UINT8 *ptr,
                  UINT16 totalLength,
                  UINT16 initial)
{
    UINT64  sum = CalculateOnesComplement(ptr, totalLength, initial, TRUE);
    fold64(sum);
    return (UINT16)~sum;
}

/*
 *----------------------------------------------------------------------------
 * CopyAndCalculateOnesComplement --
 *
 *  Given the start address and buffer length, calculate the 1's complement
 *  at same time, copt the data from src to dst.
 *
 *  This routine can be used when multiple buffers are used for a packets.
 *
 *  PLEASE NOTE, even though the last parameter is UINT64, but the assumption
 *  is it will not overflowed after adding the extra data.
 *     ------------------------------------------------
 *
 * Result:
 *    As name indicate, the final data is not 1's complemnent
 *----------------------------------------------------------------------------
 */
UINT64
CopyAndCalculateOnesComplement(UINT8 *dst,
                               UINT8 *src,
                               UINT16 length,
                               UINT64 initial,
                               BOOLEAN isEvenStart)
{
    UINT64  sum =0, val;
    UINT64 *src64, *dst64;
    union {
        UINT32 val;
        UINT8  b8[4];
    } tmp;

    src64 = (UINT64 *)src;
    dst64 = (UINT64 *)dst;

    while (length > 7) {
        val = *src64;
        *dst64 = val;
        sum += (val >> 32) + (val & 0xffffffff);
        src64++;
        dst64++;
        length -= 8;
    }

    if (length > 3) {
        val = *(UINT32 *)src64;
        *(UINT32 *)dst64 = (UINT32)val;
        sum += (UINT32)val;
        dst64 = (UINT64 *)((UINT8 *)dst64 + 4);
        src64 = (UINT64 *)((UINT8 *)src64 + 4);
        length -= 4;
    }
    src = (UINT8 *)src64;
    dst = (UINT8 *)dst64;
    tmp.val = 0;
    switch (length) {
    case 3:
        dst[2] = src[2];
        tmp.b8[2] = src[2];
    case 2:
        dst[1] = src[1];
        tmp.b8[1] = src[1];
    case 1:
        dst[0] = src[0];
        tmp.b8[0] = src[0];
        sum += tmp.val;
    }
    sum = (isEvenStart ? sum : swap64(sum)) + initial;
    return sum;
}

/*
 *----------------------------------------------------------------------------
 * CopyAndCalculateChecksum --
 *
 *  This is similar to CalculateChecksum, except it will also copy data to
 *  destination address.
 *----------------------------------------------------------------------------
 */
UINT16
CopyAndCalculateChecksum(UINT8 *dst,
                         UINT8 *src,
                         UINT16 length,
                         UINT16 initial)
{

    UINT64  sum = CopyAndCalculateOnesComplement(dst, src, length, initial,
                                                 TRUE);
    fold64(sum);
    return (UINT16)~sum;
}


/*
 *----------------------------------------------------------------------------
 * IPChecksum --
 *
 *   Give IP header, calculate the IP checksum.
 *   We assume IP checksum field is initialized properly
 *
 *  Input Pramater:
 *   ipHdr: IP header start point
 *   length: IP header length (potentially include IP options)
 *   initial: same as CalculateChecksum
 *
 *  Result:
 *   The result is already 1's complement, so can be assigned
 *   to checksum field directly
 *----------------------------------------------------------------------------
 */
UINT16
IPChecksum(UINT8 *ipHdr,
           UINT16 length,
           UINT16 initial)
{
    UINT32 sum = initial;
    UINT16 *ptr = (UINT16 *)ipHdr;
    ASSERT((length & 0x3) == 0);
    while (length > 1) {
        sum += ptr[0];
        ptr++;
        length -= 2;
    }
    fold32(sum);
    return (UINT16)~sum;
}

/*
 *----------------------------------------------------------------------------
 *  IPPseudoChecksum --
 *
 *   Give src and dst IP address, protocol value and total
 *   upper layer length(not include IP header, but include
 *   upller layer protocol header, for example it include
 *   TCP header for TCP checksum), calculate the pseudo
 *   checksum, please note this checksum is just 1's complement
 *   addition.
 *
 *  Input Parameter:
 *    src: please note it is in network byte order
 *    dst: same as src
 *    protocol: protocol value in IP header
 *    totalLength: total length of upper layer data including
 *          header.
 *
 *  Result:
 *
 *   This value should be put in TCP checksum field before
 *   calculating TCP checksum using CalculateChecksum with
 *   initial value of 0.
 *----------------------------------------------------------------------------
 */
UINT16
IPPseudoChecksum(UINT32 *src,
                 UINT32 *dst,
                 UINT8 protocol,
                 UINT16 totalLength)
{
    UINT32 sum = (UINT32)htons(totalLength) + htons(protocol);
    sum += (*src >> 16) + (*src & 0xffff);
    sum += (*dst >> 16) + (*dst & 0xffff);
    fold32(sum);
    return (UINT16)sum;
}

/*
 *----------------------------------------------------------------------------
 * IPv6PseudoChecksum --
 *
 *  Given IPv6 src and dst address, upper layer protocol and total
 *  upper layer protocol data length including upper layer header
 *  part, calculate the pseudo checksum for upper layer protocol
 *  checksum.
 *
 *  please note this checksum is just 1's complement addition.
 *
 *  Input Parameter:
 *    src:   src IPv6 address in network byte order
 *    dst:   dst IPv6 address.
 *    protocol: upper layer protocol
 *    totalLength: total length of upper layer data. Please note this is
 *         in host byte order.
 *
 *  Result:
 *
 *  Place in upper layer checksum field before calculate upper layer
 *  checksum.
 *----------------------------------------------------------------------------
 */
UINT16
IPv6PseudoChecksum(UINT32 *src,
                   UINT32 *dst,
                   UINT8 protocol,
                   UINT16 totalLength)
{
    UINT64 sum = (UINT32)htons(totalLength) + htons(protocol);
    sum += (UINT64)src[0] + src[1] + src[2] + src[3];
    sum += (UINT64)dst[0] + dst[1] + dst[2] + dst[3];
    fold64(sum);
    return (UINT16)sum;
}

/*
 *----------------------------------------------------------------------------
 * ChecksumUpdate32 --
 *
 *  Given old checksum value (as it is in checksum field),
 *  prev value of the relevant field in network byte order
 *  new value of the relevant field in the network byte order
 *  calculate the new checksum.
 *  Please check relevant RFC for reference.
 *
 *  Input Pramater:
 *     oldSum: old checksum value in checksum field
 *     prev:   previous value of relevant 32 bit feld in network
 *             byte order.
 *     new:    new value of the relevant 32 bit field in network
 *             byte order.
 *
 *  Result:
 *     new checksum value to be placed in the checksum field.
 *----------------------------------------------------------------------------
 */
UINT16
ChecksumUpdate32(UINT16 oldSum,
                 UINT32 prev,
                 UINT32 newValue)
{
    UINT32 sum = ~prev;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (newValue >> 16) + (newValue & 0xffff);
    sum += (UINT16)~oldSum;
    fold32(sum);
    return (UINT16)~sum;
}


/*
 *----------------------------------------------------------------------------
 * ChecksumUpdate16 --
 *
 *  Given old checksum value (as it is in checksum field),
 *  prev value of the relevant field in network byte order
 *  new value of the relevant field in the network byte order
 *  calculate the new checksum.
 *  Please check relevant RFC for reference.
 *
 *  Input Pramater:
 *     oldSum: old checksum value in checksum field
 *     prev:   previous value of relevant 32 bit feld in network
 *             byte order.
 *     new:    new value of the relevant 32 bit field in network
 *             byte order.
 *
 *  Result:
 *     new checksum value to be placed in the checksum field.
 *----------------------------------------------------------------------------
 */
UINT16
ChecksumUpdate16(UINT16 oldSum,
                 UINT16 prev,
                 UINT16 newValue)
{
    UINT32 sum = (UINT16)~oldSum;
    sum += (UINT32)((UINT16)~prev) + newValue;
    fold32(sum);
    return (UINT16)~sum;
}

/*
 *----------------------------------------------------------------------------
 * CalculateChecksumNB --
 *
 * Calculates checksum over a length of bytes contained in an NB.
 *
 * nb           : NB which contains the packet bytes.
 * csumDataLen  : Length of bytes to be checksummed.
 * offset       : offset to the first bytes of the data stream to be
 *                checksumed.
 *
 * Result:
 *  return 0, if there is a failure.
 *----------------------------------------------------------------------------
 */
UINT16
CalculateChecksumNB(const PNET_BUFFER nb,
                    UINT16 csumDataLen,
                    UINT32 offset)
{
    ULONG mdlLen;
    UINT16 csLen;
    PUCHAR src;
    UINT64 csum = 0;
    PMDL currentMdl;
    ULONG firstMdlLen;
    /* Running count of bytes in remainder of the MDLs including current. */
    ULONG packetLen;

    if ((nb == NULL) || (csumDataLen == 0)
            || (offset >= NET_BUFFER_DATA_LENGTH(nb))
            || (offset + csumDataLen > NET_BUFFER_DATA_LENGTH(nb))) {
        OVS_LOG_ERROR("Invalid parameters - csum length %u, offset %u,"
                "pkt%s len %u", csumDataLen, offset, nb? "":"(null)",
                nb? NET_BUFFER_DATA_LENGTH(nb) : 0);
        return 0;
    }

    currentMdl = NET_BUFFER_CURRENT_MDL(nb);
    packetLen = NET_BUFFER_DATA_LENGTH(nb);
    firstMdlLen =
        MmGetMdlByteCount(currentMdl) - NET_BUFFER_CURRENT_MDL_OFFSET(nb);

    firstMdlLen = MIN(firstMdlLen, packetLen);
    if (offset < firstMdlLen) {
        src = (PUCHAR) MmGetSystemAddressForMdlSafe(currentMdl, LowPagePriority);
        if (!src) {
            return 0;
        }
        src += (NET_BUFFER_CURRENT_MDL_OFFSET(nb) + offset);
        mdlLen = firstMdlLen - offset;
        packetLen -= firstMdlLen;
        ASSERT((INT)packetLen >= 0);
    } else {
        offset -= firstMdlLen;
        packetLen -= firstMdlLen;
        ASSERT((INT)packetLen >= 0);
        currentMdl = NDIS_MDL_LINKAGE(currentMdl);
        mdlLen = MmGetMdlByteCount(currentMdl);
        mdlLen = MIN(mdlLen, packetLen);

        while (offset >= mdlLen) {
            offset -= mdlLen;
            packetLen -= mdlLen;
            ASSERT((INT)packetLen >= 0);
            currentMdl = NDIS_MDL_LINKAGE(currentMdl);
            mdlLen = MmGetMdlByteCount(currentMdl);
            mdlLen = MIN(mdlLen, packetLen);
        }

        src = (PUCHAR)MmGetSystemAddressForMdlSafe(currentMdl, LowPagePriority);
        if (!src) {
            return 0;
        }

        src += offset;
        mdlLen -= offset;
    }

    while (csumDataLen && (currentMdl != NULL)) {
        ASSERT(mdlLen < 65536);
        csLen = MIN((UINT16) mdlLen, csumDataLen);
        //XXX Not handling odd bytes yet.
        ASSERT(((csLen & 0x1) == 0) || csumDataLen <= mdlLen);

        csum = CalculateOnesComplement(src, csLen, csum, TRUE);
        fold64(csum);

        csumDataLen -= csLen;
        currentMdl = NDIS_MDL_LINKAGE(currentMdl);
        if (csumDataLen && currentMdl) {
            src = MmGetSystemAddressForMdlSafe(currentMdl, LowPagePriority);
            if (!src) {
                return 0;
            }

            mdlLen = MmGetMdlByteCount(currentMdl);
            mdlLen = MIN(mdlLen, packetLen);
            /* packetLen does not include the current MDL from here on. */
            packetLen -= mdlLen;
            ASSERT((INT)packetLen >= 0);
        }
    }

    ASSERT(csumDataLen == 0);
    ASSERT((csum & ~0xffff) == 0);
    return (UINT16) ~csum;
}

/*
 * --------------------------------------------------------------------------
 * OvsValidateIPChecksum
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsValidateIPChecksum(PNET_BUFFER_LIST curNbl,
                      POVS_PACKET_HDR_INFO hdrInfo)
{
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;
    uint16_t checksum, hdrChecksum;
    struct IPHdr ip_storage;
    const IPHdr *ipHdr;

    if (!hdrInfo->isIPv4) {
        return NDIS_STATUS_SUCCESS;
    }

    /* First check if NIC has indicated checksum failure. */
    csumInfo.Value = NET_BUFFER_LIST_INFO(curNbl,
                                          TcpIpChecksumNetBufferListInfo);
    if (csumInfo.Receive.IpChecksumFailed) {
        return NDIS_STATUS_FAILURE;
    }

    /* Next, check if the NIC did not validate the RX checksum. */
    if (!csumInfo.Receive.IpChecksumSucceeded) {
        ipHdr = OvsGetIp(curNbl, hdrInfo->l3Offset, &ip_storage);
        if (ipHdr) {
            ip_storage = *ipHdr;
            hdrChecksum = ipHdr->check;
            ip_storage.check = 0;
            checksum = IPChecksum((uint8 *)&ip_storage, ipHdr->ihl * 4, 0);
            if (checksum != hdrChecksum) {
                return NDIS_STATUS_FAILURE;
            }
        }
    }
    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsValidateUDPChecksum
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsValidateUDPChecksum(PNET_BUFFER_LIST curNbl, BOOLEAN udpCsumZero)
{
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;

    csumInfo.Value = NET_BUFFER_LIST_INFO(curNbl, TcpIpChecksumNetBufferListInfo);

    if (udpCsumZero) {
        /* Zero is valid checksum. */
        csumInfo.Receive.UdpChecksumFailed = 0;
        NET_BUFFER_LIST_INFO(curNbl, TcpIpChecksumNetBufferListInfo) = csumInfo.Value;
        return NDIS_STATUS_SUCCESS;
    }

    /* First check if NIC has indicated UDP checksum failure. */
    if (csumInfo.Receive.UdpChecksumFailed) {
        return NDIS_STATUS_INVALID_PACKET;
    }

    return NDIS_STATUS_SUCCESS;
}

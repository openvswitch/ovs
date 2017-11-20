/*
 * Copyright (c) 2014, 2016 VMware, Inc.
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

#ifndef __OFFLOAD_H_
#define __OFFLOAD_H_ 1

typedef union _OVS_PACKET_HDR_INFO *POVS_PACKET_HDR_INFO;

UINT16 CalculateChecksum(UINT8 *ptr, UINT16 length, UINT16 initial);
UINT16 CopyAndCalculateChecksum(UINT8 *dst, UINT8 *src, UINT16 length,
                                UINT16 initial);
UINT16 IPChecksum(UINT8 *ipHdr, UINT16 length, UINT16 initial);
UINT16 IPPseudoChecksum(UINT32 *src, UINT32 *dst, UINT8 protocol,
                        UINT16 totalLength);
UINT16 IPv6PseudoChecksum(UINT32 *src, UINT32 *dst, UINT8 protocol,
                          UINT16 totalLength);
UINT16 ChecksumUpdate32(UINT16 oldSum, UINT32 prev, UINT32 newValue);
UINT16 ChecksumUpdate16(UINT16 oldSum, UINT16 prev, UINT16 newValue);
UINT16 CalculateChecksumNB(const PNET_BUFFER nb, UINT16 csumDataLen,
                           UINT32 offset);
NDIS_STATUS OvsValidateIPChecksum(PNET_BUFFER_LIST curNbl,
                                  POVS_PACKET_HDR_INFO hdrInfo);
NDIS_STATUS OvsValidateUDPChecksum(PNET_BUFFER_LIST curNbl,
                                   BOOLEAN udpCsumZero);
NDIS_STATUS OvsCalculateUDPChecksum(PNET_BUFFER_LIST curNbl,
                                    PNET_BUFFER curNb,
                                    IPHdr *ipHdr,
                                    UDPHdr *udpHdr,
                                    UINT32 packetLength,
                                    POVS_PACKET_HDR_INFO layers);

ULONG OVSGetTcpMSS(PNET_BUFFER_LIST nbl);

NDIS_STATUS OvsApplySWChecksumOnNB(POVS_PACKET_HDR_INFO layers,
                                   PNET_BUFFER_LIST nbl,
                                   PNDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO
                                                                     csumInfo);

#endif /* __OFFLOAD_H_ */

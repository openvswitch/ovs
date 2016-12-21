/*
 * Copyright (c) 2016 VMware, Inc.
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

#include "Conntrack.h"
#include "PacketParser.h"

/* Eg: 227 Entering Passive Mode (a1,a2,a3,a4,p1,p2)*/
#define FTP_PASV_RSP_PREFIX "227"

typedef enum FTP_TYPE {
    FTP_TYPE_PASV = 1,
    FTP_TYPE_ACTIVE
} FTP_TYPE;

static __inline UINT32
OvsStrncmp(const char *s1, const char *s2, size_t n)
{
    if (!s1 || !s2) {
        return 0;
    }

    const char *s2end = s2 + n;
    while (s2 < s2end && *s2 != '\0' && toupper(*s1) == toupper(*s2)) {
        s1++, s2++;
    }

    if (s2end == s2) {
        return 0;
    }

    return (UINT32)(toupper(*s1) - toupper(*s2));
}

static __inline VOID
OvsStrlcpy(char *dest, const char *src, size_t size)
{
    /* XXX Replace ret with strlen(src) instead. */
    size_t ret = size;
    if (size) {
       size_t len = (ret >= size) ? size - 1 : ret;
       memcpy(dest, src, len);
       dest[len] = '\0';
   }
}

/*
 *---------------------------------------------------------------------------
 * OvsCtExtractNumbers
 * Returns an array of numbers after parsing the string.
 *    Eg: PASV: 192,168,0,1,5,6 -> {192,168,0,1,5,6}
 *        EPRT: 192.168.0.1 -> {192,168,0,1}
 *
 *---------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsCtExtractNumbers(char *buf,
                    UINT32 bufLen,
                    UINT32 arr[],
                    UINT32 arrLen,
                    char delimiter)
{
    if (!buf) {
        return  NDIS_STATUS_INVALID_PACKET;
    }

    UINT32 i = 0;

    while (*buf != '\0') {
        if (i >= bufLen || i >= arrLen) {
            /* Non-standard FTP command */
            return NDIS_STATUS_INVALID_PARAMETER;
        }

        /* Parse the number */
        if (*buf >= '0' && *buf <= '9') {
            arr[i] = arr[i] * 10 + *buf - '0';
        } else if (*buf == delimiter) {
            i++;
        } else {
            /* End of FTP response is either ) or \r\n */
            if (*buf == ')' || *buf == '\r' || *buf == '\n') {
                return NDIS_STATUS_SUCCESS;
            }
            /* Could be non-numerals or space */
        }
        buf++;
    }

    /* Parsing ended without the correct format */
    return NDIS_STATUS_INVALID_PARAMETER;
}

/*
 *----------------------------------------------------------------------------
 * OvsCtHandleFtp
 *     Extract the FTP control data from the packet and created a related
 *     entry if it's a valid connection. This method doesn't support extended
 *     FTP yet. Supports PORT and PASV commands.
 *     Eg:
 *     'PORT 192,168,137,103,192,22\r\n' -> '192.168.137.103' and 49174
 *     '227 Entering Passive Mode (192,168,137,104,194,14)\r\n' gets extracted
 *      to '192.168.137.104' and 49678
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsCtHandleFtp(PNET_BUFFER_LIST curNbl,
               OvsFlowKey *key,
               OVS_PACKET_HDR_INFO *layers,
               UINT64 currentTime,
               POVS_CT_ENTRY entry,
               BOOLEAN request)
{
    NDIS_STATUS status;
    FTP_TYPE ftpType = 0;
    const char *buf;
    char temp[256] = { 0 };
    char ftpMsg[256] = { 0 };

    TCPHdr tcpStorage;
    const TCPHdr *tcp;
    tcp = OvsGetTcp(curNbl, layers->l4Offset, &tcpStorage);
    if (!tcp) {
        return NDIS_STATUS_INVALID_PACKET;
    }

    UINT32 len = OvsGetTcpPayloadLength(curNbl);
    if (len > sizeof(temp)) {
        /* We only care up to 256 */
        len = sizeof(temp);
    }

    buf = OvsGetPacketBytes(curNbl, len,
                            layers->l4Offset + TCP_HDR_LEN(tcp),
                            temp);
    if (buf == NULL) {
        return NDIS_STATUS_INVALID_PACKET;
    }

    OvsStrlcpy((char *)ftpMsg, (char *)buf, min(len, sizeof(ftpMsg)));
    char *req = NULL;

    if (request) {
        if ((len >= 5) && (OvsStrncmp("PORT", ftpMsg, 4) == 0)) {
            ftpType = FTP_TYPE_ACTIVE;
            req = ftpMsg + 4;
        }
    } else {
        if ((len >= 4) && (OvsStrncmp(FTP_PASV_RSP_PREFIX, ftpMsg, 3) == 0)) {
            ftpType = FTP_TYPE_PASV;
            /* There are various formats for PASV command. We try to support
             * some of them. This has been addressed by RFC 2428 - EPSV.
             * Eg:
             *    227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).
             *    227 Entering Passive Mode (h1,h2,h3,h4,p1,p2
             *    227 Entering Passive Mode. h1,h2,h3,h4,p1,p2
             *    227 =h1,h2,h3,h4,p1,p2
             */
            char *paren;
            paren = strchr(ftpMsg, '(');
            if (paren) {
                req = paren + 1;
            } else {
                /* PASV command without ( */
                req = ftpMsg + 3;
            }
        }
    }

    if (req == NULL) {
        /* Not a PORT/PASV control packet */
        return NDIS_STATUS_SUCCESS;
    }

    UINT32 arr[6] = {0};
    status = OvsCtExtractNumbers(req, len, arr, 6, ',');

    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    UINT32 ip = ntohl((arr[0] << 24) | (arr[1] << 16) |
                      (arr[2] << 8) | arr[3]);
    UINT16 port = ntohs(((arr[4] << 8) | arr[5]));

    switch (ftpType) {
    case FTP_TYPE_PASV:
        /* Ensure that the command states Server's IP address */
        ASSERT(ip == key->ipKey.nwSrc);

        OvsCtRelatedEntryCreate(key->ipKey.nwProto,
                                key->l2.dlType,
                                /* Server's IP */
                                ip,
                                /* Use intended client's IP */
                                key->ipKey.nwDst,
                                /* Dynamic port opened on server */
                                port,
                                /* We don't know the client port */
                                0,
                                currentTime,
                                entry);
        break;
    case FTP_TYPE_ACTIVE:
        OvsCtRelatedEntryCreate(key->ipKey.nwProto,
                                key->l2.dlType,
                                /* Server's default IP address */
                                key->ipKey.nwDst,
                                /* Client's IP address */
                                ip,
                                /* FTP Data Port is 20 */
                                ntohs(IPPORT_FTP_DATA),
                                /* Port opened up on Client */
                                port,
                                currentTime,
                                entry);
        break;
    default:
        OVS_LOG_ERROR("invalid ftp type:%d", ftpType);
        status = NDIS_STATUS_INVALID_PARAMETER;
        break;
    }

    return status;
}

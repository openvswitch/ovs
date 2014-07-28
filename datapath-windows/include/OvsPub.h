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

#ifndef __OVS_PUB_H_
#define __OVS_PUB_H_ 1

/* Needed by netlink-protocol.h */
#define BUILD_ASSERT(EXPR) \
      typedef char AssertOnCompileFailed[(EXPR) ? 1: -1]
#define BUILD_ASSERT_DECL(EXPR) BUILD_ASSERT(EXPR)

#include "OvsNetlink.h"

#define OVS_DRIVER_MAJOR_VER 1
#define OVS_DRIVER_MINOR_VER 0

#define OVS_DEVICE_TYPE 45000
#define OVS_IOCTL_TYPE  OVS_DEVICE_TYPE
#define OVS_DP_NUMBER   ((uint32_t) 0)
#define OVSWIN_DEVICE_NAME_MAX_LENGTH 32

#define IFF_RUNNING 0x20
#define IFF_PROMISC 0x40

#define OVS_MAX_OPAQUE_NETWORK_ID_LEN 128

#define OVS_NT_DEVICE_NAME     L"\\Device\\OvsIoctl"
#define OVS_DOS_DEVICE_NAME    L"\\DosDevices\\OvsIoctl"
#define OVS_USER_DEVICE_PATH   TEXT("\\\\.\\OvsIoctl")

#define OVS_IOCTL_DP_START   0x100
#define OVS_IOCTL_DP_DUMP \
   CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_DP_START + 0x0, METHOD_BUFFERED, FILE_READ_ACCESS)
#define OVS_IOCTL_DP_GET \
   CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_DP_START + 0x1, METHOD_OUT_DIRECT, FILE_READ_ACCESS)
#define OVS_IOCTL_DP_SET \
   CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_DP_START + 0x2, METHOD_IN_DIRECT, FILE_WRITE_ACCESS)
#define OVS_IOCTL_DP_TIMESTAMP_SET \
   CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_DP_START + 0x3, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define OVS_IOCTL_VPORT_START 0x200
#define OVS_IOCTL_VPORT_DUMP \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_VPORT_START + 0x0, METHOD_OUT_DIRECT, FILE_READ_ACCESS)
#define OVS_IOCTL_VPORT_GET \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_VPORT_START + 0x1, METHOD_OUT_DIRECT, FILE_READ_ACCESS)
#define OVS_IOCTL_VPORT_SET \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_VPORT_START + 0x2, METHOD_IN_DIRECT, FILE_WRITE_ACCESS)
#define OVS_IOCTL_VPORT_ADD \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_VPORT_START + 0x3, METHOD_IN_DIRECT, FILE_WRITE_ACCESS)
#define OVS_IOCTL_VPORT_DEL \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_VPORT_START + 0x4, METHOD_IN_DIRECT, FILE_WRITE_ACCESS)
#define OVS_IOCTL_VPORT_EXT_INFO \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_VPORT_START + 0x5, METHOD_OUT_DIRECT, FILE_READ_ACCESS)

#define OVS_IOCTL_FLOW_START 0x300
#define OVS_IOCTL_FLOW_DUMP \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_FLOW_START + 0x0, METHOD_OUT_DIRECT, FILE_READ_ACCESS)
#define OVS_IOCTL_FLOW_GET \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_FLOW_START + 0x1, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define OVS_IOCTL_FLOW_PUT \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_FLOW_START + 0x2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OVS_IOCTL_FLOW_FLUSH \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_FLOW_START + 0x3, METHOD_BUFFERED, FILE_WRITE_ACCESS)


#define OVS_IOCTL_QOS_START 0x400
#define OVS_IOCTL_QOS_QUEUE_DUMP \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_QOS_START + 0x0, METHOD_OUT_DIRECT, FILE_READ_ACCESS)
#define OVS_IOCTL_QOS_QUEUE_GET \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_QOS_START + 0x1, METHOD_OUT_DIRECT, FILE_READ_ACCESS)
#define OVS_IOCTL_QOS_QUEUE_SET \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_QOS_START + 0x2, METHOD_IN_DIRECT, FILE_WRITE_ACCESS)


#define OVS_IOCTL_DATAPATH_START 0x500
#define OVS_IOCTL_DATAPATH_SUBSCRIBE \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_DATAPATH_START + 0x0, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define OVS_IOCTL_DATAPATH_READ \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_DATAPATH_START + 0x1, METHOD_OUT_DIRECT, FILE_READ_ACCESS)
#define OVS_IOCTL_DATAPATH_EXECUTE \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_DATAPATH_START + 0x2, METHOD_IN_DIRECT, FILE_WRITE_ACCESS)
#define OVS_IOCTL_DATAPATH_OPERATE \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_DATAPATH_START + 0x3, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define OVS_IOCTL_DATAPATH_PURGE \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_DATAPATH_START + 0x4, METHOD_NEITHER, FILE_ANY_ACCESS)
#define OVS_IOCTL_DATAPATH_WAIT \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_DATAPATH_START + 0x5, METHOD_NEITHER, FILE_ANY_ACCESS)



#define OVS_IOCTL_EVENT_START 0x600
#define OVS_IOCTL_EVENT_SUBSCRIBE \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_EVENT_START + 0x0, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define OVS_IOCTL_EVENT_POLL \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_EVENT_START + 0x1, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define OVS_IOCTL_EVENT_WAIT \
    CTL_CODE (OVS_DEVICE_TYPE, OVS_IOCTL_EVENT_START + 0x2, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define OVS_IOCTL_VERSION_START 0x700
#define OVS_IOCTL_VERSION_GET \
    CTL_CODE(OVS_DEVICE_TYPE, OVS_IOCTL_VERSION_START + 0x0, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef __declspec(align(8)) uint64_t Ovs64AlignedU64;
typedef __declspec(align(8)) ovs_be64 Ovs64AlignedBe64;
#pragma pack(push, 1)


typedef struct _OVS_DP_INFO {
    char name[128];
    uint32_t dpNo;
    uint32_t queue;
    Ovs64AlignedU64 nHit;
    Ovs64AlignedU64 nMissed;
    Ovs64AlignedU64 nLost;
    Ovs64AlignedU64 nFlows;
} OVS_DP_INFO, *POVS_DP_INFO;


typedef struct _OVS_VERSION {
    uint8_t mjrDrvVer;
    uint8_t mnrDrvVer;
} OVS_VERSION, *POVS_VERSION;



#define OVS_MAX_PORT_NAME_LENGTH 32

typedef struct _OVS_VPORT_GET {
    uint32_t dpNo;
    uint32_t portNo;
    char     name[OVS_MAX_PORT_NAME_LENGTH];
} OVS_VPORT_GET, *POVS_VPORT_GET;


typedef enum {
    OVSWIN_VPORT_TYPE_UNKNOWN,
    OVSWIN_VPORT_TYPE_RESERVED,
    OVSWIN_VPORT_TYPE_EXTERNAL,
    OVSWIN_VPORT_TYPE_INTERNAL,
    OVSWIN_VPORT_TYPE_SYNTHETIC,
    OVSWIN_VPORT_TYPE_EMULATED,
    OVSWIN_VPORT_TYPE_GRE,
    OVSWIN_VPORT_TYPE_GRE64,
    OVSWIN_VPORT_TYPE_VXLAN,
    OVSWIN_VPORT_TYPE_LOCAL,    /* For bridge local port. */
} OVS_VPORT_TYPE;

static __inline const char *
OvsVportTypeToStr(OVS_VPORT_TYPE t)
{
    switch(t) {
#define STR(t) case OVSWIN_VPORT_TYPE_##t : return "VPORT_##t";
    STR(UNKNOWN)
    STR(EXTERNAL)
    STR(INTERNAL)
    STR(SYNTHETIC)
    STR(EMULATED)
    STR(GRE)
    STR(GRE64)
    STR(VXLAN)
    STR(LOCAL)
    }
#undef STR

    return "Invalid type";
}

#define MAC_ADDRESS_LEN 6

typedef struct _OVS_VPORT_INFO {
    uint32_t dpNo;
    uint32_t portNo;
    char name[OVS_MAX_PORT_NAME_LENGTH];
    uint32_t type;
    uint32_t queue;

    Ovs64AlignedU64 rxPackets;
    Ovs64AlignedU64 txPackets;
    Ovs64AlignedU64 rxBytes;
    Ovs64AlignedU64 txBytes;
    Ovs64AlignedU64 rxErrors;
    Ovs64AlignedU64 txErrors;
    Ovs64AlignedU64 rxDropped;
    Ovs64AlignedU64 txDropped;

    uint8_t macAddress[MAC_ADDRESS_LEN];
    uint16_t pad;
} OVS_VPORT_INFO, *POVS_VPORT_INFO;

typedef struct _OVS_VPORT_ADD_REQUEST {
    uint32_t dpNo;
    uint32_t type;
    char name[OVS_MAX_PORT_NAME_LENGTH];
    uint16_t dstPort;
    uint16_t pad[3];
} OVS_VPORT_ADD_REQUEST, *POVS_VPORT_ADD_REQUEST;


typedef struct _OVS_VPORT_DELETE_REQUEST {
    uint32_t dpNo;
    uint32_t portNo;
    char name[OVS_MAX_PORT_NAME_LENGTH];
} OVS_VPORT_DELETE_REQUEST, *POVS_VPORT_DELETE_REQUEST;


#define OVS_MAX_VM_UUID_LEN 128
#define OVS_MAX_VIF_UUID_LEN 128

typedef struct _OVS_VPORT_EXT_INFO {
    uint32_t dpNo;
    uint32_t portNo;
    uint8_t macAddress[MAC_ADDRESS_LEN];
    uint8_t permMACAddress[MAC_ADDRESS_LEN];
    uint8_t vmMACAddress[MAC_ADDRESS_LEN];
    uint16_t nicIndex;
    uint32_t portId;
    uint32_t type;
    uint32_t mtu;
    char name[OVS_MAX_PORT_NAME_LENGTH];
    uint32_t status;
    char vmUUID[OVS_MAX_VM_UUID_LEN];
    char vifUUID[OVS_MAX_VIF_UUID_LEN];
} OVS_VPORT_EXT_INFO, *POVS_VPORT_EXT_INFO;


/* Flows. */
#define OVSWIN_VLAN_CFI 0x1000
#define OVSWIN_INPORT_INVALID 0xffffffff

/* Used for OvsFlowKey's dlType member for frames that have no Ethernet type,
 * that is, pure 802.2 frames. */
#define OVSWIN_DL_TYPE_NONE 0x5ff

/* Fragment bits, used for IPv4 and IPv6, always zero for non-IP flows. */
#define OVSWIN_NW_FRAG_ANY   (1 << 0)   /* Set for any IP frag. */
#define OVSWIN_NW_FRAG_LATER (1 << 1)   /* Set for IP frag with nonzero
                                         * offset. */
#define OVSWIN_NW_FRAG_MASK  (OVSWIN_NW_FRAG_ANY | OVSWIN_NW_FRAG_LATER)

typedef struct L4Key {
    ovs_be16 tpSrc;              /* TCP/UDP/SCTP source port. */
    ovs_be16 tpDst;              /* TCP/UDP/SCTP destination port. */
} L4Key;

typedef struct Ipkey {
    ovs_be32 nwSrc;              /* IPv4 source address. */
    ovs_be32 nwDst;              /* IPv4 destination address. */
    uint8_t nwProto;             /* IP protocol or low 8 bits of ARP opcode. */
    uint8_t nwTos;               /* IP ToS (including DSCP and ECN). */
    uint8_t nwTtl;               /* IP TTL/Hop Limit. */
    uint8_t nwFrag;              /* FLOW_FRAG_* flags. */
    L4Key   l4;
} IpKey;  /* Size of 16 byte. */

typedef struct ArpKey {
    ovs_be32 nwSrc;              /* IPv4 source address. */
    ovs_be32 nwDst;              /* IPv4 destination address. */
    uint8_t arpSha[6];           /* ARP/ND source hardware address. */
    uint8_t arpTha[6];           /* ARP/ND target hardware address. */
    uint8_t nwProto;             /* IP protocol or low 8 bits of ARP opcode. */
    uint8_t pad[3];
} ArpKey; /* Size of 24 byte. */

typedef struct Ipv6Key {
    struct in6_addr ipv6Src;     /* IPv6 source address. */
    struct in6_addr ipv6Dst;     /* IPv6 destination address. */
    ovs_be32 ipv6Label;          /* IPv6 flow label. */
    uint8_t nwProto;             /* IP protocol or low 8 bits of ARP opcode. */
    uint8_t nwTos;               /* IP ToS (including DSCP and ECN). */
    uint8_t nwTtl;               /* IP TTL/Hop Limit. */
    uint8_t nwFrag;              /* FLOW_FRAG_* flags. */
    L4Key  l4;
    uint32_t pad;
} Ipv6Key;  /* Size of 48 byte. */

typedef struct Icmp6Key {
    struct in6_addr ipv6Src;     /* IPv6 source address. */
    struct in6_addr ipv6Dst;     /* IPv6 destination address. */
    ovs_be32 ipv6Label;          /* IPv6 flow label. */
    uint8_t nwProto;             /* IP protocol or low 8 bits of ARP opcode. */
    uint8_t nwTos;               /* IP ToS (including DSCP and ECN). */
    uint8_t nwTtl;               /* IP TTL/Hop Limit. */
    uint8_t nwFrag;              /* FLOW_FRAG_* flags. */
    L4Key  l4;
    uint8_t arpSha[6];           /* ARP/ND source hardware address. */
    uint8_t arpTha[6];           /* ARP/ND target hardware address. */
    struct in6_addr ndTarget;    /* IPv6 neighbor discovery (ND) target. */
} Icmp6Key; /* Size of 72 byte. */

typedef struct L2Key {
    uint32_t inPort;             /* Port number of input port. */
    union {
        struct {
            uint16_t offset;
            uint16_t keyLen;
        };
        uint32_t val;
    };
    uint8_t dlSrc[6];            /* Ethernet source address. */
    uint8_t dlDst[6];            /* Ethernet destination address. */
    ovs_be16 vlanTci;            /* If 802.1Q, TCI | VLAN_CFI; otherwise 0. */
    ovs_be16 dlType;             /* Ethernet frame type. */
} L2Key;  /* Size of 24 byte. */

/* Number of packet attributes required to store OVS tunnel key. */
#define NUM_PKT_ATTR_REQUIRED 3

typedef union OvsIPv4TunnelKey {
    struct {
        ovs_be32 dst;
        ovs_be32 src;
        ovs_be64 tunnelId;
        uint16_t flags;
        uint8_t  tos;
        uint8_t  ttl;
        union {
            uint32_t pad;
            struct {
                ovs_be16 dst_port;
                uint16_t flow_hash;
            };
        };
    };
    uint64_t attr[NUM_PKT_ATTR_REQUIRED];
} OvsIPv4TunnelKey;

typedef __declspec(align(8)) struct OvsFlowKey {
    OvsIPv4TunnelKey tunKey;     /* 24 bytes */
    L2Key l2;                    /* 24 bytes */
    union {
        IpKey ipKey;             /* size 16 */
        ArpKey arpKey;           /* size 24 */
        Ipv6Key ipv6Key;         /* size 48 */
        Icmp6Key icmp6Key;       /* size 72 */
    };
} OvsFlowKey;

#define OVS_WIN_TUNNEL_KEY_SIZE (sizeof (OvsIPv4TunnelKey))
#define OVS_L2_KEY_SIZE (sizeof (L2Key))
#define OVS_IP_KEY_SIZE (sizeof (IpKey))
#define OVS_IPV6_KEY_SIZE (sizeof (Ipv6Key))
#define OVS_ARP_KEY_SIZE (sizeof (ArpKey))
#define OVS_ICMPV6_KEY_SIZE (sizeof (Icmp6Key))

typedef struct OvsFlowStats {
    Ovs64AlignedU64 packetCount;
    Ovs64AlignedU64 byteCount;
    uint32_t used;
    uint8_t tcpFlags;
} OvsFlowStats;

typedef struct OvsFlowInfo {
    OvsFlowKey key;
    struct OvsFlowStats stats;
    uint32_t actionsLen;
    struct nlattr actions[0];
} OvsFlowInfo;

enum GetFlags {
    FLOW_GET_KEY =       0x00000001,
    FLOW_GET_STATS =     0x00000010,
    FLOW_GET_ACTIONS =   0x00000100,
};

typedef struct OvsFlowDumpInput {
    uint32_t dpNo;
    uint32_t position[2];   /* Offset hint to the start of flow dump. */
                            /* 0 - index of the hash table.
                             * 1 - nth element in the hash table index. */
    uint32_t getFlags;      /* Information to get in addition to keys. */
    uint32_t actionsLen;
} OvsFlowDumpInput;


typedef struct OvsFlowDumpOutput {
    /* Hint for the next flow dump operation. */
    uint32_t position[2];

    /* #flows (currently 0 or 1). In case the buffer is too small to output all
     * actions, this field indicates actual size needed to dump all actions. */
    uint32_t n;

    OvsFlowInfo flow;
} OvsFlowDumpOutput;

typedef struct OvsFlowGetInput {
    uint32_t dpNo;
    OvsFlowKey key;
    uint32_t getFlags;           /* Information to get in addition to keys. */
    uint32_t actionsLen;         /* Sizeof of buffer for actions. */
} OvsFlowGetInput;

typedef struct OvsFlowGetOutput {
    OvsFlowInfo info;            /* Variable length. */
} OvsFlowGetOutput;


typedef enum OvsFlowPutFlags {
    OVSWIN_FLOW_PUT_CREATE = 1 << 0,
    OVSWIN_FLOW_PUT_MODIFY = 1 << 1,
    OVSWIN_FLOW_PUT_DELETE = 1 << 2,

    OVSWIN_FLOW_PUT_CLEAR = 1 << 3
} OvsFlowPutFlags;


typedef struct OvsFlowPut {
    uint32_t dpNo;
    uint32_t actionsLen;
    OvsFlowKey key;
    uint32_t flags;
    struct nlattr  actions[0];  /* Variable length indicated by actionsLen. */
} OvsFlowPut;

#define OVS_MIN_PACKET_SIZE 60
typedef struct _OVS_PACKET_INFO {
    uint32_t totalLen;
    uint32_t userDataLen;
    uint32_t packetLen;
    uint32_t queue;
    uint32_t inPort;
    uint32_t cmd;
    OvsIPv4TunnelKey tunnelKey;
    /* Includes user data defined as chain of netlink attributes followed by the
     * packet data. */
    uint8_t  data[0];
} OVS_PACKET_INFO, *POVS_PACKET_INFO;

typedef struct OvsPacketExecute {
   uint32_t dpNo;
   uint32_t inPort;

   uint32_t packetLen;
   uint32_t actionsLen;
   union {
       /* Variable size blob with packet data first, followed by action
        * attrs. */
       char packetBuf[0];
       struct nlattr  actions[0];
   };
} OvsPacketExecute;


typedef struct _OVS_EVENT_SUBSCRIBE {
    uint32_t cookie;
    uint32_t dpNo;
    uint32_t subscribe;
    uint32_t mask;
} OVS_EVENT_SUBSCRIBE, *POVS_EVENT_SUBSCRIBE;

typedef struct _OVS_EVENT_POLL {
    uint32_t cookie;
    uint32_t dpNo;
} OVS_EVENT_POLL, *POVS_EVENT_POLL;

enum {
    OVS_EVENT_CONNECT       = ((uint32_t)0x1 << 0),
    OVS_EVENT_DISCONNECT    = ((uint32_t)0x1 << 1),
    OVS_EVENT_LINK_UP       = ((uint32_t)0x1 << 2),
    OVS_EVENT_LINK_DOWN     = ((uint32_t)0x1 << 3),
    OVS_EVENT_MAC_CHANGE    = ((uint32_t)0x1 << 4),
    OVS_EVENT_MTU_CHANGE    = ((uint32_t)0x1 << 5),
    OVS_EVENT_MASK_ALL      = 0x3f,
};


typedef struct _OVS_EVENT_ENTRY {
    uint32_t portNo;
    uint32_t status;
} OVS_EVENT_ENTRY, *POVS_EVENT_ENTRY;

#define OVS_DEFAULT_PORT_NO 0xffffffff
#define OVS_DEFAULT_EVENT_STATUS  0xffffffff

typedef struct _OVS_EVENT_STATUS {
    uint32_t numberEntries;
    OVS_EVENT_ENTRY eventEntries[0];
} OVS_EVENT_STATUS, *POVS_EVENT_STATUS;

#pragma pack(pop)

#endif /* __OVS_PUB_H_ */

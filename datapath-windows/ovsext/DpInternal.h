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

#ifndef __DP_INTERNAL_H_
#define __DP_INTERNAL_H_ 1

#include <netioapi.h>
#define IFNAMSIZ IF_NAMESIZE
#include "../ovsext/Netlink/Netlink.h"

#define OVS_DP_NUMBER   ((uint32_t) 0)

typedef __declspec(align(8)) uint64_t Ovs64AlignedU64;
typedef __declspec(align(8)) ovs_be64 Ovs64AlignedBe64;
#pragma pack(push, 1)

#define OVS_MAX_PORT_NAME_LENGTH IFNAMSIZ

typedef struct _OVS_VPORT_GET {
    uint32_t dpNo;
    uint32_t portNo;
    char     name[OVS_MAX_PORT_NAME_LENGTH];
} OVS_VPORT_GET, *POVS_VPORT_GET;

#define OVS_MAX_VM_UUID_LEN 128
#define OVS_MAX_VIF_UUID_LEN 128

typedef struct _OVS_VPORT_EXT_INFO {
    uint32_t dpNo;
    uint32_t portNo;
    uint8_t macAddress[ETH_ADDR_LEN];
    uint8_t permMACAddress[ETH_ADDR_LEN];
    uint8_t vmMACAddress[ETH_ADDR_LEN];
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

/* Used for OvsFlowKey's dlType member for frames that have no Ethernet type,
 * that is, pure 802.2 frames. */
#define OVSWIN_DL_TYPE_NONE 0x5ff

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

typedef struct VlanKey {
    ovs_be16 vlanTci;            /* If 802.1Q, TCI | VLAN_CFI; otherwise 0. */
    ovs_be16 vlanTpid;           /* Vlan type. Generally 802.1q or 802.1ad.*/
} VlanKey;

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
    ovs_be16 dlType;             /* Ethernet frame type. */
    struct VlanKey vlanKey;      /* VLAN header. */
    uint16_t pad[3];             /* Padding 6 bytes. */
} L2Key; /* Size of 32 byte. */

/* Number of packet attributes required to store OVS tunnel key. */
#define NUM_PKT_ATTR_REQUIRED 35
#define TUN_OPT_MAX_LEN 255

typedef union OvsIPv4TunnelKey {
    /* Options should always be the first member of tunnel key.
     * They are stored at the end of the array if they are less than the
     * maximum size. This allows us to get the benefits of variable length
     * matching for small options.
     */
    struct {
        UINT8 tunOpts[TUN_OPT_MAX_LEN];          /* Tunnel options. */
        UINT8 tunOptLen;             /* Tunnel option length in byte. */
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
} OvsIPv4TunnelKey; /* Size of 280 byte. */

static __inline uint8_t
TunnelKeyGetOptionsOffset(const OvsIPv4TunnelKey *key)
{
    return TUN_OPT_MAX_LEN - key->tunOptLen;
}

static __inline uint8_t *
TunnelKeyGetOptions(OvsIPv4TunnelKey *key)
{
    return key->tunOpts + TunnelKeyGetOptionsOffset(key);
}

static __inline uint16_t
TunnelKeyGetRealSize(OvsIPv4TunnelKey *key)
{
    return sizeof(OvsIPv4TunnelKey) - TunnelKeyGetOptionsOffset(key);
}

typedef struct MplsKey {
    ovs_be32 lse;                /* MPLS topmost label stack entry. */
    uint8    pad[4];
} MplsKey; /* Size of 8 bytes. */

typedef __declspec(align(8)) struct OvsFlowKey {
    OvsIPv4TunnelKey tunKey;     /* 280 bytes */
    L2Key l2;                    /* 32 bytes */
    union {
        /* These headers are mutually exclusive. */
        IpKey ipKey;             /* size 16 */
        ArpKey arpKey;           /* size 24 */
        Ipv6Key ipv6Key;         /* size 48 */
        Icmp6Key icmp6Key;       /* size 72 */
        MplsKey mplsKey;         /* size 8 */
    };
    UINT32 recircId;             /* Recirculation ID.  */
    UINT32 dpHash;               /* Datapath calculated hash value. */
    struct {
        /* Connection tracking fields. */
        UINT16 zone;
        UINT32 mark;
        UINT32 state;
        struct ovs_key_ct_labels labels;
        struct ovs_key_ct_tuple_ipv4 tuple_ipv4;
    } ct;                        /* Connection Tracking Flags */
} OvsFlowKey;

#define OVS_WIN_TUNNEL_KEY_SIZE (sizeof (OvsIPv4TunnelKey))
#define OVS_L2_KEY_SIZE (sizeof (L2Key))
#define OVS_IP_KEY_SIZE (sizeof (IpKey))
#define OVS_IPV6_KEY_SIZE (sizeof (Ipv6Key))
#define OVS_ARP_KEY_SIZE (sizeof (ArpKey))
#define OVS_ICMPV6_KEY_SIZE (sizeof (Icmp6Key))
#define OVS_MPLS_KEY_SIZE (sizeof (MplsKey))

typedef struct OvsFlowStats {
    Ovs64AlignedU64 packetCount;
    Ovs64AlignedU64 byteCount;
    uint64_t used;
    uint8_t tcpFlags;
} OvsFlowStats;

typedef struct OvsFlowInfo {
    OvsFlowKey key;
    struct OvsFlowStats stats;
    uint32_t actionsLen;
    PNL_ATTR actions;
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
    PNL_ATTR  actions;
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
    uint8_t *payload;
    /* Includes user data defined as chain of netlink attributes followed by the
     * packet data. */
    uint8_t  data[0];
} OVS_PACKET_INFO, *POVS_PACKET_INFO;

typedef struct OvsPacketExecute {
   uint32_t dpNo;
   uint32_t inPort;
   uint16 mru;
   uint32_t packetLen;
   uint32_t actionsLen;
   PNL_MSG_HDR nlMsgHdr;
   PCHAR packetBuf;
   PNL_ATTR actions;
   PNL_ATTR *keyAttrs;
} OvsPacketExecute;


typedef struct _OVS_EVENT_SUBSCRIBE {
    uint32_t cookie;
    uint32_t dpNo;
    uint32_t subscribe;
    uint32_t mask;
    uint32_t mcastGrp;
    uint32_t protocol;
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

enum {
    OVS_EVENT_CT_NEW        = (1 << 0),
    OVS_EVENT_CT_DELETE     = (1 << 1),
    OVS_EVENT_CT_UPDATE     = (1 << 2),
    OVS_EVENT_CT_MASK_ALL   = 0x7
};

/* Supported mcast event groups */
enum OVS_MCAST_EVENT_TYPES {
    OVS_MCAST_VPORT_EVENT,
    OVS_MCAST_CT_EVENT,
    __OVS_MCAST_EVENT_TYPES_MAX
};
#define OVS_MCAST_EVENT_TYPES_MAX (__OVS_MCAST_EVENT_TYPES_MAX \
                                   - OVS_MCAST_VPORT_EVENT)

typedef struct _OVS_VPORT_EVENT_ENTRY {
    UINT32 portNo;
    OVS_VPORT_TYPE ovsType;
    UINT32 upcallPid;
    CHAR ovsName[OVS_MAX_PORT_NAME_LENGTH];
    UINT32 type;
} OVS_VPORT_EVENT_ENTRY, *POVS_VPORT_EVENT_ENTRY;

#pragma pack(pop)

#endif /* __DP_INTERNAL_H_ */

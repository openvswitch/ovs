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

#ifndef __ETHERNET_H_
#define __ETHERNET_H_ 1

#define ETH_LADRF_LEN      2
#define ETH_ADDR_LENGTH    6

typedef UINT8 Eth_Address[ETH_ADDR_LENGTH];

#define ETH_ADDR_FMT_STR     "%02x:%02x:%02x:%02x:%02x:%02x"
#define ETH_ADDR_FMT_ARGS(a) ((UINT8 *)a)[0], ((UINT8 *)a)[1], ((UINT8 *)a)[2], \
                             ((UINT8 *)a)[3], ((UINT8 *)a)[4], ((UINT8 *)a)[5]

#define ETH_MAX_EXACT_MULTICAST_ADDRS 32

typedef enum Eth_RxMode {
    ETH_FILTER_UNICAST   = 0x0001,   /* pass unicast (directed) frames */
    ETH_FILTER_MULTICAST = 0x0002,   /* pass some multicast frames */
    ETH_FILTER_ALLMULTI  = 0x0004,   /* pass *all* multicast frames */
    ETH_FILTER_BROADCAST = 0x0008,   /* pass broadcast frames */
    ETH_FILTER_PROMISC   = 0x0010,   /* pass all frames (ie no filter) */
    ETH_FILTER_USE_LADRF = 0x0020,   /* use the LADRF for multicast filtering */
    ETH_FILTER_SINK      = 0x10000   /* pass not-matched unicast frames */
} Eth_RxMode;

/* filter flags printf helpers */
#define ETH_FILTER_FLAG_FMT_STR     "%s%s%s%s%s%s%s"
#define ETH_FILTER_FLAG_FMT_ARGS(f) (f) & ETH_FILTER_UNICAST   ? "  UNICAST"   : "", \
                                    (f) & ETH_FILTER_MULTICAST ? "  MULTICAST" : "", \
                                    (f) & ETH_FILTER_ALLMULTI  ? "  ALLMULTI"  : "", \
                                    (f) & ETH_FILTER_BROADCAST ? "  BROADCAST" : "", \
                                    (f) & ETH_FILTER_PROMISC   ? "  PROMISC"   : "", \
                                    (f) & ETH_FILTER_USE_LADRF ? "  USE_LADRF" : "", \
                                    (f) & ETH_FILTER_SINK      ? "  SINK"      : ""

/* Ethernet header type */
typedef enum {
    ETH_HEADER_TYPE_DIX,
    ETH_HEADER_TYPE_802_1PQ,
    ETH_HEADER_TYPE_802_3,
    ETH_HEADER_TYPE_802_1PQ_802_3,
} Eth_HdrType;

/* DIX type fields we care about */
typedef enum {
    ETH_TYPE_IPV4        = 0x0800,
    ETH_TYPE_IPV6        = 0x86DD,
    ETH_TYPE_ARP         = 0x0806,
    ETH_TYPE_RARP        = 0x8035,
    ETH_TYPE_LLDP        = 0x88CC,
    ETH_TYPE_CDP         = 0x2000,
    ETH_TYPE_802_1PQ     = 0x8100, // not really a DIX type, but used as such
    ETH_TYPE_LLC         = 0xFFFF, // 0xFFFF is IANA reserved, used to mark LLC
    ETH_TYPE_MPLS        = 0x8847,
    ETH_TYPE_MPLS_MCAST  = 0x8848,
} Eth_DixType;

typedef enum {
    ETH_TYPE_IPV4_NBO    = 0x0008,
    ETH_TYPE_IPV6_NBO    = 0xDD86,
    ETH_TYPE_ARP_NBO     = 0x0608,
    ETH_TYPE_RARP_NBO    = 0x3580,
    ETH_TYPE_LLDP_NBO    = 0xCC88,
    ETH_TYPE_CDP_NBO     = 0x0020,
    ETH_TYPE_AKIMBI_NBO  = 0xDE88,
    ETH_TYPE_802_1PQ_NBO = 0x0081,  // not really a DIX type, but used as such
} Eth_DixTypeNBO;

/* low two bits of the LLC control byte */
typedef enum {
    ETH_LLC_CONTROL_IFRAME  = 0x0, // both 0x0 and 0x2, only low bit of 0 needed
    ETH_LLC_CONTROL_SFRAME  = 0x1,
    ETH_LLC_CONTROL_UFRAME  = 0x3,
} Eth_LLCControlBits;

#define ETH_LLC_CONTROL_UFRAME_MASK (0x3)

typedef struct Eth_DIX {
    UINT16  typeNBO;     // indicates the higher level protocol
} Eth_DIX;

/*
 * LLC header come in two varieties:  8 bit control and 16 bit control.
 * when the lower two bits of the first byte's control are '11', this
 * indicated the 8 bit control field.
 */
typedef struct Eth_LLC8 {
    UINT8   dsap;
    UINT8   ssap;
    UINT8   control;
} Eth_LLC8;

typedef struct Eth_LLC16 {
    UINT8   dsap;
    UINT8   ssap;
    UINT16  control;
} Eth_LLC16;

typedef struct Eth_SNAP {
    UINT8   snapOrg[3];
    Eth_DIX snapType;
} Eth_SNAP;

typedef struct Eth_802_3 {
    UINT16   lenNBO;      // length of the frame
    Eth_LLC8 llc;         // LLC header
    Eth_SNAP snap;        // SNAP header
} Eth_802_3;

// 802.1p QOS/priority tags
enum {
    ETH_802_1_P_BEST_EFFORT          = 0,
    ETH_802_1_P_BACKGROUND           = 1,
    ETH_802_1_P_EXCELLENT_EFFORT     = 2,
    ETH_802_1_P_CRITICAL_APPS        = 3,
    ETH_802_1_P_VIDEO                = 4,
    ETH_802_1_P_VOICE                = 5,
    ETH_802_1_P_INTERNETWORK_CONROL  = 6,
    ETH_802_1_P_NETWORK_CONTROL      = 7
};

typedef struct Eth_802_1pq_Tag {
    UINT16 typeNBO;            // always ETH_TYPE_802_1PQ
    UINT16 vidHi:4,            // 802.1q vlan ID high nibble
           canonical:1,        // bit order? (should always be 0)
           priority:3,         // 802.1p priority tag
           vidLo:8;            // 802.1q vlan ID low byte
} Eth_802_1pq_Tag;

typedef struct Eth_802_1pq {
    Eth_802_1pq_Tag tag;       // VLAN/QOS tag
    union {
        Eth_DIX      dix;      // DIX header follows
        Eth_802_3    e802_3;   // or 802.3 header follows
    };
} Eth_802_1pq;

typedef struct Eth_Header {
    Eth_Address     dst;       // all types of ethernet frame have dst first
    Eth_Address     src;       // and the src next (at least all the ones we'll see)
    union {
        Eth_DIX      dix;      // followed by a DIX header...
        Eth_802_3    e802_3;   // ...or an 802.3 header
        Eth_802_1pq  e802_1pq; // ...or an 802.1[pq] tag and a header
    };
} Eth_Header;

#define ETH_BROADCAST_ADDRESS { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }

static Eth_Address netEthBroadcastAddr = ETH_BROADCAST_ADDRESS;

/*
 * simple predicate for 1536 boundary.
 * the parameter is a network ordered UINT16, which is compared to 0x06,
 * testing for "length" values greater than or equal to 0x0600 (1536)
 */

#define ETH_TYPENOT8023(x)      (((x) & 0xff) >= 0x06)

/*
 * header length macros
 *
 * first two are typical: ETH_HEADER_LEN_DIX, ETH_HEADER_LEN_802_1PQ
 * last two are suspicious, due to 802.3 incompleteness
 */

#define ETH_HEADER_LEN_DIX           (sizeof(Eth_Address) + \
                                      sizeof(Eth_Address) + \
                                      sizeof(Eth_DIX))
#define ETH_HEADER_LEN_802_1PQ       (sizeof(Eth_Address) + \
                                      sizeof(Eth_Address) + \
                                      sizeof(Eth_802_1pq_Tag) + \
                                      sizeof(Eth_DIX))
#define ETH_HEADER_LEN_802_2_LLC     (sizeof(Eth_Address) + \
                                      sizeof(Eth_Address) + \
                                      sizeof(UINT16) + \
                                      sizeof(Eth_LLC8))
#define ETH_HEADER_LEN_802_2_LLC16   (sizeof(Eth_Address) + \
                                      sizeof(Eth_Address) + \
                                      sizeof(UINT16) + \
                                      sizeof(Eth_LLC16))
#define ETH_HEADER_LEN_802_3         (sizeof(Eth_Address) + \
                                      sizeof(Eth_Address) + \
                                      sizeof(Eth_802_3))
#define ETH_HEADER_LEN_802_1PQ_LLC   (sizeof(Eth_Address) + \
                                      sizeof(Eth_Address) + \
                                      sizeof(Eth_802_1pq_Tag) + \
                                      sizeof(UINT16) + \
                                      sizeof(Eth_LLC8))
#define ETH_HEADER_LEN_802_1PQ_LLC16 (sizeof(Eth_Address) + \
                                      sizeof(Eth_Address) + \
                                      sizeof(Eth_802_1pq_Tag) + \
                                      sizeof(UINT16) + \
                                      sizeof(Eth_LLC16))
#define ETH_HEADER_LEN_802_1PQ_802_3 (sizeof(Eth_Address) + \
                                      sizeof(Eth_Address) + \
                                      sizeof(Eth_802_1pq_Tag) + \
                                      sizeof(Eth_802_3))

#define ETH_MIN_HEADER_LEN   (ETH_HEADER_LEN_DIX)
#define ETH_MAX_HEADER_LEN   (ETH_HEADER_LEN_802_1PQ_802_3)

#define ETH_MIN_FRAME_LEN                    60
#define ETH_MAX_STD_MTU                      1500
#define ETH_MAX_STD_FRAMELEN                 (ETH_MAX_STD_MTU + ETH_MAX_HEADER_LEN)
#define ETH_MAX_JUMBO_MTU                    9000
#define ETH_MAX_JUMBO_FRAMELEN               (ETH_MAX_JUMBO_MTU + ETH_MAX_HEADER_LEN)

#define ETH_DEFAULT_MTU                      1500

#define ETH_FCS_LEN                          4
#define ETH_VLAN_LEN                         sizeof(Eth_802_1pq_Tag)


/*
 *----------------------------------------------------------------------------
 * Do the two ethernet addresses match?
 *----------------------------------------------------------------------------
 */
static __inline BOOLEAN
Eth_IsAddrMatch(const Eth_Address addr1, const Eth_Address addr2)
{
    return !memcmp(addr1, addr2, ETH_ADDR_LENGTH);
}


/*
 *----------------------------------------------------------------------------
 * Is the address the broadcast address?
 *----------------------------------------------------------------------------
 */
static __inline BOOLEAN
Eth_IsBroadcastAddr(const Eth_Address addr)
{
    return Eth_IsAddrMatch(addr, netEthBroadcastAddr);
}


/*
 *----------------------------------------------------------------------------
 * Is the address a unicast address?
 *----------------------------------------------------------------------------
 */
static __inline BOOLEAN
Eth_IsUnicastAddr(const Eth_Address addr)
{
    // broadcast and multicast frames always have the low bit set in byte 0
    return !(((CHAR *)addr)[0] & 0x1);
}

/*
 *----------------------------------------------------------------------------
 * Is the address the all-zeros address?
 *----------------------------------------------------------------------------
 */
static __inline BOOLEAN
Eth_IsNullAddr(const Eth_Address addr)
{
    return ((addr[0] | addr[1] | addr[2] | addr[3] | addr[4] | addr[5]) == 0);
}

/*
 *----------------------------------------------------------------------------
 *
 * Eth_HeaderType --
 *      return an Eth_HdrType depending on the eth header
 *      contents.  will not work in all cases, especially since it
 *      requres ETH_HEADER_LEN_802_1PQ bytes to determine the type
 *
 *      HeaderType isn't sufficient to determine the length of
 *      the eth header.  for 802.3 header, its not clear without
 *      examination, whether a SNAP is included
 *
 *      returned type:
 *
 *      ETH_HEADER_TYPE_DIX: typical 14 byte eth header
 *      ETH_HEADER_TYPE_802_1PQ: DIX+vlan tagging
 *      ETH_HEADER_TYPE_802_3: 802.3 eth header
 *      ETH_HEADER_TYPE_802_1PQ_802_3: 802.3 + vlan tag
 *
 *      the test for DIX was moved from a 1500 boundary to a 1536
 *      boundary, since the vmxnet2 MTU was updated to 1514.  when
 *      W2K8 attempted to send LLC frames, these were interpreted
 *      as DIX frames instead of the correct 802.3 type
 *
 *      these links may help if they're valid:
 *
 *      http://standards.ieee.org/regauth/ethertype/type-tut.html
 *      http://standards.ieee.org/regauth/ethertype/type-pub.html
 *
 * Results:
 *    Eth_HdrType value
 *
 *----------------------------------------------------------------------------
 */
static __inline Eth_HdrType
Eth_HeaderType(const Eth_Header *eh)
{
    /*
     * we use 1536 (IEEE 802.3-std mentions 1536, but iana indicates
     * type of 0-0x5dc are 802.3) instead of some #def symbol to prevent
     * inadvertant reuse of the same macro for buffer size decls.
     */
    if (ETH_TYPENOT8023(eh->dix.typeNBO)) {
        if (eh->dix.typeNBO != ETH_TYPE_802_1PQ_NBO) {
         /* typical case */
            return ETH_HEADER_TYPE_DIX;
        }

        /* some type of 802.1pq tagged frame */
        if (ETH_TYPENOT8023(eh->e802_1pq.dix.typeNBO)) {
         /* vlan tagging with dix style type */
            return ETH_HEADER_TYPE_802_1PQ;
        }

        /* vlan tagging with 802.3 header */
        return ETH_HEADER_TYPE_802_1PQ_802_3;
    }

    /* assume 802.3 */
    return ETH_HEADER_TYPE_802_3;
}


/*
 *----------------------------------------------------------------------------
 *
 * Eth_EncapsulatedPktType --
 *      Get the encapsulated (layer 3) frame type.
 *      for LLC frames without SNAP, we don't have
 *      an encapsulated type, and return ETH_TYPE_LLC.
 *
 *      IANA reserves 0xFFFF, which we reuse to indicate
 *      ETH_TYPE_LLC.
 *
 * Results:
 *   NBO frame type.
 *
 *----------------------------------------------------------------------------
 */
static __inline UINT16
Eth_EncapsulatedPktType(const Eth_Header *eh)
{
    Eth_HdrType type = Eth_HeaderType(eh);

    switch (type) {
    case ETH_HEADER_TYPE_DIX: return eh->dix.typeNBO;
    case ETH_HEADER_TYPE_802_1PQ: return eh->e802_1pq.dix.typeNBO;
    case ETH_HEADER_TYPE_802_3:
        /*
         * Documentation describes SNAP headers as having ONLY
         * 0x03 as the control fields, not just the lower two bits
         * This prevents the use of Eth_IsLLCControlUFormat.
         */
        if ((eh->e802_3.llc.dsap == 0xaa) && (eh->e802_3.llc.ssap == 0xaa) &&
            (eh->e802_3.llc.control == ETH_LLC_CONTROL_UFRAME)) {
            return eh->e802_3.snap.snapType.typeNBO;
        } else {
            // LLC, no snap header, then no type
            return ETH_TYPE_LLC;
        }

    case ETH_HEADER_TYPE_802_1PQ_802_3:
        if ((eh->e802_1pq.e802_3.llc.dsap == 0xaa) &&
            (eh->e802_1pq.e802_3.llc.ssap == 0xaa) &&
            (eh->e802_1pq.e802_3.llc.control == ETH_LLC_CONTROL_UFRAME)) {
            return eh->e802_1pq.e802_3.snap.snapType.typeNBO;
        } else {
            // tagged LLC, no snap header, then no type
            return ETH_TYPE_LLC;
        }
    }

    ASSERT(FALSE);
    return 0;
}

/*
 *----------------------------------------------------------------------------
 * Is the frame of the requested protocol type or is it an 802.1[pq]
 * encapsulation of such a frame?
 *----------------------------------------------------------------------------
 */
static __inline BOOLEAN
Eth_IsDixType(const Eth_Header *eh, const Eth_DixTypeNBO type)
{
    return Eth_EncapsulatedPktType(eh) == type;
}


/*
 *----------------------------------------------------------------------------
 * Is the frame an IPV4 frame?
 *----------------------------------------------------------------------------
 */
static __inline BOOLEAN
Eth_IsIPV4(const Eth_Header *eh)
{
    return Eth_IsDixType(eh, ETH_TYPE_IPV4_NBO);
}


/*
 *----------------------------------------------------------------------------
 * Is the frame an IPV6 frame?
 *----------------------------------------------------------------------------
 */
static __inline BOOLEAN
Eth_IsIPV6(const Eth_Header *eh)
{
    return Eth_IsDixType(eh, ETH_TYPE_IPV6_NBO);
}


/*
 *----------------------------------------------------------------------------
 * Is the frame an ARP frame?
 *----------------------------------------------------------------------------
 */
static __inline BOOLEAN
Eth_IsARP(const Eth_Header *eh)
{
    return Eth_IsDixType(eh, ETH_TYPE_ARP_NBO);
}


/*
 *----------------------------------------------------------------------------
 * Does the frame contain an 802.1[pq] tag?
 *----------------------------------------------------------------------------
 */
static __inline BOOLEAN
Eth_IsFrameTagged(const Eth_Header *eh)
{
    return (eh->dix.typeNBO == ETH_TYPE_802_1PQ_NBO);
}
#endif /* __ETHERNET_H_ */

#ifndef __OPENVSWITCH_NSH_H
#define __OPENVSWITCH_NSH_H 1

#include "openvswitch/types.h"

/*
 * Network Service Header:
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Ver|O|C|R|R|R|R|R|R|    Length   |   MD Type   |  Next Proto   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Service Path ID                | Service Index |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * ~               Mandatory/Optional Context Header               ~
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * Ver = The version field is used to ensure backward compatibility
 *       going forward with future NSH updates.  It MUST be set to 0x0
 *       by the sender, in this first revision of NSH.
 *
 * O = OAM. when set to 0x1 indicates that this packet is an operations
 *     and management (OAM) packet.  The receiving SFF and SFs nodes
 *     MUST examine the payload and take appropriate action.
 *
 * C = context. Indicates that a critical metadata TLV is present.
 *
 * Length : total length, in 4-byte words, of NSH including the Base
 *          Header, the Service Path Header and the optional variable
 *          TLVs.
 * MD Type: indicates the format of NSH beyond the mandatory Base Header
 *          and the Service Path Header.
 *
 * Next Protocol: indicates the protocol type of the original packet. A
 *          new IANA registry will be created for protocol type.
 *
 * Service Path Identifier (SPI): identifies a service path.
 *          Participating nodes MUST use this identifier for Service
 *          Function Path selection.
 *
 * Service Index (SI): provides location within the SFP.
 *
 * [0] https://tools.ietf.org/html/draft-ietf-sfc-nsh-13
 */

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * struct nsh_md1_ctx - Keeps track of NSH context data
 * @nshc<1-4>: NSH Contexts.
 */
struct nsh_md1_ctx {
    ovs_16aligned_be32 c[4];
};

struct nsh_md2_tlv {
    ovs_be16 md_class;
    uint8_t type;
    uint8_t length;
    /* Followed by variable-length data. */
};

struct nsh_hdr {
    ovs_be16 ver_flags_len;
    uint8_t md_type;
    uint8_t next_proto;
    ovs_16aligned_be32 path_hdr;
    union {
        struct nsh_md1_ctx md1;
        struct nsh_md2_tlv md2;
    };
};

/* Masking NSH header fields. */
#define NSH_VER_MASK       0xc000
#define NSH_VER_SHIFT      14
#define NSH_FLAGS_MASK     0x3fc0
#define NSH_FLAGS_SHIFT    6
#define NSH_LEN_MASK       0x003f
#define NSH_LEN_SHIFT      0

#define NSH_SPI_MASK       0xffffff00
#define NSH_SPI_SHIFT      8
#define NSH_SI_MASK        0x000000ff
#define NSH_SI_SHIFT       0

#define NSH_DST_PORT    4790     /* UDP Port for NSH on VXLAN. */
#define ETH_P_NSH       0x894F   /* Ethertype for NSH. */

/* NSH Base Header Next Protocol. */
#define NSH_P_IPV4        0x01
#define NSH_P_IPV6        0x02
#define NSH_P_ETHERNET    0x03
#define NSH_P_NSH         0x04
#define NSH_P_MPLS        0x05

/* MD Type Registry. */
#define NSH_M_TYPE1     0x01
#define NSH_M_TYPE2     0x02
#define NSH_M_EXP1      0xFE
#define NSH_M_EXP2      0xFF

/* NSH Metadata Length. */
#define NSH_M_TYPE1_MDLEN 16

/* NSH Base Header Length */
#define NSH_BASE_HDR_LEN  8

/* NSH MD Type 1 header Length. */
#define NSH_M_TYPE1_LEN   24

static inline uint16_t
nsh_hdr_len(const struct nsh_hdr *nsh)
{
    return ((ntohs(nsh->ver_flags_len) & NSH_LEN_MASK) >> NSH_LEN_SHIFT) << 2;
}

static inline struct nsh_md1_ctx *
nsh_md1_ctx(struct nsh_hdr *nsh)
{
    return &nsh->md1;
}

static inline struct nsh_md2_tlv *
nsh_md2_ctx(struct nsh_hdr *nsh)
{
    return &nsh->md2;
}

#ifdef  __cplusplus
}
#endif

#endif

#ifndef __NET_VXLAN_WRAPPER_H
#define __NET_VXLAN_WRAPPER_H  1

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/udp.h>
#include <net/gre.h>

#include <linux/version.h>

#ifdef HAVE_VXLAN_METADATA
#define USE_UPSTREAM_VXLAN

#include_next <net/vxlan.h>
#endif

#ifndef VXLAN_HLEN
/* VXLAN header flags. */
#define VXLAN_HF_VNI 0x08000000
#ifndef VXLAN_HF_GBP
#define VXLAN_HF_GBP 0x80000000
#endif

#define VXLAN_N_VID     (1u << 24)
#define VXLAN_VID_MASK  (VXLAN_N_VID - 1)
#define VXLAN_HLEN (sizeof(struct udphdr) + sizeof(struct vxlanhdr))
#endif

#ifndef VXLAN_GBP_USED_BITS
/*
 * VXLAN Group Based Policy Extension:
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |1|-|-|-|1|-|-|-|R|D|R|R|A|R|R|R|        Group Policy ID        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                VXLAN Network Identifier (VNI) |   Reserved    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * D = Don't Learn bit. When set, this bit indicates that the egress
 *     VTEP MUST NOT learn the source address of the encapsulated frame.
 *
 * A = Indicates that the group policy has already been applied to
 *     this packet. Policies MUST NOT be applied by devices when the
 *     A bit is set.
 *
 * [0] https://tools.ietf.org/html/draft-smith-vxlan-group-policy
 */
struct vxlanhdr_gbp {
	__u8	vx_flags;
#ifdef __LITTLE_ENDIAN_BITFIELD
	__u8	reserved_flags1:3,
		policy_applied:1,
		reserved_flags2:2,
		dont_learn:1,
		reserved_flags3:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	reserved_flags1:1,
		dont_learn:1,
		reserved_flags2:2,
		policy_applied:1,
		reserved_flags3:3;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__be16	policy_id;
	__be32	vx_vni;
};
#define VXLAN_GBP_USED_BITS (VXLAN_HF_GBP | 0xFFFFFF)

/* skb->mark mapping
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |R|R|R|R|R|R|R|R|R|D|R|R|A|R|R|R|        Group Policy ID        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
#define VXLAN_GBP_DONT_LEARN		(BIT(6) << 16)
#define VXLAN_GBP_POLICY_APPLIED	(BIT(3) << 16)
#define VXLAN_GBP_ID_MASK		(0xFFFF)

#define VXLAN_F_GBP			0x800
#endif

#ifndef VXLAN_F_UDP_CSUM
#define VXLAN_F_UDP_CSUM                0x40
#endif

#ifndef VXLAN_F_RCV_FLAGS
#define VXLAN_F_RCV_FLAGS			VXLAN_F_GBP
#endif

#ifdef USE_UPSTREAM_VXLAN
static inline int rpl_vxlan_xmit_skb(struct vxlan_sock *vs,
                   struct rtable *rt, struct sk_buff *skb,
                   __be32 src, __be32 dst, __u8 tos, __u8 ttl, __be16 df,
                   __be16 src_port, __be16 dst_port,
		   struct vxlan_metadata *md, bool xnet, u32 vxflags)
{
	if (skb_is_gso(skb) && skb_is_encapsulated(skb)) {
		kfree_skb(skb);
		return -ENOSYS;
	}

	return vxlan_xmit_skb(rt, skb, src, dst, tos, ttl, df,
			      src_port, dst_port, md, xnet, vxflags);
}

#define vxlan_xmit_skb rpl_vxlan_xmit_skb
#else /* USE_UPSTREAM_VXLAN */

struct vxlan_metadata {
	__be32		vni;
	u32		gbp;
};

#define vxlan_sock rpl_vxlan_sock
struct rpl_vxlan_sock;

#define vxlan_rcv_t rpl_vxlan_rcv_t
typedef void (vxlan_rcv_t)(struct vxlan_sock *vh, struct sk_buff *skb,
			   struct vxlan_metadata *md);

/* per UDP socket information */
struct vxlan_sock {
	struct hlist_node hlist;
	vxlan_rcv_t	 *rcv;
	void		 *data;
	struct work_struct del_work;
	struct socket	 *sock;
	struct rcu_head	  rcu;
	u32		  flags;
};

#define vxlan_sock_add rpl_vxlan_sock_add
struct vxlan_sock *rpl_vxlan_sock_add(struct net *net, __be16 port,
				      vxlan_rcv_t *rcv, void *data,
				      bool no_share, u32 flags);

#define vxlan_sock_release rpl_vxlan_sock_release
void rpl_vxlan_sock_release(struct vxlan_sock *vs);

#define vxlan_xmit_skb rpl_vxlan_xmit_skb
int rpl_vxlan_xmit_skb(struct vxlan_sock *vs,
		       struct rtable *rt, struct sk_buff *skb,
		       __be32 src, __be32 dst, __u8 tos, __u8 ttl, __be16 df,
		       __be16 src_port, __be16 dst_port,
		       struct vxlan_metadata *md, bool xnet, u32 vxflags);

#endif /* !HAVE_VXLAN_METADATA */
#endif

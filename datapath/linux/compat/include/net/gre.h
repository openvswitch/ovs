#ifndef __LINUX_GRE_WRAPPER_H
#define __LINUX_GRE_WRAPPER_H

#include <linux/skbuff.h>
#include <net/ip_tunnels.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37) || \
   defined(HAVE_GRE_CISCO_REGISTER)
#include_next <net/gre.h>
#endif

#ifndef HAVE_GRE_CISCO_REGISTER

/* GRE demux not available, implement our own demux. */
#define MAX_GRE_PROTO_PRIORITY 255

struct gre_cisco_protocol {
	int (*handler)(struct sk_buff *skb, const struct tnl_ptk_info *tpi);
	int (*err_handler)(struct sk_buff *skb, u32 info,
			   const struct tnl_ptk_info *tpi);
	u8 priority;
};

#define gre_cisco_register rpl_gre_cisco_register
int gre_cisco_register(struct gre_cisco_protocol *proto);

#define gre_cisco_unregister rpl_gre_cisco_unregister
int gre_cisco_unregister(struct gre_cisco_protocol *proto);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
struct gre_base_hdr {
	__be16 flags;
	__be16 protocol;
};
#define GRE_HEADER_SECTION 4

static inline __be16 gre_flags_to_tnl_flags(__be16 flags)
{
	__be16 tflags = 0;

	if (flags & GRE_CSUM)
		tflags |= TUNNEL_CSUM;
	if (flags & GRE_ROUTING)
		tflags |= TUNNEL_ROUTING;
	if (flags & GRE_KEY)
		tflags |= TUNNEL_KEY;
	if (flags & GRE_SEQ)
		tflags |= TUNNEL_SEQ;
	if (flags & GRE_STRICT)
		tflags |= TUNNEL_STRICT;
	if (flags & GRE_REC)
		tflags |= TUNNEL_REC;
	if (flags & GRE_VERSION)
		tflags |= TUNNEL_VERSION;

	return tflags;
}

static inline __be16 tnl_flags_to_gre_flags(__be16 tflags)
{
	__be16 flags = 0;

	if (tflags & TUNNEL_CSUM)
		flags |= GRE_CSUM;
	if (tflags & TUNNEL_ROUTING)
		flags |= GRE_ROUTING;
	if (tflags & TUNNEL_KEY)
		flags |= GRE_KEY;
	if (tflags & TUNNEL_SEQ)
		flags |= GRE_SEQ;
	if (tflags & TUNNEL_STRICT)
		flags |= GRE_STRICT;
	if (tflags & TUNNEL_REC)
		flags |= GRE_REC;
	if (tflags & TUNNEL_VERSION)
		flags |= GRE_VERSION;

	return flags;
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0) */
#endif /* HAVE_GRE_CISCO_REGISTER */

#ifndef USE_KERNEL_TUNNEL_API

#define gre_build_header rpl_gre_build_header
void gre_build_header(struct sk_buff *skb, const struct tnl_ptk_info *tpi,
		      int hdr_len);

#define gre_handle_offloads rpl_gre_handle_offloads
struct sk_buff *gre_handle_offloads(struct sk_buff *skb, bool gre_csum);

#define ip_gre_calc_hlen rpl_ip_gre_calc_hlen
static inline int ip_gre_calc_hlen(__be16 o_flags)
{
	int addend = 4;

	if (o_flags & TUNNEL_CSUM)
		addend += 4;
	if (o_flags & TUNNEL_KEY)
		addend += 4;
	if (o_flags & TUNNEL_SEQ)
		addend += 4;
	return addend;
}
#else
static inline struct sk_buff *rpl_gre_handle_offloads(struct sk_buff *skb,
						  bool gre_csum)
{
	if (skb->encapsulation && skb_is_gso(skb)) {
		kfree_skb(skb);
		return ERR_PTR(-ENOSYS);
	}
	return gre_handle_offloads(skb, gre_csum);
}
#define gre_handle_offloads rpl_gre_handle_offloads
#endif

#endif

#ifndef __LINUX_GRE_WRAPPER_H
#define __LINUX_GRE_WRAPPER_H

#include <linux/skbuff.h>
#include <net/ip_tunnels.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,37)
#include_next <net/gre.h>

#else /* LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,37) */

#define GREPROTO_CISCO		0
#define GREPROTO_MAX		2

struct gre_protocol {
	int  (*handler)(struct sk_buff *skb);
};

int gre_add_protocol(const struct gre_protocol *proto, u8 version);
int gre_del_protocol(const struct gre_protocol *proto, u8 version);

#endif

struct gre_base_hdr {
	__be16 flags;
	__be16 protocol;
};
#define GRE_HEADER_SECTION 4

#define MAX_GRE_PROTO_PRIORITY 255
struct gre_cisco_protocol {
	int (*handler)(struct sk_buff *skb, const struct tnl_ptk_info *tpi);
	u8 priority;
};

#define gre_build_header rpl_gre_build_header
void gre_build_header(struct sk_buff *skb, const struct tnl_ptk_info *tpi,
		      int hdr_len);

#define gre_handle_offloads rpl_gre_handle_offloads
struct sk_buff *gre_handle_offloads(struct sk_buff *skb, bool gre_csum);

int gre_cisco_register(struct gre_cisco_protocol *proto);
int gre_cisco_unregister(struct gre_cisco_protocol *proto);

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
#endif

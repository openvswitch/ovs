#ifndef __LINUX_GRE_WRAPPER_H
#define __LINUX_GRE_WRAPPER_H

#include <linux/version.h>
#include <linux/skbuff.h>
#include <net/ip_tunnels.h>

#ifdef USE_UPSTREAM_TUNNEL
#include_next <net/gre.h>

static inline int rpl_ipgre_init(void)
{
	return 0;
}
static inline void rpl_ipgre_fini(void)
{}

static inline int rpl_ip6gre_init(void)
{
	return 0;
}

static inline void rpl_ip6gre_fini(void)
{}

static inline int rpl_ip6_tunnel_init(void)
{
	return 0;
}

static inline void rpl_ip6_tunnel_cleanup(void)
{
}

static inline int rpl_gre_init(void)
{
	return 0;
}

static inline void rpl_gre_exit(void)
{
}

#define gre_fb_xmit dev_queue_xmit

#ifdef CONFIG_INET
#ifndef HAVE_NAME_ASSIGN_TYPE
static inline struct net_device *rpl_gretap_fb_dev_create(
	struct net *net, const char *name, u8 name_assign_type) {
	return gretap_fb_dev_create(net, name);
}
#define gretap_fb_dev_create rpl_gretap_fb_dev_create
#endif
#endif

#else
#include_next <net/gre.h>

#define tnl_flags_to_gre_flags rpl_tnl_flags_to_gre_flags
static inline __be16 rpl_tnl_flags_to_gre_flags(__be16 tflags)
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

#define gre_flags_to_tnl_flags rpl_gre_flags_to_tnl_flags
static inline __be16 rpl_gre_flags_to_tnl_flags(__be16 flags)
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
#define gre_tnl_flags_to_gre_flags rpl_gre_tnl_flags_to_gre_flags
static inline __be16 rpl_gre_tnl_flags_to_gre_flags(__be16 tflags)
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
int rpl_gre_cisco_register(struct gre_cisco_protocol *proto);

#define gre_cisco_unregister rpl_gre_cisco_unregister
int rpl_gre_cisco_unregister(struct gre_cisco_protocol *proto);

#ifndef GRE_HEADER_SECTION
struct gre_base_hdr {
	__be16 flags;
	__be16 protocol;
};
#define GRE_HEADER_SECTION 4
#endif

#endif /* HAVE_GRE_CISCO_REGISTER */

#define gre_build_header rpl_gre_build_header
void rpl_gre_build_header(struct sk_buff *skb, const struct tnl_ptk_info *tpi,
			  int hdr_len);

int rpl_ipgre_init(void);
void rpl_ipgre_fini(void);
int rpl_ip6gre_init(void);
void rpl_ip6gre_fini(void);
int rpl_ip6_tunnel_init(void);
void rpl_ip6_tunnel_cleanup(void);
int rpl_gre_init(void);
void rpl_gre_exit(void);

#define gretap_fb_dev_create rpl_gretap_fb_dev_create
struct net_device *rpl_gretap_fb_dev_create(struct net *net, const char *name,
					u8 name_assign_type);

#define gre_parse_header rpl_gre_parse_header
int rpl_gre_parse_header(struct sk_buff *skb, struct tnl_ptk_info *tpi,
			 bool *csum_err, __be16 proto, int nhs);

#define gre_fb_xmit rpl_gre_fb_xmit
netdev_tx_t rpl_gre_fb_xmit(struct sk_buff *skb);

#define gre_add_protocol rpl_gre_add_protocol
int rpl_gre_add_protocol(const struct gre_protocol *proto, u8 version);
#define gre_del_protocol rpl_gre_del_protocol
int rpl_gre_del_protocol(const struct gre_protocol *proto, u8 version);
#endif /* USE_UPSTREAM_TUNNEL */

#define ipgre_init rpl_ipgre_init
#define ipgre_fini rpl_ipgre_fini
#define ip6gre_init rpl_ip6gre_init
#define ip6gre_fini rpl_ip6gre_fini
#define ip6_tunnel_init rpl_ip6_tunnel_init
#define ip6_tunnel_cleanup rpl_ip6_tunnel_cleanup
#define gre_init rpl_gre_init
#define gre_exit rpl_gre_exit

#define gre_fill_metadata_dst ovs_gre_fill_metadata_dst
int ovs_gre_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb);


#endif

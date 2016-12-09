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

int rpl_ipgre_init(void);
void rpl_ipgre_fini(void);

#define gretap_fb_dev_create rpl_gretap_fb_dev_create
struct net_device *rpl_gretap_fb_dev_create(struct net *net, const char *name,
					u8 name_assign_type);

#define gre_fb_xmit rpl_gre_fb_xmit
netdev_tx_t rpl_gre_fb_xmit(struct sk_buff *skb);
#endif /* USE_UPSTREAM_TUNNEL */

#define ipgre_init rpl_ipgre_init
#define ipgre_fini rpl_ipgre_fini

#define gre_fill_metadata_dst ovs_gre_fill_metadata_dst
int ovs_gre_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb);

#endif

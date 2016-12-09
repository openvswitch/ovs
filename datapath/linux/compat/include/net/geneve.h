#ifndef __NET_GENEVE_WRAPPER_H
#define __NET_GENEVE_WRAPPER_H  1

#ifdef CONFIG_INET
#include <net/udp_tunnel.h>
#endif


#ifdef USE_UPSTREAM_TUNNEL
#include_next <net/geneve.h>

static inline int rpl_geneve_init_module(void)
{
	return 0;
}
static inline void rpl_geneve_cleanup_module(void)
{}

#define geneve_xmit dev_queue_xmit

#ifdef CONFIG_INET
#ifndef HAVE_NAME_ASSIGN_TYPE
static inline struct net_device *rpl_geneve_dev_create_fb(
	struct net *net, const char *name, u8 name_assign_type, u16 dst_port) {
	return geneve_dev_create_fb(net, name, dst_port);
}
#define geneve_dev_create_fb rpl_geneve_dev_create_fb
#endif
#endif

#else
/* Geneve Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Virtual Network Identifier (VNI)       |    Reserved   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Variable Length Options                    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Option Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Option Class         |      Type     |R|R|R| Length  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                      Variable Option Data                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct geneve_opt {
	__be16	opt_class;
	u8	type;
#ifdef __LITTLE_ENDIAN_BITFIELD
	u8	length:5;
	u8	r3:1;
	u8	r2:1;
	u8	r1:1;
#else
	u8	r1:1;
	u8	r2:1;
	u8	r3:1;
	u8	length:5;
#endif
	u8	opt_data[];
};

#define GENEVE_CRIT_OPT_TYPE (1 << 7)

struct genevehdr {
#ifdef __LITTLE_ENDIAN_BITFIELD
	u8 opt_len:6;
	u8 ver:2;
	u8 rsvd1:6;
	u8 critical:1;
	u8 oam:1;
#else
	u8 ver:2;
	u8 opt_len:6;
	u8 oam:1;
	u8 critical:1;
	u8 rsvd1:6;
#endif
	__be16 proto_type;
	u8 vni[3];
	u8 rsvd2;
	struct geneve_opt options[];
};

#ifdef CONFIG_INET
#define geneve_dev_create_fb rpl_geneve_dev_create_fb
struct net_device *rpl_geneve_dev_create_fb(struct net *net, const char *name,
					u8 name_assign_type, u16 dst_port);
#endif /*ifdef CONFIG_INET */

int rpl_geneve_init_module(void);
void rpl_geneve_cleanup_module(void);

#define geneve_xmit rpl_geneve_xmit
netdev_tx_t rpl_geneve_xmit(struct sk_buff *skb);

#endif
#define geneve_init_module rpl_geneve_init_module
#define geneve_cleanup_module rpl_geneve_cleanup_module

#define geneve_fill_metadata_dst ovs_geneve_fill_metadata_dst
int ovs_geneve_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb);

#endif /*ifdef__NET_GENEVE_H */

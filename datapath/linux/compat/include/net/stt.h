#ifndef __NET_STT_H
#define __NET_STT_H  1

#include <linux/kconfig.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0) && IS_ENABLED(CONFIG_NETFILTER)
#include <net/ip_tunnels.h>
#define OVS_STT

struct stthdr {
	__u8		version;
	__u8		flags;
	__u8		l4_offset;
	__u8		reserved;
	__be16		mss;
	__be16		vlan_tci;
	__be64		key;
};

/* Padding after the end of the tunnel headers to provide alignment
 * for inner packet IP header after 14 byte Ethernet header.
 */
#define STT_ETH_PAD 2

#define STT_BASE_HLEN   (sizeof(struct stthdr) + STT_ETH_PAD)
#define STT_HEADER_LEN	(sizeof(struct tcphdr) + STT_BASE_HLEN)

static inline struct stthdr *stt_hdr(const struct sk_buff *skb)
{
	return (struct stthdr *)(skb_transport_header(skb) +
				 sizeof(struct tcphdr));
}

struct stt_sock;
typedef void (stt_rcv_t)(struct stt_sock *stt_sock, struct sk_buff *skb);

/* @list: Per-net list of STT ports.
 * @rcv: The callback is called on STT packet recv, STT reassembly can generate
 * multiple packets, in this case first packet has tunnel outer header, rest
 * of the packets are inner packet segments with no stt header.
 * @rcv_data: user data.
 * @sock: Fake TCP socket for the STT port.
 */
struct stt_sock {
	struct list_head	list;
	stt_rcv_t		*rcv;
	void			*rcv_data;
	struct socket		*sock;
	struct rcu_head		rcu;
};

#define stt_sock_add rpl_stt_sock_add
struct stt_sock *rpl_stt_sock_add(struct net *net, __be16 port,
			      stt_rcv_t *rcv, void *data);

#define stt_sock_release rpl_stt_sock_release
void rpl_stt_sock_release(struct stt_sock *stt_sock);

#define stt_xmit_skb rpl_stt_xmit_skb
int rpl_stt_xmit_skb(struct sk_buff *skb, struct rtable *rt,
		 __be32 src, __be32 dst, __u8 tos,
		 __u8 ttl, __be16 df, __be16 src_port, __be16 dst_port,
		 __be64 tun_id);

#define stt_init_module ovs_stt_init_module
int ovs_stt_init_module(void);

#define stt_cleanup_module ovs_stt_cleanup_module
void ovs_stt_cleanup_module(void);

#endif
#endif /*ifdef__NET_STT_H */

#ifndef __NET_UDP_TUNNEL_WRAPPER_H
#define __NET_UDP_TUNNEL_WRAPPER_H

#include <linux/version.h>
#include <linux/kconfig.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
#include_next <net/udp_tunnel.h>

static inline struct sk_buff *
rpl_udp_tunnel_handle_offloads(struct sk_buff *skb, bool udp_csum,
			       bool is_vxlan)
{
	if (skb_is_gso(skb) && skb_is_encapsulated(skb)) {
		kfree_skb(skb);
		return ERR_PTR(-ENOSYS);
	}
	return udp_tunnel_handle_offloads(skb, udp_csum);
}
#define udp_tunnel_handle_offloads rpl_udp_tunnel_handle_offloads

#else

#include <net/ip_tunnels.h>
#include <net/udp.h>

struct udp_port_cfg {
	u8			family;

	/* Used only for kernel-created sockets */
	union {
		struct in_addr		local_ip;
#if IS_ENABLED(CONFIG_IPV6)
		struct in6_addr		local_ip6;
#endif
	};

	union {
		struct in_addr		peer_ip;
#if IS_ENABLED(CONFIG_IPV6)
		struct in6_addr		peer_ip6;
#endif
	};

	__be16			local_udp_port;
	__be16			peer_udp_port;
	unsigned int		use_udp_checksums:1,
				use_udp6_tx_checksums:1,
				use_udp6_rx_checksums:1;
};

#define udp_sock_create rpl_udp_sock_create
int rpl_udp_sock_create(struct net *net, struct udp_port_cfg *cfg,
		        struct socket **sockp);

typedef int (*udp_tunnel_encap_rcv_t)(struct sock *sk, struct sk_buff *skb);
typedef void (*udp_tunnel_encap_destroy_t)(struct sock *sk);

struct udp_tunnel_sock_cfg {
	void *sk_user_data;     /* user data used by encap_rcv call back */
	/* Used for setting up udp_sock fields, see udp.h for details */
	__u8  encap_type;
	udp_tunnel_encap_rcv_t encap_rcv;
	udp_tunnel_encap_destroy_t encap_destroy;
};

/* Setup the given (UDP) sock to receive UDP encapsulated packets */
#define setup_udp_tunnel_sock rpl_setup_udp_tunnel_sock
void rpl_setup_udp_tunnel_sock(struct net *net, struct socket *sock,
			       struct udp_tunnel_sock_cfg *sock_cfg);

/* Transmit the skb using UDP encapsulation. */
#define udp_tunnel_xmit_skb rpl_udp_tunnel_xmit_skb
int rpl_udp_tunnel_xmit_skb(struct rtable *rt, struct sk_buff *skb,
			    __be32 src, __be32 dst, __u8 tos, __u8 ttl,
			    __be16 df, __be16 src_port, __be16 dst_port,
			    bool xnet, bool nocheck);


#define udp_tunnel_sock_release rpl_udp_tunnel_sock_release
void rpl_udp_tunnel_sock_release(struct socket *sock);

void ovs_udp_gso(struct sk_buff *skb);
void ovs_udp_csum_gso(struct sk_buff *skb);

static inline struct sk_buff *udp_tunnel_handle_offloads(struct sk_buff *skb,
                                                         bool udp_csum,
							 bool is_vxlan)
{
	int type = udp_csum ? SKB_GSO_UDP_TUNNEL_CSUM : SKB_GSO_UDP_TUNNEL;
	void (*fix_segment)(struct sk_buff *);

	if (!udp_csum)
		fix_segment = ovs_udp_gso;
	else
		fix_segment = ovs_udp_csum_gso;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
	if (!is_vxlan)
		type = 0;
#endif

	return ovs_iptunnel_handle_offloads(skb, udp_csum, type, fix_segment);
}

#define udp_tunnel_encap_enable(sock) udp_encap_enable()

#endif /* Linux version < 4.0 */
#endif

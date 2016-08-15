#ifndef __NET_UDP_TUNNEL_WRAPPER_H
#define __NET_UDP_TUNNEL_WRAPPER_H

#include <linux/version.h>
#include <linux/kconfig.h>

#include <net/addrconf.h>
#include <net/dst_metadata.h>
#include <linux/netdev_features.h>

#ifdef USE_UPSTREAM_TUNNEL
#include_next <net/udp_tunnel.h>

#else

#include <net/addrconf.h>
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
				use_udp6_rx_checksums:1,
				ipv6_v6only:1;
};

#define udp_sock_create4 rpl_udp_sock_create4
int rpl_udp_sock_create4(struct net *net, struct udp_port_cfg *cfg,
		     struct socket **sockp);

#define udp_sock_create6 rpl_udp_sock_create6
#if IS_ENABLED(CONFIG_IPV6)
int rpl_udp_sock_create6(struct net *net, struct udp_port_cfg *cfg,
		struct socket **sockp);
#else
static inline int udp_sock_create6(struct net *net, struct udp_port_cfg *cfg,
				   struct socket **sockp)
{
	return -EPFNOSUPPORT;
}
#endif

#define udp_sock_create rpl_udp_sock_create
static inline int udp_sock_create(struct net *net,
                                  struct udp_port_cfg *cfg,
                                  struct socket **sockp)
{
        if (cfg->family == AF_INET)
                return udp_sock_create4(net, cfg, sockp);

        if (cfg->family == AF_INET6)
                return udp_sock_create6(net, cfg, sockp);

        return -EPFNOSUPPORT;
}

typedef int (*udp_tunnel_encap_rcv_t)(struct sock *sk, struct sk_buff *skb);
typedef void (*udp_tunnel_encap_destroy_t)(struct sock *sk);
typedef struct sk_buff **(*udp_tunnel_gro_receive_t)(struct sock *sk,
                                                    struct sk_buff **head,
                                                    struct sk_buff *skb);
typedef int (*udp_tunnel_gro_complete_t)(struct sock *sk, struct sk_buff *skb,
                                        int nhoff);

struct udp_tunnel_sock_cfg {
	void *sk_user_data;     /* user data used by encap_rcv call back */
	/* Used for setting up udp_sock fields, see udp.h for details */
	__u8  encap_type;
	udp_tunnel_encap_rcv_t encap_rcv;
	udp_tunnel_encap_destroy_t encap_destroy;
#ifdef HAVE_UDP_TUNNEL_SOCK_CFG_GRO_RECEIVE
	udp_tunnel_gro_receive_t gro_receive;
	udp_tunnel_gro_complete_t gro_complete;
#endif
};

/* Setup the given (UDP) sock to receive UDP encapsulated packets */
#define setup_udp_tunnel_sock rpl_setup_udp_tunnel_sock
void rpl_setup_udp_tunnel_sock(struct net *net, struct socket *sock,
			       struct udp_tunnel_sock_cfg *sock_cfg);

/* Transmit the skb using UDP encapsulation. */
#define udp_tunnel_xmit_skb rpl_udp_tunnel_xmit_skb
void rpl_udp_tunnel_xmit_skb(struct rtable *rt,
			    struct sock *sk, struct sk_buff *skb,
			    __be32 src, __be32 dst, __u8 tos, __u8 ttl,
			    __be16 df, __be16 src_port, __be16 dst_port,
			    bool xnet, bool nocheck);


#define udp_tunnel_sock_release rpl_udp_tunnel_sock_release
void rpl_udp_tunnel_sock_release(struct socket *sock);

#define udp_tunnel_encap_enable rpl_udp_tunnel_encap_enable
static inline void udp_tunnel_encap_enable(struct socket *sock)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (sock->sk->sk_family == PF_INET6)
#ifdef HAVE_IPV6_STUB
		ipv6_stub->udpv6_encap_enable();
#else
		udpv6_encap_enable();
#endif
	else
#endif
		udp_encap_enable();
}

#if IS_ENABLED(CONFIG_IPV6)
#define udp_tunnel6_xmit_skb rpl_udp_tunnel6_xmit_skb
int rpl_udp_tunnel6_xmit_skb(struct dst_entry *dst, struct sock *sk,
			 struct sk_buff *skb,
			 struct net_device *dev, struct in6_addr *saddr,
			 struct in6_addr *daddr,
			 __u8 prio, __u8 ttl, __be32 label, __be16 src_port,
			 __be16 dst_port, bool nocheck);
#endif

static inline void udp_tunnel_gro_complete(struct sk_buff *skb, int nhoff)
{
	struct udphdr *uh;

	uh = (struct udphdr *)(skb->data + nhoff - sizeof(struct udphdr));
	skb_shinfo(skb)->gso_type |= uh->check ?
		SKB_GSO_UDP_TUNNEL_CSUM : SKB_GSO_UDP_TUNNEL;
}

void ovs_udp_gso(struct sk_buff *skb);
void ovs_udp_csum_gso(struct sk_buff *skb);

static inline int rpl_udp_tunnel_handle_offloads(struct sk_buff *skb,
						 bool udp_csum)
{
	void (*fix_segment)(struct sk_buff *);
	int type = 0;

	type |= udp_csum ? SKB_GSO_UDP_TUNNEL_CSUM : SKB_GSO_UDP_TUNNEL;
#ifndef USE_UPSTREAM_TUNNEL_GSO
	if (!udp_csum)
		fix_segment = ovs_udp_gso;
	else
		fix_segment = ovs_udp_csum_gso;
	/* This functuin is not used by vxlan lan tunnel. On older
	 * udp offload only supports vxlan, therefore fallback to software
	 * segmentation.
	 */
	type = 0;
#else
	fix_segment = NULL;
#endif

	return ovs_iptunnel_handle_offloads(skb, type, fix_segment);
}

#define udp_tunnel_handle_offloads rpl_udp_tunnel_handle_offloads
static inline void ovs_udp_tun_rx_dst(struct metadata_dst *md_dst,
				      struct sk_buff *skb,
				      unsigned short family,
				      __be16 flags, __be64 tunnel_id, int md_size)
{
	struct ip_tunnel_info *info = &md_dst->u.tun_info;

	if (family == AF_INET)
		ovs_ip_tun_rx_dst(md_dst, skb, flags, tunnel_id, md_size);
	else
		ovs_ipv6_tun_rx_dst(md_dst, skb, flags, tunnel_id, md_size);

	info->key.tp_src = udp_hdr(skb)->source;
	info->key.tp_dst = udp_hdr(skb)->dest;
	if (udp_hdr(skb)->check)
		info->key.tun_flags |= TUNNEL_CSUM;
}
#endif /* USE_UPSTREAM_TUNNEL */

#endif

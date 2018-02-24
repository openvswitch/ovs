#include <linux/version.h>

#ifndef USE_UPSTREAM_TUNNEL

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <net/ip_tunnels.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/net_namespace.h>
#include <net/ip6_checksum.h>
#include <net/ip6_tunnel.h>

#include "gso.h"

int rpl_udp_sock_create4(struct net *net, struct udp_port_cfg *cfg,
			 struct socket **sockp)
{
	int err;
	struct socket *sock = NULL;
	struct sockaddr_in udp_addr;

	err = sock_create_kern(net, AF_INET, SOCK_DGRAM, 0, &sock);
	if (err < 0)
		goto error;

	udp_addr.sin_family = AF_INET;
	udp_addr.sin_addr = cfg->local_ip;
	udp_addr.sin_port = cfg->local_udp_port;
	err = kernel_bind(sock, (struct sockaddr *)&udp_addr,
			sizeof(udp_addr));
	if (err < 0)
		goto error;

	if (cfg->peer_udp_port) {
		udp_addr.sin_family = AF_INET;
		udp_addr.sin_addr = cfg->peer_ip;
		udp_addr.sin_port = cfg->peer_udp_port;
		err = kernel_connect(sock, (struct sockaddr *)&udp_addr,
				sizeof(udp_addr), 0);
		if (err < 0)
			goto error;
	}
#ifdef HAVE_SK_NO_CHECK_TX
	sock->sk->sk_no_check_tx = !cfg->use_udp_checksums;
#endif
	*sockp = sock;
	return 0;

error:
	if (sock) {
		kernel_sock_shutdown(sock, SHUT_RDWR);
		sock_release(sock);
	}
	*sockp = NULL;
	return err;
}
EXPORT_SYMBOL(rpl_udp_sock_create4);

int rpl_udp_sock_create6(struct net *net, struct udp_port_cfg *cfg,
			 struct socket **sockp)
{
	struct sockaddr_in6 udp6_addr;
	int err;
	struct socket *sock = NULL;

	err = sock_create_kern(net, AF_INET6, SOCK_DGRAM, 0, &sock);
	if (err < 0)
		goto error;

	if (cfg->ipv6_v6only) {
		int val = 1;

		err = kernel_setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,
				(char *) &val, sizeof(val));
		if (err < 0)
			goto error;
	}

	udp6_addr.sin6_family = AF_INET6;
	memcpy(&udp6_addr.sin6_addr, &cfg->local_ip6,
			sizeof(udp6_addr.sin6_addr));
	udp6_addr.sin6_port = cfg->local_udp_port;
	err = kernel_bind(sock, (struct sockaddr *)&udp6_addr,
			sizeof(udp6_addr));
	if (err < 0)
		goto error;

	if (cfg->peer_udp_port) {
		udp6_addr.sin6_family = AF_INET6;
		memcpy(&udp6_addr.sin6_addr, &cfg->peer_ip6,
				sizeof(udp6_addr.sin6_addr));
		udp6_addr.sin6_port = cfg->peer_udp_port;
		err = kernel_connect(sock,
				(struct sockaddr *)&udp6_addr,
				sizeof(udp6_addr), 0);
	}
	if (err < 0)
		goto error;

	udp_set_no_check6_tx(sock->sk, !cfg->use_udp6_tx_checksums);
	udp_set_no_check6_rx(sock->sk, !cfg->use_udp6_rx_checksums);

	*sockp = sock;
	return 0;

error:
	if (sock) {
		kernel_sock_shutdown(sock, SHUT_RDWR);
		sock_release(sock);
	}
	*sockp = NULL;
	return err;
}
EXPORT_SYMBOL_GPL(rpl_udp_sock_create6);

void rpl_setup_udp_tunnel_sock(struct net *net, struct socket *sock,
			       struct udp_tunnel_sock_cfg *cfg)
{
	struct sock *sk = sock->sk;

	/* Disable multicast loopback */
	inet_sk(sk)->mc_loop = 0;

	rcu_assign_sk_user_data(sk, cfg->sk_user_data);

	udp_sk(sk)->encap_type = cfg->encap_type;
	udp_sk(sk)->encap_rcv = cfg->encap_rcv;
	udp_sk(sk)->encap_destroy = cfg->encap_destroy;
#ifdef HAVE_UDP_TUNNEL_SOCK_CFG_GRO_RECEIVE
	udp_sk(sk)->gro_receive = cfg->gro_receive;
	udp_sk(sk)->gro_complete = cfg->gro_complete;
#endif

	udp_tunnel_encap_enable(sock);
}
EXPORT_SYMBOL_GPL(rpl_setup_udp_tunnel_sock);

void rpl_udp_tunnel_xmit_skb(struct rtable *rt, struct sock *sk,
			    struct sk_buff *skb, __be32 src, __be32 dst,
			    __u8 tos, __u8 ttl, __be16 df, __be16 src_port,
			    __be16 dst_port, bool xnet, bool nocheck)
{
	struct udphdr *uh;

	__skb_push(skb, sizeof(*uh));
	skb_reset_transport_header(skb);
	uh = udp_hdr(skb);

	uh->dest = dst_port;
	uh->source = src_port;
	uh->len = htons(skb->len);

	udp_set_csum(nocheck, skb, src, dst, skb->len);

	iptunnel_xmit(sk, rt, skb, src, dst, IPPROTO_UDP, tos, ttl, df, xnet);
}
EXPORT_SYMBOL_GPL(rpl_udp_tunnel_xmit_skb);

void rpl_udp_tunnel_sock_release(struct socket *sock)
{
	rcu_assign_sk_user_data(sock->sk, NULL);
	kernel_sock_shutdown(sock, SHUT_RDWR);
	sock_release(sock);
}
EXPORT_SYMBOL_GPL(rpl_udp_tunnel_sock_release);

#if IS_ENABLED(CONFIG_IPV6)

#define udp_v6_check rpl_udp_v6_check
static __sum16 udp_v6_check(int len,
				   const struct in6_addr *saddr,
				   const struct in6_addr *daddr,
				   __wsum base)
{
	return csum_ipv6_magic(saddr, daddr, len, IPPROTO_UDP, base);
}

#define udp6_set_csum rpl_udp6_set_csum
static void udp6_set_csum(bool nocheck, struct sk_buff *skb,
			  const struct in6_addr *saddr,
			  const struct in6_addr *daddr, int len)
{
	struct udphdr *uh = udp_hdr(skb);

	if (nocheck)
		uh->check = 0;
	else if (skb_is_gso(skb))
		uh->check = ~udp_v6_check(len, saddr, daddr, 0);
	else if (skb->ip_summed == CHECKSUM_PARTIAL) {
		uh->check = 0;
		uh->check = udp_v6_check(len, saddr, daddr, lco_csum(skb));
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;
	} else {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
		uh->check = ~udp_v6_check(len, saddr, daddr, 0);
	}
}

#define ip6_flow_hdr rpl_ip6_flow_hdr
static inline void ip6_flow_hdr(struct ipv6hdr *hdr, unsigned int tclass,
		__be32 flowlabel)
{
	*(__be32 *)hdr = htonl(0x60000000 | (tclass << 20)) | flowlabel;
}

int rpl_udp_tunnel6_xmit_skb(struct dst_entry *dst, struct sock *sk,
			 struct sk_buff *skb,
			 struct net_device *dev, struct in6_addr *saddr,
			 struct in6_addr *daddr,
			 __u8 prio, __u8 ttl, __be32 label, __be16 src_port,
			 __be16 dst_port, bool nocheck)
{
	struct udphdr *uh;
	struct ipv6hdr *ip6h;

	__skb_push(skb, sizeof(*uh));
	skb_reset_transport_header(skb);
	uh = udp_hdr(skb);

	uh->dest = dst_port;
	uh->source = src_port;

	uh->len = htons(skb->len);

	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED
			    | IPSKB_REROUTED);
	skb_dst_set(skb, dst);

	udp6_set_csum(nocheck, skb, saddr, daddr, skb->len);

	__skb_push(skb, sizeof(*ip6h));
	skb_reset_network_header(skb);
	ip6h		  = ipv6_hdr(skb);
	ip6_flow_hdr(ip6h, prio, label);
	ip6h->payload_len = htons(skb->len);
	ip6h->nexthdr     = IPPROTO_UDP;
	ip6h->hop_limit   = ttl;
	ip6h->daddr	  = *daddr;
	ip6h->saddr	  = *saddr;

	ip6tunnel_xmit(sk, skb, dev);
	return 0;
}
#endif

#ifndef USE_UPSTREAM_TUNNEL_GSO
void ovs_udp_gso(struct sk_buff *skb)
{
	int udp_offset = skb_transport_offset(skb);
	struct udphdr *uh;

	uh = udp_hdr(skb);
	uh->len = htons(skb->len - udp_offset);
}
EXPORT_SYMBOL_GPL(ovs_udp_gso);

void ovs_udp_csum_gso(struct sk_buff *skb)
{
	int udp_offset = skb_transport_offset(skb);

	ovs_udp_gso(skb);

	if (!OVS_GSO_CB(skb)->ipv6) {
		struct iphdr *iph = ip_hdr(skb);

		/* csum segment if tunnel sets skb with csum. The cleanest way
		 * to do this just to set it up from scratch. */
		udp_set_csum(false, skb, iph->saddr, iph->daddr,
				skb->len - udp_offset);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		struct ipv6hdr *ip6h;

		ip6h = ipv6_hdr(skb);
		udp6_set_csum(false, skb, &ip6h->saddr, &ip6h->daddr,
			      skb->len - udp_offset);
#endif
	}
}
EXPORT_SYMBOL_GPL(ovs_udp_csum_gso);
#endif /* USE_UPSTREAM_TUNNEL_GSO */

#endif

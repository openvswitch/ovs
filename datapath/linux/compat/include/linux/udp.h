#ifndef __LINUX_UDP_WRAPPER_H
#define __LINUX_UDP_WRAPPER_H  1

#include_next <linux/udp.h>
#include <linux/ipv6.h>

#ifndef HAVE_NO_CHECK6_TX
static inline void udp_set_no_check6_tx(struct sock *sk, bool val)
{
#ifdef HAVE_SK_NO_CHECK_TX
	sk->sk_no_check_tx = val;
#endif
}

static inline void udp_set_no_check6_rx(struct sock *sk, bool val)
{
#ifdef HAVE_SK_NO_CHECK_TX
	sk->sk_no_check_rx = val;
#else
	/* since netwroking stack is not checking for zero UDP checksum
	 * check it in OVS module. */
	#define OVS_CHECK_UDP_TUNNEL_ZERO_CSUM
#endif
}
#endif

#ifdef OVS_CHECK_UDP_TUNNEL_ZERO_CSUM
#define udp6_csum_zero_error rpl_udp6_csum_zero_error

void rpl_udp6_csum_zero_error(struct sk_buff *skb);
#endif

#endif

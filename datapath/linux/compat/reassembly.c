/*
 * Backported from upstream commit a72a5e2d34ec
 * ("inet: kill unused skb_free op")
 *
 *      IPv6 fragment reassembly
 *      Linux INET6 implementation
 *
 *      Authors:
 *      Pedro Roque             <roque@di.fc.ul.pt>
 *
 *      Based on: net/ipv4/ip_fragment.c
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

/*
 *      Fixes:
 *      Andi Kleen      Make it work with multiple hosts.
 *                      More RFC compliance.
 *
 *      Horst von Brand Add missing #include <linux/string.h>
 *      Alexey Kuznetsov        SMP races, threading, cleanup.
 *      Patrick McHardy         LRU queue of frag heads for evictor.
 *      Mitsuru KANDA @USAGI    Register inet6_protocol{}.
 *      David Stevens and
 *      YOSHIFUJI,H. @USAGI     Always remove fragment header to
 *                              calculate ICV correctly.
 */

#define pr_fmt(fmt) "IPv6: " fmt

#if defined(OVS_FRAGMENT_BACKPORT) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/jiffies.h>
#include <linux/net.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/export.h>

#include <net/sock.h>
#include <net/snmp.h>

#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/protocol.h>
#include <net/transp_v6.h>
#include <net/rawv6.h>
#include <net/ndisc.h>
#include <net/addrconf.h>
#include <net/inet_frag.h>
#include <net/inet_ecn.h>

void ip6_expire_frag_queue(struct net *net, struct frag_queue *fq,
			   struct inet_frags *frags)
{
	struct net_device *dev = NULL;

	spin_lock(&fq->q.lock);

	if (qp_flags(fq) & INET_FRAG_COMPLETE)
		goto out;

	inet_frag_kill(&fq->q, frags);

	rcu_read_lock();
	dev = dev_get_by_index_rcu(net, fq->iif);
	if (!dev)
		goto out_rcu_unlock;

	IP6_INC_STATS_BH(net, __in6_dev_get(dev), IPSTATS_MIB_REASMFAILS);

	if (inet_frag_evicting(&fq->q))
		goto out_rcu_unlock;

	IP6_INC_STATS_BH(net, __in6_dev_get(dev), IPSTATS_MIB_REASMTIMEOUT);

	/* Don't send error if the first segment did not arrive. */
	if (!(qp_flags(fq) & INET_FRAG_FIRST_IN) || !fq->q.fragments)
		goto out_rcu_unlock;

	/* But use as source device on which LAST ARRIVED
	 * segment was received. And do not use fq->dev
	 * pointer directly, device might already disappeared.
	 */
	fq->q.fragments->dev = dev;
	icmpv6_send(fq->q.fragments, ICMPV6_TIME_EXCEED, ICMPV6_EXC_FRAGTIME, 0);
out_rcu_unlock:
	rcu_read_unlock();
out:
	spin_unlock(&fq->q.lock);
	inet_frag_put(&fq->q, frags);
}

#endif /* OVS_FRAGMENT_BACKPORT */

#ifdef SUPPORT_SNAT
/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2008 Nicira Networks
 */

#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/in.h>
#include <net/ip.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <net/arp.h>
#include <net/route.h>

#include "forward.h"
#include "dp_act.h"
#include "nx_act_snat.h"


/* We need these fake structures to make netfilter happy --
 * lots of places assume that skb->dst != NULL, which isn't
 * all that unreasonable.
 *
 * Currently, we fill in the PMTU entry because netfilter
 * refragmentation needs it, and the rt_flags entry because
 * ipt_REJECT needs it.  Future netfilter modules might
 * require us to fill additional fields. */
static struct net_device __fake_net_device = {
	.hard_header_len	= ETH_HLEN
};

static struct rtable __fake_rtable = {
	.u = {
		.dst = {
			.__refcnt	   = ATOMIC_INIT(1),
			.dev			= &__fake_net_device,
			.path		   = &__fake_rtable.u.dst,
			.metrics		= {[RTAX_MTU - 1] = 1500},
			.flags		  = DST_NOXFRM,
		}
	},
	.rt_flags   = 0,
};

/* Define ARP for IP since the Linux headers don't do it cleanly. */
struct ip_arphdr {
	uint16_t ar_hrd;
	uint16_t ar_pro;
	uint8_t ar_hln;
	uint8_t ar_pln;
	uint16_t ar_op;
	uint8_t ar_sha[ETH_ALEN];
	uint32_t ar_sip;
	uint8_t ar_tha[ETH_ALEN];
	uint32_t ar_tip;
} __attribute__((packed));
OFP_ASSERT(sizeof(struct ip_arphdr) == 28);


/* Push the Ethernet header back on and tranmit the packet. */
static int
dp_xmit_skb_push(struct sk_buff *skb)
{
	skb_push(skb, ETH_HLEN);
	return dp_xmit_skb(skb);
}

/* Perform maintainence related to a SNAT'd interface.  Currently, this only 
 * checks whether MAC->IP bindings have expired.
 *
 * Called with the RCU read lock */
void
snat_maint(struct net_bridge_port *p)
{
	struct snat_conf *sc;
	struct snat_mapping *m, *n;
	unsigned long flags;
	unsigned long timeout;

	spin_lock_irqsave(&p->lock, flags);
	sc = p->snat;
	if (!sc)
		goto done;

	timeout = sc->mac_timeout * HZ;

	list_for_each_entry_safe (m, n, &sc->mappings, node) {
		if (time_after(jiffies, m->used + timeout)) {
			list_del(&m->node);
			kfree(m);
		}
	}

done:
	spin_unlock_irqrestore(&p->lock, flags);
}

/* When the packet is bound for a local interface, strip off the fake
 * routing table.
 */
void snat_local_in(struct sk_buff *skb)
{
	if (skb->dst == (struct dst_entry *)&__fake_rtable) {
		dst_release(skb->dst);
		skb->dst = NULL;
	}
}

/* Check whether destination IP's address is in the IP->MAC mappings.
 * If it is, then overwrite the destination MAC with the value from the
 * cache.
 *
 * Returns -1 if there is a problem, otherwise 0. */
static int
dnat_mac(struct net_bridge_port *p, struct sk_buff *skb)
{
	struct snat_conf *sc = p->snat;
	struct iphdr *iph = ip_hdr(skb);
	struct ethhdr *eh = eth_hdr(skb);
	struct snat_mapping *m;

	if (skb->protocol != htons(ETH_P_IP)) 
		return 0;

	list_for_each_entry (m, &sc->mappings, node) {
		if (m->ip_addr == iph->daddr){
			/* Found it! */
			if (!make_writable(&skb)) {
				if (net_ratelimit())
					printk("make_writable failed\n");
				return -EINVAL;
			}
			m->used = jiffies;
			memcpy(eh->h_dest, m->hw_addr, ETH_ALEN);
			break;
		}
	}

	return 0;
}

static int
__snat_this_address(struct snat_conf *sc, u32 ip_addr)
{
	if (sc) {
		u32 h_ip_addr = ntohl(ip_addr);
		return (h_ip_addr >= sc->ip_addr_start &&
			h_ip_addr <= sc->ip_addr_end);
	}
	return 0;
}

static int
snat_this_address(struct net_bridge_port *p, u32 ip_addr)
{
	unsigned long int flags;
	int retval;

	spin_lock_irqsave(&p->lock, flags);
	retval = __snat_this_address(p->snat, ip_addr);
	spin_unlock_irqrestore(&p->lock, flags);

	return retval;
}

static int
snat_pre_route_finish(struct sk_buff *skb)
{
	struct net_bridge_port *p = skb->dev->br_port;
	struct snat_conf *sc;
	struct iphdr *iph = ip_hdr(skb);
	unsigned long flags;

	skb->dst = (struct dst_entry *)&__fake_rtable;
	dst_hold(skb->dst);

	/* Don't process packets that were not translated due to NAT */
	spin_lock_irqsave(&p->lock, flags);
	sc = p->snat;
	if (!__snat_this_address(sc, iph->daddr)) {
		/* If SNAT is configured for this input device, check the
		 * IP->MAC mappings to see if we should update the destination
		 * MAC. */
		if (sc)
			dnat_mac(skb->dev->br_port, skb);

	}
	spin_unlock_irqrestore(&p->lock, flags);

	/* Pass the translated packet as input to the OpenFlow stack, which
	 * consumes it. */
	skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	fwd_port_input(p->dp->chain, skb, p);

	return 0;
}

/* Checks whether 'skb' is an ARP request for an SNAT'd interface.  If
 * so, it will generate a response.  
 *
 * Returns 0 if the packet was not handled.  Otherwise, -1 is returned
 * and the caller is responsible for freeing 'skb'. */
static int 
handle_arp_snat(struct sk_buff *skb)
{
	struct net_bridge_port *p = skb->dev->br_port;
	struct ip_arphdr *ah;

	if (!pskb_may_pull(skb, sizeof *ah))
		return 0;

	ah = (struct ip_arphdr *)arp_hdr(skb);
	if ((ah->ar_op != htons(ARPOP_REQUEST)) 
			|| ah->ar_hln != ETH_ALEN
			|| ah->ar_pro != htons(ETH_P_IP)
			|| ah->ar_pln != 4)
		return 0;

	/* We're only interested in addresses we rewrite. */
	if (!snat_this_address(p, ah->ar_tip)) {
		return 0;
	}

	arp_send(ARPOP_REPLY, ETH_P_ARP, ah->ar_sip, skb->dev, ah->ar_tip, 
			 ah->ar_sha, p->dp->netdev->dev_addr, ah->ar_sha);

	return -1;
}

/* Checks whether 'skb' is a ping request for an SNAT'd interface.  If
 * so, it will generate a response.  
 *
 * Returns 0 if the packet was not handled.  Otherwise, -1 is returned
 * and the caller is responsible for freeing 'skb'. */
static int 
handle_icmp_snat(struct sk_buff *skb)
{
	struct net_bridge_port *p = skb->dev->br_port;
	struct ethhdr *eh;
	struct iphdr *iph;
	struct icmphdr *icmph;
	uint8_t tmp_eth[ETH_ALEN];
	uint32_t tmp_ip;
	struct sk_buff *nskb;

	/* We're only interested in addresses we rewrite. */
	iph = ip_hdr(skb);
	if (!snat_this_address(p, iph->daddr)) {
		return 0;
	}

	/* Drop fragments and packets not long enough to hold the ICMP
	 * header. */
	if ((ntohs(iph->frag_off) & IP_OFFSET) != 0 ||
	    !pskb_may_pull(skb, skb_transport_offset(skb) + 4))
		return 0;

	/* We only respond to echo requests to our address.  Continue 
	 * processing replies and other ICMP messages since they may be 
	 * intended for NAT'd hosts. */
	icmph = icmp_hdr(skb);
	if (icmph->type != ICMP_ECHO)
		return 0;

	/* Send an echo reply in response */
	nskb = skb_copy(skb, GFP_ATOMIC);
	if (!nskb) {
		if (net_ratelimit())
			printk("skb copy failed for icmp reply\n");
		return -1;
	}

	/* Update Ethernet header. */
	eh = eth_hdr(nskb);
	memcpy(tmp_eth, eh->h_dest, ETH_ALEN);
	memcpy(eh->h_dest, eh->h_source, ETH_ALEN);
	memcpy(eh->h_source, tmp_eth, ETH_ALEN);

	/* Update IP header.
	 * This is kind of busted, at least in that it doesn't check that the
	 * echoed IP options make sense. */
	iph = ip_hdr(nskb);
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = IPDEFTTL;
	iph->check = 0;
	tmp_ip = iph->daddr;
	iph->daddr = iph->saddr;
	iph->saddr = tmp_ip;
	iph->check = ip_fast_csum(iph, iph->ihl);

	/* Update ICMP header. */
	icmph = icmp_hdr(nskb);
	icmph->type = ICMP_ECHOREPLY;
	icmph->checksum = 0;
	icmph->checksum = ip_compute_csum(icmph,
					  nskb->tail - nskb->transport_header);

	dp_xmit_skb_push(nskb);

	return -1;
}

/* Check if any SNAT maintenance needs to be done on 'skb' before it's 
 * checked against the datapath's tables.  This includes DNAT
 * modification based on prior SNAT action and responding to ARP and
 * echo requests for the SNAT interface. 
 *
 * Returns -1 if the packet was handled and consumed, 0 if the caller
 * should continue to process 'skb'.
 */
int
snat_pre_route(struct sk_buff *skb)
{
	struct iphdr *iph;
	int len;

	WARN_ON_ONCE(skb_network_offset(skb));
	if (skb->protocol == htons(ETH_P_ARP)) {
		if (handle_arp_snat(skb))
			goto consume;
		return 0;
	}
	else if (skb->protocol != htons(ETH_P_IP)) 
		return 0;

	if (!pskb_may_pull(skb, sizeof *iph))
		goto consume;

	iph = ip_hdr(skb);
	if (iph->ihl < 5 || iph->version != 4)
		goto consume;

	if (!pskb_may_pull(skb, ip_hdrlen(skb)))
		goto consume;
	skb_set_transport_header(skb, ip_hdrlen(skb));

	/* Check if we need to echo reply for this address */
	iph = ip_hdr(skb);
	if ((iph->protocol == IPPROTO_ICMP) && (handle_icmp_snat(skb))) 
		goto consume;

	iph = ip_hdr(skb);
	if (unlikely(ip_fast_csum(iph, iph->ihl)))
		goto consume;

	len = ntohs(iph->tot_len);
	if ((skb->len < len) || len < (iph->ihl*4))
		goto consume;

	if (pskb_trim_rcsum(skb, len))
		goto consume;

	NF_HOOK(PF_INET, NF_INET_PRE_ROUTING, skb, skb->dev, NULL,
		snat_pre_route_finish);
	return -1;

consume:
	kfree_skb(skb);
	return -1;
}


static int 
snat_skb_finish(struct sk_buff *skb)
{
	NF_HOOK(PF_INET, NF_INET_POST_ROUTING, skb, NULL, skb->dev, 
			dp_xmit_skb_push);

	return 0;
}

/* Update the MAC->IP mappings for the private side of the SNAT'd
 * interface. */
static void
update_mapping(struct net_bridge_port *p, const struct sk_buff *skb)
{
	unsigned long flags;
	struct snat_conf *sc;
	const struct iphdr *iph = ip_hdr(skb);
	const struct ethhdr *eh = eth_hdr(skb);
	struct snat_mapping *m;

	spin_lock_irqsave(&p->lock, flags);
	sc = p->snat;
	if (!sc) 
		goto done;
	
	list_for_each_entry (m, &sc->mappings, node) {
		if (m->ip_addr == iph->saddr){
			memcpy(m->hw_addr, eh->h_source, ETH_ALEN);
			m->used = jiffies;
			goto done;
		}
	}

	m = kmalloc(sizeof *m, GFP_ATOMIC);
	if (!m)
		goto done;
	m->ip_addr = iph->saddr;
	memcpy(m->hw_addr, eh->h_source, ETH_ALEN);
	m->used = jiffies;

	list_add(&m->node, &sc->mappings);

done:
	spin_unlock_irqrestore(&p->lock, flags);
}

/* Perform SNAT modification on 'skb' and send out 'out_port'.  If the 
 * port was not configured for SNAT, it will be sent through the interface 
 * unmodified.  'skb' is not consumed, so caller will need to free it.
 */
void 
snat_skb(struct datapath *dp, const struct sk_buff *skb, int out_port)
{
	struct net_bridge_port *p = dp->ports[out_port];
	struct sk_buff *nskb;

	if (!p)
		return;

	/* FIXME: Expensive.  Just need to skb_clone() here?
	 * (However, the skb_copy() does linearize and ensure that the headers
	 * are accessible.) */
	nskb = skb_copy(skb, GFP_ATOMIC);
	if (!nskb)
		return;

	nskb->dev = p->dev;

	/* We only SNAT IP, so just send it on its way if not */
	if (skb->protocol != htons(ETH_P_IP)) {
		dp_xmit_skb(nskb);
		return;
	}

	/* Set the source MAC to the OF interface */
	memcpy(eth_hdr(nskb)->h_source, dp->netdev->dev_addr, ETH_ALEN);

	update_mapping(p, skb);

	/* Take the Ethernet header back off for netfilter hooks. */
	skb_pull(nskb, ETH_HLEN);

	NF_HOOK(PF_INET, NF_INET_FORWARD, nskb, skb->dev, nskb->dev, 
			snat_skb_finish);
}

/* Remove SNAT configuration on port 'p'.  
 *
 * NB: The caller must hold the port's spinlock. */
int
snat_free_conf(struct net_bridge_port *p)
{
	struct snat_conf *sc = p->snat;

	if (!sc) 
		return -EINVAL;

	/* Free existing mapping entries */
	while (!list_empty(&sc->mappings)) {
		struct snat_mapping *m = list_entry(sc->mappings.next, 
				struct snat_mapping, node);
		list_del(&m->node);
		kfree(m);
	}

	kfree(p->snat);
	p->snat = NULL;

	return 0;
}

/* Remove SNAT configuration from an interface. */
static int 
snat_del_port(struct datapath *dp, uint16_t port)
{
	unsigned long flags;
	struct net_bridge_port *p = dp->ports[port];

	if (!p) {
		if (net_ratelimit()) 
			printk("Attempt to remove snat on non-existent port: %d\n", port);
		return -EINVAL;
	}

	spin_lock_irqsave(&p->lock, flags);
	if (snat_free_conf(p)) {
		/* SNAT not configured on this port */
		spin_unlock_irqrestore(&p->lock, flags);
		if (net_ratelimit()) 
			printk("Attempt to remove snat on non-snat port: %d\n", port);
		return -EINVAL;
	}

	spin_unlock_irqrestore(&p->lock, flags);

	return 0;
}

/* Add SNAT configuration to an interface.  */
static int 
snat_add_port(struct datapath *dp, uint16_t port, 
		uint32_t ip_addr_start, uint32_t ip_addr_end,
		uint16_t mac_timeout)
{
	unsigned long flags;
	struct net_bridge_port *p = dp->ports[port];
	struct snat_conf *sc;
	

	if (mac_timeout == 0)
		mac_timeout = MAC_TIMEOUT_DEFAULT;

	if (!p) {
		if (net_ratelimit()) 
			printk("Attempt to add snat on non-existent port: %d\n", port);
		return -EINVAL;
	}
	
	/* If SNAT is already configured on the port, check whether the same
	 * IP addresses are used.  If so, just update the mac timeout
	 * configuration. Otherwise, drop all SNAT configuration and
	 * reconfigure it. */
	spin_lock_irqsave(&p->lock, flags);
	if (p->snat) {
		if ((p->snat->ip_addr_start == ip_addr_start) 
				&& (p->snat->ip_addr_end == ip_addr_end)) {
			p->snat->mac_timeout = mac_timeout;
			spin_unlock_irqrestore(&p->lock, flags);
			return 0;
		}

		/* Free the existing configuration and mappings. */
		snat_free_conf(p);
	}

	sc = kzalloc(sizeof *sc, GFP_ATOMIC);
	if (!sc) {
		spin_unlock_irqrestore(&p->lock, flags);
		return -ENOMEM;
	}

	sc->ip_addr_start = ip_addr_start;
	sc->ip_addr_end = ip_addr_end;
	sc->mac_timeout = mac_timeout;
	INIT_LIST_HEAD(&sc->mappings);

	p->snat = sc;
	spin_unlock_irqrestore(&p->lock, flags);

	return 0;
}

/* Handle a SNAT configuration message. 
 *
 * Returns 0 if no problems are found.  Otherwise, a negative errno. */
int 
snat_mod_config(struct datapath *dp, const struct nx_act_config *nac)
{
	int n_entries = (ntohs(nac->header.header.length) - sizeof *nac)
			/ sizeof (struct nx_snat_config);
	int ret = 0;
	int i;

	for (i=0; i<n_entries; i++) {
		const struct nx_snat_config *sc = &nac->snat[i];
		uint16_t port = ntohs(sc->port);
		int r = 0;

		if (sc->command == NXSC_ADD)
			r = snat_add_port(dp, port, 
					ntohl(sc->ip_addr_start), ntohl(sc->ip_addr_end), 
					ntohs(sc->mac_timeout));
		else 
			r = snat_del_port(dp, port);

		if (r)
			ret = r;
	}

	return ret;
}
#endif

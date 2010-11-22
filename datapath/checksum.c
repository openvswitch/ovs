/*
 * Copyright (c) 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "checksum.h"
#include "datapath.h"

 /* Types of checksums that we can receive (these all refer to L4 checksums):
 * 1. CHECKSUM_NONE: Device that did not compute checksum, contains full
 *	(though not verified) checksum in packet but not in skb->csum.  Packets
 *	from the bridge local port will also have this type.
 * 2. CHECKSUM_COMPLETE (CHECKSUM_HW): Good device that computes checksums,
 *	also the GRE module.  This is the same as CHECKSUM_NONE, except it has
 *	a valid skb->csum.  Importantly, both contain a full checksum (not
 *	verified) in the packet itself.  The only difference is that if the
 *	packet gets to L4 processing on this machine (not in DomU) we won't
 *	have to recompute the checksum to verify.  Most hardware devices do not
 *	produce packets with this type, even if they support receive checksum
 *	offloading (they produce type #5).
 * 3. CHECKSUM_PARTIAL (CHECKSUM_HW): Packet without full checksum and needs to
 *	be computed if it is sent off box.  Unfortunately on earlier kernels,
 *	this case is impossible to distinguish from #2, despite having opposite
 *	meanings.  Xen adds an extra field on earlier kernels (see #4) in order
 *	to distinguish the different states.
 * 4. CHECKSUM_UNNECESSARY (with proto_csum_blank true): This packet was
 *	generated locally by a Xen DomU and has a partial checksum.  If it is
 *	handled on this machine (Dom0 or DomU), then the checksum will not be
 *	computed.  If it goes off box, the checksum in the packet needs to be
 *	completed.  Calling skb_checksum_setup converts this to CHECKSUM_HW
 *	(CHECKSUM_PARTIAL) so that the checksum can be completed.  In later
 *	kernels, this combination is replaced with CHECKSUM_PARTIAL.
 * 5. CHECKSUM_UNNECESSARY (with proto_csum_blank false): Packet with a correct
 *	full checksum or using a protocol without a checksum.  skb->csum is
 *	undefined.  This is common from devices with receive checksum
 *	offloading.  This is somewhat similar to CHECKSUM_NONE, except that
 *	nobody will try to verify the checksum with CHECKSUM_UNNECESSARY.
 *
 * Note that on earlier kernels, CHECKSUM_COMPLETE and CHECKSUM_PARTIAL are
 * both defined as CHECKSUM_HW.  Normally the meaning of CHECKSUM_HW is clear
 * based on whether it is on the transmit or receive path.  After the datapath
 * it will be intepreted as CHECKSUM_PARTIAL.  If the packet already has a
 * checksum, we will panic.  Since we can receive packets with checksums, we
 * assume that all CHECKSUM_HW packets have checksums and map them to
 * CHECKSUM_NONE, which has a similar meaning (the it is only different if the
 * packet is processed by the local IP stack, in which case it will need to
 * be reverified).  If we receive a packet with CHECKSUM_HW that really means
 * CHECKSUM_PARTIAL, it will be sent with the wrong checksum.  However, there
 * shouldn't be any devices that do this with bridging.
 */
#ifdef NEED_CSUM_NORMALIZE
void compute_ip_summed(struct sk_buff *skb, bool xmit)
{
	/* For our convenience these defines change repeatedly between kernel
	 * versions, so we can't just copy them over...
	 */
	switch (skb->ip_summed) {
	case CHECKSUM_NONE:
		OVS_CB(skb)->ip_summed = OVS_CSUM_NONE;
		break;
	case CHECKSUM_UNNECESSARY:
		OVS_CB(skb)->ip_summed = OVS_CSUM_UNNECESSARY;
		break;
#ifdef CHECKSUM_HW
	/* In theory this could be either CHECKSUM_PARTIAL or CHECKSUM_COMPLETE.
	 * However, on the receive side we should only get CHECKSUM_PARTIAL
	 * packets from Xen, which uses some special fields to represent this
	 * (see below).  Since we can only make one type work, pick the one
	 * that actually happens in practice.
	 *
	 * On the transmit side (basically after skb_checksum_setup()
	 * has been run or on internal dev transmit), packets with
	 * CHECKSUM_COMPLETE aren't generated, so assume CHECKSUM_PARTIAL.
	 */
	case CHECKSUM_HW:
		if (!xmit)
			OVS_CB(skb)->ip_summed = OVS_CSUM_COMPLETE;
		else
			OVS_CB(skb)->ip_summed = OVS_CSUM_PARTIAL;

		break;
#else
	case CHECKSUM_COMPLETE:
		OVS_CB(skb)->ip_summed = OVS_CSUM_COMPLETE;
		break;
	case CHECKSUM_PARTIAL:
		OVS_CB(skb)->ip_summed = OVS_CSUM_PARTIAL;
		break;
#endif
	}

#if defined(CONFIG_XEN) && defined(HAVE_PROTO_DATA_VALID)
	/* Xen has a special way of representing CHECKSUM_PARTIAL on older
	 * kernels. It should not be set on the transmit path though.
	 */
	if (skb->proto_csum_blank)
		OVS_CB(skb)->ip_summed = OVS_CSUM_PARTIAL;

	WARN_ON_ONCE(skb->proto_csum_blank && xmit);
#endif
}

u8 get_ip_summed(struct sk_buff *skb)
{
	return OVS_CB(skb)->ip_summed;
}
#endif /* NEED_CSUM_NORMALIZE */

#if defined(CONFIG_XEN) && defined(HAVE_PROTO_DATA_VALID)
/* This code is based on skb_checksum_setup() from Xen's net/dev/core.c.  We
 * can't call this function directly because it isn't exported in all
 * versions. */
int vswitch_skb_checksum_setup(struct sk_buff *skb)
{
	struct iphdr *iph;
	unsigned char *th;
	int err = -EPROTO;
	__u16 csum_start, csum_offset;

	if (!skb->proto_csum_blank)
		return 0;

	if (skb->protocol != htons(ETH_P_IP))
		goto out;

	if (!pskb_may_pull(skb, skb_network_header(skb) + sizeof(struct iphdr) - skb->data))
		goto out;

	iph = ip_hdr(skb);
	th = skb_network_header(skb) + 4 * iph->ihl;

	csum_start = th - skb->head;
	switch (iph->protocol) {
	case IPPROTO_TCP:
		csum_offset = offsetof(struct tcphdr, check);
		break;
	case IPPROTO_UDP:
		csum_offset = offsetof(struct udphdr, check);
		break;
	default:
		if (net_ratelimit())
			pr_err("Attempting to checksum a non-TCP/UDP packet, "
			       "dropping a protocol %d packet",
			       iph->protocol);
		goto out;
	}

	if (!pskb_may_pull(skb, th + csum_offset + 2 - skb->data))
		goto out;

	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->proto_csum_blank = 0;
	set_skb_csum_pointers(skb, csum_start, csum_offset);

	err = 0;

out:
	return err;
}
#endif /* CONFIG_XEN && HAVE_PROTO_DATA_VALID */

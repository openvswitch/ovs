#include <linux/ipv6.h>
#include <linux/version.h>
#include <net/ipv6.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
int rpl_ipv6_skip_exthdr(const struct sk_buff *skb, int start,
			 u8 *nexthdrp, __be16 *frag_offp)
{
	u8 nexthdr = *nexthdrp;

	*frag_offp = 0;

	while (ipv6_ext_hdr(nexthdr)) {
		struct ipv6_opt_hdr _hdr, *hp;
		int hdrlen;

		if (nexthdr == NEXTHDR_NONE)
			return -1;
		hp = skb_header_pointer(skb, start, sizeof(_hdr), &_hdr);
		if (hp == NULL)
			return -1;
		if (nexthdr == NEXTHDR_FRAGMENT) {
			__be16 _frag_off, *fp;
			fp = skb_header_pointer(skb,
						start+offsetof(struct frag_hdr,
							       frag_off),
						sizeof(_frag_off),
						&_frag_off);
			if (fp == NULL)
				return -1;

			*frag_offp = *fp;
			if (ntohs(*frag_offp) & ~0x7)
				break;
			hdrlen = 8;
		} else if (nexthdr == NEXTHDR_AUTH)
			hdrlen = (hp->hdrlen+2)<<2;
		else
			hdrlen = ipv6_optlen(hp);

		nexthdr = hp->nexthdr;
		start += hdrlen;
	}

	*nexthdrp = nexthdr;
	return start;
}
EXPORT_SYMBOL_GPL(rpl_ipv6_skip_exthdr);
#endif /* Kernel version < 3.3 */

#ifndef HAVE_IP6_FH_F_SKIP_RH
/*
 * find the offset to specified header or the protocol number of last header
 * if target < 0. "last header" is transport protocol header, ESP, or
 * "No next header".
 *
 * Note that *offset is used as input/output parameter. an if it is not zero,
 * then it must be a valid offset to an inner IPv6 header. This can be used
 * to explore inner IPv6 header, eg. ICMPv6 error messages.
 *
 * If target header is found, its offset is set in *offset and return protocol
 * number. Otherwise, return -1.
 *
 * If the first fragment doesn't contain the final protocol header or
 * NEXTHDR_NONE it is considered invalid.
 *
 * Note that non-1st fragment is special case that "the protocol number
 * of last header" is "next header" field in Fragment header. In this case,
 * *offset is meaningless and fragment offset is stored in *fragoff if fragoff
 * isn't NULL.
 *
 * if flags is not NULL and it's a fragment, then the frag flag
 * IP6_FH_F_FRAG will be set. If it's an AH header, the
 * IP6_FH_F_AUTH flag is set and target < 0, then this function will
 * stop at the AH header. If IP6_FH_F_SKIP_RH flag was passed, then this
 * function will skip all those routing headers, where segements_left was 0.
 */
int rpl_ipv6_find_hdr(const struct sk_buff *skb, unsigned int *offset,
		  int target, unsigned short *fragoff, int *flags)
{
	unsigned int start = skb_network_offset(skb) + sizeof(struct ipv6hdr);
	u8 nexthdr = ipv6_hdr(skb)->nexthdr;
	unsigned int len;
	bool found;

	if (fragoff)
		*fragoff = 0;

	if (*offset) {
		struct ipv6hdr _ip6, *ip6;

		ip6 = skb_header_pointer(skb, *offset, sizeof(_ip6), &_ip6);
		if (!ip6 || (ip6->version != 6)) {
			printk(KERN_ERR "IPv6 header not found\n");
			return -EBADMSG;
		}
		start = *offset + sizeof(struct ipv6hdr);
		nexthdr = ip6->nexthdr;
	}
	len = skb->len - start;

	do {
		struct ipv6_opt_hdr _hdr, *hp;
		unsigned int hdrlen;
		found = (nexthdr == target);

		if ((!ipv6_ext_hdr(nexthdr)) || nexthdr == NEXTHDR_NONE) {
			if (target < 0 || found)
				break;
			return -ENOENT;
		}

		hp = skb_header_pointer(skb, start, sizeof(_hdr), &_hdr);
		if (hp == NULL)
			return -EBADMSG;

		if (nexthdr == NEXTHDR_ROUTING) {
			struct ipv6_rt_hdr _rh, *rh;

			rh = skb_header_pointer(skb, start, sizeof(_rh),
						&_rh);
			if (rh == NULL)
				return -EBADMSG;

			if (flags && (*flags & IP6_FH_F_SKIP_RH) &&
			    rh->segments_left == 0)
				found = false;
		}

		if (nexthdr == NEXTHDR_FRAGMENT) {
			unsigned short _frag_off;
			__be16 *fp;

			if (flags)	/* Indicate that this is a fragment */
				*flags |= IP6_FH_F_FRAG;
			fp = skb_header_pointer(skb,
						start+offsetof(struct frag_hdr,
							       frag_off),
						sizeof(_frag_off),
						&_frag_off);
			if (fp == NULL)
				return -EBADMSG;

			_frag_off = ntohs(*fp) & ~0x7;
			if (_frag_off) {
				if (target < 0 &&
				    ((!ipv6_ext_hdr(hp->nexthdr)) ||
				     hp->nexthdr == NEXTHDR_NONE)) {
					if (fragoff)
						*fragoff = _frag_off;
					return hp->nexthdr;
				}
				return -ENOENT;
			}
			hdrlen = 8;
		} else if (nexthdr == NEXTHDR_AUTH) {
			if (flags && (*flags & IP6_FH_F_AUTH) && (target < 0))
				break;
			hdrlen = (hp->hdrlen + 2) << 2;
		} else
			hdrlen = ipv6_optlen(hp);

		if (!found) {
			nexthdr = hp->nexthdr;
			len -= hdrlen;
			start += hdrlen;
		}
	} while (!found);

	*offset = start;
	return nexthdr;
}
EXPORT_SYMBOL_GPL(rpl_ipv6_find_hdr);

#endif

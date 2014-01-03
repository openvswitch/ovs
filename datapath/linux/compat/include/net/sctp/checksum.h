#ifndef __SCTP_CHECKSUM_WRAPPER_H
#define __SCTP_CHECKSUM_WRAPPER_H 1

#include_next <net/sctp/checksum.h>

#ifndef HAVE_SCTP_COMPUTE_CKSUM
static inline __le32 sctp_compute_cksum(const struct sk_buff *skb,
					unsigned int offset)
{
	const struct sk_buff *iter;

	__u32 crc32 = sctp_start_cksum(skb->data + offset,
				       skb_headlen(skb) - offset);
	skb_walk_frags(skb, iter)
		crc32 = sctp_update_cksum((__u8 *) iter->data,
					  skb_headlen(iter), crc32);

	/* Open-code sctp_end_cksum() to avoid a sparse warning due to a bug in
	 * sparse annotations in Linux fixed in 3.10 in commit eee1d5a14 (sctp:
	 * Correct type and usage of sctp_end_cksum()). */
	return cpu_to_le32(~crc32);
}
#endif

#endif

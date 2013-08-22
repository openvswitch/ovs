#ifndef __LINUX_SCTP_WRAPPER_H
#define __LINUX_SCTP_WRAPPER_H 1

#include_next <linux/sctp.h>

#ifndef HAVE_SKBUFF_HEADER_HELPERS
static inline struct sctphdr *sctp_hdr(const struct sk_buff *skb)
{
	return (struct sctphdr *)skb_transport_header(skb);
}
#endif /* HAVE_SKBUFF_HEADER_HELPERS */

#endif

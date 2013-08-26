#ifndef __NET_CHECKSUM_WRAPPER_H
#define __NET_CHECKSUM_WRAPPER_H 1

#include_next <net/checksum.h>

#ifndef HAVE_CSUM_UNFOLD
static inline __wsum csum_unfold(__sum16 n)
{
	return (__force __wsum)n;
}
#endif /* !HAVE_CSUM_UNFOLD */

/* Workaround for debugging included in certain versions of XenServer.  It only
 * applies to 32-bit x86.
 */
#if defined(HAVE_CSUM_COPY_DBG) && defined(CONFIG_X86_32)
#define csum_and_copy_to_user(src, dst, len, sum, err_ptr) \
	csum_and_copy_to_user(src, dst, len, sum, NULL, err_ptr)
#endif

#ifndef HAVE_CSUM_REPLACE4
static inline void csum_replace4(__sum16 *sum, __be32 from, __be32 to)
{
	__be32 diff[] = { ~from, to };

	*sum = csum_fold(csum_partial((char *)diff, sizeof(diff), ~csum_unfold(*sum)));
}

static inline void csum_replace2(__sum16 *sum, __be16 from, __be16 to)
{
	csum_replace4(sum, (__force __be32)from, (__force __be32)to);
}
#endif

#ifndef CSUM_MANGLED_0
#define CSUM_MANGLED_0 ((__force __sum16)0xffff)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
void inet_proto_csum_replace16(__sum16 *sum, struct sk_buff *skb,
			       const __be32 *from, const __be32 *to,
			       int pseudohdr);
#endif
#endif /* checksum.h */

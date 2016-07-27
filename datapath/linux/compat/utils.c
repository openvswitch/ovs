#include <linux/module.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/inet.h>
#include <linux/mm.h>
#include <linux/net.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/ratelimit.h>

#include <net/sock.h>

#include <asm/byteorder.h>
#include <asm/uaccess.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
void rpl_inet_proto_csum_replace16(__sum16 *sum, struct sk_buff *skb,
			           const __be32 *from, const __be32 *to,
			           int pseudohdr)
{
	__be32 diff[] = {
		~from[0], ~from[1], ~from[2], ~from[3],
		to[0], to[1], to[2], to[3],
	};
	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		*sum = csum_fold(csum_partial(diff, sizeof(diff),
					~csum_unfold(*sum)));
		if (skb->ip_summed == CHECKSUM_COMPLETE && pseudohdr)
			skb->csum = ~csum_partial(diff, sizeof(diff),
					~skb->csum);
	} else if (pseudohdr)
		*sum = ~csum_fold(csum_partial(diff, sizeof(diff),
					csum_unfold(*sum)));
}
EXPORT_SYMBOL_GPL(rpl_inet_proto_csum_replace16);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)

bool rpl___net_get_random_once(void *buf, int nbytes, bool *done,
			   atomic_t *done_key)
{
	static DEFINE_SPINLOCK(lock);
	unsigned long flags;

	spin_lock_irqsave(&lock, flags);
	if (*done) {
		spin_unlock_irqrestore(&lock, flags);
		return false;
	}

	get_random_bytes(buf, nbytes);
	*done = true;
	spin_unlock_irqrestore(&lock, flags);

	atomic_set(done_key, 1);

	return true;
}
EXPORT_SYMBOL_GPL(rpl___net_get_random_once);

#endif

#ifdef NEED_ALLOC_PERCPU_GFP
void __percpu *__alloc_percpu_gfp(size_t size, size_t align, gfp_t gfp)
{
	void __percpu *p;
	int i;

	/* older kernel do not allow all GFP flags, specifically atomic
	 * allocation.
	 */
	if (gfp & ~(GFP_KERNEL | __GFP_ZERO))
		return NULL;
	p = __alloc_percpu(size, align);
	if (!p)
		return p;

	if (!(gfp & __GFP_ZERO))
		return p;

	for_each_possible_cpu(i) {
		void *d;

		d = per_cpu_ptr(p, i);
		memset(d, 0, size);
	}
	return p;
}
#endif

#ifndef HAVE_NLA_PUT_64BIT
int rpl_nla_put_64bit(struct sk_buff *skb, int attrtype, int attrlen,
		      const void *data, int padattr)
{
	size_t len;

	if (nla_need_padding_for_64bit(skb))
		len = nla_total_size_64bit(attrlen);
	else
		len = nla_total_size(attrlen);
	if (unlikely(skb_tailroom(skb) < len))
		return -EMSGSIZE;

	__nla_put_64bit(skb, attrtype, attrlen, data, padattr);
	return 0;
}
EXPORT_SYMBOL_GPL(rpl_nla_put_64bit);

void rpl___nla_put_64bit(struct sk_buff *skb, int attrtype, int attrlen,
			const void *data, int padattr)
{
	struct nlattr *nla;

	nla = __nla_reserve_64bit(skb, attrtype, attrlen, padattr);
	memcpy(nla_data(nla), data, attrlen);
}
EXPORT_SYMBOL_GPL(rpl___nla_put_64bit);

struct nlattr *rpl___nla_reserve_64bit(struct sk_buff *skb, int attrtype,
				       int attrlen, int padattr)
{
	if (nla_need_padding_for_64bit(skb))
		nla_align_64bit(skb, padattr);

	return __nla_reserve(skb, attrtype, attrlen);
}
EXPORT_SYMBOL_GPL(rpl___nla_reserve_64bit);
#endif

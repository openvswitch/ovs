#include <linux/module.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/inet.h>
#include <linux/mm.h>
#include <linux/net.h>
#include <net/checksum.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/ratelimit.h>

#include <net/sock.h>

#include <asm/byteorder.h>
#include <asm/uaccess.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
void inet_proto_csum_replace16(__sum16 *sum, struct sk_buff *skb,
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
#endif

bool __net_get_random_once(void *buf, int nbytes, bool *done,
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

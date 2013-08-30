#include <asm/div64.h>
#include <linux/reciprocal_div.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
/* definition is required since reciprocal_value() is not exported */
u32 reciprocal_value(u32 k)
{
	u64 val = (1LL << 32) + (k - 1);
	do_div(val, k);
	return (u32)val;
}
#endif

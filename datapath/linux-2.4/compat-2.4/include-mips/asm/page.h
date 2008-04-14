#ifndef __ASM_MIPS_PAGE_H_WRAPPER
#define __ASM_MIPS_PAGE_H_WRAPPER 1

#include <linux/version.h>
#include_next <asm/page.h>
#include <asm/break.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,25)

#define BUG()                                                           \
do {                                                                    \
        __asm__ __volatile__("break %0" : : "i" (BRK_BUG));             \
} while (0)

#endif /* linux kernel < 2.4.25 */

#endif /* asm/page.h */

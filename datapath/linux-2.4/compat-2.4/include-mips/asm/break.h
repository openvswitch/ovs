#ifndef __ASM_MIPS_BREAK_H_WRAPPER
#define __ASM_MIPS_BREAK_H_WRAPPER 1

#include <linux/version.h>
#include_next <asm/break.h>


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,25)

/*
 * The following break codes are or were in use for specific purposes in
 * other MIPS operating systems.  Linux/MIPS doesn't use all of them.  The
 * unused ones are here as placeholders; we might encounter them in
 * non-Linux/MIPS object files or make use of them in the future.
 */
#define BRK_USERBP  0   /* User bp (used by debuggers) */
#define BRK_KERNELBP    1   /* Break in the kernel */
#define BRK_ABORT   2   /* Sometimes used by abort(3) to SIGIOT */
#define BRK_BD_TAKEN    3   /* For bd slot emulation - not implemented */
#define BRK_BD_NOTTAKEN 4   /* For bd slot emulation - not implemented */
#define BRK_SSTEPBP 5   /* User bp (used by debuggers) */
#define BRK_OVERFLOW    6   /* Overflow check */
#define BRK_DIVZERO 7   /* Divide by zero check */
#define BRK_RANGE   8   /* Range error check */
#define BRK_STACKOVERFLOW 9 /* For Ada stackchecking */
#define BRK_NORLD   10  /* No rld found - not used by Linux/MIPS */
#define _BRK_THREADBP   11  /* For threads, user bp (used by debuggers) */
#define BRK_MULOVF  1023    /* Multiply overflow */
#define BRK_BUG     512 /* Used by BUG() */

#endif /* linux kernel < 2.4.25 */

#endif /* asm/break.h */

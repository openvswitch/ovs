#ifndef __LINUX_POISON_WRAPPER_H
#define __LINUX_POISON_WRAPPER_H 1

#include_next <linux/poison.h>

#ifndef FLEX_ARRAY_FREE
/********** lib/flex_array.c **********/
#define FLEX_ARRAY_FREE 0x6c    /* for use-after-free poisoning */
#endif

#endif

#ifndef __LINUX_CHECKSUM_WRAPPER_H
#define __LINUX_CHECKSUM_WRAPPER_H 1

#include_next <linux/checksum.h>

#ifndef CSUM_MANGLED_0
#define CSUM_MANGLED_0 ((__force __sum16)0xffff)
#endif

#endif

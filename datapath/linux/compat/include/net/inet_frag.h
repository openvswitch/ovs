#ifndef __NET_INET_FRAG_WRAPPER_H
#define __NET_INET_FRAG_WRAPPER_H 1

#include <linux/version.h>
#include_next <net/inet_frag.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
#define inet_frag_evictor(nf, f, force)					\
	do {								\
		if (force || atomic_read(&nf->mem) > nf->high_thresh) { \
			inet_frag_evictor(nf, f);			\
		}							\
	} while (0)
#endif

#endif /* inet_frag.h */

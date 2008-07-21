dist_modules += compat24

compat24_sources = \
	linux-2.4/compat-2.4/attr.c \
	linux-2.4/compat-2.4/compat24.c \
	linux-2.4/compat-2.4/genetlink.c \
	linux-2.4/compat-2.4/kernel.c \
	linux-2.4/compat-2.4/kthread.c \
	linux-2.4/compat-2.4/netlink.c \
	linux-2.4/compat-2.4/random32.c \
	linux-2.4/compat-2.4/rcupdate.c \
	linux-2.4/compat-2.4/sched.c \
	linux-2.4/compat-2.4/string.c

compat24_headers = \
	linux-2.4/compat-2.4/compat24.h \
	linux-2.4/compat-2.4/include-arm/asm/atomic.h \
	linux-2.4/compat-2.4/include-i386/asm/atomic.h \
	linux-2.4/compat-2.4/include-mips/asm/atomic.h \
	linux-2.4/compat-2.4/include-mips/asm/barrier.h \
	linux-2.4/compat-2.4/include-mips/asm/break.h \
	linux-2.4/compat-2.4/include-mips/asm/page.h \
	linux-2.4/compat-2.4/include-mips/asm/system.h \
	linux-2.4/compat-2.4/include/asm/system.h \
	linux-2.4/compat-2.4/include/linux/compiler.h \
	linux-2.4/compat-2.4/include/linux/delay.h \
	linux-2.4/compat-2.4/include/linux/etherdevice.h \
	linux-2.4/compat-2.4/include/linux/genetlink.h \
	linux-2.4/compat-2.4/include/linux/gfp.h \
	linux-2.4/compat-2.4/include/linux/if_ether.h \
	linux-2.4/compat-2.4/include/linux/if_vlan.h \
	linux-2.4/compat-2.4/include/linux/ip.h \
	linux-2.4/compat-2.4/include/linux/ipv6.h \
	linux-2.4/compat-2.4/include/linux/jiffies.h \
	linux-2.4/compat-2.4/include/linux/kernel.h \
	linux-2.4/compat-2.4/include/linux/kthread.h \
	linux-2.4/compat-2.4/include/linux/list.h \
	linux-2.4/compat-2.4/include/linux/llc.h \
	linux-2.4/compat-2.4/include/linux/module.h \
	linux-2.4/compat-2.4/include/linux/mutex.h \
	linux-2.4/compat-2.4/include/linux/netdevice.h \
	linux-2.4/compat-2.4/include/linux/netlink.h \
	linux-2.4/compat-2.4/include/linux/random.h \
	linux-2.4/compat-2.4/include/linux/rculist.h \
	linux-2.4/compat-2.4/include/linux/rcupdate.h \
	linux-2.4/compat-2.4/include/linux/sched.h \
	linux-2.4/compat-2.4/include/linux/skbuff.h \
	linux-2.4/compat-2.4/include/linux/slab.h \
	linux-2.4/compat-2.4/include/linux/sockios.h \
	linux-2.4/compat-2.4/include/linux/spinlock.h \
	linux-2.4/compat-2.4/include/linux/string.h \
	linux-2.4/compat-2.4/include/linux/tcp.h \
	linux-2.4/compat-2.4/include/linux/timer.h \
	linux-2.4/compat-2.4/include/linux/types.h \
	linux-2.4/compat-2.4/include/linux/udp.h \
	linux-2.4/compat-2.4/include/net/checksum.h \
	linux-2.4/compat-2.4/include/net/genetlink.h \
	linux-2.4/compat-2.4/include/net/llc_pdu.h \
	linux-2.4/compat-2.4/include/net/netlink.h

EXTRA_DIST += linux-2.4/compat-2.4/TODO

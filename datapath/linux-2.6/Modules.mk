openvswitch_sources += \
	linux-2.6/compat-2.6/addrconf_core-openvswitch.c \
	linux-2.6/compat-2.6/dev-openvswitch.c \
	linux-2.6/compat-2.6/genetlink-openvswitch.c \
	linux-2.6/compat-2.6/ip_output-openvswitch.c \
	linux-2.6/compat-2.6/kmemdup.c \
	linux-2.6/compat-2.6/netdevice.c \
	linux-2.6/compat-2.6/skbuff-openvswitch.c \
	linux-2.6/compat-2.6/time.c
openvswitch_headers += \
	linux-2.6/compat-2.6/include/asm-generic/bug.h \
	linux-2.6/compat-2.6/include/linux/bottom_half.h \
	linux-2.6/compat-2.6/include/linux/compiler.h \
	linux-2.6/compat-2.6/include/linux/compiler-gcc.h \
	linux-2.6/compat-2.6/include/linux/cpumask.h \
	linux-2.6/compat-2.6/include/linux/dmi.h \
	linux-2.6/compat-2.6/include/linux/err.h \
	linux-2.6/compat-2.6/include/linux/genetlink.h \
	linux-2.6/compat-2.6/include/linux/icmp.h \
	linux-2.6/compat-2.6/include/linux/if.h \
	linux-2.6/compat-2.6/include/linux/if_arp.h \
	linux-2.6/compat-2.6/include/linux/if_ether.h \
	linux-2.6/compat-2.6/include/linux/if_vlan.h \
	linux-2.6/compat-2.6/include/linux/in.h \
	linux-2.6/compat-2.6/include/linux/inetdevice.h \
	linux-2.6/compat-2.6/include/linux/ip.h \
	linux-2.6/compat-2.6/include/linux/ipv6.h \
	linux-2.6/compat-2.6/include/linux/jiffies.h \
	linux-2.6/compat-2.6/include/linux/kernel.h \
	linux-2.6/compat-2.6/include/linux/kobject.h \
	linux-2.6/compat-2.6/include/linux/lockdep.h \
	linux-2.6/compat-2.6/include/linux/log2.h \
	linux-2.6/compat-2.6/include/linux/mutex.h \
	linux-2.6/compat-2.6/include/linux/netdevice.h \
	linux-2.6/compat-2.6/include/linux/netfilter_bridge.h \
	linux-2.6/compat-2.6/include/linux/netfilter_ipv4.h \
	linux-2.6/compat-2.6/include/linux/netlink.h \
	linux-2.6/compat-2.6/include/linux/rculist.h \
	linux-2.6/compat-2.6/include/linux/rcupdate.h \
	linux-2.6/compat-2.6/include/linux/rtnetlink.h \
	linux-2.6/compat-2.6/include/linux/skbuff.h \
	linux-2.6/compat-2.6/include/linux/slab.h \
	linux-2.6/compat-2.6/include/linux/stddef.h \
	linux-2.6/compat-2.6/include/linux/tcp.h \
	linux-2.6/compat-2.6/include/linux/timer.h \
	linux-2.6/compat-2.6/include/linux/types.h \
	linux-2.6/compat-2.6/include/linux/udp.h \
	linux-2.6/compat-2.6/include/linux/workqueue.h \
	linux-2.6/compat-2.6/include/net/checksum.h \
	linux-2.6/compat-2.6/include/net/dst.h \
	linux-2.6/compat-2.6/include/net/genetlink.h \
	linux-2.6/compat-2.6/include/net/ip.h \
	linux-2.6/compat-2.6/include/net/netlink.h \
	linux-2.6/compat-2.6/include/net/protocol.h \
	linux-2.6/compat-2.6/include/net/route.h \
	linux-2.6/compat-2.6/genetlink.inc

both_modules += brcompat
brcompat_sources = \
	linux-2.6/compat-2.6/genetlink-brcompat.c \
	brcompat.c \
	brc_procfs.c
brcompat_headers = \
	brc_procfs.h

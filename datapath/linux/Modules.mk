openvswitch_sources += \
	linux/compat/addrconf_core-openvswitch.c \
	linux/compat/dev-openvswitch.c \
	linux/compat/flex_array.c \
	linux/compat/genetlink-openvswitch.c \
	linux/compat/ip_output-openvswitch.c \
	linux/compat/kmemdup.c \
	linux/compat/netdevice.c \
	linux/compat/reciprocal_div.c \
	linux/compat/skbuff-openvswitch.c \
	linux/compat/time.c
openvswitch_headers += \
	linux/compat/include/asm-generic/bug.h \
	linux/compat/include/linux/bottom_half.h \
	linux/compat/include/linux/compiler.h \
	linux/compat/include/linux/compiler-gcc.h \
	linux/compat/include/linux/cpumask.h \
	linux/compat/include/linux/dmi.h \
	linux/compat/include/linux/err.h \
	linux/compat/include/linux/flex_array.h \
	linux/compat/include/linux/genetlink.h \
	linux/compat/include/linux/icmp.h \
	linux/compat/include/linux/icmpv6.h \
	linux/compat/include/linux/if.h \
	linux/compat/include/linux/if_arp.h \
	linux/compat/include/linux/if_ether.h \
	linux/compat/include/linux/if_vlan.h \
	linux/compat/include/linux/in.h \
	linux/compat/include/linux/inetdevice.h \
	linux/compat/include/linux/ip.h \
	linux/compat/include/linux/ipv6.h \
	linux/compat/include/linux/jiffies.h \
	linux/compat/include/linux/kernel.h \
	linux/compat/include/linux/kobject.h \
	linux/compat/include/linux/lockdep.h \
	linux/compat/include/linux/log2.h \
	linux/compat/include/linux/mutex.h \
	linux/compat/include/linux/netdevice.h \
	linux/compat/include/linux/netfilter_bridge.h \
	linux/compat/include/linux/netfilter_ipv4.h \
	linux/compat/include/linux/netlink.h \
	linux/compat/include/linux/poison.h \
	linux/compat/include/linux/rculist.h \
	linux/compat/include/linux/rcupdate.h \
	linux/compat/include/linux/reciprocal_div.h \
	linux/compat/include/linux/rtnetlink.h \
	linux/compat/include/linux/skbuff.h \
	linux/compat/include/linux/slab.h \
	linux/compat/include/linux/stddef.h \
	linux/compat/include/linux/tcp.h \
	linux/compat/include/linux/timer.h \
	linux/compat/include/linux/types.h \
	linux/compat/include/linux/udp.h \
	linux/compat/include/linux/workqueue.h \
	linux/compat/include/net/checksum.h \
	linux/compat/include/net/dst.h \
	linux/compat/include/net/genetlink.h \
	linux/compat/include/net/ip.h \
	linux/compat/include/net/net_namespace.h \
	linux/compat/include/net/netlink.h \
	linux/compat/include/net/protocol.h \
	linux/compat/include/net/route.h \
	linux/compat/genetlink.inc

both_modules += brcompat
brcompat_sources = linux/compat/genetlink-brcompat.c brcompat.c
brcompat_headers =

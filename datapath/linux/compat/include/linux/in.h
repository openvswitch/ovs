#ifndef __LINUX_IN_WRAPPER_H
#define __LINUX_IN_WRAPPER_H 1

#include_next <linux/in.h>

#include <linux/module.h>
#ifndef HAVE_PROTO_PORTS_OFFSET
static inline int proto_ports_offset(int proto)
{
	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_DCCP:
	case IPPROTO_ESP:	/* SPI */
	case IPPROTO_SCTP:
	case IPPROTO_UDPLITE:
		return 0;
	case IPPROTO_AH:	/* SPI */
		return 4;
	default:
		return -EINVAL;
	}
}
#endif

#ifndef HAVE_IPV4_IS_MULTICAST

static inline bool ipv4_is_loopback(__be32 addr)
{
	return (addr & htonl(0xff000000)) == htonl(0x7f000000);
}

static inline bool ipv4_is_multicast(__be32 addr)
{
	return (addr & htonl(0xf0000000)) == htonl(0xe0000000);
}

static inline bool ipv4_is_local_multicast(__be32 addr)
{
	return (addr & htonl(0xffffff00)) == htonl(0xe0000000);
}

static inline bool ipv4_is_lbcast(__be32 addr)
{
	/* limited broadcast */
	return addr == htonl(INADDR_BROADCAST);
}

static inline bool ipv4_is_zeronet(__be32 addr)
{
	return (addr & htonl(0xff000000)) == htonl(0x00000000);
}

#endif /* !HAVE_IPV4_IS_MULTICAST */

#endif

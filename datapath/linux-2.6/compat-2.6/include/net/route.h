#ifndef __NET_ROUTE_WRAPPER_H
#define __NET_ROUTE_WRAPPER_H 1

#include_next <net/route.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

#define ip_route_output_key(net, rp, flp) \
		ip_route_output_key((rp), (flp))

#endif /* linux kernel < 2.6.25 */

#endif

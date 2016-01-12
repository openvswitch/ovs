#ifndef __LINUX_NETDEV_FEATURES_WRAPPER_H
#define __LINUX_NETDEV_FEATURES_WRAPPER_H

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
#include_next <linux/netdev_features.h>
#endif

#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0)
/* On RHEL 6, netdev features are defined in netdevice.h header. */
#include <linux/netdevice.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define NETIF_F_HW_VLAN_CTAG_TX NETIF_F_HW_VLAN_TX
#endif

#ifndef NETIF_F_GSO_GRE
#define NETIF_F_GSO_GRE 0
#endif

#ifndef NETIF_F_GSO_GRE_CSUM
#define NETIF_F_GSO_GRE_CSUM 0
#else
#define HAVE_NETIF_F_GSO_GRE_CSUM
#endif

#ifndef NETIF_F_GSO_IPIP
#define NETIF_F_GSO_IPIP 0
#endif

#ifndef NETIF_F_GSO_SIT
#define NETIF_F_GSO_SIT 0
#endif

#ifndef NETIF_F_GSO_UDP_TUNNEL
#define NETIF_F_GSO_UDP_TUNNEL 0
#else
#define HAVE_NETIF_F_GSO_UDP_TUNNEL 0
#endif

#ifndef NETIF_F_GSO_UDP_TUNNEL_CSUM
#define NETIF_F_GSO_UDP_TUNNEL_CSUM 0
#define SKB_GSO_UDP_TUNNEL_CSUM 0
#endif

#ifndef NETIF_F_GSO_MPLS
#define NETIF_F_GSO_MPLS 0
#endif

#ifndef NETIF_F_HW_VLAN_STAG_TX
#define NETIF_F_HW_VLAN_STAG_TX 0
#endif

#ifndef NETIF_F_GSO_TUNNEL_REMCSUM
#define NETIF_F_GSO_TUNNEL_REMCSUM 0
#define SKB_GSO_TUNNEL_REMCSUM 0
#else
/* support for REM_CSUM is added in 3.19 but API are not defined
 * till 4.0, so turn on REMSUM support on kernel 4.0 onwards.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
#define HAVE_NETIF_F_GSO_TUNNEL_REMCSUM
#endif
#endif

#ifndef NETIF_F_RXCSUM
#define NETIF_F_RXCSUM	0
#endif

#ifndef NETIF_F_GSO_ENCAP_ALL
#define NETIF_F_GSO_ENCAP_ALL	(NETIF_F_GSO_GRE |			\
				 NETIF_F_GSO_GRE_CSUM |			\
				 NETIF_F_GSO_IPIP |			\
				 NETIF_F_GSO_SIT |			\
				 NETIF_F_GSO_UDP_TUNNEL |		\
				 NETIF_F_GSO_UDP_TUNNEL_CSUM |		\
				 NETIF_F_GSO_MPLS)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
#define SKB_GSO_GRE 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define SKB_GSO_UDP_TUNNEL 0
#endif

#ifndef HAVE_NETIF_F_GSO_GRE_CSUM
#define SKB_GSO_GRE_CSUM 0
#endif

#endif

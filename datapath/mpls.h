#ifndef MPLS_H
#define MPLS_H 1

#include <linux/if_ether.h>

#define MPLS_BOS_MASK	0x00000100
#define MPLS_HLEN 4

static inline bool eth_p_mpls(__be16 eth_type)
{
	return eth_type == htons(ETH_P_MPLS_UC) ||
		eth_type == htons(ETH_P_MPLS_MC);
}

#endif

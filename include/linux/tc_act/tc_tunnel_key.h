#ifndef __LINUX_TC_ACT_TC_TUNNEL_KEY_WRAPPER_H
#define __LINUX_TC_ACT_TC_TUNNEL_KEY_WRAPPER_H 1

#if defined(__KERNEL__) || defined(HAVE_TCA_TUNNEL_KEY_ENC_DST_PORT)
#include_next <linux/tc_act/tc_tunnel_key.h>
#else

/*
 * Copyright (c) 2016, Amir Vadai <amir@vadai.me>
 * Copyright (c) 2016, Mellanox Technologies. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/pkt_cls.h>

#define TCA_TUNNEL_KEY_ACT_SET	    1
#define TCA_TUNNEL_KEY_ACT_RELEASE  2

struct tc_tunnel_key {
	tc_gen;
	int t_action;
};

enum {
	TCA_TUNNEL_KEY_UNSPEC,
	TCA_TUNNEL_KEY_TM,
	TCA_TUNNEL_KEY_PARMS,
	TCA_TUNNEL_KEY_ENC_IPV4_SRC,	/* be32 */
	TCA_TUNNEL_KEY_ENC_IPV4_DST,	/* be32 */
	TCA_TUNNEL_KEY_ENC_IPV6_SRC,	/* struct in6_addr */
	TCA_TUNNEL_KEY_ENC_IPV6_DST,	/* struct in6_addr */
	TCA_TUNNEL_KEY_ENC_KEY_ID,	/* be64 */
	TCA_TUNNEL_KEY_PAD,
	TCA_TUNNEL_KEY_ENC_DST_PORT,	/* be16 */
	__TCA_TUNNEL_KEY_MAX,
};

#define TCA_TUNNEL_KEY_MAX (__TCA_TUNNEL_KEY_MAX - 1)

#endif /* __KERNEL__ || HAVE_TCA_TUNNEL_KEY_ENC_DST_PORT */

#endif /* __LINUX_TC_ACT_TC_TUNNEL_KEY_WRAPPER_H */

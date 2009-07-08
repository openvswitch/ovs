/*
 * Copyright (c) 2009 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef DP_DEV_H
#define DP_DEV_H 1

#include <linux/percpu.h>

struct dp_dev {
	struct datapath *dp;
	int port_no;

	struct net_device *dev;
	struct net_device_stats stats;
	struct pcpu_lstats *lstats;
};

static inline struct dp_dev *dp_dev_priv(struct net_device *netdev)
{
	return netdev_priv(netdev);
}

struct net_device *dp_dev_create(struct datapath *, const char *, int port_no);
void dp_dev_destroy(struct net_device *);
int dp_dev_recv(struct net_device *, struct sk_buff *);
int is_dp_dev(struct net_device *);
struct datapath *dp_dev_get_dp(struct net_device *);

#endif /* dp_dev.h */

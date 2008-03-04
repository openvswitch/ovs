#ifndef DATAPATH_T_H
#define DATAPATH_T_H 1

#include <linux/socket.h>
#include <linux/capability.h>
#include <linux/skbuff.h>
#include <net/genetlink.h>
#include "openflow-netlink.h"

int dp_genl_benchmark_nl(struct sk_buff *, struct genl_info *);

#endif

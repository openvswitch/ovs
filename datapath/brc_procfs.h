/*
 * Copyright (c) 2009 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef BRC_PROCFS_H
#define BRC_PROCFS_H 1

struct sk_buff;
struct genl_info;

void brc_procfs_exit(void);
int brc_genl_set_proc(struct sk_buff *skb, struct genl_info *info);

#endif /* brc_procfs.h */


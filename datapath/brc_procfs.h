/*
 * Copyright (c) 2009, 2011 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef BRC_PROCFS_H
#define BRC_PROCFS_H 1

struct sk_buff;
struct genl_info;

/* Maximum length of BRC_GENL_A_PROC_DIR and BRC_GENL_A_PROC_NAME strings. */
#define BRC_NAME_LEN_MAX 32

void brc_procfs_exit(void);
int brc_genl_set_proc(struct sk_buff *skb, struct genl_info *info);

#endif /* brc_procfs.h */


/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/genetlink.h>
#include "brc_procfs.h"
#include "openvswitch/brcompat-netlink.h"

/* This code implements a Generic Netlink command BRC_GENL_C_SET_PROC that can
 * be used to add, modify, and delete arbitrary files in selected
 * subdirectories of /proc.  It's a horrible kluge prompted by the need to
 * simulate certain /proc/net/vlan and /proc/net/bonding files for software
 * that wants to read them, and with any luck it will go away eventually.
 *
 * The implementation is a kluge too.  In particular, we want to release the
 * strings copied into the 'data' members of proc_dir_entry when the
 * proc_dir_entry structures are freed, but there doesn't appear to be a way to
 * hook that, so instead we have to rely on being the only entity modifying the
 * directories in question.
 */

static int brc_seq_show(struct seq_file *seq, void *unused)
{
	seq_puts(seq, seq->private);
	return 0;
}

static int brc_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, brc_seq_show, PDE(inode)->data);
}

static struct file_operations brc_fops = {
	.owner = THIS_MODULE,
	.open    = brc_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

static struct proc_dir_entry *proc_vlan_dir;
static struct proc_dir_entry *proc_bonding_dir;

static struct proc_dir_entry *brc_lookup_entry(struct proc_dir_entry *de, const char *name)
{
	int namelen = strlen(name);
	for (de = de->subdir; de; de = de->next) {
		if (de->namelen != namelen)
			continue;
		if (!memcmp(name, de->name, de->namelen))
			return de;
	}
	return NULL;
}

static struct proc_dir_entry *brc_open_dir(const char *dir_name,
					   struct proc_dir_entry *parent,
					   struct proc_dir_entry **dirp)
{
	if (!*dirp) {
		struct proc_dir_entry *dir;
		if (brc_lookup_entry(parent, dir_name)) {
			pr_warn("%s proc directory exists, can't simulate--"
				"probably its real module is loaded\n",
				dir_name);
			return NULL;
		}
		dir = *dirp = proc_mkdir(dir_name, parent);
	}
	return *dirp;
}

int brc_genl_set_proc(struct sk_buff *skb, struct genl_info *info)
{
	struct proc_dir_entry *dir, *entry;
	const char *dir_name, *name;
	char *data;

	if (!info->attrs[BRC_GENL_A_PROC_DIR] ||
	    VERIFY_NUL_STRING(info->attrs[BRC_GENL_A_PROC_DIR], BRC_NAME_LEN_MAX) ||
	    !info->attrs[BRC_GENL_A_PROC_NAME] ||
	    VERIFY_NUL_STRING(info->attrs[BRC_GENL_A_PROC_NAME], BRC_NAME_LEN_MAX) ||
	    (info->attrs[BRC_GENL_A_PROC_DATA] &&
	     VERIFY_NUL_STRING(info->attrs[BRC_GENL_A_PROC_DATA], INT_MAX)))
		return -EINVAL;

	dir_name = nla_data(info->attrs[BRC_GENL_A_PROC_DIR]);
	name = nla_data(info->attrs[BRC_GENL_A_PROC_NAME]);

	if (!strcmp(dir_name, "net/vlan"))
		dir = brc_open_dir("vlan", proc_net, &proc_vlan_dir);
	else if (!strcmp(dir_name, "net/bonding"))
		dir = brc_open_dir("bonding", proc_net, &proc_bonding_dir);
	else
		return -EINVAL;
	if (!dir) {
		/* Probably failed because the module that really implements
		 * the function in question is loaded and already owns the
		 * directory in question.*/
		return -EBUSY;
	}

	entry = brc_lookup_entry(dir, name);
	if (!info->attrs[BRC_GENL_A_PROC_DATA]) {
		if (!entry)
			return -ENOENT;

		data = entry->data;
		remove_proc_entry(name, dir);
		if (brc_lookup_entry(dir, name))
			return -EBUSY; /* Shouldn't happen */

		kfree(data);
	} else {
		data = kstrdup(nla_data(info->attrs[BRC_GENL_A_PROC_DATA]),
			       GFP_KERNEL);
		if (!data)
			return -ENOMEM;

		if (entry) {
			char *old_data = entry->data;
			entry->data = data;
			kfree(old_data);
			return 0;
		}

		entry = create_proc_entry(name, S_IFREG|S_IRUSR|S_IWUSR, dir);
		if (!entry) {
			kfree(data);
			return -ENOBUFS;
		}
		entry->proc_fops = &brc_fops;
		entry->data = data;
	}
	return 0;
}

static void kill_proc_dir(const char *dir_name,
			  struct proc_dir_entry *parent,
			  struct proc_dir_entry *dir)
{
	if (!dir)
		return;
	for (;;) {
		struct proc_dir_entry *e;
		char *data;
		char name[BRC_NAME_LEN_MAX + 1];

		e = dir->subdir;
		if (!e)
			break;

		if (e->namelen >= sizeof(name)) {
			/* Can't happen: we prevent adding names this long by
			 * limiting the BRC_GENL_A_PROC_NAME string to
			 * BRC_NAME_LEN_MAX bytes.  */
			WARN_ON(1);
			break;
		}
		strcpy(name, e->name);

		data = e->data;
		e->data = NULL;
		kfree(data);

		remove_proc_entry(name, dir);
	}
	remove_proc_entry(dir_name, parent);
}

void brc_procfs_exit(void)
{
	kill_proc_dir("vlan", proc_net, proc_vlan_dir);
	kill_proc_dir("bonding", proc_net, proc_bonding_dir);
}

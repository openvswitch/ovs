/*
 * Copyright (c) 2007-2012 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#include <linux/completion.h>
#include <net/genetlink.h>
#include "genl_exec.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)

static DEFINE_MUTEX(genl_exec_lock);

static genl_exec_func_t	 genl_exec_function;
static int		 genl_exec_function_ret;
static void		*genl_exec_data;
static struct completion done;

static struct sk_buff *genlmsg_skb;

static int genl_exec_cmd(struct sk_buff *dummy, struct genl_info *dummy2)
{
	genl_exec_function_ret = genl_exec_function(genl_exec_data);
	complete(&done);
	return 0;
}

enum exec_cmd {
	GENL_EXEC_UNSPEC,
	GENL_EXEC_RUN,
};

static struct genl_family genl_exec_family = {
	.id = GENL_ID_GENERATE,
	.name = "ovs_genl_exec",
	.version = 1,
};

static struct genl_ops genl_exec_ops[] = {
	{
	 .cmd = GENL_EXEC_RUN,
	 .doit = genl_exec_cmd,
	 .flags = CAP_NET_ADMIN,
	},
};

int genl_exec_init(void)
{
	int err;

	err = genl_register_family_with_ops(&genl_exec_family,
			genl_exec_ops, ARRAY_SIZE(genl_exec_ops));

	if (err)
		return err;

	genlmsg_skb = genlmsg_new(0, GFP_KERNEL);
	if (!genlmsg_skb) {
		genl_unregister_family(&genl_exec_family);
		return -ENOMEM;
	}
	return 0;
}

void genl_exec_exit(void)
{
	kfree_skb(genlmsg_skb);
	genl_unregister_family(&genl_exec_family);
}

/* genl_lock() is not exported from older kernel.
 * Following function allows any function to be executed with
 * genl_mutex held. */

int genl_exec(genl_exec_func_t func, void *data)
{
	int ret;

	mutex_lock(&genl_exec_lock);

	init_completion(&done);
	skb_get(genlmsg_skb);
	genlmsg_put(genlmsg_skb, 0, 0, &genl_exec_family,
		    NLM_F_REQUEST, GENL_EXEC_RUN);

	genl_exec_function = func;
	genl_exec_data = data;

	/* There is no need to send msg to current namespace. */
	ret = genlmsg_unicast(&init_net, genlmsg_skb, 0);

	if (!ret) {
		wait_for_completion(&done);
		ret = genl_exec_function_ret;
	} else {
		pr_err("genl_exec send error %d\n", ret);
	}

	/* Wait for genetlink to kfree skb. */
	while (skb_shared(genlmsg_skb))
		cpu_relax();

	genlmsg_skb->data = genlmsg_skb->head;
	skb_reset_tail_pointer(genlmsg_skb);

	mutex_unlock(&genl_exec_lock);

	return ret;
}

#else

int genl_exec(genl_exec_func_t func, void *data)
{
	int ret;

	genl_lock();
	ret = func(data);
	genl_unlock();
	return ret;
}

int genl_exec_init(void)
{
	return 0;
}

void genl_exec_exit(void)
{
}
#endif

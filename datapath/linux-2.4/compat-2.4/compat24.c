/*
 * Distributed under the terms of the GNU GPL version 2.
 */

#include <linux/module.h>
#include "compat24.h"

int __init compat24_init(void)
{
	int err;

	rcu_init();

	err = random32_init();
	if (err)
		return err;

	return genl_init();

}
module_init(compat24_init);

void __exit compat24_exit(void)
{
	genl_exit();
}
module_exit(compat24_exit);

/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008 The Board of Trustees of The Leland 
 * Stanford Junior University
 */

#include <linux/autoconf.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/errno.h>

#include "unit.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static char run[1024];
module_param_string(run, run, sizeof run, 0);
MODULE_PARM_DESC(run_tests, "run=\"test1,[test2,...]\"\n");
#else
static char *run;
MODULE_PARM(run, "s");
#endif

static int test_failed;
static const char *test_name;

void unit_fail_function(const char *function, const char *msg, ...) 
{
	va_list args;

	printk("%s: FAIL: %s: ", test_name, function);
	va_start(args, msg);
	vprintk(msg, args);
	va_end(args);
	printk("\n");
	test_failed = 1;
}

int unit_failed(void) 
{
	return test_failed;
}

static int run_test(const char *name, size_t len)
{
	static const struct test {
		const char *name;
		void (*func)(void);
	} tests[] = {
#define UNIT_TEST(NAME) {#NAME, run_##NAME},
		UNIT_TESTS
#undef UNIT_TEST
	};

	const struct test *p;

	for (p = tests; p < &tests[ARRAY_SIZE(tests)]; p++)
		if (len == strlen(p->name)
			&& !memcmp(name, p->name, len)) {
			test_name = p->name;
			test_failed = 0;
			p->func();
			printk("%s: %s\n", test_name,
						test_failed ? "FAIL" : "PASS");
			return !test_failed;
		}
	printk("unknown unit test %.*s\n", (int) len, name);
	return 0;
}

int unit_init(void)
{
	int n_pass = 0, n_fail = 0;
	char *p = run ?: "";
	for (;;) {
		static const char white_space[] = " \t\r\n\v,";
		int len;

		p += strspn(p, white_space);
		if (!*p)
			break;

		len = strcspn(p, white_space);
		if (run_test(p, len))
			n_pass++;
		else
			n_fail++;
		p += len;
	}

	if (n_pass + n_fail == 0)
		printk("no tests specified (use run=\"test1 [test2...]\")\n");
	else
		printk("%d tests passed, %d failed\n", n_pass, n_fail);

	return -ENODEV;
}

module_init(unit_init);
MODULE_LICENSE("GPL");

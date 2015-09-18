#ifndef __LINUX_NET_WRAPPER_H
#define __LINUX_NET_WRAPPER_H 1

#include_next <linux/net.h>
#include <linux/types.h>

#ifndef net_ratelimited_function
#define net_ratelimited_function(function, ...)			\
do {								\
	if (net_ratelimit())					\
		function(__VA_ARGS__);				\
} while (0)

#define net_emerg_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_emerg, fmt, ##__VA_ARGS__)
#define net_alert_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_alert, fmt, ##__VA_ARGS__)
#define net_crit_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_crit, fmt, ##__VA_ARGS__)
#define net_err_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_err, fmt, ##__VA_ARGS__)
#define net_notice_ratelimited(fmt, ...)			\
	net_ratelimited_function(pr_notice, fmt, ##__VA_ARGS__)
#define net_warn_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_warn, fmt, ##__VA_ARGS__)
#define net_info_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_info, fmt, ##__VA_ARGS__)
#define net_dbg_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_debug, fmt, ##__VA_ARGS__)
#endif

#ifndef net_get_random_once
#define __net_get_random_once rpl___net_get_random_once
bool rpl___net_get_random_once(void *buf, int nbytes, bool *done,
			   atomic_t *done_key);

#define ___NET_RANDOM_STATIC_KEY_INIT	ATOMIC_INIT(0)


#define net_get_random_once(buf, nbytes)			\
({								\
	bool ___ret = false;					\
	static bool ___done = false;				\
	static atomic_t ___done_key =				\
			___NET_RANDOM_STATIC_KEY_INIT;		\
	if (!atomic_read(&___done_key))				\
	        ___ret = __net_get_random_once(buf,		\
					       nbytes,		\
					       &___done,	\
					       &___done_key);	\
	___ret;							\
})
#endif

#ifndef HAVE_SOCK_CREATE_KERN_NET
int ovs_sock_create_kern(struct net *net, int family, int type, int protocol, struct socket **res);
void ovs_sock_release(struct socket *sock);
#define sock_create_kern ovs_sock_create_kern
#define sock_release ovs_sock_release
#endif

#endif

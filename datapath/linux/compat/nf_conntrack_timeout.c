#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_timeout.h>

#ifdef CONFIG_NF_CONNTRACK_TIMEOUT
#ifndef HAVE_NF_CT_SET_TIMEOUT
static void rpl__nf_ct_timeout_put(struct nf_ct_timeout *timeout)
{
	typeof(nf_ct_timeout_put_hook) timeout_put;

	timeout_put = rcu_dereference(nf_ct_timeout_put_hook);
	if (timeout_put)
		timeout_put(timeout);
}

int rpl_nf_ct_set_timeout(struct net *net, struct nf_conn *ct,
			 u8 l3num, u8 l4num, const char *timeout_name)
{
	typeof(nf_ct_timeout_find_get_hook) timeout_find_get;
	struct nf_ct_timeout *timeout;
	struct nf_conn_timeout *timeout_ext;
	const char *errmsg = NULL;
	int ret = 0;

	rcu_read_lock();
	timeout_find_get = rcu_dereference(nf_ct_timeout_find_get_hook);
	if (!timeout_find_get) {
		ret = -ENOENT;
		errmsg = "Timeout policy base is empty";
		goto out;
	}

#ifdef HAVE_NF_CT_TIMEOUT_FIND_GET_HOOK_NET
	timeout = timeout_find_get(net, timeout_name);
#else
	timeout = timeout_find_get(timeout_name);
#endif
	if (!timeout) {
		ret = -ENOENT;
		pr_info_ratelimited("No such timeout policy \"%s\"\n",
				    timeout_name);
		goto out;
	}

	if (timeout->l3num != l3num) {
		ret = -EINVAL;
		pr_info_ratelimited("Timeout policy `%s' can only be used by "
				    "L%d protocol number %d\n",
				    timeout_name, 3, timeout->l3num);
		goto err_put_timeout;
	}
	/* Make sure the timeout policy matches any existing protocol tracker,
	 * otherwise default to generic.
	 */
	if (timeout->l4proto->l4proto != l4num) {
		ret = -EINVAL;
		pr_info_ratelimited("Timeout policy `%s' can only be used by "
				    "L%d protocol number %d\n",
				    timeout_name, 4, timeout->l4proto->l4proto);
		goto err_put_timeout;
	}
	timeout_ext = nf_ct_timeout_ext_add(ct, timeout, GFP_ATOMIC);
	if (!timeout_ext) {
		ret = -ENOMEM;
		goto err_put_timeout;
	}

	rcu_read_unlock();
	return ret;

err_put_timeout:
	rpl__nf_ct_timeout_put(timeout);
out:
	rcu_read_unlock();
	if (errmsg)
		pr_info_ratelimited("%s\n", errmsg);
	return ret;
}
EXPORT_SYMBOL_GPL(rpl_nf_ct_set_timeout);

void rpl_nf_ct_destroy_timeout(struct nf_conn *ct)
{
	struct nf_conn_timeout *timeout_ext;
	typeof(nf_ct_timeout_put_hook) timeout_put;

	rcu_read_lock();
	timeout_put = rcu_dereference(nf_ct_timeout_put_hook);

	if (timeout_put) {
		timeout_ext = nf_ct_timeout_find(ct);
		if (timeout_ext) {
			timeout_put(timeout_ext->timeout);
			RCU_INIT_POINTER(timeout_ext->timeout, NULL);
		}
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(rpl_nf_ct_destroy_timeout);

#endif /* HAVE_NF_CT_SET_TIMEOUT */
#endif /* CONFIG_NF_CONNTRACK_TIMEOUT */

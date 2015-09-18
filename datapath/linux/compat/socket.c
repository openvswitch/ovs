#include <linux/module.h>
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <net/ip_tunnels.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/net_namespace.h>


#ifndef HAVE_SOCK_CREATE_KERN_NET
#undef sock_create_kern

int ovs_sock_create_kern(struct net *net, int family, int type, int protocol, struct socket **res)
{
	int err;

	err = sock_create_kern(family, type, protocol, res);
	if (err < 0)
		return err;

	sk_change_net((*res)->sk, net);
	return err;
}
#undef sk_release_kernel
void ovs_sock_release(struct socket *sock)
{
	sk_release_kernel(sock->sk);
}
#endif

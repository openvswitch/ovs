/*
 * NETLINK      Netlink attributes
 *
 * 		Authors:	Thomas Graf <tgraf@suug.ch>
 * 				Alexey Kuznetsov <kuznet@ms2.inr.ac.ru>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/types.h>
#include <net/netlink.h>
#include <net/sock.h>

/**
 * netlink_queue_skip - Skip netlink message while processing queue.
 * @nlh: Netlink message to be skipped
 * @skb: Socket buffer containing the netlink messages.
 *
 * Pulls the given netlink message off the socket buffer so the next
 * call to netlink_queue_run() will not reconsider the message.
 */
static void netlink_queue_skip(struct nlmsghdr *nlh, struct sk_buff *skb)
{
	int msglen = NLMSG_ALIGN(nlh->nlmsg_len);

	if (msglen > skb->len)
		msglen = skb->len;

	skb_pull(skb, msglen);
}

static int netlink_rcv_skb(struct sk_buff *skb, int (*cb)(struct sk_buff *,
						     struct nlmsghdr *))
{
	struct nlmsghdr *nlh;
	int err;

	while (skb->len >= nlmsg_total_size(0)) {
		nlh = nlmsg_hdr(skb);
		err = 0;

		if (nlh->nlmsg_len < NLMSG_HDRLEN || skb->len < nlh->nlmsg_len)
			return 0;

		/* Only requests are handled by the kernel */
		if (!(nlh->nlmsg_flags & NLM_F_REQUEST))
			goto skip;

		/* Skip control messages */
		if (nlh->nlmsg_type < NLMSG_MIN_TYPE)
			goto skip;

		err = cb(skb, nlh);
		if (err == -EINTR) {
			/* Not an error, but we interrupt processing */
			netlink_queue_skip(nlh, skb);
			return err;
		}
skip:
		if (nlh->nlmsg_flags & NLM_F_ACK || err)
			netlink_ack(skb, nlh, err);

		netlink_queue_skip(nlh, skb);
	}

	return 0;
}

/**
 * netlink_run_queue - Process netlink receive queue.
 * @sk: Netlink socket containing the queue
 * @qlen: Place to store queue length upon entry
 * @cb: Callback function invoked for each netlink message found
 *
 * Processes as much as there was in the queue upon entry and invokes
 * a callback function for each netlink message found. The callback
 * function may refuse a message by returning a negative error code
 * but setting the error pointer to 0 in which case this function
 * returns with a qlen != 0.
 *
 * qlen must be initialized to 0 before the initial entry, afterwards
 * the function may be called repeatedly until qlen reaches 0.
 *
 * The callback function may return -EINTR to signal that processing
 * of netlink messages shall be interrupted. In this case the message
 * currently being processed will NOT be requeued onto the receive
 * queue.
 */
void netlink_run_queue(struct sock *sk, unsigned int *qlen,
		       int (*cb)(struct sk_buff *, struct nlmsghdr *))
{
	struct sk_buff *skb;

	if (!*qlen || *qlen > skb_queue_len(&sk->receive_queue))
		*qlen = skb_queue_len(&sk->receive_queue);

	for (; *qlen; (*qlen)--) {
		skb = skb_dequeue(&sk->receive_queue);
		if (netlink_rcv_skb(skb, cb)) {
			if (skb->len)
				skb_queue_head(&sk->receive_queue, skb);
			else {
				kfree_skb(skb);
				(*qlen)--;
			}
			break;
		}

		kfree_skb(skb);
	}
}

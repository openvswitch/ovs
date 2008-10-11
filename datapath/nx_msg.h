#ifndef NX_MSG_H
#define NX_MSG_H 1

int nx_recv_msg(struct sw_chain *chain, const struct sender *sender,
		const void *msg);

#endif /* nx_msg.h */

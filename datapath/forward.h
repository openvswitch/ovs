#ifndef FORWARD_H
#define FORWARD_H 1

#include <linux/types.h>
#include "datapath.h"
#include "flow.h"

struct sk_buff;
struct sw_chain;
struct sender;

/* Buffers are identified to userspace by a 31-bit opaque ID.  We divide the ID
 * into a buffer number (low bits) and a cookie (high bits).  The buffer number
 * is an index into an array of buffers.  The cookie distinguishes between
 * different packets that have occupied a single buffer.  Thus, the more
 * buffers we have, the lower-quality the cookie... */
#define PKT_BUFFER_BITS 8
#define N_PKT_BUFFERS (1 << PKT_BUFFER_BITS)
#define PKT_BUFFER_MASK (N_PKT_BUFFERS - 1)

#define PKT_COOKIE_BITS (32 - PKT_BUFFER_BITS)


void fwd_port_input(struct sw_chain *, struct sk_buff *,
		    struct net_bridge_port *);
int run_flow_through_tables(struct sw_chain *, struct sk_buff *,
			    struct net_bridge_port *);
int fwd_control_input(struct sw_chain *, const struct sender *,
		      const void *, size_t);

uint32_t fwd_save_skb(struct sk_buff *skb);
void fwd_discard_all(void);
void fwd_exit(void);

#endif /* forward.h */

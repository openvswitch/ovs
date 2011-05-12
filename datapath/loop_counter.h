/*
 * Copyright (c) 2010, 2011 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef LOOP_COUNTER_H
#define LOOP_COUNTER_H 1

#include "datapath.h"
#include "flow.h"

/* We limit the number of times that we pass into dp_process_received_packet()
 * to avoid blowing out the stack in the event that we have a loop. */
#define MAX_LOOPS 5

struct loop_counter {
	u8 count;		/* Count. */
	bool looping;		/* Loop detected? */
};

struct loop_counter *loop_get_counter(void);
void loop_put_counter(void);
int loop_suppress(struct datapath *, struct sw_flow_actions *);

#endif /* loop_counter.h */

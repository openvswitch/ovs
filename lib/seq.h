/*
 * Copyright (c) 2013, 2014 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SEQ_H
#define SEQ_H 1

/* Thread-safe, pollable sequence number.
 *
 *
 * Motivation
 * ==========
 *
 * It is sometimes desirable to take an action whenever an object changes.
 * Suppose we associate a sequence number with an object and increment the
 * sequence number whenver we change the object.  An observer can then record
 * the sequence number it sees.  Later on, if the current sequence number
 * differs from the one it saw last, then the observer knows to examine the
 * object for changes.
 *
 * Code that wants to run when a sequence number changes is challenging to
 * implement in a multithreaded environment.  A naive implementation, that
 * simply checks whether the sequence number changed and, if so, calls
 * poll_immediate_wake(), will fail when another thread increments the sequence
 * number after the check (including during poll_block()).
 *
 * struct seq is a solution.  It implements a sequence number along with enough
 * internal infrastructure so that a thread waiting on a particular value will
 * wake up if the sequence number changes, or even if the "struct seq" is
 * destroyed.
 *
 *
 * Usage
 * =====
 *
 * The object that includes a sequence number should use seq_create() and
 * seq_destroy() at creation and destruction, and seq_change() whenever the
 * object's observable state changes.
 *
 * An observer may seq_read() to read the current sequence number and
 * seq_wait() to cause poll_block() to wake up when the sequence number changes
 * from a specified value.
 *
 * To avoid races, observers should use seq_read() to check for changes,
 * process any changes, and then use seq_wait() to wait for a change from the
 * previously read value.  That is, a correct usage looks something like this:
 *
 *    new_seq = seq_read(seq);
 *    if (new_seq != last_seq) {
 *        ...process changes...
 *        last_seq = new_seq;
 *    }
 *    seq_wait(seq, new_seq);
 *    poll_block();
 *
 *
 * Alternate Usage
 * ===============
 *
 * struct seq can also be used as a sort of pollable condition variable.
 * Suppose that we want a thread to process items in a queue, and thus to be
 * able to wake up whenever the queue is nonempty.  This requires a lock to
 * protect the queue and a seq to signal that the queue has become nonempty,
 * e.g.:
 *
 *    struct ovs_mutex mutex;
 *    struct ovs_list queue OVS_GUARDED_BY(mutex);
 *    struct seq nonempty_seq;
 *
 * To add an element to the queue:
 *
 *    ovs_mutex_lock(&mutex);
 *    ovs_list_push_back(&queue, ...element...);
 *    if (ovs_list_is_singleton(&queue)) {   // The 'if' test here is optional.
 *        seq_change(&nonempty_seq);
 *    }
 *    ovs_mutex_unlock(&mutex);
 *
 * To wait for the queue to become nonempty:
 *
 *    ovs_mutex_lock(&mutex);
 *    if (ovs_list_is_empty(&queue)) {
 *        seq_wait(&nonempty_seq, seq_read(&nonempty_seq));
 *    } else {
 *        poll_immediate_wake();
 *    }
 *    ovs_mutex_unlock(&mutex);
 *
 * (In the above code 'mutex' prevents the queue from changing between
 * seq_read() and seq_wait().  Otherwise, it would be necessary to seq_read(),
 * check for a nonempty queue, and then seq_wait() on the previously read
 * sequence number, as under Usage above.)
 *
 *
 * Thread-safety
 * =============
 *
 * Fully thread safe.  seq_change() synchronizes with seq_read() and
 * seq_wait() on the same variable in release-acquire fashion.  That
 * is, all effects of the memory accesses performed by a thread prior
 * to seq_change() are visible to the threads returning from
 * seq_read() or seq_wait() observing that change.
 */

#include <stdint.h>
#include "util.h"

/* For implementation of an object with a sequence number attached. */
struct seq *seq_create(void);
void seq_destroy(struct seq *);
void seq_change(struct seq *);
void seq_change_protected(struct seq *);
void seq_lock(void);
int seq_try_lock(void);
void seq_unlock(void);

/* For observers. */
uint64_t seq_read(const struct seq *);
uint64_t seq_read_protected(const struct seq *);

void seq_wait_at(const struct seq *, uint64_t value, const char *where);
#define seq_wait(seq, value) seq_wait_at(seq, value, OVS_SOURCE_LOCATOR)

/* For poll_block() internal use. */
void seq_woke(void);

#endif /* seq.h */

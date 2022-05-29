/*
 * Copyright (c) 2021 NVIDIA Corporation.
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

#include <config.h>

#include "ovs-atomic.h"

#include "mpsc-queue.h"

/* Multi-producer, single-consumer queue
 * =====================================
 *
 * This an implementation of the MPSC queue described by Dmitri Vyukov [1].
 *
 * One atomic exchange operation is done per insertion.  Removal in most cases
 * will not require atomic operation and will use one atomic exchange to close
 * the queue chain.
 *
 * Insertion
 * =========
 *
 * The queue is implemented using a linked-list.  Insertion is done at the
 * back of the queue, by swapping the current end with the new node atomically,
 * then pointing the previous end toward the new node.  To follow Vyukov
 * nomenclature, the end-node of the chain is called head.  A producer will
 * only manipulate the head.
 *
 * The head swap is atomic, however the link from the previous head to the new
 * one is done in a separate operation.  This means that the chain is
 * momentarily broken, when the previous head still points to NULL and the
 * current head has been inserted.
 *
 * Considering a series of insertions, the queue state will remain consistent
 * and the insertions order is compatible with their precedence, thus the
 * queue is serializable.  However, because an insertion consists in two
 * separate memory transactions, it is not linearizable.
 *
 * Removal
 * =======
 *
 * The consumer must deal with the queue inconsistency.  It will manipulate
 * the tail of the queue and move it along the latest consumed elements.
 * When an end of the chain of elements is found (the next pointer is NULL),
 * the tail is compared with the head.
 *
 * If both points to different addresses, then the queue is in an inconsistent
 * state: the tail cannot move forward as the next is NULL, but the head is not
 * the last element in the chain: this can only happen if the chain is broken.
 *
 * In this case, the consumer must wait for the producer to finish writing the
 * next pointer of its current tail: 'MPSC_QUEUE_RETRY' is returned.
 *
 * Removal is thus in most cases (when there are elements in the queue)
 * accomplished without using atomics, until the last element of the queue.
 * There, the head is atomically loaded. If the queue is in a consistent state,
 * the head is moved back to the queue stub by inserting the stub in the queue:
 * ending the queue is the same as an insertion, which is one atomic XCHG.
 *
 * Forward guarantees
 * ==================
 *
 * Insertion and peeking are wait-free: they will execute in a known bounded
 * number of instructions, regardless of the state of the queue.
 *
 * However, while removal consists in peeking and a constant write to
 * update the tail, it can repeatedly fail until the queue become consistent.
 * It is thus dependent on other threads progressing.  This means that the
 * queue forward progress is obstruction-free only.  It has a potential for
 * livelocking.
 *
 * The chain will remain broken as long as a producer is not finished writing
 * its next pointer.  If a producer is cancelled for example, the queue could
 * remain broken for any future readings.  This queue should either be used
 * with cooperative threads or insertion must only be done outside cancellable
 * sections.
 *
 * Performances
 * ============
 *
 * In benchmarks this structure was better than alternatives such as:
 *
 *   * A reversed Treiber stack [2], using 1 CAS per operations
 *     and requiring reversal of the node list on removal.
 *
 *   * Michael-Scott lock-free queue [3], using 2 CAS per operations.
 *
 * While it is not linearizable, this queue is well-suited for message passing.
 * If a proper hardware XCHG operation is used, it scales better than
 * CAS-based implementations.
 *
 * References
 * ==========
 *
 * [1]: http://www.1024cores.net/home/lock-free-algorithms/queues/intrusive-mpsc-node-based-queue
 *
 * [2]: R. K. Treiber. Systems programming: Coping with parallelism.
 *      Technical Report RJ 5118, IBM Almaden Research Center, April 1986.
 *
 * [3]: M. M. Michael, Simple, Fast, and Practical Non-Blocking and
 *      Blocking Concurrent Queue Algorithms
 * [3]: https://www.cs.rochester.edu/research/synchronization/pseudocode/queues.html
 *
 */

void
mpsc_queue_init(struct mpsc_queue *queue)
{
    atomic_store_relaxed(&queue->head, &queue->stub);
    atomic_store_relaxed(&queue->tail, &queue->stub);
    atomic_store_relaxed(&queue->stub.next, NULL);

    ovs_mutex_init(&queue->read_lock);
}

void
mpsc_queue_destroy(struct mpsc_queue *queue)
    OVS_EXCLUDED(queue->read_lock)
{
    ovs_mutex_destroy(&queue->read_lock);
}

enum mpsc_queue_poll_result
mpsc_queue_poll(struct mpsc_queue *queue, struct mpsc_queue_node **node)
    OVS_REQUIRES(queue->read_lock)
{
    struct mpsc_queue_node *tail;
    struct mpsc_queue_node *next;
    struct mpsc_queue_node *head;

    atomic_read_relaxed(&queue->tail, &tail);
    atomic_read_explicit(&tail->next, &next, memory_order_acquire);

    if (tail == &queue->stub) {
        if (next == NULL) {
            return MPSC_QUEUE_EMPTY;
        }

        atomic_store_relaxed(&queue->tail, next);
        tail = next;
        atomic_read_explicit(&tail->next, &next, memory_order_acquire);
    }

    if (next != NULL) {
        atomic_store_relaxed(&queue->tail, next);
        *node = tail;
        return MPSC_QUEUE_ITEM;
    }

    atomic_read_explicit(&queue->head, &head, memory_order_acquire);
    if (tail != head) {
        return MPSC_QUEUE_RETRY;
    }

    mpsc_queue_insert(queue, &queue->stub);

    atomic_read_explicit(&tail->next, &next, memory_order_acquire);
    if (next != NULL) {
        atomic_store_relaxed(&queue->tail, next);
        *node = tail;
        return MPSC_QUEUE_ITEM;
    }

    return MPSC_QUEUE_EMPTY;
}

struct mpsc_queue_node *
mpsc_queue_pop(struct mpsc_queue *queue)
    OVS_REQUIRES(queue->read_lock)
{
    enum mpsc_queue_poll_result result;
    struct mpsc_queue_node *node;

    do {
        result = mpsc_queue_poll(queue, &node);
        if (result == MPSC_QUEUE_EMPTY) {
            return NULL;
        }
    } while (result == MPSC_QUEUE_RETRY);

    return node;
}

void
mpsc_queue_push_front(struct mpsc_queue *queue, struct mpsc_queue_node *node)
    OVS_REQUIRES(queue->read_lock)
{
    struct mpsc_queue_node *tail;

    atomic_read_relaxed(&queue->tail, &tail);
    atomic_store_relaxed(&node->next, tail);
    atomic_store_relaxed(&queue->tail, node);
}

struct mpsc_queue_node *
mpsc_queue_tail(struct mpsc_queue *queue)
    OVS_REQUIRES(queue->read_lock)
{
    struct mpsc_queue_node *tail;
    struct mpsc_queue_node *next;

    atomic_read_relaxed(&queue->tail, &tail);
    atomic_read_explicit(&tail->next, &next, memory_order_acquire);

    if (tail == &queue->stub) {
        if (next == NULL) {
            return NULL;
        }

        atomic_store_relaxed(&queue->tail, next);
        tail = next;
    }

    return tail;
}

/* Get the next element of a node. */
struct mpsc_queue_node *mpsc_queue_next(struct mpsc_queue *queue,
                                        struct mpsc_queue_node *prev)
    OVS_REQUIRES(queue->read_lock)
{
    struct mpsc_queue_node *next;

    atomic_read_explicit(&prev->next, &next, memory_order_acquire);
    if (next == &queue->stub) {
        atomic_read_explicit(&next->next, &next, memory_order_acquire);
    }
    return next;
}

void
mpsc_queue_insert(struct mpsc_queue *queue, struct mpsc_queue_node *node)
{
    struct mpsc_queue_node *prev;

    atomic_store_relaxed(&node->next, NULL);
    prev = atomic_exchange_explicit(&queue->head, node, memory_order_acq_rel);
    atomic_store_explicit(&prev->next, node, memory_order_release);
}

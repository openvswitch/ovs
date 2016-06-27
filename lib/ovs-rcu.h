/*
 * Copyright (c) 2014, 2015, 2016 Nicira, Inc.
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

#ifndef OVS_RCU_H
#define OVS_RCU_H 1

/* Read-Copy-Update (RCU)
 * ======================
 *
 * Introduction
 * ------------
 *
 * Atomic pointer access makes it pretty easy to implement lock-free
 * algorithms.  There is one big problem, though: when a writer updates a
 * pointer to point to a new data structure, some thread might be reading the
 * old version, and there's no convenient way to free the old version when all
 * threads are done with the old version.
 *
 * The function ovsrcu_postpone() solves that problem.  The function pointer
 * passed in as its argument is called only after all threads are done with old
 * versions of data structures.  The function callback frees an old version of
 * data no longer in use.  This technique is called "read-copy-update", or RCU
 * for short.
 *
 *
 * Details
 * -------
 *
 * A "quiescent state" is a time at which a thread holds no pointers to memory
 * that is managed by RCU; that is, when the thread is known not to reference
 * memory that might be an old version of some object freed via RCU.  For
 * example, poll_block() includes a quiescent state.
 *
 * The following functions manage the recognition of quiescent states:
 *
 *     void ovsrcu_quiesce(void)
 *
 *         Recognizes a momentary quiescent state in the current thread.
 *
 *     void ovsrcu_quiesce_start(void)
 *     void ovsrcu_quiesce_end(void)
 *
 *         Brackets a time period during which the current thread is quiescent.
 *
 * A newly created thread is initially active, not quiescent. When a process
 * becomes multithreaded, the main thread becomes active, not quiescent.
 *
 * When a quiescient state has occurred in every thread, we say that a "grace
 * period" has occurred.  Following a grace period, all of the callbacks
 * postponed before the start of the grace period MAY be invoked.  OVS takes
 * care of this automatically through the RCU mechanism: while a process still
 * has only a single thread, it invokes the postponed callbacks directly from
 * ovsrcu_quiesce() and ovsrcu_quiesce_start(); after additional threads have
 * been created, it creates an extra helper thread to invoke callbacks.
 *
 * Please note that while a postponed function call is guaranteed to happen
 * after the next time all participating threads have quiesced at least once,
 * there is no quarantee that all postponed functions are called as early as
 * possible, or that the functions postponed by different threads would be
 * called in the order the registrations took place.  In particular, even if
 * two threads provably postpone a function each in a specific order, the
 * postponed functions may still be called in the opposite order, depending on
 * the timing of when the threads call ovsrcu_quiesce(), how many functions
 * they postpone, and when the ovs-rcu thread happens to grab the functions to
 * be called.
 *
 * All functions postponed by a single thread are guaranteed to execute in the
 * order they were postponed, however.
 *
 * Usage
 * -----
 *
 * Use OVSRCU_TYPE(TYPE) to declare a pointer to RCU-protected data, e.g. the
 * following declares an RCU-protected "struct flow *" named flowp:
 *
 *     OVSRCU_TYPE(struct flow *) flowp;
 *
 * Use ovsrcu_get(TYPE, VAR) to read an RCU-protected pointer, e.g. to read the
 * pointer variable declared above:
 *
 *     struct flow *flow = ovsrcu_get(struct flow *, &flowp);
 *
 * If the pointer variable is currently protected against change (because
 * the current thread holds a mutex that protects it), ovsrcu_get_protected()
 * may be used instead.  Only on the Alpha architecture is this likely to
 * generate different code, but it may be useful documentation.
 *
 * (With GNU C or Clang, you get a compiler error if TYPE is wrong; other
 * compilers will merrily carry along accepting the wrong type.)
 *
 * Use ovsrcu_set() to write an RCU-protected pointer and ovsrcu_postpone() to
 * free the previous data.  ovsrcu_set_hidden() can be used on RCU protected
 * data not visible to any readers yet, but will be made visible by a later
 * ovsrcu_set().   ovsrcu_init() can be used to initialize RCU pointers when
 * no readers are yet executing.  If more than one thread can write the
 * pointer, then some form of external synchronization, e.g. a mutex, is
 * needed to prevent writers from interfering with one another.  For example,
 * to write the pointer variable declared above while safely freeing the old
 * value:
 *
 *     static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
 *
 *     OVSRCU_TYPE(struct flow *) flowp;
 *
 *     void
 *     change_flow(struct flow *new_flow)
 *     {
 *         ovs_mutex_lock(&mutex);
 *         ovsrcu_postpone(free,
 *                         ovsrcu_get_protected(struct flow *, &flowp));
 *         ovsrcu_set(&flowp, new_flow);
 *         ovs_mutex_unlock(&mutex);
 *     }
 *
 */

#include "compiler.h"
#include "ovs-atomic.h"

#if __GNUC__
#define OVSRCU_TYPE(TYPE) struct { ATOMIC(TYPE) p; }
#define OVSRCU_INITIALIZER(VALUE) { ATOMIC_VAR_INIT(VALUE) }
#define ovsrcu_get__(TYPE, VAR, ORDER)                                  \
    ({                                                                  \
        TYPE value__;                                                   \
        typeof(VAR) ovsrcu_var = (VAR);                                 \
                                                                        \
        atomic_read_explicit(CONST_CAST(ATOMIC(TYPE) *, &ovsrcu_var->p), \
                             &value__, ORDER);                          \
                                                                        \
        value__;                                                        \
    })
#define ovsrcu_get(TYPE, VAR) \
    ovsrcu_get__(TYPE, VAR, memory_order_consume)
#define ovsrcu_get_protected(TYPE, VAR) \
    ovsrcu_get__(TYPE, VAR, memory_order_relaxed)

/* 'VALUE' may be an atomic operation, which must be evaluated before
 * any of the body of the atomic_store_explicit.  Since the type of
 * 'VAR' is not fixed, we cannot use an inline function to get
 * function semantics for this. */
#define ovsrcu_set__(VAR, VALUE, ORDER)                                 \
    ({                                                                  \
        typeof(VAR) ovsrcu_var = (VAR);                                 \
        typeof(VALUE) ovsrcu_value = (VALUE);                           \
        memory_order ovsrcu_order = (ORDER);                            \
                                                                        \
        atomic_store_explicit(&ovsrcu_var->p, ovsrcu_value, ovsrcu_order); \
        (void *) 0;                                                     \
    })
#else  /* not GNU C */
struct ovsrcu_pointer { ATOMIC(void *) p; };
#define OVSRCU_TYPE(TYPE) struct ovsrcu_pointer
#define OVSRCU_INITIALIZER(VALUE) { ATOMIC_VAR_INIT(VALUE) }
static inline void *
ovsrcu_get__(const struct ovsrcu_pointer *pointer, memory_order order)
{
    void *value;
    atomic_read_explicit(&CONST_CAST(struct ovsrcu_pointer *, pointer)->p,
                         &value, order);
    return value;
}
#define ovsrcu_get(TYPE, VAR) \
    CONST_CAST(TYPE, ovsrcu_get__(VAR, memory_order_consume))
#define ovsrcu_get_protected(TYPE, VAR) \
    CONST_CAST(TYPE, ovsrcu_get__(VAR, memory_order_relaxed))

static inline void ovsrcu_set__(struct ovsrcu_pointer *pointer,
                                const void *value,
                                memory_order order)
{
    atomic_store_explicit(&pointer->p, CONST_CAST(void *, value), order);
}
#endif

/* Writes VALUE to the RCU-protected pointer whose address is VAR.
 *
 * Users require external synchronization (e.g. a mutex).  See "Usage" above
 * for an example. */
#define ovsrcu_set(VAR, VALUE) \
    ovsrcu_set__(VAR, VALUE, memory_order_release)

/* This can be used for initializing RCU pointers before any readers can
 * see them.  A later ovsrcu_set() needs to make the bigger structure this
 * is part of visible to the readers. */
#define ovsrcu_set_hidden(VAR, VALUE) \
    ovsrcu_set__(VAR, VALUE, memory_order_relaxed)

/* This can be used for initializing RCU pointers before any readers are
 * executing. */
#define ovsrcu_init(VAR, VALUE) atomic_init(&(VAR)->p, VALUE)

/* Calls FUNCTION passing ARG as its pointer-type argument following the next
 * grace period.  See "Usage" above for an example. */
void ovsrcu_postpone__(void (*function)(void *aux), void *aux);
#define ovsrcu_postpone(FUNCTION, ARG)                          \
    (/* Verify that ARG is appropriate for FUNCTION. */         \
     (void) sizeof((FUNCTION)(ARG), 1),                         \
     /* Verify that ARG is a pointer type. */                   \
     (void) sizeof(*(ARG)),                                     \
     ovsrcu_postpone__((void (*)(void *))(FUNCTION), ARG))

/* Quiescent states. */
void ovsrcu_quiesce_start(void);
void ovsrcu_quiesce_end(void);
void ovsrcu_quiesce(void);
bool ovsrcu_is_quiescent(void);

/* Synchronization.  Waits for all non-quiescent threads to quiesce at least
 * once.  This can block for a relatively long time. */
void ovsrcu_synchronize(void);

#endif /* ovs-rcu.h */

/* This header implements atomic operation locking helpers. */
#ifndef IN_OVS_ATOMIC_H
#error "This header should only be included indirectly via ovs-atomic.h."
#endif

#define OVS_ATOMIC_LOCKED_IMPL 1

void atomic_lock__(void *);
void atomic_unlock__(void *);

#define atomic_store_locked(DST, SRC)           \
    (atomic_lock__(DST),                        \
     *(DST) = (SRC),                            \
     atomic_unlock__(DST),                      \
     (void) 0)

#define atomic_read_locked(SRC, DST)            \
    (atomic_lock__(SRC),                        \
     *(DST) = *(SRC),                           \
     atomic_unlock__(SRC),                      \
     (void) 0)

/* XXX: Evaluates EXP multiple times. */
#define atomic_compare_exchange_locked(DST, EXP, SRC)   \
    (atomic_lock__(DST),                                \
     (*(DST) == *(EXP)                                  \
      ? (*(DST) = (SRC),                                \
         atomic_unlock__(DST),                          \
         true)                                          \
      : (*(EXP) = *(DST),                               \
         atomic_unlock__(DST),                          \
         false)))

#define atomic_op_locked_add +=
#define atomic_op_locked_sub -=
#define atomic_op_locked_or  |=
#define atomic_op_locked_xor ^=
#define atomic_op_locked_and &=
#define atomic_op_locked(RMW, OP, OPERAND, ORIG)    \
    (atomic_lock__(RMW),                            \
     *(ORIG) = *(RMW),                              \
     *(RMW) atomic_op_locked_##OP (OPERAND),        \
     atomic_unlock__(RMW))

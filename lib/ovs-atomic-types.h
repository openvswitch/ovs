/* This header defines atomic_* types using an ATOMIC macro provided by the
* caller. */
#ifndef IN_OVS_ATOMIC_H
#error "This header should only be included indirectly via ovs-atomic.h."
#endif

#ifndef OMIT_STANDARD_ATOMIC_TYPES
typedef ATOMIC(bool)               atomic_bool;

typedef ATOMIC(char)               atomic_char;
typedef ATOMIC(signed char)        atomic_schar;
typedef ATOMIC(unsigned char)      atomic_uchar;

typedef ATOMIC(short)              atomic_short;
typedef ATOMIC(unsigned short)     atomic_ushort;

typedef ATOMIC(int)                atomic_int;
typedef ATOMIC(unsigned int)       atomic_uint;

typedef ATOMIC(long)               atomic_long;
typedef ATOMIC(unsigned long)      atomic_ulong;

typedef ATOMIC(long long)          atomic_llong;
typedef ATOMIC(unsigned long long) atomic_ullong;

typedef ATOMIC(size_t)             atomic_size_t;
typedef ATOMIC(ptrdiff_t)          atomic_ptrdiff_t;

typedef ATOMIC(intmax_t)           atomic_intmax_t;
typedef ATOMIC(uintmax_t)          atomic_uintmax_t;

typedef ATOMIC(intptr_t)           atomic_intptr_t;
typedef ATOMIC(uintptr_t)          atomic_uintptr_t;
#endif  /* !OMIT_STANDARD_ATOMIC_TYPES */

/* Nonstandard atomic types. */
typedef ATOMIC(uint8_t)   atomic_uint8_t;
typedef ATOMIC(uint16_t)  atomic_uint16_t;
typedef ATOMIC(uint32_t)  atomic_uint32_t;
typedef ATOMIC(uint64_t)  atomic_uint64_t;

typedef ATOMIC(int8_t)    atomic_int8_t;
typedef ATOMIC(int16_t)   atomic_int16_t;
typedef ATOMIC(int32_t)   atomic_int32_t;
typedef ATOMIC(int64_t)   atomic_int64_t;

#undef OMIT_STANDARD_ATOMIC_TYPES

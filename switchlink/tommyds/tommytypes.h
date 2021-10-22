/*
 * Copyright (c) 2010, Andrea Mazzoleni. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/** \file
 * Generic types.
 */

#ifndef __TOMMYTYPES_H
#define __TOMMYTYPES_H

/******************************************************************************/
/* types */

#include <stddef.h>

#ifdef _MSC_VER
typedef unsigned tommy_uint32_t; /**< Generic uint32_t type. */
typedef unsigned _int64 tommy_uint64_t; /**< Generic uint64_t type. */
typedef size_t tommy_uintptr_t; /**< Generic uintptr_t type. */
#ifdef _WIN64
#define TOMMY_SIZE_BIT 64
typedef unsigned _int64_t tommy_size_t; /**< Generic size_t type. */
typedef _int64_t tommy_ssize_t; /**< Generic ssize_t type. */
#else
#define TOMMY_SIZE_BIT 32
typedef unsigned tommy_size_t; /**< Generic size_t type. */
typedef int tommy_ssize_t; /**< Generic ssize_t type. */
#endif
#else
#include <stdint.h>
typedef uint32_t tommy_uint32_t; /**< Generic uint32_t type. */
typedef uint64_t tommy_uint64_t; /**< Generic uint64_t type. */
typedef uintptr_t tommy_uintptr_t; /**< Generic uintptr_t type. */
#if SIZE_MAX == UINT64_MAX
#define TOMMY_SIZE_BIT 64
typedef uint64_t tommy_size_t; /**< Generic size_t type. */
typedef int64_t tommy_ssize_t; /**< Generic ssize_t type. */
#elif SIZE_MAX == UINT32_MAX
#define TOMMY_SIZE_BIT 32
typedef uint32_t tommy_size_t; /**< Generic size_t type. */
typedef int32_t tommy_ssize_t; /**< Generic ssize_t type. */
#else
#error Unsupported SIZE_MAX
#endif
#endif

typedef ptrdiff_t tommy_ptrdiff_t; /**< Generic ptrdiff_t type. */
typedef int tommy_bool_t; /**< Generic boolean type. */

/**
 * Generic unsigned integer type.
 *
 * It has no specific size, as is used to store only small values.
 * To make the code more efficient, a full 32 bit integer is used.
 */
typedef tommy_uint32_t tommy_uint_t;

/** \internal
 * Type cast required for the C++ compilation.
 * When compiling in C++ we cannot convert a void* pointer to another pointer.
 * In such case we need an explicit cast.
 */
#ifdef __cplusplus
#define tommy_cast(type, value) static_cast<type>(value)
#else
#define tommy_cast(type, value) (value)
#endif

/******************************************************************************/
/* heap */

/* by default uses malloc/calloc/realloc/free */

/**
 * Generic malloc(), calloc(), realloc() and free() functions.
 * Redefine them to what you need. By default they map to the C malloc(), calloc(), realloc() and free().
 */
#if !defined(tommy_malloc) || !defined(tommy_calloc) || !defined(tommy_realloc) || !defined(tommy_free)
#include <stdlib.h>
#endif
#if !defined(tommy_malloc)
#define tommy_malloc malloc
#endif
#if !defined(tommy_calloc)
#define tommy_calloc calloc
#endif
#if !defined(tommy_realloc)
#define tommy_realloc realloc
#endif
#if !defined(tommy_free)
#define tommy_free free
#endif

/******************************************************************************/
/* modificators */

/** \internal
 * Definition of the inline keyword if available.
 */
#if !defined(tommy_inline)
#if defined(_MSC_VER) || defined(__GNUC__)
#define tommy_inline static __inline
#else
#define tommy_inline static
#endif
#endif

/** \internal
 * Definition of the restrict keyword if available.
 */
#if !defined(tommy_restrict)
#if __STDC_VERSION__ >= 199901L
#define tommy_restrict restrict
#elif defined(_MSC_VER) || defined(__GNUC__)
#define tommy_restrict __restrict
#else
#define tommy_restrict
#endif
#endif

/** \internal
 * Hints the compiler that a condition is likely true.
 */
#if !defined(tommy_likely)
#if defined(__GNUC__)
#define tommy_likely(x) __builtin_expect(!!(x), 1)
#else
#define tommy_likely(x) (x)
#endif
#endif

/** \internal
 * Hints the compiler that a condition is likely false.
 */
#if !defined(tommy_unlikely)
#if defined(__GNUC__)
#define tommy_unlikely(x) __builtin_expect(!!(x), 0)
#else
#define tommy_unlikely(x) (x)
#endif
#endif

/******************************************************************************/
/* key/hash */

/**
 * Type used in indexed data structures to store the key of a object.
 */
typedef tommy_size_t tommy_key_t;

/**
 * Type used in hashtables to store the hash of a object.
 */
typedef tommy_size_t tommy_hash_t;

/******************************************************************************/
/* node */

/**
 * Data structure node.
 * This node type is shared between all the data structures and used to store some
 * info directly into the objects you want to store.
 *
 * A typical declaration is:
 * \code
 * struct object {
 *     tommy_node node;
 *     // other fields
 * };
 * \endcode
 */
typedef struct tommy_node_struct {
    /**
     * Next node.
     * The tail node has it at 0, like a 0 terminated list.
     */
    struct tommy_node_struct* next;

    /**
     * Previous node.
     * The head node points to the tail node, like a circular list.
     */
    struct tommy_node_struct* prev;

    /**
     * Pointer to the object containing the node.
     * This field is initialized when inserting nodes into a data structure.
     */
    void* data;

    /**
     * Index of the node.
     * With tries this field is used to store the key.
     * With hashtables this field is used to store the hash value.
     * With lists this field is not used.
     */
    tommy_size_t index;
} tommy_node;

/******************************************************************************/
/* compare */

/**
 * Compare function for elements.
 * \param obj_a Pointer to the first object to compare.
 * \param obj_b Pointer to the second object to compare.
 * \return <0 if the first element is less than the second, ==0 equal, >0 if greather.
 *
 * This function is like the C strcmp().
 *
 * \code
 * struct object {
 *     tommy_node node;
 *     int value;
 * };
 *
 * int compare(const void* obj_a, const void* obj_b)
 * {
 *     if (((const struct object*)obj_a)->value < ((const struct object*)obj_b)->value)
 *         return -1;
 *     if (((const struct object*)obj_a)->value > ((const struct object*)obj_b)->value)
 *         return 1;
 *     return 0;
 * }
 *
 * tommy_list_sort(&list, compare);
 * \endcode
 *
 */
typedef int tommy_compare_func(const void* obj_a, const void* obj_b);

/**
 * Search function for elements.
 * \param arg Pointer to the value to search as passed at the search function.
 * \param obj Pointer to the object to compare to.
 * \return ==0 if the value matches the element. !=0 if different.
 *
 * The first argument is a pointer to the value to search exactly
 * as it's passed at the search function called.
 * The second argument is a pointer to the object inside the hashtable to compare.
 *
 * The return value has to be 0 if the values are equal. != 0 if they are different.
 *
 * \code
 * struct object {
 *     tommy_node node;
 *     int value;
 * };
 *
 * int compare(const void* arg, const void* obj)
 * {
 *     const int* value_to_find = arg;
 *     const struct object* object_to_compare = obj;
 *
 *     return *value_to_find != object_to_compare->value;
 * }
 *
 * int value_to_find = 1;
 * struct object* obj = tommy_hashtable_search(&hashtable, compare, &value_to_find, tommy_inthash_u32(value_to_find));
 * if (!obj) {
 *     // not found
 * } else {
 *     // found
 * }
 * \endcode
 *
 */
typedef int tommy_search_func(const void* arg, const void* obj);

/**
 * Foreach function.
 * \param obj Pointer to the object to iterate.
 *
 * A typical example is to use free() to deallocate all the objects in a list.
 * \code
 * tommy_list_foreach(&list, (tommy_foreach_func*)free);
 * \endcode
 */
typedef void tommy_foreach_func(void* obj);

/**
 * Foreach function with an argument.
 * \param arg Pointer to a generic argument.
 * \param obj Pointer to the object to iterate.
 */
typedef void tommy_foreach_arg_func(void* arg, void* obj);

/******************************************************************************/
/* bit hacks */

#if defined(_MSC_VER) && !defined(__cplusplus)
#include <intrin.h>
#pragma intrinsic(_BitScanReverse)
#pragma intrinsic(_BitScanForward)
#if TOMMY_SIZE_BIT == 64
#pragma intrinsic(_BitScanReverse64)
#pragma intrinsic(_BitScanForward64)
#endif
#endif

/** \internal
 * Integer log2 for constants.
 * You can use it only for exact power of 2 up to 256.
 */
#define TOMMY_ILOG2(value) ((value) == 256 ? 8 : (value) == 128 ? 7 : (value) == 64 ? 6 : (value) == 32 ? 5 : (value) == 16 ? 4 : (value) == 8 ? 3 : (value) == 4 ? 2 : (value) == 2 ? 1 : 0)

/**
 * Bit scan reverse or integer log2.
 * Return the bit index of the most significant 1 bit.
 *
 * If no bit is set, the result is undefined.
 * To force a return 0 in this case, you can use tommy_ilog2_u32(value | 1).
 *
 * Other interesting ways for bitscan are at:
 *
 * Bit Twiddling Hacks
 * http://graphics.stanford.edu/~seander/bithacks.html
 *
 * Chess Programming BitScan
 * http://chessprogramming.wikispaces.com/BitScan
 *
 * \param value Value to scan. 0 is not allowed.
 * \return The index of the most significant bit set.
 */
tommy_inline tommy_uint_t tommy_ilog2_u32(tommy_uint32_t value)
{
#if defined(_MSC_VER)
    unsigned long count;
    _BitScanReverse(&count, value);
    return count;
#elif defined(__GNUC__)
    /*
     * GCC implements __builtin_clz(x) as "__builtin_clz(x) = bsr(x) ^ 31"
     *
     * Where "x ^ 31 = 31 - x", but gcc does not optimize "31 - __builtin_clz(x)" to bsr(x),
     * but generates 31 - (bsr(x) xor 31).
     *
     * So we write "__builtin_clz(x) ^ 31" instead of "31 - __builtin_clz(x)",
     * to allow the double xor to be optimized out.
     */
    return __builtin_clz(value) ^ 31;
#else
    /* Find the log base 2 of an N-bit integer in O(lg(N)) operations with multiply and lookup */
    /* from http://graphics.stanford.edu/~seander/bithacks.html */
    static unsigned char TOMMY_DE_BRUIJN_INDEX_ILOG2[32] = {
        0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30,
        8, 12, 20, 28, 15, 17, 24, 7, 19, 27, 23, 6, 26, 5, 4, 31
    };

    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;

    return TOMMY_DE_BRUIJN_INDEX_ILOG2[(tommy_uint32_t)(value * 0x07C4ACDDU) >> 27];
#endif
}

#if TOMMY_SIZE_BIT == 64
/**
 * Bit scan reverse or integer log2 for 64 bits.
 */
tommy_inline tommy_uint_t tommy_ilog2_u64(tommy_uint64_t value)
{
#if defined(_MSC_VER)
    unsigned long count;
    _BitScanReverse64(&count, value);
    return count;
#elif defined(__GNUC__)
    return __builtin_clzll(value) ^ 63;
#else
    uint32_t l = value & 0xFFFFFFFFU;
    uint32_t h = value >> 32;
    if (h)
        return tommy_ilog2_u32(h) + 32;
    else
        return tommy_ilog2_u32(l);
#endif
}
#endif

/**
 * Bit scan forward or trailing zero count.
 * Return the bit index of the least significant 1 bit.
 *
 * If no bit is set, the result is undefined.
 * \param value Value to scan. 0 is not allowed.
 * \return The index of the least significant bit set.
 */
tommy_inline tommy_uint_t tommy_ctz_u32(tommy_uint32_t value)
{
#if defined(_MSC_VER)
    unsigned long count;
    _BitScanForward(&count, value);
    return count;
#elif defined(__GNUC__)
    return __builtin_ctz(value);
#else
    /* Count the consecutive zero bits (trailing) on the right with multiply and lookup */
    /* from http://graphics.stanford.edu/~seander/bithacks.html */
    static const unsigned char TOMMY_DE_BRUIJN_INDEX_CTZ[32] = {
        0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
        31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9
    };

    return TOMMY_DE_BRUIJN_INDEX_CTZ[(tommy_uint32_t)(((value & - value) * 0x077CB531U)) >> 27];
#endif
}

#if TOMMY_SIZE_BIT == 64
/**
 * Bit scan forward or trailing zero count for 64 bits.
 */
tommy_inline tommy_uint_t tommy_ctz_u64(tommy_uint64_t value)
{
#if defined(_MSC_VER)
    unsigned long count;
    _BitScanForward64(&count, value);
    return count;
#elif defined(__GNUC__)
    return __builtin_ctzll(value);
#else
    uint32_t l = value & 0xFFFFFFFFU;
    uint32_t h = value >> 32;
    if (l)
        return tommy_ctz_u32(l);
    else
        return tommy_ctz_u32(h) + 32;
#endif
}
#endif

/**
 * Rounds up to the next power of 2.
 * For the value 0, the result is undefined.
 * \return The smallest power of 2 not less than the specified value.
 */
tommy_inline tommy_uint32_t tommy_roundup_pow2_u32(tommy_uint32_t value)
{
    /* Round up to the next highest power of 2 */
    /* from http://graphics.stanford.edu/~seander/bithacks.html */

    --value;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
    ++value;

    return value;
}

/**
 * Rounds up to the next power of 2 for 64 bits.
 */
tommy_inline tommy_uint64_t tommy_roundup_pow2_u64(tommy_uint64_t value)
{
    --value;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
    value |= value >> 32;
    ++value;

    return value;
}

/**
 * Check if the specified word has a byte at 0.
 * \return 0 or 1.
 */
tommy_inline int tommy_haszero_u32(tommy_uint32_t value)
{
    return ((value - 0x01010101) & ~value & 0x80808080) != 0;
}

/*
 * Bit depth mapping.
 */
#if TOMMY_SIZE_BIT == 64
#define tommy_ilog2 tommy_ilog2_u64
#define tommy_ctz tommy_ctz_u64
#define tommy_roundup_pow2 tommy_roundup_pow2_u64
#else
#define tommy_ilog2 tommy_ilog2_u32
#define tommy_ctz tommy_ctz_u32
#define tommy_roundup_pow2 tommy_roundup_pow2_u32
#endif

#endif

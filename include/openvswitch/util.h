/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2016, 2017 Nicira, Inc.
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

#ifndef OPENVSWITCH_UTIL_H
#define OPENVSWITCH_UTIL_H 1

#include <openvswitch/compiler.h>
#include <openvswitch/version.h>
#include <openvswitch/types.h>

#ifdef __cplusplus
extern "C" {
#endif

void ovs_set_program_name(const char *name, const char *version);

const char *ovs_get_program_name(void);
const char *ovs_get_program_version(void);

/* Expands to a string that looks like "<file>:<line>", e.g. "tmp.c:10".
 *
 * See http://c-faq.com/ansi/stringize.html for an explanation of OVS_STRINGIZE
 * and OVS_STRINGIZE2. */
#define OVS_SOURCE_LOCATOR __FILE__ ":" OVS_STRINGIZE(__LINE__)
#define OVS_STRINGIZE(ARG) OVS_STRINGIZE2(ARG)
#define OVS_STRINGIZE2(ARG) #ARG

/* Saturating multiplication of "unsigned int"s: overflow yields UINT_MAX. */
#define OVS_SAT_MUL(X, Y)                                               \
    ((Y) == 0 ? 0                                                       \
     : (X) <= UINT_MAX / (Y) ? (unsigned int) (X) * (unsigned int) (Y)  \
     : UINT_MAX)

/* A special function that is intended to explicitly ignore results of
 * functions marked with __attribute__((warn_unused_result)), if necessary. */
void ovs_ignore(bool);

/* Like the standard assert macro, except:
 *
 *    - Writes the failure message to the log.
 *
 *    - Always evaluates the condition, even with NDEBUG. */
#ifndef NDEBUG
#define ovs_assert(CONDITION)                                           \
    (OVS_LIKELY(CONDITION)                                              \
     ? (void) 0                                                         \
     : ovs_assert_failure(OVS_SOURCE_LOCATOR, __func__, #CONDITION))
#else
#define ovs_assert ovs_ignore
#endif
OVS_NO_RETURN void ovs_assert_failure(const char *, const char *, const char *);

/* This is a void expression that issues a compiler error if POINTER cannot be
 * compared for equality with the given pointer TYPE.  This generally means
 * that POINTER is a qualified or unqualified TYPE.  However,
 * BUILD_ASSERT_TYPE(POINTER, void *) will accept any pointer to object type,
 * because any pointer to object can be compared for equality with "void *".
 *
 * POINTER can be any expression.  The use of "sizeof" ensures that the
 * expression is not actually evaluated, so that any side effects of the
 * expression do not occur.
 *
 * The cast to int is present only to suppress an "expression using sizeof
 * bool" warning from "sparse" (see
 * http://permalink.gmane.org/gmane.comp.parsers.sparse/2967). */
#define BUILD_ASSERT_TYPE(POINTER, TYPE) \
    ((void) sizeof ((int) ((POINTER) == (TYPE) (POINTER))))

/* Casts 'pointer' to 'type' and issues a compiler warning if the cast changes
 * anything other than an outermost "const" or "volatile" qualifier. */
#define CONST_CAST(TYPE, POINTER)                               \
    (BUILD_ASSERT_TYPE(POINTER, TYPE),                          \
     (TYPE) (POINTER))

/* Given a pointer-typed lvalue OBJECT, expands to a pointer type that may be
 * assigned to OBJECT. */
#ifdef __GNUC__
#define OVS_TYPEOF(OBJECT) typeof(OBJECT)
#elif defined (__cplusplus)
#define OVS_TYPEOF(OBJECT) decltype(OBJECT)
#else
#define OVS_TYPEOF(OBJECT) void *
#endif

/* Given OBJECT of type pointer-to-structure, expands to the offset of MEMBER
 * within an instance of the structure.
 *
 * The GCC-specific version avoids the technicality of undefined behavior if
 * OBJECT is null, invalid, or not yet initialized.  This makes some static
 * checkers (like Coverity) happier.  But the non-GCC version does not actually
 * dereference any pointer, so it would be surprising for it to cause any
 * problems in practice.
 */
#ifdef __GNUC__
#define OBJECT_OFFSETOF(OBJECT, MEMBER) offsetof(typeof(*(OBJECT)), MEMBER)
#else
#define OBJECT_OFFSETOF(OBJECT, MEMBER) \
    ((char *) &(OBJECT)->MEMBER - (char *) (OBJECT))
#endif

/* Yields the size of MEMBER within STRUCT. */
#define MEMBER_SIZEOF(STRUCT, MEMBER) (sizeof(((STRUCT *) NULL)->MEMBER))

/* Yields the offset of the end of MEMBER within STRUCT. */
#define OFFSETOFEND(STRUCT, MEMBER) \
        (offsetof(STRUCT, MEMBER) + MEMBER_SIZEOF(STRUCT, MEMBER))

/* Given POINTER, the address of the given MEMBER in a STRUCT object, returns
   the STRUCT object. */
#define CONTAINER_OF(POINTER, STRUCT, MEMBER)                           \
        ((STRUCT *) (void *) ((char *) (POINTER) - offsetof (STRUCT, MEMBER)))

/* Given POINTER, the address of the given MEMBER within an object of the type
 * that that OBJECT points to, returns OBJECT as an assignment-compatible
 * pointer type (either the correct pointer type or "void *").  OBJECT must be
 * an lvalue.
 *
 * This is the same as CONTAINER_OF except that it infers the structure type
 * from the type of '*OBJECT'. */
#define OBJECT_CONTAINING(POINTER, OBJECT, MEMBER)                      \
    ((OVS_TYPEOF(OBJECT)) (void *)                                      \
     ((char *) (POINTER) - OBJECT_OFFSETOF(OBJECT, MEMBER)))

/* Given POINTER, the address of the given MEMBER within an object of the type
 * that that OBJECT points to, assigns the address of the outer object to
 * OBJECT, which must be an lvalue.
 *
 * Evaluates to (void) 0 as the result is not to be used. */
#define ASSIGN_CONTAINER(OBJECT, POINTER, MEMBER) \
    ((OBJECT) = OBJECT_CONTAINING(POINTER, OBJECT, MEMBER), (void) 0)

/* As explained in the comment above OBJECT_OFFSETOF(), non-GNUC compilers
 * like MSVC will complain about un-initialized variables if OBJECT
 * hasn't already been initialized. To prevent such warnings, INIT_CONTAINER()
 * can be used as a wrapper around ASSIGN_CONTAINER. */
#define INIT_CONTAINER(OBJECT, POINTER, MEMBER) \
    ((OBJECT) = NULL, ASSIGN_CONTAINER(OBJECT, POINTER, MEMBER))

/* Multi-variable container iterators.
 *
 * The following macros facilitate safe iteration over data structures
 * contained in objects. It does so by using an internal iterator variable of
 * the type of the member object pointer (i.e: pointer to the data structure).
 */

/* Multi-variable iterator variable name.
 * Returns the name of the internal iterator variable.
 */
#define ITER_VAR(NAME) NAME ## __iterator__

/* Multi-variable initialization. Creates an internal iterator variable that
 * points to the provided pointer. The type of the iterator variable is
 * ITER_TYPE*. It must be the same type as &VAR->MEMBER.
 *
 * The _EXP version evaluates the extra expressions once.
 */
#define INIT_MULTIVAR(VAR, MEMBER, POINTER, ITER_TYPE)                  \
    INIT_MULTIVAR_EXP(VAR, MEMBER, POINTER, ITER_TYPE, (void) 0)

#define INIT_MULTIVAR_EXP(VAR, MEMBER, POINTER, ITER_TYPE, ...)         \
    ITER_TYPE *ITER_VAR(VAR) = ( __VA_ARGS__ , (ITER_TYPE *) POINTER)

/* Multi-variable condition.
 * Evaluates the condition expression (that must be based on the internal
 * iterator variable). Only if the result of expression is true, the OBJECT is
 * set to the object containing the current value of the iterator variable.
 *
 * It is up to the caller to make sure it is safe to run OBJECT_CONTAINING on
 * the pointers that verify the condition.
 */
#define CONDITION_MULTIVAR(VAR, MEMBER, EXPR)                                 \
    ((EXPR) ?                                                                 \
     (((VAR) = OBJECT_CONTAINING(ITER_VAR(VAR), VAR, MEMBER)), 1) :           \
     (((VAR) = NULL), 0))

/* Multi-variable update.
 * Sets the iterator value to NEXT_ITER.
 */
#define UPDATE_MULTIVAR(VAR, NEXT_ITER)                                       \
    (ITER_VAR(VAR) = NEXT_ITER)

/* In the safe version of the multi-variable container iteration, the next
 * value of the iterator is precalculated on the condition expression.
 * This allows for the iterator to be freed inside the loop.
 *
 * Two versions of the macros are provided:
 *
 * * In the _SHORT version, the user does not have to provide a variable to
 * store the next value of the iterator. Instead, a second iterator variable
 * is declared in the INIT_ macro and its name is determined by
 * ITER_NEXT_VAR(OBJECT).
 *
 * * In the _LONG version, the user provides another variable of the same type
 * as the iterator object variable to store the next containing object.
 * We still declare an iterator variable inside the loop but in this case it's
 * name is derived from the name of the next containing variable.
 * The value of the next containing object will only be set
 * (via OBJECT_CONTAINING) if an additional condition is statisfied. This
 * second condition must ensure it is safe to call OBJECT_CONTAINING on the
 * next iterator variable.
 * With respect to the value of the next containing object:
 *  - Inside of the loop: the variable is either NULL or safe to use.
 *  - Outside of the loop: the variable is NULL if the loop ends normally.
 *     If the loop ends with a "break;" statement, rules of Inside the loop
 *     apply.
 */
#define ITER_NEXT_VAR(NAME) NAME ## __iterator__next__

/* Safe initialization declares both iterators. */
#define INIT_MULTIVAR_SAFE_SHORT(VAR, MEMBER, POINTER, ITER_TYPE)             \
    INIT_MULTIVAR_SAFE_SHORT_EXP(VAR, MEMBER, POINTER, ITER_TYPE, (void) 0)

#define INIT_MULTIVAR_SAFE_SHORT_EXP(VAR, MEMBER, POINTER, ITER_TYPE, ...)    \
    ITER_TYPE *ITER_VAR(VAR) = ( __VA_ARGS__ , (ITER_TYPE *) POINTER),        \
        *ITER_NEXT_VAR(VAR) = NULL

/* Evaluate the condition expression and, if satisfied, update the _next_
 * iterator with the NEXT_EXPR.
 * Both EXPR and NEXT_EXPR should only use ITER_VAR(VAR) and
 * ITER_NEXT_VAR(VAR).
 */
#define CONDITION_MULTIVAR_SAFE_SHORT(VAR, MEMBER, EXPR, NEXT_EXPR)           \
    ((EXPR) ?                                                                 \
     (((VAR) = OBJECT_CONTAINING(ITER_VAR(VAR), VAR, MEMBER)),                \
      (NEXT_EXPR), 1) :                                                       \
     (((VAR) = NULL), 0))

#define UPDATE_MULTIVAR_SAFE_SHORT(VAR)                                       \
    UPDATE_MULTIVAR(VAR, ITER_NEXT_VAR(VAR))

/* _LONG versions of the macros. */

#define INIT_MULTIVAR_SAFE_LONG(VAR, NEXT_VAR, MEMBER, POINTER, ITER_TYPE)    \
    INIT_MULTIVAR_SAFE_LONG_EXP(VAR, NEXT_VAR, MEMBER, POINTER, ITER_TYPE,    \
                                (void) 0)                                     \

#define INIT_MULTIVAR_SAFE_LONG_EXP(VAR, NEXT_VAR, MEMBER, POINTER,           \
                                    ITER_TYPE, ...)                           \
    ITER_TYPE  *ITER_VAR(VAR) = ( __VA_ARGS__ , (ITER_TYPE *) POINTER),       \
        *ITER_VAR(NEXT_VAR) = NULL

/* Evaluate the condition expression and, if satisfied, update the _next_
 * iterator with the NEXT_EXPR. After, evaluate the NEXT_COND and, if
 * satisfied, set the value to NEXT_VAR. NEXT_COND must use ITER_VAR(NEXT_VAR).
 *
 * Both EXPR and NEXT_EXPR should only use ITER_VAR(VAR) and
 * ITER_VAR(NEXT_VAR).
 */
#define CONDITION_MULTIVAR_SAFE_LONG(VAR, NEXT_VAR, MEMBER, EXPR, NEXT_EXPR,  \
                                     NEXT_COND)                               \
    ((EXPR) ?                                                                 \
     (((VAR) = OBJECT_CONTAINING(ITER_VAR(VAR), VAR, MEMBER)),                \
      (NEXT_EXPR), ((NEXT_COND) ?                                             \
       ((NEXT_VAR) =                                                          \
        OBJECT_CONTAINING(ITER_VAR(NEXT_VAR), NEXT_VAR, MEMBER)) :            \
       ((NEXT_VAR) = NULL)), 1) :                                             \
     (((VAR) = NULL), ((NEXT_VAR) = NULL), 0))

#define UPDATE_MULTIVAR_SAFE_LONG(VAR, NEXT_VAR)                              \
    UPDATE_MULTIVAR(VAR, ITER_VAR(NEXT_VAR))

/* Helpers to allow overloading the *_SAFE iterator macros and select either
 * the LONG or the SHORT version depending on the number of arguments.
 */
#define GET_SAFE_MACRO2(_1, _2, NAME, ...) NAME
#define GET_SAFE_MACRO3(_1, _2, _3, NAME, ...) NAME
#define GET_SAFE_MACRO4(_1, _2, _3, _4, NAME, ...) NAME
#define GET_SAFE_MACRO5(_1, _2, _3, _4, _5, NAME, ...) NAME
#define GET_SAFE_MACRO6(_1, _2, _3, _4, _5, _6, NAME, ...) NAME
#define GET_SAFE_MACRO(MAX_ARGS) GET_SAFE_MACRO ## MAX_ARGS

/* MSVC treats __VA_ARGS__ as a simple token in argument lists. Introduce
 * a level of indirection to work around that. */
#define EXPAND_MACRO(name, args) name args

/* Overload the LONG and the SHORT version of the macros. MAX_ARGS is the
 * maximum number of arguments (i.e: the number of arguments of the LONG
 * version). */
#define OVERLOAD_SAFE_MACRO(LONG, SHORT, MAX_ARGS, ...) \
        EXPAND_MACRO(GET_SAFE_MACRO(MAX_ARGS), \
                     (__VA_ARGS__, LONG, SHORT))(__VA_ARGS__)

/* Returns the number of elements in ARRAY. */
#define ARRAY_SIZE(ARRAY) __ARRAY_SIZE(ARRAY)

/* Returns X / Y, rounding up.  X must be nonnegative to round correctly. */
#define DIV_ROUND_UP(X, Y) (((X) + ((Y) - 1)) / (Y))

/* Returns X rounded up to the nearest multiple of Y. */
#define ROUND_UP(X, Y) (DIV_ROUND_UP(X, Y) * (Y))

/* Returns the least number that, when added to X, yields a multiple of Y. */
#define PAD_SIZE(X, Y) (ROUND_UP(X, Y) - (X))

/* Returns X rounded down to the nearest multiple of Y. */
#define ROUND_DOWN(X, Y) ((X) / (Y) * (Y))

/* Returns true if X is a power of 2, otherwise false. */
#define IS_POW2(X) ((X) && !((X) & ((X) - 1)))

/* Expands to an anonymous union that contains:
 *
 *    - MEMBERS in a nested anonymous struct.
 *
 *    - An array as large as MEMBERS plus padding to a multiple of UNIT bytes.
 *
 * The effect is to pad MEMBERS to a multiple of UNIT bytes.
 *
 * For example, the struct below is 8 bytes long, with 6 bytes of padding:
 *
 *     struct padded_struct {
 *         PADDED_MEMBERS(8, uint8_t x; uint8_t y;);
 *     };
 */
#define PAD_PASTE2(x, y) x##y
#define PAD_PASTE(x, y) PAD_PASTE2(x, y)
#define PAD_ID PAD_PASTE(pad, __COUNTER__)
#ifndef __cplusplus
#define PADDED_MEMBERS(UNIT, MEMBERS)                               \
    union {                                                         \
        struct { MEMBERS };                                         \
        uint8_t PAD_ID[ROUND_UP(sizeof(struct { MEMBERS }), UNIT)]; \
    }
#else
/* C++ doesn't allow a type declaration within "sizeof", but it does support
 * scoping for member names, so we can just declare a second member, with a
 * name and the same type, and then use its size. */
#define PADDED_MEMBERS(UNIT, MEMBERS)                                       \
    struct named_member__ { MEMBERS };                                      \
    union {                                                                 \
        struct { MEMBERS };                                                 \
        uint8_t PAD_ID[ROUND_UP(sizeof(struct named_member__), UNIT)];      \
    }
#endif

/* Similar to PADDED_MEMBERS with additional cacheline marker:
 *
 *    - OVS_CACHE_LINE_MARKER is a cacheline marker
 *    - MEMBERS in a nested anonymous struct.
 *    - An array as large as MEMBERS plus padding to a multiple of UNIT bytes.
 *
 * The effect is to add cacheline marker and pad MEMBERS to a multiple of
 * UNIT bytes.
 *
 * Example:
 *     struct padded_struct {
 *         PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline0,
 *             uint8_t x;
 *             uint8_t y;
 *         );
 *     };
 *
 * The PADDED_MEMBERS_CACHELINE_MARKER macro in above structure expands as:
 *
 *     struct padded_struct {
 *            union {
 *                    OVS_CACHE_LINE_MARKER cacheline0;
 *                    struct {
 *                            uint8_t x;
 *                            uint8_t y;
 *                    };
 *                    uint8_t         pad0[64];
 *            };
 *            *--- cacheline 1 boundary (64 bytes) ---*
 *     };
 */
#ifndef __cplusplus
#define PADDED_MEMBERS_CACHELINE_MARKER(UNIT, CACHELINE, MEMBERS)   \
    union {                                                         \
        OVS_CACHE_LINE_MARKER CACHELINE;                            \
        struct { MEMBERS };                                         \
        uint8_t PAD_ID[ROUND_UP(sizeof(struct { MEMBERS }), UNIT)]; \
    }
#else
#define PADDED_MEMBERS_CACHELINE_MARKER(UNIT, CACHELINE, MEMBERS)           \
    struct struct_##CACHELINE { MEMBERS };                                  \
    union {                                                                 \
        OVS_CACHE_LINE_MARKER CACHELINE;                                    \
        struct { MEMBERS };                                                 \
        uint8_t PAD_ID[ROUND_UP(sizeof(struct struct_##CACHELINE), UNIT)];  \
    }
#endif

static inline bool
is_pow2(uintmax_t x)
{
    return IS_POW2(x);
}

/* Returns X rounded up to a power of 2.  X must be a constant expression. */
#define ROUND_UP_POW2(X) RUP2__(X)
#define RUP2__(X) (RUP2_1(X) + 1)
#define RUP2_1(X) (RUP2_2(X) | (RUP2_2(X) >> 16))
#define RUP2_2(X) (RUP2_3(X) | (RUP2_3(X) >> 8))
#define RUP2_3(X) (RUP2_4(X) | (RUP2_4(X) >> 4))
#define RUP2_4(X) (RUP2_5(X) | (RUP2_5(X) >> 2))
#define RUP2_5(X) (RUP2_6(X) | (RUP2_6(X) >> 1))
#define RUP2_6(X) ((X) - 1)

/* Returns X rounded down to a power of 2.  X must be a constant expression. */
#define ROUND_DOWN_POW2(X) RDP2__(X)
#define RDP2__(X) (RDP2_1(X) - (RDP2_1(X) >> 1))
#define RDP2_1(X) (RDP2_2(X) | (RDP2_2(X) >> 16))
#define RDP2_2(X) (RDP2_3(X) | (RDP2_3(X) >> 8))
#define RDP2_3(X) (RDP2_4(X) | (RDP2_4(X) >> 4))
#define RDP2_4(X) (RDP2_5(X) | (RDP2_5(X) >> 2))
#define RDP2_5(X) (      (X) | (      (X) >> 1))

/* Macros for sizing bitmaps */
#define BITMAP_ULONG_BITS (sizeof(unsigned long) * CHAR_BIT)
#define BITMAP_N_LONGS(N_BITS) DIV_ROUND_UP(N_BITS, BITMAP_ULONG_BITS)

/* Given ATTR, and TYPE, cast the ATTR to TYPE by first casting ATTR to (void
 * *).  This suppresses the alignment warning issued by Clang and newer
 * versions of GCC when a pointer is cast to a type with a stricter alignment.
 *
 * Add ALIGNED_CAST only if you are sure that the cast is actually correct,
 * that is, that the pointer is actually properly aligned for the stricter
 * type.  On RISC architectures, dereferencing a misaligned pointer can cause a
 * segfault, so it is important to be aware of correct alignment. */
#define ALIGNED_CAST(TYPE, ATTR) ((TYPE) (void *) (ATTR))

#define IS_PTR_ALIGNED(OBJ) \
    (!(OBJ) || (uintptr_t) (OBJ) % __alignof__(OVS_TYPEOF(OBJ)) == 0)

#ifdef __cplusplus
}
#endif

#endif

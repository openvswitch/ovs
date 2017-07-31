/*
 * Copyright (c) 2008, 2011, 2015 Nicira, Inc.
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

#ifndef OPENVSWITCH_TYPE_PROPS_H
#define OPENVSWITCH_TYPE_PROPS_H 1

#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

/* True if TYPE is _Bool, false otherwise. */
#define TYPE_IS_BOOL(TYPE) ((TYPE) 1 == (TYPE) 2)

/* True if TYPE is an integer type (including _Bool), false if it is a
 * floating-point type. */
#define TYPE_IS_INTEGER(TYPE) ((TYPE) 1.5 == (TYPE) 1)

/* True if TYPE is a signed integer or floating point type, otherwise false. */
#define TYPE_IS_SIGNED(TYPE) ((TYPE) 1 > (TYPE) -1)

/* The number of value bits in an signed or unsigned integer TYPE:
 *
 *    - _Bool has 1 value bit.
 *
 *    - An N-bit unsigned integer type has N value bits.
 *
 *    - An N-bit signed integer type has N-1 value bits.
 */
#define TYPE_VALUE_BITS(TYPE) \
    (TYPE_IS_BOOL(TYPE) ? 1 : sizeof(TYPE) * CHAR_BIT - TYPE_IS_SIGNED(TYPE))

/* The minimum or maximum value of a signed or unsigned integer TYPE. */
#define TYPE_MINIMUM(TYPE) (TYPE_IS_SIGNED(TYPE) ? -TYPE_MAXIMUM(TYPE) - 1 : 0)
#define TYPE_MAXIMUM(TYPE) \
    ((((TYPE)1 << (TYPE_VALUE_BITS(TYPE) - 1)) - 1) * 2 + 1)

/* Number of decimal digits required to format an integer of the given TYPE.
 * Includes space for a sign, if TYPE is signed, but not for a null
 * terminator.
 *
 * The value is an overestimate. */
#define INT_STRLEN(TYPE) (TYPE_IS_SIGNED(TYPE) + TYPE_VALUE_BITS(TYPE) / 3 + 1)

#ifdef __cplusplus
}
#endif

#endif /* type-props.h */

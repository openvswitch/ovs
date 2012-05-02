/*
 * Copyright (c) 2008, 2011 Nicira, Inc.
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

#ifndef TYPE_PROPS_H
#define TYPE_PROPS_H 1

#include <limits.h>

#define TYPE_IS_INTEGER(TYPE) ((TYPE) 1.5 == (TYPE) 1)
#define TYPE_IS_SIGNED(TYPE) ((TYPE) 1 > (TYPE) -1)
#define TYPE_VALUE_BITS(TYPE) (sizeof(TYPE) * CHAR_BIT - TYPE_IS_SIGNED(TYPE))
#define TYPE_MINIMUM(TYPE) (TYPE_IS_SIGNED(TYPE) \
                            ? ~(TYPE)0 << TYPE_VALUE_BITS(TYPE) \
                            : 0)
#define TYPE_MAXIMUM(TYPE) (TYPE_IS_SIGNED(TYPE) \
                            ? ~(~(TYPE)0 << TYPE_VALUE_BITS(TYPE)) \
                            : (TYPE)-1)

/* Number of decimal digits required to format an integer of the given TYPE.
 * Includes space for a sign, if TYPE is signed, but not for a null
 * terminator.
 *
 * The value is an overestimate. */
#define INT_STRLEN(TYPE) (TYPE_IS_SIGNED(TYPE) + TYPE_VALUE_BITS(TYPE) / 3 + 1)

#endif /* type-props.h */

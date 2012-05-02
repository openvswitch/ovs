/*
 * Copyright (c) 2009, 2010 Nicira, Inc.
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

#ifndef UNICODE_H
#define UNICODE_H 1

#include <stdbool.h>
#include <stddef.h>
#include "compiler.h"

/* Returns true if 'c' is a Unicode code point, otherwise false. */
static inline bool
uc_is_code_point(int c)
{
    return c >= 0 && c <= 0x10ffff;
}

/* Returns true if 'c' is a Unicode code point for a leading surrogate. */
static inline bool
uc_is_leading_surrogate(int c)
{
    return c >= 0xd800 && c <= 0xdbff;
}

/* Returns true if 'c' is a Unicode code point for a trailing surrogate. */
static inline bool
uc_is_trailing_surrogate(int c)
{
    return c >= 0xdc00 && c <= 0xdfff;
}

/* Returns true if 'c' is a Unicode code point for a leading or trailing
 * surrogate. */
static inline bool
uc_is_surrogate(int c)
{
    return c >= 0xd800 && c <= 0xdfff;
}

int utf16_decode_surrogate_pair(int leading, int trailing);

size_t utf8_length(const char *);
char *utf8_validate(const char *, size_t *lengthp) WARN_UNUSED_RESULT;

#endif /* unicode.h */

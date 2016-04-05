/*
 * Copyright (c) 2008, 2009, 2011, 2015 Nicira, Inc.
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
#include "openvswitch/type-props.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MUST_SUCCEED(EXPRESSION)                    \
    if (!(EXPRESSION)) {                            \
        fprintf(stderr, "%s:%d: %s failed\n",       \
                __FILE__, __LINE__, #EXPRESSION);   \
        exit(EXIT_FAILURE);                         \
    }

#define TEST_TYPE(type, minimum, maximum, is_signed)    \
    MUST_SUCCEED(TYPE_IS_INTEGER(type));                \
    MUST_SUCCEED(TYPE_IS_SIGNED(type) == is_signed);    \
    MUST_SUCCEED(TYPE_MAXIMUM(type) == maximum);        \
    MUST_SUCCEED(TYPE_MINIMUM(type) == minimum);        \
    sprintf(max_s, "%"PRIuMAX, (uintmax_t) (maximum));  \
    MUST_SUCCEED(strlen(max_s) <= INT_STRLEN(type));    \
    sprintf(min_s, "%"PRIdMAX, (intmax_t) (minimum));   \
    MUST_SUCCEED(strlen(min_s) <= INT_STRLEN(type));

int
main (void)
{
    char max_s[128];
    char min_s[128];

#ifndef __CHECKER__             /* sparse hates sizeof(bool). */
    TEST_TYPE(_Bool, 0, 1, 0);
#endif

    TEST_TYPE(char, CHAR_MIN, CHAR_MAX, (CHAR_MIN < 0));

    TEST_TYPE(signed char, SCHAR_MIN, SCHAR_MAX, 1);
    TEST_TYPE(short int, SHRT_MIN, SHRT_MAX, 1);
    TEST_TYPE(int, INT_MIN, INT_MAX, 1);
    TEST_TYPE(long int, LONG_MIN, LONG_MAX, 1);
    TEST_TYPE(long long int, LLONG_MIN, LLONG_MAX, 1);

    TEST_TYPE(unsigned char, 0, UCHAR_MAX, 0);
    TEST_TYPE(unsigned short int, 0, USHRT_MAX, 0);
    TEST_TYPE(unsigned int, 0, UINT_MAX, 0);
    TEST_TYPE(unsigned long int, 0, ULONG_MAX, 0);
    TEST_TYPE(unsigned long long int, 0, ULLONG_MAX, 0);

    MUST_SUCCEED(!(TYPE_IS_INTEGER(float)));
    MUST_SUCCEED(!(TYPE_IS_INTEGER(double)));
    MUST_SUCCEED(!(TYPE_IS_INTEGER(long double)));

    return 0;
}

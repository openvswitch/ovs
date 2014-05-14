/*
 * Copyright (c) 2013, 2014 Nicira, Inc.
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
#include "util.h"
#include "ovstest.h"

#define TEST_ATOMIC_TYPE(ATOMIC_TYPE, BASE_TYPE)        \
    {                                                   \
        ATOMIC_TYPE x = ATOMIC_VAR_INIT(1);             \
        BASE_TYPE value, orig;                          \
                                                        \
        atomic_read(&x, &value);                        \
        ovs_assert(value == 1);                         \
                                                        \
        atomic_store(&x, 2);                            \
        atomic_read(&x, &value);                        \
        ovs_assert(value == 2);                         \
                                                        \
        atomic_init(&x, 3);                             \
        atomic_read(&x, &value);                        \
        ovs_assert(value == 3);                         \
                                                        \
        atomic_add(&x, 1, &orig);                       \
        ovs_assert(orig == 3);                          \
        atomic_read(&x, &value);                        \
        ovs_assert(value == 4);                         \
                                                        \
        atomic_sub(&x, 2, &orig);                       \
        ovs_assert(orig == 4);                          \
        atomic_read(&x, &value);                        \
        ovs_assert(value == 2);                         \
                                                        \
        atomic_or(&x, 6, &orig);                        \
        ovs_assert(orig == 2);                          \
        atomic_read(&x, &value);                        \
        ovs_assert(value == 6);                         \
                                                        \
        atomic_and(&x, 10, &orig);                      \
        ovs_assert(orig == 6);                          \
        atomic_read(&x, &value);                        \
        ovs_assert(value == 2);                         \
                                                        \
        atomic_xor(&x, 10, &orig);                      \
        ovs_assert(orig == 2);                          \
        atomic_read(&x, &value);                        \
        ovs_assert(value == 8);                         \
    }

static void
test_atomic_flag(void)
{
    atomic_flag flag = ATOMIC_FLAG_INIT;
    ovs_assert(atomic_flag_test_and_set(&flag) == false);
    ovs_assert(atomic_flag_test_and_set(&flag) == true);
    atomic_flag_clear(&flag);
    ovs_assert(atomic_flag_test_and_set(&flag) == false);
}


static void
test_atomic_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    TEST_ATOMIC_TYPE(atomic_char, char);
    TEST_ATOMIC_TYPE(atomic_uchar, unsigned char);
    TEST_ATOMIC_TYPE(atomic_schar, signed char);
    TEST_ATOMIC_TYPE(atomic_short, short);
    TEST_ATOMIC_TYPE(atomic_ushort, unsigned short);
    TEST_ATOMIC_TYPE(atomic_int, int);
    TEST_ATOMIC_TYPE(atomic_uint, unsigned int);
    TEST_ATOMIC_TYPE(atomic_long, long int);
    TEST_ATOMIC_TYPE(atomic_ulong, unsigned long int);
    TEST_ATOMIC_TYPE(atomic_llong, long long int);
    TEST_ATOMIC_TYPE(atomic_ullong, unsigned long long int);
    TEST_ATOMIC_TYPE(atomic_size_t, size_t);
    TEST_ATOMIC_TYPE(atomic_ptrdiff_t, ptrdiff_t);
    TEST_ATOMIC_TYPE(atomic_intmax_t, intmax_t);
    TEST_ATOMIC_TYPE(atomic_uintmax_t, uintmax_t);
    TEST_ATOMIC_TYPE(atomic_intptr_t, intptr_t);
    TEST_ATOMIC_TYPE(atomic_uintptr_t, uintptr_t);
    TEST_ATOMIC_TYPE(atomic_uint8_t, uint8_t);
    TEST_ATOMIC_TYPE(atomic_int8_t, int8_t);
    TEST_ATOMIC_TYPE(atomic_uint16_t, uint16_t);
    TEST_ATOMIC_TYPE(atomic_int16_t, int16_t);
    TEST_ATOMIC_TYPE(atomic_uint32_t, uint32_t);
    TEST_ATOMIC_TYPE(atomic_int32_t, int32_t);

    test_atomic_flag();
}

OVSTEST_REGISTER("test-atomic", test_atomic_main);

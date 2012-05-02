/*
 * Copyright (c) 2008, 2009, 2011 Nicira, Inc.
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

#ifndef LEAK_CHECKER_H
#define LEAK_CHECKER_H 1

#include <sys/types.h>

#define LEAK_CHECKER_OPTION_ENUMS               \
    OPT_CHECK_LEAKS,                            \
    OPT_LEAK_LIMIT
#define LEAK_CHECKER_LONG_OPTIONS                           \
    {"check-leaks", required_argument, NULL, OPT_CHECK_LEAKS}, \
    {"leak-limit", required_argument, NULL, OPT_LEAK_LIMIT}
#define LEAK_CHECKER_OPTION_HANDLERS                \
        case OPT_CHECK_LEAKS:                       \
            leak_checker_start(optarg);             \
            break;                                  \
        case OPT_LEAK_LIMIT:                        \
            leak_checker_set_limit(atol(optarg));   \
            break;
void leak_checker_start(const char *file_name);
void leak_checker_set_limit(off_t limit);
void leak_checker_stop(void);
void leak_checker_claim(const void *);
void leak_checker_usage(void);

#endif /* leak-checker.h */

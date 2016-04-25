/*
 * Copyright (c) 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
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

#ifndef DUMMY_H
#define DUMMY_H 1

#include <stdbool.h>

/* Degree of dummy support.
 *
 * Beyond enabling support for dummies, it can be useful to replace some kinds
 * of bridges and netdevs, or all kinds, by dummies.  This enum expresses the
 * degree to which this should happen. */
enum dummy_level {
    DUMMY_OVERRIDE_NONE,        /* Support dummy but don't force its use. */
    DUMMY_OVERRIDE_SYSTEM,      /* Replace "system" by dummy. */
    DUMMY_OVERRIDE_ALL,         /* Replace all types by dummy. */
};

/* For client programs to call directly to enable dummy support. */
void dummy_enable(const char *arg);

/* Implementation details. */
void dpif_dummy_register(enum dummy_level);
void netdev_dummy_register(enum dummy_level);
void timeval_dummy_register(void);
void ofpact_dummy_enable(void);

#endif /* dummy.h */

/*
 * Copyright (c) 2010, 2011, 2012, 2013 Nicira, Inc.
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

/* For client programs to call directly to enable dummy support. */
void dummy_enable(bool override);

/* Implementation details. */
void dpif_dummy_register(bool override);
void netdev_dummy_register(bool override);
void timeval_dummy_register(void);
void vlandev_dummy_enable(void);

#endif /* dummy.h */

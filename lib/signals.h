/*
 * Copyright (c) 2008, 2011, 2013 Nicira, Inc.
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

#ifndef SIGNALS_H
#define SIGNALS_H 1

#include <signal.h>
#include <stddef.h>
#include "type-props.h"

enum { SIGNAL_NAME_BUFSIZE = 7 + INT_STRLEN(int) + 1 };
const char *signal_name(int signum, char *namebuf, size_t bufsize);

void xsigaction(int signum, const struct sigaction *, struct sigaction *old);

#endif /* signals.h */

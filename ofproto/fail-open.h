/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira, Inc.
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

#ifndef FAIL_OPEN_H
#define FAIL_OPEN_H 1

#include <stdbool.h>
#include <stdint.h>
#include "flow.h"

struct connmgr;
struct fail_open;
struct ofproto;

/* Priority of the rule added by the fail-open subsystem when a switch enters
 * fail-open mode.  This priority value uniquely identifies a fail-open flow
 * (OpenFlow priorities max out at 65535 and nothing else in Open vSwitch
 * creates flows with this priority).  And "f0" is mnemonic for "fail open"! */
#define FAIL_OPEN_PRIORITY 0xf0f0f0

struct fail_open *fail_open_create(struct ofproto *, struct connmgr *);
void fail_open_destroy(struct fail_open *);
void fail_open_wait(struct fail_open *);
bool fail_open_is_active(const struct fail_open *);
void fail_open_run(struct fail_open *);
void fail_open_maybe_recover(struct fail_open *);
void fail_open_flushed(struct fail_open *);

#endif /* fail-open.h */

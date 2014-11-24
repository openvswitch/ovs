/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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

#ifndef OPENVSWITCH_UTIL_H
#define OPENVSWITCH_UTIL_H 1

#include <openvswitch/version.h>

void ovs_set_program_name__(const char *name, const char *version,
                            const char *date, const char *time);

#define ovs_set_program_name(name, version) \
        ovs_set_program_name__(name, version, __DATE__, __TIME__)

const char *ovs_get_program_name(void);
const char *ovs_get_program_version(void);

#endif

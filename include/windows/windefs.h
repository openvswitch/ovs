/*
 * Copyright (c) 2013 Nicira, Inc.
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

#ifndef WINDEFS_H
#define WINDEFS_H 1

#include <Winsock2.h>
#include <In6addr.h>
#include <WS2tcpip.h>
#include <windows.h>
#include <BaseTsd.h>
#include <io.h>
#include <inttypes.h>

#pragma comment(lib, "advapi32")

#define inline __inline
#define __func__ __FUNCTION__
#define ssize_t SSIZE_T
#define u_int8_t uint8_t
#define u_int16_t uint16_t
#define u_int32_t uint32_t
#define u_int64_t uint64_t

typedef int pid_t;

char *strsep(char **stringp, const char *delim);

#define srandom srand
#define random rand

#endif /* windefs.h */

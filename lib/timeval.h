/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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

#ifndef TIMEVAL_H
#define TIMEVAL_H 1

#include <time.h>
#include "type-props.h"
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct pollfd;
struct timespec;
struct timeval;

/* POSIX allows floating-point time_t, but we don't support it. */
BUILD_ASSERT_DECL(TYPE_IS_INTEGER(time_t));

/* We do try to cater to unsigned time_t, but I want to know about it if we
 * ever encounter such a platform. */
BUILD_ASSERT_DECL(TYPE_IS_SIGNED(time_t));

#define TIME_MAX TYPE_MAXIMUM(time_t)
#define TIME_MIN TYPE_MINIMUM(time_t)

/* Interval between updates to the reported time, in ms.  This should not be
 * adjusted much below 10 ms or so with the current implementation, or too
 * much time will be wasted in signal handlers and calls to clock_gettime(). */
#define TIME_UPDATE_INTERVAL 100

void time_disable_restart(void);
void time_enable_restart(void);
void time_postfork(void);
void time_refresh(void);
time_t time_now(void);
time_t time_wall(void);
long long int time_msec(void);
long long int time_wall_msec(void);
void time_timespec(struct timespec *);
void time_wall_timespec(struct timespec *);
void time_alarm(unsigned int secs);
int time_poll(struct pollfd *, int n_pollfds, int timeout);

long long int timespec_to_msec(const struct timespec *);
long long int timeval_to_msec(const struct timeval *);

void xgettimeofday(struct timeval *);

int get_cpu_usage(void);

#ifdef  __cplusplus
}
#endif

#endif /* timeval.h */

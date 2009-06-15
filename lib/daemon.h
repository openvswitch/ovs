/*
 * Copyright (c) 2008 Nicira Networks.
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

#ifndef DAEMON_H
#define DAEMON_H 1

#include <stdbool.h>
#include <sys/types.h>

#define DAEMON_LONG_OPTIONS                         \
        {"detach",      no_argument, 0, 'D'},       \
        {"force",       no_argument, 0, 'f'},       \
        {"pidfile",     optional_argument, 0, 'P'}

#define DAEMON_OPTION_HANDLERS                  \
        case 'D':                               \
            set_detach();                       \
            break;                              \
                                                \
        case 'P':                               \
            set_pidfile(optarg);                \
            break;                              \
                                                \
        case 'f':                               \
            ignore_existing_pidfile();          \
            break;

char *make_pidfile_name(const char *name);
void set_pidfile(const char *name);
const char *get_pidfile(void);
void set_detach(void);
void daemonize(void);
void die_if_already_running(void);
void ignore_existing_pidfile(void);
void daemon_usage(void);
pid_t read_pidfile(const char *name);

#endif /* daemon.h */

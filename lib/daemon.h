/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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

#include <limits.h>
#include <stdbool.h>
#include <sys/types.h>

#define DAEMON_OPTION_ENUMS                     \
    OPT_DETACH,                                 \
    OPT_NO_CHDIR,                               \
    OPT_OVERWRITE_PIDFILE,                      \
    OPT_PIDFILE,                                \
    OPT_MONITOR

#define DAEMON_LONG_OPTIONS                                             \
        {"detach",            no_argument, NULL, OPT_DETACH},           \
        {"no-chdir",          no_argument, NULL, OPT_NO_CHDIR},         \
        {"pidfile",           optional_argument, NULL, OPT_PIDFILE},    \
        {"overwrite-pidfile", no_argument, NULL, OPT_OVERWRITE_PIDFILE}, \
        {"monitor",           no_argument, NULL, OPT_MONITOR}

#define DAEMON_OPTION_HANDLERS                  \
        case OPT_DETACH:                        \
            set_detach();                       \
            break;                              \
                                                \
        case OPT_NO_CHDIR:                      \
            set_no_chdir();                     \
            break;                              \
                                                \
        case OPT_PIDFILE:                       \
            set_pidfile(optarg);                \
            break;                              \
                                                \
        case OPT_OVERWRITE_PIDFILE:             \
            ignore_existing_pidfile();          \
            break;                              \
                                                \
        case OPT_MONITOR:                       \
            daemon_set_monitor();               \
            break;

char *make_pidfile_name(const char *name);
void set_pidfile(const char *name);
const char *get_pidfile(void);
void set_no_chdir(void);
bool is_chdir_enabled(void);
void set_detach(void);
bool get_detach(void);
void daemon_set_monitor(void);
void daemon_save_fd(int fd);
void daemonize(void);
void daemonize_start(void);
void daemonize_complete(void);
void ignore_existing_pidfile(void);
void daemon_usage(void);
pid_t read_pidfile(const char *name);
pid_t read_pidfile_if_exists(const char *name);

pid_t fork_and_clean_up(void);
void daemonize_post_detach(void);

#endif /* daemon.h */

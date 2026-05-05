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

/* This file provides an interface for utilities to run in the background
 * as daemons on POSIX platforms.
 *
 * More descriptive comments on individual functions are provided
 * in daemon-unix.c.

 * The DAEMON_OPTION_ENUMS, DAEMON_LONG_OPTIONS and DAEMON_OPTION_HANDLERS
 * macros are useful for parsing command-line options in individual utilities.
 * For e.g., the command-line option "--monitor" is recognized on Linux
 * and results in calling the daemon_set_monitor() function.
 */

#define DAEMON_OPTION_ENUMS                     \
    OPT_DETACH,                                 \
    OPT_NO_SELF_CONFINEMENT,                    \
    OPT_NO_CHDIR,                               \
    OPT_OVERWRITE_PIDFILE,                      \
    OPT_PIDFILE,                                \
    OPT_MONITOR,                                \
    OPT_USER_GROUP

#define DAEMON_LONG_OPTIONS                                              \
        {"detach",            no_argument, NULL, OPT_DETACH},            \
        {"no-self-confinement", no_argument, NULL, OPT_NO_SELF_CONFINEMENT}, \
        {"no-chdir",          no_argument, NULL, OPT_NO_CHDIR},          \
        {"pidfile",           optional_argument, NULL, OPT_PIDFILE},     \
        {"overwrite-pidfile", no_argument, NULL, OPT_OVERWRITE_PIDFILE}, \
        {"monitor",           no_argument, NULL, OPT_MONITOR},           \
        {"user",              required_argument, NULL, OPT_USER_GROUP}

#define DAEMON_OPTION_HANDLERS                  \
        case OPT_DETACH:                        \
            set_detach();                       \
            break;                              \
                                                \
        case OPT_NO_SELF_CONFINEMENT:           \
            daemon_disable_self_confinement();  \
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
            break;                              \
                                                \
        case OPT_USER_GROUP:                    \
            daemon_set_new_user(optarg);        \
            break;

#define DAEMON_OPTION_CASES                     \
        case OPT_DETACH:                        \
        case OPT_NO_SELF_CONFINEMENT:           \
        case OPT_NO_CHDIR:                      \
        case OPT_PIDFILE:                       \
        case OPT_OVERWRITE_PIDFILE:             \
        case OPT_MONITOR:                       \
        case OPT_USER_GROUP:

void set_detach(void);
void daemon_set_monitor(void);
void set_no_chdir(void);
void ignore_existing_pidfile(void);
pid_t read_pidfile(const char *name);

bool get_detach(void);
void daemon_save_fd(int fd);
void daemonize(void);
void daemonize_start(bool access_datapath, bool access_hardware_ports);
void daemonize_complete(void);
void daemon_set_new_user(const char * user_spec);
void daemon_become_new_user(bool access_datapath, bool access_hardware_ports);
void daemon_usage(void);
void daemon_disable_self_confinement(void);
bool daemon_should_self_confine(void);
void set_pidfile(const char *name);
void close_standard_fds(void);

#endif /* daemon.h */

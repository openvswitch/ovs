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
 * as daemons on POSIX platforms like Linux or as services on Windows platform.
 * Some of the functionalities defined in this file are only applicable to
 * POSIX platforms and some are applicable only on Windows. As such, the
 * function definitions unique to each platform are separated out with
 * ifdef macros. More descriptive comments on individual functions are provided
 * in daemon-unix.c (for POSIX platforms) and daemon-windows.c (for Windows).

 * The DAEMON_OPTION_ENUMS, DAEMON_LONG_OPTIONS and DAEMON_OPTION_HANDLERS
 * macros are useful for parsing command-line options in individual utilities.
 * For e.g., the command-line option "--monitor" is recognized on Linux
 * and results in calling the daemon_set_monitor() function. The same option is
 * not recognized on Windows platform.
 */

#ifndef _WIN32
#define DAEMON_OPTION_ENUMS                     \
    OPT_DETACH,                                 \
    OPT_NO_CHDIR,                               \
    OPT_OVERWRITE_PIDFILE,                      \
    OPT_PIDFILE,                                \
    OPT_MONITOR,                                \
    OPT_USER_GROUP

#define DAEMON_LONG_OPTIONS                                              \
        {"detach",            no_argument, NULL, OPT_DETACH},            \
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

void set_detach(void);
void daemon_set_monitor(void);
void set_no_chdir(void);
void ignore_existing_pidfile(void);
pid_t read_pidfile(const char *name);
#else
#define DAEMON_OPTION_ENUMS                    \
    OPT_DETACH,                                \
    OPT_NO_CHDIR,                              \
    OPT_PIDFILE,                               \
    OPT_PIPE_HANDLE,                           \
    OPT_SERVICE,                               \
    OPT_SERVICE_MONITOR,                       \
    OPT_USER_GROUP

#define DAEMON_LONG_OPTIONS                                               \
        {"detach",             no_argument, NULL, OPT_DETACH},            \
        {"no-chdir",           no_argument, NULL, OPT_NO_CHDIR},          \
        {"pidfile",            optional_argument, NULL, OPT_PIDFILE},     \
        {"pipe-handle",        required_argument, NULL, OPT_PIPE_HANDLE}, \
        {"service",            no_argument, NULL, OPT_SERVICE},           \
        {"service-monitor",    no_argument, NULL, OPT_SERVICE_MONITOR},   \
        {"user",               required_argument, NULL, OPT_USER_GROUP}

#define DAEMON_OPTION_HANDLERS                  \
        case OPT_DETACH:                        \
            break;                              \
                                                \
        case OPT_NO_CHDIR:                      \
            break;                              \
                                                \
        case OPT_PIDFILE:                       \
            set_pidfile(optarg);                \
            break;                              \
                                                \
        case OPT_PIPE_HANDLE:                   \
            set_pipe_handle(optarg);            \
            break;                              \
                                                \
        case OPT_SERVICE:                       \
            break;                              \
                                                \
        case OPT_SERVICE_MONITOR:               \
            break;                              \
                                                \
        case OPT_USER_GROUP:                    \
            daemon_set_new_user(optarg);

void control_handler(DWORD request);
void set_pipe_handle(const char *pipe_handle);
#endif /* _WIN32 */

bool get_detach(void);
void daemon_save_fd(int fd);
void daemonize(void);
void daemonize_start(bool access_datapath);
void daemonize_complete(void);
void daemon_set_new_user(const char * user_spec);
void daemon_become_new_user(bool access_datapath);
void daemon_usage(void);
void service_start(int *argcp, char **argvp[]);
void service_stop(void);
bool should_service_stop(void);
void set_pidfile(const char *name);
void close_standard_fds(void);

#endif /* daemon.h */

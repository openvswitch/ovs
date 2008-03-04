/* Copyright (C) 2007 Board of Trustees, Leland Stanford Jr. University.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef VLOG_H
#define VLOG_H 1

#include <stdbool.h>

/* Logging importance levels. */
enum vlog_level {
    VLL_EMER,
    VLL_ERR,
    VLL_WARN,
    VLL_DBG,
    VLL_N_LEVELS
};

const char *vlog_get_level_name(enum vlog_level);
enum vlog_level vlog_get_level_val(const char *name);

/* Facilities that we can log to. */
enum vlog_facility {
    VLF_SYSLOG,
    VLF_CONSOLE,
    VLF_N_FACILITIES,
    VLF_ANY_FACILITY = -1
};

const char *vlog_get_facility_name(enum vlog_facility);
enum vlog_facility vlog_get_facility_val(const char *name);

/* Modules that can emit log messages. */
#define VLOG_MODULES                            \
        VLOG_MODULE(controller)                 \
        VLOG_MODULE(ctlpath)                    \
        VLOG_MODULE(dpif)                       \
        VLOG_MODULE(dpctl)                      \
        VLOG_MODULE(fault)                      \
        VLOG_MODULE(flow)                       \
        VLOG_MODULE(netlink)                    \
        VLOG_MODULE(secchan)                    \
        VLOG_MODULE(socket_util)                \
        VLOG_MODULE(vconn_netlink)              \
        VLOG_MODULE(vconn_tcp)                  \
        VLOG_MODULE(vconn)                      \

/* VLM_ constant for each vlog module. */
enum vlog_module {
#define VLOG_MODULE(NAME) VLM_##NAME,
    VLOG_MODULES
#undef VLOG_MODULE
    VLM_N_MODULES,
    VLM_ANY_MODULE = -1
};

const char *vlog_get_module_name(enum vlog_module);
enum vlog_module vlog_get_module_val(const char *name);

/* Configuring how each module logs messages. */
enum vlog_level vlog_get_level(enum vlog_module, enum vlog_facility);
void vlog_set_levels(enum vlog_module, enum vlog_facility, enum vlog_level);
char *vlog_set_levels_from_string(const char *);
char *vlog_get_levels(void);
void vlog_set_verbosity(const char *arg);

/* Function for actual logging. */
void vlog_init(void);
void vlog_exit(void);
void vlog(enum vlog_module, enum vlog_level, const char *format, ...)
    __attribute__((format(printf, 3, 4)));

/* Convenience macros.  To use these, define THIS_MODULE as a macro that
 * expands to the module used by the current source file, e.g.
 *      #include "vlog.h"
 *      #define THIS_MODULE VLM_NETLINK
 */
#define VLOG_EMER(...) vlog(THIS_MODULE, VLL_EMER, __VA_ARGS__)
#define VLOG_ERR(...) vlog(THIS_MODULE, VLL_ERR, __VA_ARGS__)
#define VLOG_WARN(...) vlog(THIS_MODULE, VLL_WARN, __VA_ARGS__)
#define VLOG_DBG(...) vlog(THIS_MODULE, VLL_DBG, __VA_ARGS__)

#endif /* vlog.h */

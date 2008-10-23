/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
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

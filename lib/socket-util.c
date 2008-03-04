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

#include "socket-util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>

#include "vlog.h"
#define THIS_MODULE VLM_socket_util

/* Sets 'fd' to non-blocking mode.  Returns 0 if successful, otherwise a
 * positive errno value. */
int
set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) {
        return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1 ? 0 : errno;
    } else {
        return errno;
    }
}

/* Translates 'host_name', which may be a DNS name or an IP address, into a
 * numeric IP address in '*addr'.  Returns 0 if successful, otherwise a
 * positive errno value. */
int
lookup_ip(const char *host_name, struct in_addr *addr) 
{
    if (!inet_aton(host_name, addr)) {
        struct hostent *he = gethostbyname(host_name);
        if (he == NULL) {
            VLOG_ERR("gethostbyname(%s): %s", host_name,
                     (h_errno == HOST_NOT_FOUND ? "host not found"
                      : h_errno == TRY_AGAIN ? "try again"
                      : h_errno == NO_RECOVERY ? "non-recoverable error"
                      : h_errno == NO_ADDRESS ? "no address"
                      : "unknown error"));
            return ENOENT;
        }
        addr->s_addr = *(uint32_t *) he->h_addr;
    }
    return 0;
}

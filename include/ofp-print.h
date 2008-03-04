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

/* OpenFlow protocol pretty-printer. */

#ifndef __OFP_PRINT_H__
#define __OFP_ORINT_H __1

#include <stdio.h>

struct ofp_flow_mod;
struct ofp_table;

#ifdef  __cplusplus
extern "C" {
#endif

void ofp_print(FILE *, const void *, size_t, int verbosity);
void ofp_print_table(FILE *stream, const struct ofp_table* ot);
void ofp_print_flow_mod(FILE *stream, const void *data, size_t len, int verbosity);
void ofp_print_flow_expired(FILE *stream, const void *data, size_t len, int verbosity);
void ofp_print_data_hello(FILE *stream, const void *data, size_t len, int verbosity);
void ofp_print_packet(FILE *stream, const void *data, size_t len, size_t total_len);
void ofp_print_port_status(FILE *stream, const void *oh, size_t len, int verbosity);

#ifdef  __cplusplus
}
#endif

#endif /* ofppp.h */

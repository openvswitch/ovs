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
#ifndef VCONN_SSL_H
#define VCONN_SSL_H 1

#include <stdbool.h>

#ifdef HAVE_OPENSSL
bool vconn_ssl_is_configured(void);
void vconn_ssl_set_private_key_file(const char *file_name);
void vconn_ssl_set_certificate_file(const char *file_name);
void vconn_ssl_set_ca_cert_file(const char *file_name, bool bootstrap);
void vconn_ssl_set_peer_ca_cert_file(const char *file_name);

#define VCONN_SSL_LONG_OPTIONS                      \
        {"private-key", required_argument, 0, 'p'}, \
        {"certificate", required_argument, 0, 'c'}, \
        {"ca-cert",     required_argument, 0, 'C'},

#define VCONN_SSL_OPTION_HANDLERS                       \
        case 'p':                                       \
            vconn_ssl_set_private_key_file(optarg);     \
            break;                                      \
                                                        \
        case 'c':                                       \
            vconn_ssl_set_certificate_file(optarg);     \
            break;                                      \
                                                        \
        case 'C':                                       \
            vconn_ssl_set_ca_cert_file(optarg, false);  \
            break;
#else /* !HAVE_OPENSSL */
static inline bool vconn_ssl_is_configured(void) 
{
    return false;
}
#define VCONN_SSL_LONG_OPTIONS
#define VCONN_SSL_OPTION_HANDLERS
#endif /* !HAVE_OPENSSL */

#endif /* vconn-ssl.h */

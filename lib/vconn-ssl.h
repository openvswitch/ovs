/*
 * Copyright (c) 2008 Nicira Networks.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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

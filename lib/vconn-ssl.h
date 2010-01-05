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
#ifndef VCONN_SSL_H
#define VCONN_SSL_H 1

#include <stdbool.h>

#ifdef HAVE_OPENSSL
bool vconn_ssl_is_configured(void);
void vconn_ssl_set_private_key_file(const char *file_name);
void vconn_ssl_set_certificate_file(const char *file_name);
void vconn_ssl_set_ca_cert_file(const char *file_name, bool bootstrap);
void vconn_ssl_set_peer_ca_cert_file(const char *file_name);

/* Define the long options for SSL support.
 *
 * Note that the definition includes a final comma, and therefore a comma 
 * must not be supplied when using the definition.  This is done so that 
 * compilation succeeds whether or not HAVE_OPENSSL is defined. */
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

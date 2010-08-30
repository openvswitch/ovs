/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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
#ifndef STREAM_SSL_H
#define STREAM_SSL_H 1

#include <stdbool.h>

#ifdef HAVE_OPENSSL
bool stream_ssl_is_configured(void);

void stream_ssl_set_private_key_file(const char *file_name);
void stream_ssl_set_certificate_file(const char *file_name);
void stream_ssl_set_ca_cert_file(const char *file_name, bool bootstrap);

void stream_ssl_set_key_and_cert(const char *private_key_file,
                                 const char *certificate_file);


void stream_ssl_set_peer_ca_cert_file(const char *file_name);

/* Define the long options for SSL support.
 *
 * Note that the definition includes a final comma, and therefore a comma
 * must not be supplied when using the definition.  This is done so that
 * compilation succeeds whether or not HAVE_OPENSSL is defined. */
#define STREAM_SSL_LONG_OPTIONS                      \
        {"private-key", required_argument, 0, 'p'}, \
        {"certificate", required_argument, 0, 'c'}, \
        {"ca-cert",     required_argument, 0, 'C'},

#define STREAM_SSL_OPTION_HANDLERS                      \
        case 'p':                                       \
            stream_ssl_set_private_key_file(optarg);    \
            break;                                      \
                                                        \
        case 'c':                                       \
            stream_ssl_set_certificate_file(optarg);    \
            break;                                      \
                                                        \
        case 'C':                                       \
            stream_ssl_set_ca_cert_file(optarg, false); \
            break;
#else /* !HAVE_OPENSSL */
static inline bool stream_ssl_is_configured(void)
{
    return false;
}
#define STREAM_SSL_LONG_OPTIONS
#define STREAM_SSL_OPTION_HANDLERS
#endif /* !HAVE_OPENSSL */

#endif /* stream-ssl.h */

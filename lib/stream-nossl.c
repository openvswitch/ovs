/*
 * Copyright (c) 2011 Nicira, Inc.
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

#include <config.h>
#include "stream-ssl.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(stream_nossl);

/* Dummy function definitions, used when OVS is built without OpenSSL. */

bool
stream_ssl_is_configured(void)
{
    return false;
}

static void NO_RETURN
nossl_option(const char *detail)
{
    VLOG_FATAL("%s specified but Open vSwitch was built without SSL support",
               detail);
}

void
stream_ssl_set_private_key_file(const char *file_name)
{
    if (file_name != NULL) {
        nossl_option("Private key");
    }
}

void
stream_ssl_set_certificate_file(const char *file_name)
{
    if (file_name != NULL) {
        nossl_option("Certificate");
    }
}

void
stream_ssl_set_ca_cert_file(const char *file_name, bool bootstrap OVS_UNUSED)
{
    if (file_name != NULL) {
        nossl_option("CA certificate");
    }
}

void
stream_ssl_set_peer_ca_cert_file(const char *file_name)
{
    if (file_name != NULL) {
        nossl_option("Peer CA certificate");
    }
}

void
stream_ssl_set_key_and_cert(const char *private_key_file,
                            const char *certificate_file)
{
    stream_ssl_set_private_key_file(private_key_file);
    stream_ssl_set_certificate_file(certificate_file);
}

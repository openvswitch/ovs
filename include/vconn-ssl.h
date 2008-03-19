#ifndef VCONN_SSL_H
#define VCONN_SSL_H 1

#ifdef HAVE_OPENSSL
void vconn_ssl_set_private_key_file(const char *file_name);
void vconn_ssl_set_certificate_file(const char *file_name);
void vconn_ssl_set_ca_cert_file(const char *file_name);
#endif

#endif /* vconn-ssl.h */

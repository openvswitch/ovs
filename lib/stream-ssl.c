/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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
#include "dhparams.h"
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "coverage.h"
#include "openvswitch/dynamic-string.h"
#include "entropy.h"
#include "openvswitch/ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/shash.h"
#include "socket-util.h"
#include "util.h"
#include "stream-provider.h"
#include "stream.h"
#include "timeval.h"
#include "openvswitch/vlog.h"

#ifdef _WIN32
/* Ref: https://www.openssl.org/support/faq.html#PROG2
 * Your application must link against the same version of the Win32 C-Runtime
 * against which your openssl libraries were linked.  The default version for
 * OpenSSL is /MD - "Multithreaded DLL". If we compile Open vSwitch with
 * something other than /MD, instead of re-compiling OpenSSL
 * toolkit, openssl/applink.c can be #included. Also, it is important
 * to add CRYPTO_malloc_init prior first call to OpenSSL.
 *
 * XXX: The behavior of the following #include when Open vSwitch is
 * compiled with /MD is not tested. */
#include <openssl/applink.c>
#define SHUT_RDWR SD_BOTH
#endif

VLOG_DEFINE_THIS_MODULE(stream_ssl);

/* Active SSL. */

enum ssl_state {
    STATE_TCP_CONNECTING,
    STATE_SSL_CONNECTING
};

enum session_type {
    CLIENT,
    SERVER
};

struct ssl_stream
{
    struct stream stream;
    enum ssl_state state;
    enum session_type type;
    int fd;
    SSL *ssl;
    struct ofpbuf *txbuf;
    unsigned int session_nr;

    /* rx_want and tx_want record the result of the last call to SSL_read()
     * and SSL_write(), respectively:
     *
     *    - If the call reported that data needed to be read from the file
     *      descriptor, the corresponding member is set to SSL_READING.
     *
     *    - If the call reported that data needed to be written to the file
     *      descriptor, the corresponding member is set to SSL_WRITING.
     *
     *    - Otherwise, the member is set to SSL_NOTHING, indicating that the
     *      call completed successfully (or with an error) and that there is no
     *      need to block.
     *
     * These are needed because there is no way to ask OpenSSL what a data read
     * or write would require without giving it a buffer to receive into or
     * data to send, respectively.  (Note that the SSL_want() status is
     * overwritten by each SSL_read() or SSL_write() call, so we can't rely on
     * its value.)
     *
     * A single call to SSL_read() or SSL_write() can perform both reading
     * and writing and thus invalidate not one of these values but actually
     * both.  Consider this situation, for example:
     *
     *    - SSL_write() blocks on a read, so tx_want gets SSL_READING.
     *
     *    - SSL_read() laters succeeds reading from 'fd' and clears out the
     *      whole receive buffer, so rx_want gets SSL_READING.
     *
     *    - Client calls stream_wait(STREAM_RECV) and stream_wait(STREAM_SEND)
     *      and blocks.
     *
     *    - Now we're stuck blocking until the peer sends us data, even though
     *      SSL_write() could now succeed, which could easily be a deadlock
     *      condition.
     *
     * On the other hand, we can't reset both tx_want and rx_want on every call
     * to SSL_read() or SSL_write(), because that would produce livelock,
     * e.g. in this situation:
     *
     *    - SSL_write() blocks, so tx_want gets SSL_READING or SSL_WRITING.
     *
     *    - SSL_read() blocks, so rx_want gets SSL_READING or SSL_WRITING,
     *      but tx_want gets reset to SSL_NOTHING.
     *
     *    - Client calls stream_wait(STREAM_RECV) and stream_wait(STREAM_SEND)
     *      and blocks.
     *
     *    - Client wakes up immediately since SSL_NOTHING in tx_want indicates
     *      that no blocking is necessary.
     *
     * The solution we adopt here is to set tx_want to SSL_NOTHING after
     * calling SSL_read() only if the SSL state of the connection changed,
     * which indicates that an SSL-level renegotiation made some progress, and
     * similarly for rx_want and SSL_write().  This prevents both the
     * deadlock and livelock situations above.
     */
    int rx_want, tx_want;

    /* A few bytes of header data in case SSL negotiation fails. */
    uint8_t head[2];
    short int n_head;
};

/* SSL context created by ssl_init(). */
static SSL_CTX *ctx;

struct ssl_config_file {
    bool read;                  /* Whether the file was successfully read. */
    char *file_name;            /* Configured file name, if any. */
    struct timespec mtime;      /* File mtime as of last time we read it. */
};

/* SSL configuration files. */
static struct ssl_config_file private_key;
static struct ssl_config_file certificate;
static struct ssl_config_file ca_cert;
static char *ssl_protocols = "TLSv1,TLSv1.1,TLSv1.2";
static char *ssl_ciphers = "HIGH:!aNULL:!MD5";

/* Ordinarily, the SSL client and server verify each other's certificates using
 * a CA certificate.  Setting this to false disables this behavior.  (This is a
 * security risk.) */
static bool verify_peer_cert = true;

/* Ordinarily, we require a CA certificate for the peer to be locally
 * available.  We can, however, bootstrap the CA certificate from the peer at
 * the beginning of our first connection then use that certificate on all
 * subsequent connections, saving it to a file for use in future runs also.  In
 * this case, 'bootstrap_ca_cert' is true. */
static bool bootstrap_ca_cert;

/* Session number.  Used in debug logging messages to uniquely identify a
 * session. */
static unsigned int next_session_nr;

/* Who knows what can trigger various SSL errors, so let's throttle them down
 * quite a bit. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 25);

static int ssl_init(void);
static int do_ssl_init(void);
static bool ssl_wants_io(int ssl_error);
static void ssl_close(struct stream *);
static void ssl_clear_txbuf(struct ssl_stream *);
static void interpret_queued_ssl_error(const char *function);
static int interpret_ssl_error(const char *function, int ret, int error,
                               int *want);
static DH *tmp_dh_callback(SSL *ssl, int is_export OVS_UNUSED, int keylength);
static void log_ca_cert(const char *file_name, X509 *cert);
static void stream_ssl_set_ca_cert_file__(const char *file_name,
                                          bool bootstrap, bool force);
static void ssl_protocol_cb(int write_p, int version, int content_type,
                            const void *, size_t, SSL *, void *sslv_);
static bool update_ssl_config(struct ssl_config_file *, const char *file_name);
static int sock_errno(void);

static short int
want_to_poll_events(int want)
{
    switch (want) {
    case SSL_NOTHING:
        OVS_NOT_REACHED();

    case SSL_READING:
        return POLLIN;

    case SSL_WRITING:
        return POLLOUT;

    default:
        OVS_NOT_REACHED();
    }
}

/* Takes ownership of 'name'. */
static int
new_ssl_stream(char *name, int fd, enum session_type type,
               enum ssl_state state, struct stream **streamp)
{
    struct ssl_stream *sslv;
    SSL *ssl = NULL;
    int retval;

    /* Check for all the needful configuration. */
    retval = 0;
    if (!private_key.read) {
        VLOG_ERR("Private key must be configured to use SSL");
        retval = ENOPROTOOPT;
    }
    if (!certificate.read) {
        VLOG_ERR("Certificate must be configured to use SSL");
        retval = ENOPROTOOPT;
    }
    if (!ca_cert.read && verify_peer_cert && !bootstrap_ca_cert) {
        VLOG_ERR("CA certificate must be configured to use SSL");
        retval = ENOPROTOOPT;
    }
    if (!retval && !SSL_CTX_check_private_key(ctx)) {
        VLOG_ERR("Private key does not match certificate public key: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        retval = ENOPROTOOPT;
    }
    if (retval) {
        goto error;
    }

    /* Disable Nagle.
     * On windows platforms, this can only be called upon TCP connected.
     */
    if (state == STATE_SSL_CONNECTING) {
        setsockopt_tcp_nodelay(fd);
    }

    /* Create and configure OpenSSL stream. */
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        VLOG_ERR("SSL_new: %s", ERR_error_string(ERR_get_error(), NULL));
        retval = ENOPROTOOPT;
        goto error;
    }
    if (SSL_set_fd(ssl, fd) == 0) {
        VLOG_ERR("SSL_set_fd: %s", ERR_error_string(ERR_get_error(), NULL));
        retval = ENOPROTOOPT;
        goto error;
    }
    if (!verify_peer_cert || (bootstrap_ca_cert && type == CLIENT)) {
        SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
    }

    /* Create and return the ssl_stream. */
    sslv = xmalloc(sizeof *sslv);
    stream_init(&sslv->stream, &ssl_stream_class, EAGAIN, name);
    sslv->state = state;
    sslv->type = type;
    sslv->fd = fd;
    sslv->ssl = ssl;
    sslv->txbuf = NULL;
    sslv->rx_want = sslv->tx_want = SSL_NOTHING;
    sslv->session_nr = next_session_nr++;
    sslv->n_head = 0;

    if (VLOG_IS_DBG_ENABLED()) {
        SSL_set_msg_callback(ssl, ssl_protocol_cb);
        SSL_set_msg_callback_arg(ssl, sslv);
    }

    *streamp = &sslv->stream;
    return 0;

error:
    if (ssl) {
        SSL_free(ssl);
    }
    closesocket(fd);
    free(name);
    return retval;
}

static struct ssl_stream *
ssl_stream_cast(struct stream *stream)
{
    stream_assert_class(stream, &ssl_stream_class);
    return CONTAINER_OF(stream, struct ssl_stream, stream);
}

static int
ssl_open(const char *name, char *suffix, struct stream **streamp, uint8_t dscp)
{
    int error, fd;

    error = ssl_init();
    if (error) {
        return error;
    }

    error = inet_open_active(SOCK_STREAM, suffix, OFP_PORT, NULL, &fd,
                             dscp);
    if (fd >= 0) {
        int state = error ? STATE_TCP_CONNECTING : STATE_SSL_CONNECTING;
        return new_ssl_stream(xstrdup(name), fd, CLIENT, state, streamp);
    } else {
        VLOG_ERR("%s: connect: %s", name, ovs_strerror(error));
        return error;
    }
}

static int
do_ca_cert_bootstrap(struct stream *stream)
{
    struct ssl_stream *sslv = ssl_stream_cast(stream);
    STACK_OF(X509) *chain;
    X509 *cert;
    FILE *file;
    int error;
    int fd;

    chain = SSL_get_peer_cert_chain(sslv->ssl);
    if (!chain || !sk_X509_num(chain)) {
        VLOG_ERR("could not bootstrap CA cert: no certificate presented by "
                 "peer");
        return EPROTO;
    }
    cert = sk_X509_value(chain, sk_X509_num(chain) - 1);

    /* Check that 'cert' is self-signed.  Otherwise it is not a CA
     * certificate and we should not attempt to use it as one. */
    error = X509_check_issued(cert, cert);
    if (error) {
        VLOG_ERR("could not bootstrap CA cert: obtained certificate is "
                 "not self-signed (%s)",
                 X509_verify_cert_error_string(error));
        if (sk_X509_num(chain) < 2) {
            VLOG_ERR("only one certificate was received, so probably the peer "
                     "is not configured to send its CA certificate");
        }
        return EPROTO;
    }

    fd = open(ca_cert.file_name, O_CREAT | O_EXCL | O_WRONLY, 0444);
    if (fd < 0) {
        if (errno == EEXIST) {
            VLOG_INFO_RL(&rl, "reading CA cert %s created by another process",
                         ca_cert.file_name);
            stream_ssl_set_ca_cert_file__(ca_cert.file_name, true, true);
            return EPROTO;
        } else {
            VLOG_ERR("could not bootstrap CA cert: creating %s failed: %s",
                     ca_cert.file_name, ovs_strerror(errno));
            return errno;
        }
    }

    file = fdopen(fd, "w");
    if (!file) {
        error = errno;
        VLOG_ERR("could not bootstrap CA cert: fdopen failed: %s",
                 ovs_strerror(error));
        unlink(ca_cert.file_name);
        return error;
    }

    if (!PEM_write_X509(file, cert)) {
        VLOG_ERR("could not bootstrap CA cert: PEM_write_X509 to %s failed: "
                 "%s", ca_cert.file_name,
                 ERR_error_string(ERR_get_error(), NULL));
        fclose(file);
        unlink(ca_cert.file_name);
        return EIO;
    }

    if (fclose(file)) {
        error = errno;
        VLOG_ERR("could not bootstrap CA cert: writing %s failed: %s",
                 ca_cert.file_name, ovs_strerror(error));
        unlink(ca_cert.file_name);
        return error;
    }

    VLOG_INFO("successfully bootstrapped CA cert to %s", ca_cert.file_name);
    log_ca_cert(ca_cert.file_name, cert);
    bootstrap_ca_cert = false;
    ca_cert.read = true;

    /* SSL_CTX_add_client_CA makes a copy of cert's relevant data. */
    SSL_CTX_add_client_CA(ctx, cert);

    SSL_CTX_set_cert_store(ctx, X509_STORE_new());
    if (SSL_CTX_load_verify_locations(ctx, ca_cert.file_name, NULL) != 1) {
        VLOG_ERR("SSL_CTX_load_verify_locations: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        return EPROTO;
    }
    VLOG_INFO("killing successful connection to retry using CA cert");
    return EPROTO;
}

static char *
get_peer_common_name(const struct ssl_stream *sslv)
{
    X509 *peer_cert = SSL_get_peer_certificate(sslv->ssl);
    if (!peer_cert) {
        return NULL;
    }

    int cn_index = X509_NAME_get_index_by_NID(X509_get_subject_name(peer_cert),
                                              NID_commonName, -1);
    if (cn_index < 0) {
        return NULL;
    }

    X509_NAME_ENTRY *cn_entry = X509_NAME_get_entry(
        X509_get_subject_name(peer_cert), cn_index);
    if (!cn_entry) {
        return NULL;
    }

    ASN1_STRING *cn_data = X509_NAME_ENTRY_get_data(cn_entry);
    if (!cn_data) {
        return NULL;
    }

    const char *cn;
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined (LIBRESSL_VERSION_NUMBER)
    /* ASN1_STRING_data() is deprecated as of OpenSSL version 1.1 */
    cn = (const char *)ASN1_STRING_data(cn_data);
#else
    cn = (const char *)ASN1_STRING_get0_data(cn_data);
 #endif
    return xstrdup(cn);
}

static int
ssl_connect(struct stream *stream)
{
    struct ssl_stream *sslv = ssl_stream_cast(stream);
    int retval;

    switch (sslv->state) {
    case STATE_TCP_CONNECTING:
        retval = check_connection_completion(sslv->fd);
        if (retval) {
            return retval;
        }
        sslv->state = STATE_SSL_CONNECTING;
        setsockopt_tcp_nodelay(sslv->fd);
        /* Fall through. */

    case STATE_SSL_CONNECTING:
        /* Capture the first few bytes of received data so that we can guess
         * what kind of funny data we've been sent if SSL negotiation fails. */
        if (sslv->n_head <= 0) {
            sslv->n_head = recv(sslv->fd, sslv->head, sizeof sslv->head,
                                MSG_PEEK);
        }

        retval = (sslv->type == CLIENT
                   ? SSL_connect(sslv->ssl) : SSL_accept(sslv->ssl));
        if (retval != 1) {
            int error = SSL_get_error(sslv->ssl, retval);
            if (retval < 0 && ssl_wants_io(error)) {
                return EAGAIN;
            } else {
                int unused;

                interpret_ssl_error((sslv->type == CLIENT ? "SSL_connect"
                                     : "SSL_accept"), retval, error, &unused);
                shutdown(sslv->fd, SHUT_RDWR);
                stream_report_content(sslv->head, sslv->n_head, STREAM_SSL,
                                      &this_module, stream_get_name(stream));
                return EPROTO;
            }
        } else if (bootstrap_ca_cert) {
            return do_ca_cert_bootstrap(stream);
        } else if (verify_peer_cert
                   && ((SSL_get_verify_mode(sslv->ssl)
                       & (SSL_VERIFY_NONE | SSL_VERIFY_PEER))
                       != SSL_VERIFY_PEER)) {
            /* Two or more SSL connections completed at the same time while we
             * were in bootstrap mode.  Only one of these can finish the
             * bootstrap successfully.  The other one(s) must be rejected
             * because they were not verified against the bootstrapped CA
             * certificate.  (Alternatively we could verify them against the CA
             * certificate, but that's more trouble than it's worth.  These
             * connections will succeed the next time they retry, assuming that
             * they have a certificate against the correct CA.) */
            VLOG_INFO("rejecting SSL connection during bootstrap race window");
            return EPROTO;
        } else {
            char *cn = get_peer_common_name(sslv);

            if (cn) {
                stream_set_peer_id(stream, cn);
                free(cn);
            }
            return 0;
        }
    }

    OVS_NOT_REACHED();
}

static void
ssl_close(struct stream *stream)
{
    struct ssl_stream *sslv = ssl_stream_cast(stream);
    ssl_clear_txbuf(sslv);

    /* Attempt clean shutdown of the SSL connection.  This will work most of
     * the time, as long as the kernel send buffer has some free space and the
     * SSL connection isn't renegotiating, etc.  That has to be good enough,
     * since we don't have any way to continue the close operation in the
     * background. */
    SSL_shutdown(sslv->ssl);

    /* SSL_shutdown() might have signaled an error, in which case we need to
     * flush it out of the OpenSSL error queue or the next OpenSSL operation
     * will falsely signal an error. */
    ERR_clear_error();

    SSL_free(sslv->ssl);
    closesocket(sslv->fd);
    free(sslv);
}

static void
interpret_queued_ssl_error(const char *function)
{
    int queued_error = ERR_get_error();
    if (queued_error != 0) {
        VLOG_WARN_RL(&rl, "%s: %s",
                     function, ERR_error_string(queued_error, NULL));
    } else {
        VLOG_ERR_RL(&rl, "%s: SSL_ERROR_SSL without queued error", function);
    }
}

static int
interpret_ssl_error(const char *function, int ret, int error,
                    int *want)
{
    *want = SSL_NOTHING;

    switch (error) {
    case SSL_ERROR_NONE:
        VLOG_ERR_RL(&rl, "%s: unexpected SSL_ERROR_NONE", function);
        break;

    case SSL_ERROR_ZERO_RETURN:
        VLOG_ERR_RL(&rl, "%s: unexpected SSL_ERROR_ZERO_RETURN", function);
        break;

    case SSL_ERROR_WANT_READ:
        *want = SSL_READING;
        return EAGAIN;

    case SSL_ERROR_WANT_WRITE:
        *want = SSL_WRITING;
        return EAGAIN;

    case SSL_ERROR_WANT_CONNECT:
        VLOG_ERR_RL(&rl, "%s: unexpected SSL_ERROR_WANT_CONNECT", function);
        break;

    case SSL_ERROR_WANT_ACCEPT:
        VLOG_ERR_RL(&rl, "%s: unexpected SSL_ERROR_WANT_ACCEPT", function);
        break;

    case SSL_ERROR_WANT_X509_LOOKUP:
        VLOG_ERR_RL(&rl, "%s: unexpected SSL_ERROR_WANT_X509_LOOKUP",
                    function);
        break;

    case SSL_ERROR_SYSCALL: {
        int queued_error = ERR_get_error();
        if (queued_error == 0) {
            if (ret < 0) {
                int status = errno;
                VLOG_WARN_RL(&rl, "%s: system error (%s)",
                             function, ovs_strerror(status));
                return status;
            } else {
                VLOG_WARN_RL(&rl, "%s: unexpected SSL connection close",
                             function);
                return EPROTO;
            }
        } else {
            VLOG_WARN_RL(&rl, "%s: %s",
                         function, ERR_error_string(queued_error, NULL));
            break;
        }
    }

    case SSL_ERROR_SSL:
        interpret_queued_ssl_error(function);
        break;

    default:
        VLOG_ERR_RL(&rl, "%s: bad SSL error code %d", function, error);
        break;
    }
    return EIO;
}

static ssize_t
ssl_recv(struct stream *stream, void *buffer, size_t n)
{
    struct ssl_stream *sslv = ssl_stream_cast(stream);
    int old_state;
    ssize_t ret;

    /* Behavior of zero-byte SSL_read is poorly defined. */
    ovs_assert(n > 0);

    old_state = SSL_get_state(sslv->ssl);
    ret = SSL_read(sslv->ssl, buffer, n);
    if (old_state != SSL_get_state(sslv->ssl)) {
        sslv->tx_want = SSL_NOTHING;
    }
    sslv->rx_want = SSL_NOTHING;

    if (ret > 0) {
        return ret;
    } else {
        int error = SSL_get_error(sslv->ssl, ret);
        if (error == SSL_ERROR_ZERO_RETURN) {
            return 0;
        } else {
            return -interpret_ssl_error("SSL_read", ret, error,
                                        &sslv->rx_want);
        }
    }
}

static void
ssl_clear_txbuf(struct ssl_stream *sslv)
{
    ofpbuf_delete(sslv->txbuf);
    sslv->txbuf = NULL;
}

static int
ssl_do_tx(struct stream *stream)
{
    struct ssl_stream *sslv = ssl_stream_cast(stream);

    for (;;) {
        int old_state = SSL_get_state(sslv->ssl);
        int ret = SSL_write(sslv->ssl, sslv->txbuf->data, sslv->txbuf->size);
        if (old_state != SSL_get_state(sslv->ssl)) {
            sslv->rx_want = SSL_NOTHING;
        }
        sslv->tx_want = SSL_NOTHING;
        if (ret > 0) {
            ofpbuf_pull(sslv->txbuf, ret);
            if (sslv->txbuf->size == 0) {
                return 0;
            }
        } else {
            int ssl_error = SSL_get_error(sslv->ssl, ret);
            if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                VLOG_WARN_RL(&rl, "SSL_write: connection closed");
                return EPIPE;
            } else {
                return interpret_ssl_error("SSL_write", ret, ssl_error,
                                           &sslv->tx_want);
            }
        }
    }
}

static ssize_t
ssl_send(struct stream *stream, const void *buffer, size_t n)
{
    struct ssl_stream *sslv = ssl_stream_cast(stream);

    if (sslv->txbuf) {
        return -EAGAIN;
    } else {
        int error;

        sslv->txbuf = ofpbuf_clone_data(buffer, n);
        error = ssl_do_tx(stream);
        switch (error) {
        case 0:
            ssl_clear_txbuf(sslv);
            return n;
        case EAGAIN:
            return n;
        default:
            ssl_clear_txbuf(sslv);
            return -error;
        }
    }
}

static void
ssl_run(struct stream *stream)
{
    struct ssl_stream *sslv = ssl_stream_cast(stream);

    if (sslv->txbuf && ssl_do_tx(stream) != EAGAIN) {
        ssl_clear_txbuf(sslv);
    }
}

static void
ssl_run_wait(struct stream *stream)
{
    struct ssl_stream *sslv = ssl_stream_cast(stream);

    if (sslv->tx_want != SSL_NOTHING) {
        poll_fd_wait(sslv->fd, want_to_poll_events(sslv->tx_want));
    }
}

static void
ssl_wait(struct stream *stream, enum stream_wait_type wait)
{
    struct ssl_stream *sslv = ssl_stream_cast(stream);

    switch (wait) {
    case STREAM_CONNECT:
        if (stream_connect(stream) != EAGAIN) {
            poll_immediate_wake();
        } else {
            switch (sslv->state) {
            case STATE_TCP_CONNECTING:
                poll_fd_wait(sslv->fd, POLLOUT);
                break;

            case STATE_SSL_CONNECTING:
                /* ssl_connect() called SSL_accept() or SSL_connect(), which
                 * set up the status that we test here. */
                poll_fd_wait(sslv->fd,
                               want_to_poll_events(SSL_want(sslv->ssl)));
                break;

            default:
                OVS_NOT_REACHED();
            }
        }
        break;

    case STREAM_RECV:
        if (sslv->rx_want != SSL_NOTHING) {
            poll_fd_wait(sslv->fd, want_to_poll_events(sslv->rx_want));
        } else {
            poll_immediate_wake();
        }
        break;

    case STREAM_SEND:
        if (!sslv->txbuf) {
            /* We have room in our tx queue. */
            poll_immediate_wake();
        } else {
            /* stream_run_wait() will do the right thing; don't bother with
             * redundancy. */
        }
        break;

    default:
        OVS_NOT_REACHED();
    }
}

const struct stream_class ssl_stream_class = {
    "ssl",                      /* name */
    true,                       /* needs_probes */
    ssl_open,                   /* open */
    ssl_close,                  /* close */
    ssl_connect,                /* connect */
    ssl_recv,                   /* recv */
    ssl_send,                   /* send */
    ssl_run,                    /* run */
    ssl_run_wait,               /* run_wait */
    ssl_wait,                   /* wait */
};

/* Passive SSL. */

struct pssl_pstream
{
    struct pstream pstream;
    int fd;
};

const struct pstream_class pssl_pstream_class;

static struct pssl_pstream *
pssl_pstream_cast(struct pstream *pstream)
{
    pstream_assert_class(pstream, &pssl_pstream_class);
    return CONTAINER_OF(pstream, struct pssl_pstream, pstream);
}

static int
pssl_open(const char *name OVS_UNUSED, char *suffix, struct pstream **pstreamp,
          uint8_t dscp)
{
    struct sockaddr_storage ss;
    struct pssl_pstream *pssl;
    uint16_t port;
    int retval;
    int fd;

    retval = ssl_init();
    if (retval) {
        return retval;
    }

    fd = inet_open_passive(SOCK_STREAM, suffix, OFP_PORT, &ss, dscp, true);
    if (fd < 0) {
        return -fd;
    }

    port = ss_get_port(&ss);

    struct ds bound_name = DS_EMPTY_INITIALIZER;
    ds_put_format(&bound_name, "pssl:%"PRIu16":", port);
    ss_format_address(&ss, &bound_name);

    pssl = xmalloc(sizeof *pssl);
    pstream_init(&pssl->pstream, &pssl_pstream_class,
                 ds_steal_cstr(&bound_name));
    pstream_set_bound_port(&pssl->pstream, htons(port));
    pssl->fd = fd;
    *pstreamp = &pssl->pstream;

    return 0;
}

static void
pssl_close(struct pstream *pstream)
{
    struct pssl_pstream *pssl = pssl_pstream_cast(pstream);
    closesocket(pssl->fd);
    free(pssl);
}

static int
pssl_accept(struct pstream *pstream, struct stream **new_streamp)
{
    struct pssl_pstream *pssl = pssl_pstream_cast(pstream);
    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof ss;
    int new_fd;
    int error;

    new_fd = accept(pssl->fd, (struct sockaddr *) &ss, &ss_len);
    if (new_fd < 0) {
        error = sock_errno();
#ifdef _WIN32
        if (error == WSAEWOULDBLOCK) {
            error = EAGAIN;
        }
#endif
        if (error != EAGAIN) {
            VLOG_DBG_RL(&rl, "accept: %s", sock_strerror(error));
        }
        return error;
    }

    error = set_nonblocking(new_fd);
    if (error) {
        closesocket(new_fd);
        return error;
    }

    struct ds name = DS_EMPTY_INITIALIZER;
    ds_put_cstr(&name, "ssl:");
    ss_format_address(&ss, &name);
    ds_put_format(&name, ":%"PRIu16, ss_get_port(&ss));
    return new_ssl_stream(ds_steal_cstr(&name), new_fd, SERVER,
                          STATE_SSL_CONNECTING, new_streamp);
}

static void
pssl_wait(struct pstream *pstream)
{
    struct pssl_pstream *pssl = pssl_pstream_cast(pstream);
    poll_fd_wait(pssl->fd, POLLIN);
}

const struct pstream_class pssl_pstream_class = {
    "pssl",
    true,
    pssl_open,
    pssl_close,
    pssl_accept,
    pssl_wait,
};

/*
 * Returns true if OpenSSL error is WANT_READ or WANT_WRITE, indicating that
 * OpenSSL is requesting that we call it back when the socket is ready for read
 * or writing, respectively.
 */
static bool
ssl_wants_io(int ssl_error)
{
    return (ssl_error == SSL_ERROR_WANT_WRITE
            || ssl_error == SSL_ERROR_WANT_READ);
}

static int
ssl_init(void)
{
    static int init_status = -1;
    if (init_status < 0) {
        init_status = do_ssl_init();
        ovs_assert(init_status >= 0);
    }
    return init_status;
}

static int
do_ssl_init(void)
{
    SSL_METHOD *method;

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined (LIBRESSL_VERSION_NUMBER)
#ifdef _WIN32
    /* The following call is needed if we "#include <openssl/applink.c>". */
    CRYPTO_malloc_init();
#endif
    SSL_library_init();
    SSL_load_error_strings();
#endif

    if (!RAND_status()) {
        /* We occasionally see OpenSSL fail to seed its random number generator
         * in heavily loaded hypervisors.  I suspect the following scenario:
         *
         * 1. OpenSSL calls read() to get 32 bytes from /dev/urandom.
         * 2. The kernel generates 10 bytes of randomness and copies it out.
         * 3. A signal arrives (perhaps SIGALRM).
         * 4. The kernel interrupts the system call to service the signal.
         * 5. Userspace gets 10 bytes of entropy.
         * 6. OpenSSL doesn't read again to get the final 22 bytes.  Therefore
         *    OpenSSL doesn't have enough entropy to consider itself
         *    initialized.
         *
         * The only part I'm not entirely sure about is #6, because the OpenSSL
         * code is so hard to read. */
        uint8_t seed[32];
        int retval;

        VLOG_WARN("OpenSSL random seeding failed, reseeding ourselves");

        retval = get_entropy(seed, sizeof seed);
        if (retval) {
            VLOG_ERR("failed to obtain entropy (%s)",
                     ovs_retval_to_string(retval));
            return retval > 0 ? retval : ENOPROTOOPT;
        }

        RAND_seed(seed, sizeof seed);
    }

    /* OpenSSL has a bunch of "connection methods": SSLv2_method(),
     * SSLv3_method(), TLSv1_method(), SSLv23_method(), ...  Most of these
     * support exactly one version of SSL, e.g. TLSv1_method() supports TLSv1
     * only, not any earlier *or later* version.  The only exception is
     * SSLv23_method(), which in fact supports *any* version of SSL and TLS.
     * We don't want SSLv2 or SSLv3 support, so we turn it off below with
     * SSL_CTX_set_options().
     *
     * The cast is needed to avoid a warning with newer versions of OpenSSL in
     * which SSLv23_method() returns a "const" pointer. */
    method = CONST_CAST(SSL_METHOD *, SSLv23_method());
    if (method == NULL) {
        VLOG_ERR("TLSv1_method: %s", ERR_error_string(ERR_get_error(), NULL));
        return ENOPROTOOPT;
    }

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        VLOG_ERR("SSL_CTX_new: %s", ERR_error_string(ERR_get_error(), NULL));
        return ENOPROTOOPT;
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_tmp_dh_callback(ctx, tmp_dh_callback);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       NULL);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5");

    return 0;
}

static DH *
tmp_dh_callback(SSL *ssl OVS_UNUSED, int is_export OVS_UNUSED, int keylength)
{
    struct dh {
        int keylength;
        DH *dh;
        DH *(*constructor)(void);
    };

    static struct dh dh_table[] = {
        {1024, NULL, get_dh1024},
        {2048, NULL, get_dh2048},
        {4096, NULL, get_dh4096},
    };

    struct dh *dh;

    for (dh = dh_table; dh < &dh_table[ARRAY_SIZE(dh_table)]; dh++) {
        if (dh->keylength == keylength) {
            if (!dh->dh) {
                dh->dh = dh->constructor();
                if (!dh->dh) {
                    out_of_memory();
                }
            }
            return dh->dh;
        }
    }
    VLOG_ERR_RL(&rl, "no Diffie-Hellman parameters for key length %d",
                keylength);
    return NULL;
}

/* Returns true if SSL is at least partially configured. */
bool
stream_ssl_is_configured(void)
{
    return private_key.file_name || certificate.file_name || ca_cert.file_name;
}

static bool
update_ssl_config(struct ssl_config_file *config, const char *file_name)
{
    struct timespec mtime;
    int error;

    if (ssl_init() || !file_name) {
        return false;
    }

    /* If the file name hasn't changed and neither has the file contents, stop
     * here. */
    error = get_mtime(file_name, &mtime);
    if (error && error != ENOENT) {
        VLOG_ERR_RL(&rl, "%s: stat failed (%s)",
                    file_name, ovs_strerror(error));
    }
    if (config->file_name
        && !strcmp(config->file_name, file_name)
        && mtime.tv_sec == config->mtime.tv_sec
        && mtime.tv_nsec == config->mtime.tv_nsec) {
        return false;
    }

    /* Update 'config'. */
    config->mtime = mtime;
    if (file_name != config->file_name) {
        free(config->file_name);
        config->file_name = xstrdup(file_name);
    }
    return true;
}

static void
stream_ssl_set_private_key_file__(const char *file_name)
{
    if (SSL_CTX_use_PrivateKey_file(ctx, file_name, SSL_FILETYPE_PEM) == 1) {
        private_key.read = true;
    } else {
        VLOG_ERR("SSL_use_PrivateKey_file: %s",
                 ERR_error_string(ERR_get_error(), NULL));
    }
}

void
stream_ssl_set_private_key_file(const char *file_name)
{
    if (update_ssl_config(&private_key, file_name)) {
        stream_ssl_set_private_key_file__(file_name);
    }
}

static void
stream_ssl_set_certificate_file__(const char *file_name)
{
    if (SSL_CTX_use_certificate_file(ctx, file_name, SSL_FILETYPE_PEM) == 1) {
        certificate.read = true;
    } else {
        VLOG_ERR("SSL_use_certificate_file: %s",
                 ERR_error_string(ERR_get_error(), NULL));
    }
}

void
stream_ssl_set_certificate_file(const char *file_name)
{
    if (update_ssl_config(&certificate, file_name)) {
        stream_ssl_set_certificate_file__(file_name);
    }
}

/* Sets the private key and certificate files in one operation.  Use this
 * interface, instead of calling stream_ssl_set_private_key_file() and
 * stream_ssl_set_certificate_file() individually, in the main loop of a
 * long-running program whose key and certificate might change at runtime.
 *
 * This is important because of OpenSSL's behavior.  If an OpenSSL context
 * already has a certificate, and stream_ssl_set_private_key_file() is called
 * to install a new private key, OpenSSL will report an error because the new
 * private key does not match the old certificate.  The other order, of setting
 * a new certificate, then setting a new private key, does work.
 *
 * If this were the only problem, calling stream_ssl_set_certificate_file()
 * before stream_ssl_set_private_key_file() would fix it.  But, if the private
 * key is changed before the certificate (e.g. someone "scp"s or "mv"s the new
 * private key in place before the certificate), then OpenSSL would reject that
 * change, and then the change of certificate would succeed, but there would be
 * no associated private key (because it had only changed once and therefore
 * there was no point in re-reading it).
 *
 * This function avoids both problems by, whenever either the certificate or
 * the private key file changes, re-reading both of them, in the correct order.
 */
void
stream_ssl_set_key_and_cert(const char *private_key_file,
                            const char *certificate_file)
{
    if (update_ssl_config(&private_key, private_key_file)
        || update_ssl_config(&certificate, certificate_file)) {
        stream_ssl_set_certificate_file__(certificate_file);
        stream_ssl_set_private_key_file__(private_key_file);
    }
}

/* Sets SSL ciphers based on string input. Aborts with an error message
 * if 'arg' is invalid. */
void
stream_ssl_set_ciphers(const char *arg)
{
    if (ssl_init() || !arg || !strcmp(ssl_ciphers, arg)) {
        return;
    }
    if (SSL_CTX_set_cipher_list(ctx,arg) == 0) {
        VLOG_ERR("SSL_CTX_set_cipher_list: %s",
                 ERR_error_string(ERR_get_error(), NULL));
    }
    ssl_ciphers = xstrdup(arg);
}

/* Set SSL protocols based on the string input. Aborts with an error message
 * if 'arg' is invalid. */
void
stream_ssl_set_protocols(const char *arg)
{
    if (ssl_init() || !arg || !strcmp(arg, ssl_protocols)){
        return;
    }

    /* Start with all the flags off and turn them on as requested. */
    long protocol_flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;
    protocol_flags |= SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2;

    char *s = xstrdup(arg);
    char *save_ptr = NULL;
    char *word = strtok_r(s, " ,\t", &save_ptr);
    if (word == NULL) {
        VLOG_ERR("SSL protocol settings invalid");
        goto exit;
    }
    while (word != NULL) {
        long on_flag;
        if (!strcasecmp(word, "TLSv1.2")){
            on_flag = SSL_OP_NO_TLSv1_2;
        } else if (!strcasecmp(word, "TLSv1.1")){
            on_flag = SSL_OP_NO_TLSv1_1;
        } else if (!strcasecmp(word, "TLSv1")){
            on_flag = SSL_OP_NO_TLSv1;
        } else {
            VLOG_ERR("%s: SSL protocol not recognized", word);
            goto exit;
        }
        /* Reverse the no flag and mask it out in the flags
         * to turn on that protocol. */
        protocol_flags &= ~on_flag;
        word = strtok_r(NULL, " ,\t", &save_ptr);
    };

    /* Set the actual options. */
    SSL_CTX_set_options(ctx, protocol_flags);

    ssl_protocols = xstrdup(arg);

exit:
    free(s);
}

/* Reads the X509 certificate or certificates in file 'file_name'.  On success,
 * stores the address of the first element in an array of pointers to
 * certificates in '*certs' and the number of certificates in the array in
 * '*n_certs', and returns 0.  On failure, stores a null pointer in '*certs', 0
 * in '*n_certs', and returns a positive errno value.
 *
 * The caller is responsible for freeing '*certs'. */
static int
read_cert_file(const char *file_name, X509 ***certs, size_t *n_certs)
{
    FILE *file;
    size_t allocated_certs = 0;

    *certs = NULL;
    *n_certs = 0;

    file = fopen(file_name, "r");
    if (!file) {
        VLOG_ERR("failed to open %s for reading: %s",
                 file_name, ovs_strerror(errno));
        return errno;
    }

    for (;;) {
        X509 *cert;
        int c;

        /* Read certificate from file. */
        cert = PEM_read_X509(file, NULL, NULL, NULL);
        if (!cert) {
            size_t i;

            VLOG_ERR("PEM_read_X509 failed reading %s: %s",
                     file_name, ERR_error_string(ERR_get_error(), NULL));
            for (i = 0; i < *n_certs; i++) {
                X509_free((*certs)[i]);
            }
            free(*certs);
            *certs = NULL;
            *n_certs = 0;
            fclose(file);
            return EIO;
        }

        /* Add certificate to array. */
        if (*n_certs >= allocated_certs) {
            *certs = x2nrealloc(*certs, &allocated_certs, sizeof **certs);
        }
        (*certs)[(*n_certs)++] = cert;

        /* Are there additional certificates in the file? */
        do {
            c = getc(file);
        } while (isspace(c));
        if (c == EOF) {
            break;
        }
        ungetc(c, file);
    }
    fclose(file);
    return 0;
}


/* Sets 'file_name' as the name of a file containing one or more X509
 * certificates to send to the peer.  Typical use in OpenFlow is to send the CA
 * certificate to the peer, which enables a switch to pick up the controller's
 * CA certificate on its first connection. */
void
stream_ssl_set_peer_ca_cert_file(const char *file_name)
{
    X509 **certs;
    size_t n_certs;
    size_t i;

    if (ssl_init()) {
        return;
    }

    if (!read_cert_file(file_name, &certs, &n_certs)) {
        for (i = 0; i < n_certs; i++) {
            if (SSL_CTX_add_extra_chain_cert(ctx, certs[i]) != 1) {
                VLOG_ERR("SSL_CTX_add_extra_chain_cert: %s",
                         ERR_error_string(ERR_get_error(), NULL));
            }
        }
        free(certs);
    }
}

/* Logs fingerprint of CA certificate 'cert' obtained from 'file_name'. */
static void
log_ca_cert(const char *file_name, X509 *cert)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int n_bytes;
    struct ds fp;
    char *subject;

    ds_init(&fp);
    if (!X509_digest(cert, EVP_sha1(), digest, &n_bytes)) {
        ds_put_cstr(&fp, "<out of memory>");
    } else {
        unsigned int i;
        for (i = 0; i < n_bytes; i++) {
            if (i) {
                ds_put_char(&fp, ':');
            }
            ds_put_format(&fp, "%02x", digest[i]);
        }
    }
    subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    VLOG_INFO("Trusting CA cert from %s (%s) (fingerprint %s)", file_name,
              subject ? subject : "<out of memory>", ds_cstr(&fp));
    OPENSSL_free(subject);
    ds_destroy(&fp);
}

static void
stream_ssl_set_ca_cert_file__(const char *file_name,
                              bool bootstrap, bool force)
{
    struct stat s;

    if (!update_ssl_config(&ca_cert, file_name) && !force) {
        return;
    }

    if (!strcmp(file_name, "none")) {
        verify_peer_cert = false;
        VLOG_WARN("Peer certificate validation disabled "
                  "(this is a security risk)");
    } else if (bootstrap && stat(file_name, &s) && errno == ENOENT) {
        bootstrap_ca_cert = true;
    } else {
        STACK_OF(X509_NAME) *cert_names = SSL_load_client_CA_file(file_name);
        if (cert_names) {
            /* Set up list of CAs that the server will accept from the
             * client. */
            SSL_CTX_set_client_CA_list(ctx, cert_names);

            /* Set up CAs for OpenSSL to trust in verifying the peer's
             * certificate. */
            SSL_CTX_set_cert_store(ctx, X509_STORE_new());
            if (SSL_CTX_load_verify_locations(ctx, file_name, NULL) != 1) {
                VLOG_ERR("SSL_CTX_load_verify_locations: %s",
                         ERR_error_string(ERR_get_error(), NULL));
                return;
            }
            bootstrap_ca_cert = false;
        } else {
            VLOG_ERR("failed to load client certificates from %s: %s",
                     file_name, ERR_error_string(ERR_get_error(), NULL));
        }
    }
    ca_cert.read = true;
}

/* Sets 'file_name' as the name of the file from which to read the CA
 * certificate used to verify the peer within SSL connections.  If 'bootstrap'
 * is false, the file must exist.  If 'bootstrap' is false, then the file is
 * read if it is exists; if it does not, then it will be created from the CA
 * certificate received from the peer on the first SSL connection. */
void
stream_ssl_set_ca_cert_file(const char *file_name, bool bootstrap)
{
    stream_ssl_set_ca_cert_file__(file_name, bootstrap, false);
}

/* SSL protocol logging. */

static const char *
ssl_alert_level_to_string(uint8_t type)
{
    switch (type) {
    case 1: return "warning";
    case 2: return "fatal";
    default: return "<unknown>";
    }
}

static const char *
ssl_alert_description_to_string(uint8_t type)
{
    switch (type) {
    case 0: return "close_notify";
    case 10: return "unexpected_message";
    case 20: return "bad_record_mac";
    case 21: return "decryption_failed";
    case 22: return "record_overflow";
    case 30: return "decompression_failure";
    case 40: return "handshake_failure";
    case 42: return "bad_certificate";
    case 43: return "unsupported_certificate";
    case 44: return "certificate_revoked";
    case 45: return "certificate_expired";
    case 46: return "certificate_unknown";
    case 47: return "illegal_parameter";
    case 48: return "unknown_ca";
    case 49: return "access_denied";
    case 50: return "decode_error";
    case 51: return "decrypt_error";
    case 60: return "export_restriction";
    case 70: return "protocol_version";
    case 71: return "insufficient_security";
    case 80: return "internal_error";
    case 90: return "user_canceled";
    case 100: return "no_renegotiation";
    default: return "<unknown>";
    }
}

static const char *
ssl_handshake_type_to_string(uint8_t type)
{
    switch (type) {
    case 0: return "hello_request";
    case 1: return "client_hello";
    case 2: return "server_hello";
    case 11: return "certificate";
    case 12: return "server_key_exchange";
    case 13: return "certificate_request";
    case 14: return "server_hello_done";
    case 15: return "certificate_verify";
    case 16: return "client_key_exchange";
    case 20: return "finished";
    default: return "<unknown>";
    }
}

static void
ssl_protocol_cb(int write_p, int version OVS_UNUSED, int content_type,
                const void *buf_, size_t len, SSL *ssl OVS_UNUSED, void *sslv_)
{
    const struct ssl_stream *sslv = sslv_;
    const uint8_t *buf = buf_;
    struct ds details;

    if (!VLOG_IS_DBG_ENABLED()) {
        return;
    }

    ds_init(&details);
    if (content_type == 20) {
        ds_put_cstr(&details, "change_cipher_spec");
    } else if (content_type == 21) {
        ds_put_format(&details, "alert: %s, %s",
                      ssl_alert_level_to_string(buf[0]),
                      ssl_alert_description_to_string(buf[1]));
    } else if (content_type == 22) {
        ds_put_format(&details, "handshake: %s",
                      ssl_handshake_type_to_string(buf[0]));
    } else {
        ds_put_format(&details, "type %d", content_type);
    }

    VLOG_DBG("%s%u%s%s %s (%"PRIuSIZE" bytes)",
             sslv->type == CLIENT ? "client" : "server",
             sslv->session_nr, write_p ? "-->" : "<--",
             stream_get_name(&sslv->stream), ds_cstr(&details), len);

    ds_destroy(&details);
}

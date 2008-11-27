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

#include <config.h>
#include "vconn-ssl.h"
#include "dhparams.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "dynamic-string.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "socket-util.h"
#include "util.h"
#include "vconn-provider.h"
#include "vconn.h"

#include "vlog.h"
#define THIS_MODULE VLM_vconn_ssl

/* Active SSL. */

enum ssl_state {
    STATE_TCP_CONNECTING,
    STATE_SSL_CONNECTING
};

enum session_type {
    CLIENT,
    SERVER
};

struct ssl_vconn
{
    struct vconn vconn;
    enum ssl_state state;
    int connect_error;
    enum session_type type;
    int fd;
    SSL *ssl;
    struct ofpbuf *rxbuf;
    struct ofpbuf *txbuf;
    struct poll_waiter *tx_waiter;

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
     *    - Client calls vconn_wait(WAIT_RECV) and vconn_wait(WAIT_SEND) and
     *      blocks.
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
     *    - Client calls vconn_wait(WAIT_RECV) and vconn_wait(WAIT_SEND) and
     *      blocks.
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
};

/* SSL context created by ssl_init(). */
static SSL_CTX *ctx;

/* Required configuration. */
static bool has_private_key, has_certificate, has_ca_cert;

/* Ordinarily, we require a CA certificate for the peer to be locally
 * available.  'has_ca_cert' is true when this is the case, and neither of the
 * following variables matter.
 *
 * We can, however, bootstrap the CA certificate from the peer at the beginning
 * of our first connection then use that certificate on all subsequent
 * connections, saving it to a file for use in future runs also.  In this case,
 * 'has_ca_cert' is false, 'bootstrap_ca_cert' is true, and 'ca_cert_file'
 * names the file to be saved. */
static bool bootstrap_ca_cert;
static char *ca_cert_file;

/* Who knows what can trigger various SSL errors, so let's throttle them down
 * quite a bit. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 25);

static int ssl_init(void);
static int do_ssl_init(void);
static bool ssl_wants_io(int ssl_error);
static void ssl_close(struct vconn *);
static void ssl_clear_txbuf(struct ssl_vconn *);
static int interpret_ssl_error(const char *function, int ret, int error,
                               int *want);
static void ssl_tx_poll_callback(int fd, short int revents, void *vconn_);
static DH *tmp_dh_callback(SSL *ssl, int is_export UNUSED, int keylength);
static void log_ca_cert(const char *file_name, X509 *cert);

short int
want_to_poll_events(int want)
{
    switch (want) {
    case SSL_NOTHING:
        NOT_REACHED();

    case SSL_READING:
        return POLLIN;

    case SSL_WRITING:
        return POLLOUT;

    default:
        NOT_REACHED();
    }
}

static int
new_ssl_vconn(const char *name, int fd, enum session_type type,
              enum ssl_state state, const struct sockaddr_in *sin,
              struct vconn **vconnp)
{
    struct ssl_vconn *sslv;
    SSL *ssl = NULL;
    int on = 1;
    int retval;

    /* Check for all the needful configuration. */
    if (!has_private_key) {
        VLOG_ERR("Private key must be configured to use SSL");
        goto error;
    }
    if (!has_certificate) {
        VLOG_ERR("Certificate must be configured to use SSL");
        goto error;
    }
    if (!has_ca_cert && !bootstrap_ca_cert) {
        VLOG_ERR("CA certificate must be configured to use SSL");
        goto error;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        VLOG_ERR("Private key does not match certificate public key: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

    /* Disable Nagle. */
    retval = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
    if (retval) {
        VLOG_ERR("%s: setsockopt(TCP_NODELAY): %s", name, strerror(errno));
        close(fd);
        return errno;
    }

    /* Create and configure OpenSSL stream. */
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        VLOG_ERR("SSL_new: %s", ERR_error_string(ERR_get_error(), NULL));
        close(fd);
        return ENOPROTOOPT;
    }
    if (SSL_set_fd(ssl, fd) == 0) {
        VLOG_ERR("SSL_set_fd: %s", ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }
    if (bootstrap_ca_cert && type == CLIENT) {
        SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
    }

    /* Create and return the ssl_vconn. */
    sslv = xmalloc(sizeof *sslv);
    vconn_init(&sslv->vconn, &ssl_vconn_class, EAGAIN, sin->sin_addr.s_addr,
               name);
    sslv->state = state;
    sslv->type = type;
    sslv->fd = fd;
    sslv->ssl = ssl;
    sslv->rxbuf = NULL;
    sslv->txbuf = NULL;
    sslv->tx_waiter = NULL;
    sslv->rx_want = sslv->tx_want = SSL_NOTHING;
    *vconnp = &sslv->vconn;
    return 0;

error:
    if (ssl) {
        SSL_free(ssl);
    }
    close(fd);
    return ENOPROTOOPT;
}

static struct ssl_vconn *
ssl_vconn_cast(struct vconn *vconn)
{
    vconn_assert_class(vconn, &ssl_vconn_class);
    return CONTAINER_OF(vconn, struct ssl_vconn, vconn);
}

static int
ssl_open(const char *name, char *suffix, struct vconn **vconnp)
{
    char *save_ptr, *host_name, *port_string;
    struct sockaddr_in sin;
    int retval;
    int fd;

    retval = ssl_init();
    if (retval) {
        return retval;
    }

    /* Glibc 2.7 has a bug in strtok_r when compiling with optimization that
     * can cause segfaults here:
     * http://sources.redhat.com/bugzilla/show_bug.cgi?id=5614.
     * Using "::" instead of the obvious ":" works around it. */
    host_name = strtok_r(suffix, "::", &save_ptr);
    port_string = strtok_r(NULL, "::", &save_ptr);
    if (!host_name) {
        ofp_error(0, "%s: bad peer name format", name);
        return EAFNOSUPPORT;
    }

    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    if (lookup_ip(host_name, &sin.sin_addr)) {
        return ENOENT;
    }
    sin.sin_port = htons(port_string && *port_string ? atoi(port_string)
                         : OFP_SSL_PORT);

    /* Create socket. */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        VLOG_ERR("%s: socket: %s", name, strerror(errno));
        return errno;
    }
    retval = set_nonblocking(fd);
    if (retval) {
        close(fd);
        return retval;
    }

    /* Connect socket. */
    retval = connect(fd, (struct sockaddr *) &sin, sizeof sin);
    if (retval < 0) {
        if (errno == EINPROGRESS) {
            return new_ssl_vconn(name, fd, CLIENT, STATE_TCP_CONNECTING,
                                 &sin, vconnp);
        } else {
            int error = errno;
            VLOG_ERR("%s: connect: %s", name, strerror(error));
            close(fd);
            return error;
        }
    } else {
        return new_ssl_vconn(name, fd, CLIENT, STATE_SSL_CONNECTING,
                             &sin, vconnp);
    }
}

static int
do_ca_cert_bootstrap(struct vconn *vconn)
{
    struct ssl_vconn *sslv = ssl_vconn_cast(vconn);
    STACK_OF(X509) *chain;
    X509 *ca_cert;
    FILE *file;
    int error;
    int fd;

    chain = SSL_get_peer_cert_chain(sslv->ssl);
    if (!chain || !sk_X509_num(chain)) {
        VLOG_ERR("could not bootstrap CA cert: no certificate presented by "
                 "peer");
        return EPROTO;
    }
    ca_cert = sk_X509_value(chain, sk_X509_num(chain) - 1);

    /* Check that 'ca_cert' is self-signed.  Otherwise it is not a CA
     * certificate and we should not attempt to use it as one. */
    error = X509_check_issued(ca_cert, ca_cert);
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

    fd = open(ca_cert_file, O_CREAT | O_EXCL | O_WRONLY, 0444);
    if (fd < 0) {
        VLOG_ERR("could not bootstrap CA cert: creating %s failed: %s",
                 ca_cert_file, strerror(errno));
        return errno;
    }

    file = fdopen(fd, "w");
    if (!file) {
        int error = errno;
        VLOG_ERR("could not bootstrap CA cert: fdopen failed: %s",
                 strerror(error));
        unlink(ca_cert_file);
        return error;
    }

    if (!PEM_write_X509(file, ca_cert)) {
        VLOG_ERR("could not bootstrap CA cert: PEM_write_X509 to %s failed: "
                 "%s", ca_cert_file, ERR_error_string(ERR_get_error(), NULL));
        fclose(file);
        unlink(ca_cert_file);
        return EIO;
    }

    if (fclose(file)) {
        int error = errno;
        VLOG_ERR("could not bootstrap CA cert: writing %s failed: %s",
                 ca_cert_file, strerror(error));
        unlink(ca_cert_file);
        return error;
    }

    VLOG_WARN("successfully bootstrapped CA cert to %s", ca_cert_file);
    log_ca_cert(ca_cert_file, ca_cert);
    bootstrap_ca_cert = false;
    has_ca_cert = true;

    /* SSL_CTX_add_client_CA makes a copy of ca_cert's relevant data. */
    SSL_CTX_add_client_CA(ctx, ca_cert);

    /* SSL_CTX_use_certificate() takes ownership of the certificate passed in.
     * 'ca_cert' is owned by sslv->ssl, so we need to duplicate it. */
    ca_cert = X509_dup(ca_cert);
    if (!ca_cert) {
        out_of_memory();
    }
    if (SSL_CTX_load_verify_locations(ctx, ca_cert_file, NULL) != 1) {
        VLOG_ERR("SSL_CTX_load_verify_locations: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        return EPROTO;
    }
    VLOG_WARN("killing successful connection to retry using CA cert");
    return EPROTO;
}

static int
ssl_connect(struct vconn *vconn)
{
    struct ssl_vconn *sslv = ssl_vconn_cast(vconn);
    int retval;

    switch (sslv->state) {
    case STATE_TCP_CONNECTING:
        retval = check_connection_completion(sslv->fd);
        if (retval) {
            return retval;
        }
        sslv->state = STATE_SSL_CONNECTING;
        /* Fall through. */

    case STATE_SSL_CONNECTING:
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
                return EPROTO;
            }
        } else if (bootstrap_ca_cert) {
            return do_ca_cert_bootstrap(vconn);
        } else if ((SSL_get_verify_mode(sslv->ssl)
                    & (SSL_VERIFY_NONE | SSL_VERIFY_PEER))
                   != SSL_VERIFY_PEER) {
            /* Two or more SSL connections completed at the same time while we
             * were in bootstrap mode.  Only one of these can finish the
             * bootstrap successfully.  The other one(s) must be rejected
             * because they were not verified against the bootstrapped CA
             * certificate.  (Alternatively we could verify them against the CA
             * certificate, but that's more trouble than it's worth.  These
             * connections will succeed the next time they retry, assuming that
             * they have a certificate against the correct CA.) */
            VLOG_ERR("rejecting SSL connection during bootstrap race window");
            return EPROTO;
        } else {
            return 0;
        }
    }

    NOT_REACHED();
}

static void
ssl_close(struct vconn *vconn)
{
    struct ssl_vconn *sslv = ssl_vconn_cast(vconn);
    poll_cancel(sslv->tx_waiter);
    ssl_clear_txbuf(sslv);
    ofpbuf_delete(sslv->rxbuf);
    SSL_free(sslv->ssl);
    close(sslv->fd);
    free(sslv);
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
                             function, strerror(status));
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

    case SSL_ERROR_SSL: {
        int queued_error = ERR_get_error();
        if (queued_error != 0) {
            VLOG_WARN_RL(&rl, "%s: %s",
                         function, ERR_error_string(queued_error, NULL));
        } else {
            VLOG_ERR_RL(&rl, "%s: SSL_ERROR_SSL without queued error",
                        function);
        }
        break;
    }

    default:
        VLOG_ERR_RL(&rl, "%s: bad SSL error code %d", function, error);
        break;
    }
    return EIO;
}

static int
ssl_recv(struct vconn *vconn, struct ofpbuf **bufferp)
{
    struct ssl_vconn *sslv = ssl_vconn_cast(vconn);
    struct ofpbuf *rx;
    size_t want_bytes;
    int old_state;
    ssize_t ret;

    if (sslv->rxbuf == NULL) {
        sslv->rxbuf = ofpbuf_new(1564);
    }
    rx = sslv->rxbuf;

again:
    if (sizeof(struct ofp_header) > rx->size) {
        want_bytes = sizeof(struct ofp_header) - rx->size;
    } else {
        struct ofp_header *oh = rx->data;
        size_t length = ntohs(oh->length);
        if (length < sizeof(struct ofp_header)) {
            VLOG_ERR_RL(&rl, "received too-short ofp_header (%zu bytes)",
                        length);
            return EPROTO;
        }
        want_bytes = length - rx->size;
        if (!want_bytes) {
            *bufferp = rx;
            sslv->rxbuf = NULL;
            return 0;
        }
    }
    ofpbuf_prealloc_tailroom(rx, want_bytes);

    /* Behavior of zero-byte SSL_read is poorly defined. */
    assert(want_bytes > 0);

    old_state = SSL_get_state(sslv->ssl);
    ret = SSL_read(sslv->ssl, ofpbuf_tail(rx), want_bytes);
    if (old_state != SSL_get_state(sslv->ssl)) {
        sslv->tx_want = SSL_NOTHING;
        if (sslv->tx_waiter) {
            poll_cancel(sslv->tx_waiter);
            ssl_tx_poll_callback(sslv->fd, POLLIN, vconn);
        }
    }
    sslv->rx_want = SSL_NOTHING;

    if (ret > 0) {
        rx->size += ret;
        if (ret == want_bytes) {
            if (rx->size > sizeof(struct ofp_header)) {
                *bufferp = rx;
                sslv->rxbuf = NULL;
                return 0;
            } else {
                goto again;
            }
        }
        return EAGAIN;
    } else {
        int error = SSL_get_error(sslv->ssl, ret);
        if (error == SSL_ERROR_ZERO_RETURN) {
            /* Connection closed (EOF). */
            if (rx->size) {
                VLOG_WARN_RL(&rl, "SSL_read: unexpected connection close");
                return EPROTO;
            } else {
                return EOF;
            }
        } else {
            return interpret_ssl_error("SSL_read", ret, error, &sslv->rx_want);
        }
    }
}

static void
ssl_clear_txbuf(struct ssl_vconn *sslv)
{
    ofpbuf_delete(sslv->txbuf);
    sslv->txbuf = NULL;
    sslv->tx_waiter = NULL;
}

static void
ssl_register_tx_waiter(struct vconn *vconn)
{
    struct ssl_vconn *sslv = ssl_vconn_cast(vconn);
    sslv->tx_waiter = poll_fd_callback(sslv->fd,
                                       want_to_poll_events(sslv->tx_want),
                                       ssl_tx_poll_callback, vconn);
}

static int
ssl_do_tx(struct vconn *vconn)
{
    struct ssl_vconn *sslv = ssl_vconn_cast(vconn);

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

static void
ssl_tx_poll_callback(int fd UNUSED, short int revents UNUSED, void *vconn_)
{
    struct vconn *vconn = vconn_;
    struct ssl_vconn *sslv = ssl_vconn_cast(vconn);
    int error = ssl_do_tx(vconn);
    if (error != EAGAIN) {
        ssl_clear_txbuf(sslv);
    } else {
        ssl_register_tx_waiter(vconn);
    }
}

static int
ssl_send(struct vconn *vconn, struct ofpbuf *buffer)
{
    struct ssl_vconn *sslv = ssl_vconn_cast(vconn);

    if (sslv->txbuf) {
        return EAGAIN;
    } else {
        int error;

        sslv->txbuf = buffer;
        error = ssl_do_tx(vconn);
        switch (error) {
        case 0:
            ssl_clear_txbuf(sslv);
            return 0;
        case EAGAIN:
            ssl_register_tx_waiter(vconn);
            return 0;
        default:
            sslv->txbuf = NULL;
            return error;
        }
    }
}

static void
ssl_wait(struct vconn *vconn, enum vconn_wait_type wait)
{
    struct ssl_vconn *sslv = ssl_vconn_cast(vconn);

    switch (wait) {
    case WAIT_CONNECT:
        if (vconn_connect(vconn) != EAGAIN) {
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
                NOT_REACHED();
            }
        }
        break;

    case WAIT_RECV:
        if (sslv->rx_want != SSL_NOTHING) {
            poll_fd_wait(sslv->fd, want_to_poll_events(sslv->rx_want));
        } else {
            poll_immediate_wake();
        }
        break;

    case WAIT_SEND:
        if (!sslv->txbuf) {
            /* We have room in our tx queue. */
            poll_immediate_wake();
        } else {
            /* The call to ssl_tx_poll_callback() will wake us up. */
        }
        break;

    default:
        NOT_REACHED();
    }
}

struct vconn_class ssl_vconn_class = {
    "ssl",                      /* name */
    ssl_open,                   /* open */
    ssl_close,                  /* close */
    ssl_connect,                /* connect */
    ssl_recv,                   /* recv */
    ssl_send,                   /* send */
    ssl_wait,                   /* wait */
};

/* Passive SSL. */

struct pssl_pvconn
{
    struct pvconn pvconn;
    int fd;
};

struct pvconn_class pssl_pvconn_class;

static struct pssl_pvconn *
pssl_pvconn_cast(struct pvconn *pvconn)
{
    pvconn_assert_class(pvconn, &pssl_pvconn_class);
    return CONTAINER_OF(pvconn, struct pssl_pvconn, pvconn);
}

static int
pssl_open(const char *name, char *suffix, struct pvconn **pvconnp)
{
    struct sockaddr_in sin;
    struct pssl_pvconn *pssl;
    int retval;
    int fd;
    unsigned int yes = 1;

    retval = ssl_init();
    if (retval) {
        return retval;
    }

    /* Create socket. */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        int error = errno;
        VLOG_ERR("%s: socket: %s", name, strerror(error));
        return error;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) < 0) {
        int error = errno;
        VLOG_ERR("%s: setsockopt(SO_REUSEADDR): %s", name, strerror(errno));
        return error;
    }

    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(atoi(suffix) ? atoi(suffix) : OFP_SSL_PORT);
    retval = bind(fd, (struct sockaddr *) &sin, sizeof sin);
    if (retval < 0) {
        int error = errno;
        VLOG_ERR("%s: bind: %s", name, strerror(error));
        close(fd);
        return error;
    }

    retval = listen(fd, 10);
    if (retval < 0) {
        int error = errno;
        VLOG_ERR("%s: listen: %s", name, strerror(error));
        close(fd);
        return error;
    }

    retval = set_nonblocking(fd);
    if (retval) {
        close(fd);
        return retval;
    }

    pssl = xmalloc(sizeof *pssl);
    pvconn_init(&pssl->pvconn, &pssl_pvconn_class, name);
    pssl->fd = fd;
    *pvconnp = &pssl->pvconn;
    return 0;
}

static void
pssl_close(struct pvconn *pvconn)
{
    struct pssl_pvconn *pssl = pssl_pvconn_cast(pvconn);
    close(pssl->fd);
    free(pssl);
}

static int
pssl_accept(struct pvconn *pvconn, struct vconn **new_vconnp)
{
    struct pssl_pvconn *pssl = pssl_pvconn_cast(pvconn);
    struct sockaddr_in sin;
    socklen_t sin_len = sizeof sin;
    char name[128];
    int new_fd;
    int error;

    new_fd = accept(pssl->fd, &sin, &sin_len);
    if (new_fd < 0) {
        int error = errno;
        if (error != EAGAIN) {
            VLOG_DBG_RL(&rl, "accept: %s", strerror(error));
        }
        return error;
    }

    error = set_nonblocking(new_fd);
    if (error) {
        close(new_fd);
        return error;
    }

    sprintf(name, "ssl:"IP_FMT, IP_ARGS(&sin.sin_addr));
    if (sin.sin_port != htons(OFP_SSL_PORT)) {
        sprintf(strchr(name, '\0'), ":%"PRIu16, ntohs(sin.sin_port));
    }
    return new_ssl_vconn(name, new_fd, SERVER, STATE_SSL_CONNECTING, &sin,
                         new_vconnp);
}

static void
pssl_wait(struct pvconn *pvconn)
{
    struct pssl_pvconn *pssl = pssl_pvconn_cast(pvconn);
    poll_fd_wait(pssl->fd, POLLIN);
}

struct pvconn_class pssl_pvconn_class = {
    "pssl",
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
        assert(init_status >= 0);
    }
    return init_status;
}

static int
do_ssl_init(void)
{
    SSL_METHOD *method;

    SSL_library_init();
    SSL_load_error_strings();

    method = TLSv1_method();
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

    return 0;
}

static DH *
tmp_dh_callback(SSL *ssl, int is_export UNUSED, int keylength)
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
                    ofp_fatal(ENOMEM, "out of memory constructing "
                              "Diffie-Hellman parameters");
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
vconn_ssl_is_configured(void) 
{
    return has_private_key || has_certificate || has_ca_cert;
}

void
vconn_ssl_set_private_key_file(const char *file_name)
{
    if (ssl_init()) {
        return;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, file_name, SSL_FILETYPE_PEM) != 1) {
        VLOG_ERR("SSL_use_PrivateKey_file: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        return;
    }
    has_private_key = true;
}

void
vconn_ssl_set_certificate_file(const char *file_name)
{
    if (ssl_init()) {
        return;
    }
    if (SSL_CTX_use_certificate_chain_file(ctx, file_name) != 1) {
        VLOG_ERR("SSL_use_certificate_file: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        return;
    }
    has_certificate = true;
}

/* Reads the X509 certificate or certificates in file 'file_name'.  On success,
 * stores the address of the first element in an array of pointers to
 * certificates in '*certs' and the number of certificates in the array in
 * '*n_certs', and returns 0.  On failure, stores a null pointer in '*certs', 0
 * in '*n_certs', and returns a positive errno value.
 *
 * The caller is responsible for freeing '*certs'. */
int
read_cert_file(const char *file_name, X509 ***certs, size_t *n_certs)
{
    FILE *file;
    size_t allocated_certs = 0;

    *certs = NULL;
    *n_certs = 0;

    file = fopen(file_name, "r");
    if (!file) {
        VLOG_ERR("failed to open %s for reading: %s",
                 file_name, strerror(errno));
        return errno;
    }

    for (;;) {
        X509 *certificate;
        int c;

        /* Read certificate from file. */
        certificate = PEM_read_X509(file, NULL, NULL, NULL);
        if (!certificate) {
            size_t i;

            VLOG_ERR("PEM_read_X509 failed reading %s: %s",
                     file_name, ERR_error_string(ERR_get_error(), NULL));
            for (i = 0; i < *n_certs; i++) {
                X509_free((*certs)[i]);
            }
            free(*certs);
            *certs = NULL;
            *n_certs = 0;
            return EIO;
        }

        /* Add certificate to array. */
        if (*n_certs >= allocated_certs) {
            allocated_certs = 1 + 2 * allocated_certs;
            *certs = xrealloc(*certs, sizeof *certs * allocated_certs);
        }
        (*certs)[(*n_certs)++] = certificate;

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
vconn_ssl_set_peer_ca_cert_file(const char *file_name)
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
            ds_put_format(&fp, "%02hhx", digest[i]);
        }
    }
    subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    VLOG_WARN("Trusting CA cert from %s (%s) (fingerprint %s)", file_name,
              subject ? subject : "<out of memory>", ds_cstr(&fp));
    free(subject);
    ds_destroy(&fp);
}

/* Sets 'file_name' as the name of the file from which to read the CA
 * certificate used to verify the peer within SSL connections.  If 'bootstrap'
 * is false, the file must exist.  If 'bootstrap' is false, then the file is
 * read if it is exists; if it does not, then it will be created from the CA
 * certificate received from the peer on the first SSL connection. */
void
vconn_ssl_set_ca_cert_file(const char *file_name, bool bootstrap)
{
    X509 **certs;
    size_t n_certs;
    struct stat s;

    if (ssl_init()) {
        return;
    }

    if (bootstrap && stat(file_name, &s) && errno == ENOENT) {
        bootstrap_ca_cert = true;
        ca_cert_file = xstrdup(file_name);
    } else if (!read_cert_file(file_name, &certs, &n_certs)) {
        size_t i;

        /* Set up list of CAs that the server will accept from the client. */
        for (i = 0; i < n_certs; i++) {
            /* SSL_CTX_add_client_CA makes a copy of the relevant data. */
            if (SSL_CTX_add_client_CA(ctx, certs[i]) != 1) {
                VLOG_ERR("failed to add client certificate %d from %s: %s",
                         i, file_name,
                         ERR_error_string(ERR_get_error(), NULL));
            } else {
                log_ca_cert(file_name, certs[i]);
            }
            X509_free(certs[i]);
        }

        /* Set up CAs for OpenSSL to trust in verifying the peer's
         * certificate. */
        if (SSL_CTX_load_verify_locations(ctx, file_name, NULL) != 1) {
            VLOG_ERR("SSL_CTX_load_verify_locations: %s",
                     ERR_error_string(ERR_get_error(), NULL));
            return;
        }

        has_ca_cert = true;
    }
}

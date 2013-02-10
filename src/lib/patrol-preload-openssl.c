#include "common.h"
#include "patrol.h"
#include "patrol-openssl.h"
#include "patrol-preload.h"

#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define LIBSSL "libssl.so"

#define PROTONAMELEN 32

static PatrolConfig cfg;

/** Get result of peer certificate verification.
 *
 * @return X509_V_OK on success, error codes are documented in openssl-verify(1).
 */
long
SSL_get_verify_result (const SSL *ssl)
{
    LOG_DEBUG(">> SSL_get_verify_result: 0x%lx", (unsigned long)ssl);
    static int (*get_verify_result)(const SSL *ssl) = NULL;
    if (!get_verify_result)
        get_verify_result = getfunc("SSL_get_verify_result", LIBSSL);
    if (!get_verify_result)
        return X509_V_ERR_APPLICATION_VERIFICATION;

    /* Get OpenSSL's verify result */
    int ret = get_verify_result(ssl);
    LOG_DEBUG(">>> result = %d", ret);

    BIO *bio = SSL_get_rbio(ssl);
    int fd = BIO_get_fd(bio, NULL);

    /* Get TLS server name if available */
    const char *hostname = NULL;
#ifndef OPENSSL_NO_TLSEXT
    hostname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
#endif

    int proto;
    uint16_t port;
    char protoname[PROTONAMELEN];
    char addr[INET6_ADDRSTRLEN];
    if (0 != PATROL_get_peer_addr(fd, &proto, protoname, PROTONAMELEN, &port, addr))
        return ret;

    PATROL_init();
    if (!cfg.loaded)
        PATROL_get_config(&cfg);

    PatrolData *chain = NULL;
    size_t chain_len
        = PATROL_OPENSSL_convert_chain(SSL_get_peer_cert_chain(ssl), &chain);

    PatrolRC pret = PATROL_check(&cfg, chain, chain_len, PATROL_CERT_X509,
                                 ret == X509_V_OK ? PATROL_OK : PATROL_ERROR,
                                 hostname, addr, protoname, port);
    LOG_DEBUG(">>> patrol result = %d", pret);

    PATROL_OPENSSL_free_chain(chain, chain_len);
    PATROL_deinit();

    return pret == PATROL_OK ? X509_V_OK : X509_V_ERR_CERT_UNTRUSTED;
}

#ifdef DEBUG
/** Initiate the TLS/SSL handshake with an TLS/SSL server.
 *
 * @return < 0 on error
 */
int
SSL_connect (SSL *s)
{
    LOG_DEBUG(">> SSL_connect: 0x%lx", (unsigned long)s);
    static int (*ssl_connect)(SSL *s) = NULL;
    if (!ssl_connect)
        ssl_connect = getfunc("SSL_connect", LIBSSL);
    if (!ssl_connect)
        return -1;

    return ssl_connect(s);
}
#endif

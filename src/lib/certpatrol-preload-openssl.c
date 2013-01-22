#include "common.h"
#include "certpatrol.h"
#include "certpatrol-openssl.h"
#include "certpatrol-preload.h"

#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define LIBSSL "libssl.so"

/** Get result of peer certificate verification.
 *
 * @return X509_V_OK on success, error codes are documented in openssl-verify(1).
 */
long
SSL_get_verify_result (const SSL *ssl)
{
    LOG_DEBUG(">> SSL_get_verify_result: 0x%lx\n", (unsigned long)ssl);
    static int (*get_verify_result)(const SSL *ssl) = NULL;
    if (!get_verify_result)
        get_verify_result = getfunc("SSL_get_verify_result", LIBSSL);
    if (!get_verify_result)
        return X509_V_ERR_APPLICATION_VERIFICATION;

    /* Get OpenSSL's verify result */
    int ret = get_verify_result(ssl);
    LOG_DEBUG(">>> result = %d\n", ret);

    BIO *bio = SSL_get_rbio(ssl);
    int fd = BIO_get_fd(bio, NULL);

    /* Get TLS server name if available */
    const char *hostname = NULL;
#ifndef OPENSSL_NO_TLSEXT
    hostname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
#endif

    int proto, port;
    #define PROTONAMELEN 32
    char protoname[PROTONAMELEN];
    char addr[INET6_ADDRSTRLEN];
    if (CertPatrol_get_peer_addr(fd, &proto, protoname, PROTONAMELEN, &port, addr) != 0)
        return ret;

    int cp_ret = CertPatrol_OpenSSL_verify(SSL_get_peer_cert_chain(ssl),
                                           hostname, strlen(hostname),
                                           addr, strlen(addr),
                                           protoname, strlen(protoname), port);
    LOG_DEBUG(">>> CP result = %d\n", cp_ret);

    return cp_ret == CERTPATROL_OK ? X509_V_OK : X509_V_ERR_CERT_UNTRUSTED;
}

#ifdef DEBUG
/** Initiate the TLS/SSL handshake with an TLS/SSL server.
 *
 * @return < 0 on error
 */
int
SSL_connect (SSL *s)
{
    LOG_DEBUG(">> SSL_connect: 0x%lx\n", (unsigned long)s);
    static int (*ssl_connect)(SSL *s) = NULL;
    if (!ssl_connect)
        ssl_connect = getfunc("SSL_connect", LIBSSL);
    if (!ssl_connect)
        return -1;

    return ssl_connect(s);
}
#endif

#include "common.h"
#include "patrol.h"
#include "patrol-gnutls.h"
#include "patrol-preload.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define LIBGNUTLS "libgnutls.so"

#define PROTONAMELEN 32

#define GNUTLS_EXTENSION_SERVER_NAME 0
#define MAX_SERVER_NAME_SIZE 128
#define MAX_SERVER_NAME_EXTENSIONS 3

typedef struct {
    uint8_t name[MAX_SERVER_NAME_SIZE];
    unsigned name_length;
    gnutls_server_name_type_t type;
} server_name_st;

typedef struct {
    server_name_st server_names[MAX_SERVER_NAME_EXTENSIONS];
    /* limit server_name extensions */
    unsigned server_names_size;
} server_name_ext_st;

typedef union {
    void *ptr;
    uint32_t num;
} extension_priv_data_t;

int
_gnutls_ext_get_session_data (gnutls_session_t session,
                              uint16_t type, extension_priv_data_t *);

const void *
_gnutls_get_cred (gnutls_session_t session,
                  gnutls_credentials_type_t kx, int *err);

/** Verify the peer's certificate.
 *
 * Store the status in the status variable as bitwise or'd
 * gnutls_certificate_status_t values or zero if the certificate is trusted.
 *
 * @return A negative error code on error and GNUTLS_E_SUCCESS (0) on success.
 */
int
gnutls_certificate_verify_peers3 (gnutls_session_t session,
                                  const char* hostname,
                                  unsigned int * status)
{
    LOG_DEBUG(">> gnutls_certificate_verify_peers3");
    static int (*verify_peers3)(gnutls_session_t, const char* hostname,
                                unsigned int *status) = NULL;
    if (!verify_peers3)
        verify_peers3 = getfunc("gnutls_certificate_verify_peers3", LIBGNUTLS);
    if (!verify_peers3)
        return GNUTLS_E_CERTIFICATE_ERROR;

    int ret = verify_peers3(session, hostname, status);
    LOG_DEBUG(">>> result = %d, %d", ret, *status);

    int fd = (int)(intptr_t) gnutls_transport_get_ptr(session);

    int proto;
    uint16_t port;
    char protoname[PROTONAMELEN] = "";
    char addr[INET6_ADDRSTRLEN] = "";
    if (PATROL_OK != PATROL_get_peer_addr(fd, &proto, protoname,
                                          PROTONAMELEN, &port, addr))
        return GNUTLS_E_CERTIFICATE_ERROR;

    unsigned int chain_len;
    const gnutls_datum_t *chain = gnutls_certificate_get_peers(session,
                                                               &chain_len);

    int pret = PATROL_GNUTLS_verify(chain, chain_len,
                                    gnutls_certificate_type_get(session), ret,
                                    hostname, strlen(hostname),
                                    addr, strlen(addr),
                                    protoname, strlen(protoname), port);
    LOG_DEBUG(">>> patrol result = %d", pret);

    return pret == PATROL_OK
        ? GNUTLS_E_SUCCESS
        : GNUTLS_E_CERTIFICATE_ERROR;
}

/** Verify the peer's certificate.
 *
 * Store the status in the status variable as bitwise or'd
 * gnutls_certificate_status_t values or zero if the certificate is trusted.
 *
 * @return A negative error code on error and GNUTLS_E_SUCCESS (0) on success.
 */
int
gnutls_certificate_verify_peers2 (gnutls_session_t session,
                                  unsigned int *status) {
    LOG_DEBUG(">> gnutls_certificate_verify_peers2");
    static int (*verify_peers2)(gnutls_session_t, unsigned int *status) = NULL;
    if (!verify_peers2)
        verify_peers2 = getfunc("gnutls_certificate_verify_peers2", LIBGNUTLS);
    if (!verify_peers2)
        return GNUTLS_E_CERTIFICATE_ERROR;

    int ret = verify_peers2(session, status);
    LOG_DEBUG(">>> result = %d, %d", ret, *status);

    char hostname[MAX_SERVER_NAME_SIZE+1] = "";
    unsigned int hostlen = 0;

    /* Get hostname set by gnutls_server_name_set().
     * We can't use gnutls_server_name_get() as it checks if it's a server session,
     * otherwise returns an error in client mode.
     */
    server_name_ext_st *priv;
    extension_priv_data_t epriv;
    if (0 >= _gnutls_ext_get_session_data(session, GNUTLS_EXTENSION_SERVER_NAME,
                                          &epriv)) {
        priv = epriv.ptr;
        if (priv->server_names_size > 0) {
            hostlen = priv->server_names[0].name_length;
            if (hostlen <= MAX_SERVER_NAME_SIZE) {
                memcpy(hostname, priv->server_names[0].name,
                       priv->server_names[0].name_length);
                hostname[hostlen] = '\0';
                LOG_DEBUG(">>> hostname = %s", hostname);
            }
        }
    }

    int fd = (int)(intptr_t) gnutls_transport_get_ptr(session);

    int proto;
    uint16_t port;
    char protoname[PROTONAMELEN] = "";
    char addr[INET6_ADDRSTRLEN] = "";
    if (PATROL_OK != PATROL_get_peer_addr(fd, &proto, protoname,
                                          PROTONAMELEN, &port, addr))
        return GNUTLS_E_CERTIFICATE_ERROR;

    unsigned int chain_len = 0;
    const gnutls_datum_t *chain = gnutls_certificate_get_peers(session,
                                                               &chain_len);

    int pret = PATROL_GNUTLS_verify_credentials(chain, chain_len,
                                                gnutls_certificate_type_get(session), ret,
                                                (gnutls_certificate_credentials_t)
                                                _gnutls_get_cred(session, GNUTLS_CRD_CERTIFICATE, NULL),
                                                hostname, strlen(hostname),
                                                addr, strlen(addr),
                                                protoname, strlen(protoname), port);
    LOG_DEBUG(">>> patrol result = %d", pret);

    return pret == PATROL_OK
        ? GNUTLS_E_SUCCESS
        : GNUTLS_E_CERTIFICATE_ERROR;
}

#ifdef DEBUG
/** Check if the given certificate's subject matches the given hostname.
 *
 * @return Non-zero for a successful match, and zero on failure.
 */
int
gnutls_x509_crt_check_hostname (gnutls_x509_crt_t cert,
                                const char *hostname)
{
    LOG_DEBUG(">> gnutls_x509_crt_check_hostname: %s", hostname);
    static int (*check_hostname)(gnutls_x509_crt_t cert,
                                 const char *hostname) = NULL;
    if (!check_hostname)
        check_hostname = getfunc("gnutls_x509_crt_check_hostname", LIBGNUTLS);
    if (!check_hostname)
        return 0;

    int ret = check_hostname(cert, hostname);
    LOG_DEBUG(">>> result = %d", ret);
    return ret;
}
#endif

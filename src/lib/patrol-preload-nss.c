#include "common.h"
#include "patrol.h"
#include "patrol-nss.h"
#include "patrol-preload.h"

#include <nss.h>
#include <cert.h>

#include <prio.h>
#include <prnetdb.h>

#define LIBNSS3 "libnss3.so"
#define LIBSSL3 "libssl3.so"

static PatrolConfig cfg;
static PRFileDesc *nss_fd;

/** Sets the domain name of the intended server in the client's SSL socket. */
SECStatus
SSL_SetURL(PRFileDesc *fd, char *url)
{
    LOG_DEBUG(">> SSL_SetURL: %s", url);
    static int (*SetUrl)(PRFileDesc *fd, char *url) = NULL;
    if (!SetUrl)
        SetUrl = getfunc("SSL_SetURL", LIBSSL3);
    if (!SetUrl)
        return SECFailure;

    int ret = SetUrl(fd, url);
    LOG_DEBUG(">>> fd = %zx", (intptr_t) fd);
    LOG_DEBUG(">>> result = %d", ret);
    nss_fd = fd;
    return ret;
}

/** Compares the common name specified in the subject DN for a certificate
  * with a specified hostname.
  */
SECStatus
CERT_VerifyCertName(const CERTCertificate *cert, const char *hostname)
{
    LOG_DEBUG(">> CERT_VerifyCertName: %s", hostname);
    static SECStatus (*VerifyCertName)(CERTCertificate *cert,
                                       const char *hostname) = NULL;
    if (!VerifyCertName)
        VerifyCertName = getfunc("CERT_VerifyCertName", LIBNSS3);
    if (!VerifyCertName)
        return SECFailure;

    SECStatus ret = VerifyCertName(cert, hostname);
    LOG_DEBUG(">>> result = %d", ret);

    PATROL_init();
    if (!cfg.loaded)
        PATROL_get_config(&cfg);

    PRNetAddr addr;
    if (PR_SUCCESS != PR_GetPeerName(nss_fd, &addr))
        return ret;

    PatrolData *chain = NULL;
    size_t chain_len
        = PATROL_NSS_convert_chain(CERT_GetCertChainFromCert(cert, PR_Now(),
                                                             certUsageSSLCA),
                                   &chain);

    PatrolRC pret = PATROL_check(&cfg, chain, chain_len, PATROL_CERT_X509,
                                 ret == SECSuccess ? PATROL_OK : PATROL_ERROR,
                                 hostname, 0, "tcp", // FIXME
                                 PR_ntohs((addr.raw.family == PR_AF_INET6)
                                          ? addr.ipv6.port : addr.inet.port));
    LOG_DEBUG(">>> patrol result = %d", pret);

    free(chain);
    PATROL_deinit();

    return pret == PATROL_OK ? SECSuccess : SECFailure;
}

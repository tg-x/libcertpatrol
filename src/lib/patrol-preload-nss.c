#include "common.h"
#include "patrol.h"
#include "patrol-nss.h"
#include "patrol-preload.h"

#define LIBNSS3 "libnss3.so"
#define LIBSSL3 "libssl3.so"

static PRFileDesc *nss_fd = NULL;

/** Sets the domain name of the intended server in the client's SSL socket. */
SECStatus
SSL_SetURL(PRFileDesc *fd, char *url)
{
    LOG_DEBUG(">> SSL_SetURL: %s\n", url);
    static int (*SetUrl)(PRFileDesc *fd, char *url) = NULL;
    if (!SetUrl)
        SetUrl = getfunc("SSL_SetURL", LIBSSL3);
    if (!SetUrl)
        return SECFailure;

    int ret = SetUrl(fd, url);
    LOG_DEBUG(">>> result = %d\n", ret);
    nss_fd = fd;
    return ret;
}

/** Compares the common name specified in the subject DN for a certificate
  * with a specified hostname.
  */
SECStatus
CERT_VerifyCertName(CERTCertificate *cert, const char *hostname)
{
    LOG_DEBUG(">> CERT_VerifyCertName: %s\n", hostname);
    static SECStatus (*VerifyCertName)(CERTCertificate *cert,
                                       const char *hostname) = NULL;
    if (!VerifyCertName)
        VerifyCertName = getfunc("CERT_VerifyCertName", LIBNSS3);
    if (!VerifyCertName)
        return SECFailure;

    SECStatus ret = VerifyCertName(cert, hostname);
    LOG_DEBUG(">>> result = %d\n", ret);
    return ret;
}

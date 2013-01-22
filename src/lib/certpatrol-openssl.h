#ifndef CERTPATROL_OPENSSL_H
# define CERTPATROL_OPENSSL_H

#include <openssl/ssl.h>

CertPatrolRC
CertPatrol_OpenSSL_verify (const STACK_OF(X509) *chain,
                           const char *host, size_t host_len,
                           const char *addr, size_t addr_len,
                           const char *proto, size_t proto_len, int port);

#endif // CERTPATROL_OPENSSL_H

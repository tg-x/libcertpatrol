#ifndef CERTPATROL_GNUTLS_H
# define CERTPATROL_GNUTLS_H

#include <gnutls/gnutls.h>

CertPatrolRC
CertPatrol_GnuTLS_verify (const gnutls_datum_t *chain, size_t chain_len,
                          const char *host, size_t host_len,
                          const char *addr, size_t addr_len,
                          const char *proto, size_t proto_len,
                          uint16_t port);

#endif // CERTPATROL_GNUTLS_H

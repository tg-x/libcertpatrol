#ifndef PATROL_GNUTLS_H
# define PATROL_GNUTLS_H

#include <gnutls/gnutls.h>

PatrolRC
PATROL_GNUTLS_verify (const gnutls_datum_t *chain, size_t chain_len,
                      gnutls_certificate_type_t chain_type,
                      PatrolRC chain_result,
                      const char *host, size_t host_len,
                      const char *addr, size_t addr_len,
                      const char *proto, size_t proto_len,
                      uint16_t port);

#endif // PATROL_GNUTLS_H

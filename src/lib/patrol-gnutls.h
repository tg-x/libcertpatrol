#ifndef PATROL_GNUTLS_H
# define PATROL_GNUTLS_H

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

PatrolRC
PATROL_GNUTLS_verify (const gnutls_datum_t *chain, size_t chain_len,
                      gnutls_certificate_type_t chain_type,
                      //const gnutls_datum_t *ca_list, size_t ca_list_len,
                      int chain_result, //unsigned int chain_status,
                      const char *host, size_t host_len,
                      const char *addr, size_t addr_len,
                      const char *proto, size_t proto_len,
                      uint16_t port);

PatrolRC
PATROL_GNUTLS_verify_trust_list (const gnutls_datum_t *chain, size_t chain_len,
                                 gnutls_certificate_type_t chain_type,
                                 int chain_result, //unsigned int chain_status,
                                 const gnutls_x509_trust_list_t trust_list,
                                 const char *host, size_t host_len,
                                 const char *addr, size_t addr_len,
                                 const char *proto, size_t proto_len,
                                 uint16_t port);

PatrolRC
PATROL_GNUTLS_verify_credentials (const gnutls_datum_t *chain, size_t chain_len,
                                  gnutls_certificate_type_t chain_type,
                                  int chain_result, //unsigned int chain_status,
                                  const gnutls_certificate_credentials_t credentials,
                                  const char *host, size_t host_len,
                                  const char *addr, size_t addr_len,
                                  const char *proto, size_t proto_len,
                                  uint16_t port);

#endif // PATROL_GNUTLS_H

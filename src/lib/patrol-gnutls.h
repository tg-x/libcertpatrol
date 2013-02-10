#ifndef PATROL_GNUTLS_H
# define PATROL_GNUTLS_H

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#if GNUTLS_CHECK_VERSION(3,0,0)

PatrolRC
PATROL_GNUTLS_complete_chain_from_trust_list (const gnutls_datum_t *chain, size_t chain_len,
                                              gnutls_certificate_type_t chain_type,
                                              const gnutls_x509_trust_list_t trust_list,
                                              gnutls_datum_t **new_chain, size_t *new_chain_len);

PatrolRC
PATROL_GNUTLS_complete_chain_from_credentials (const gnutls_datum_t *chain, size_t chain_len,
                                               gnutls_certificate_type_t chain_type,
                                               const gnutls_certificate_credentials_t credentials,
                                               gnutls_datum_t **new_chain, size_t *new_chain_len);

void
PATROL_GNUTLS_free_completed_chain (gnutls_datum_t *new_chain, size_t new_len,
                                    size_t old_len);

#endif // 3.0.0

#endif // PATROL_GNUTLS_H

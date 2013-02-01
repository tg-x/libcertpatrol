#ifndef PATROL_OPENSSL_H
# define PATROL_OPENSSL_H

#include <openssl/ssl.h>

size_t
PATROL_OPENSSL_convert_chain (const STACK_OF(X509) *chain, PatrolData **pchain);

void
PATROL_OPENSSL_free_chain (PatrolData *chain, size_t chain_len);

#endif // PATROL_OPENSSL_H

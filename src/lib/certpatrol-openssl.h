#ifndef PATROL_OPENSSL_H
# define PATROL_OPENSSL_H

#include <openssl/ssl.h>

PatrolRC
PATROL_OPENSSL_verify (const STACK_OF(X509) *chain,
                       const char *host, size_t host_len,
                       const char *addr, size_t addr_len,
                       const char *proto, size_t proto_len,
                       uint16_t port);

#endif // PATROL_OPENSSL_H

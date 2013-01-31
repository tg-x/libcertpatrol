#ifndef PATROL_NSS_H
# define PATROL_NSS_H

#include <nss.h>
#include <nss/cert.h>

PatrolRC
PATROL_NSS_verify (const CERTCertList *chain, PatrolRC chain_result,
                   const char *host, size_t host_len,
                   const char *addr, size_t addr_len,
                   const char *proto, size_t proto_len,
                   uint16_t port);

#endif // PATROL_NSS_H

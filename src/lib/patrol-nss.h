#ifndef PATROL_NSS_H
# define PATROL_NSS_H

#include <nss.h>
#include <nss/cert.h>

size_t
PATROL_NSS_convert_chain (const CERTCertList *chain, PatrolData **pchain);

#endif // PATROL_NSS_H

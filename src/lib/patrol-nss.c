#include "common.h"
#include "patrol.h"
#include "patrol-nss.h"

#include <nss.h>
#include <nss/cert.h>

PatrolRC
PATROL_NSS_verify (const CERTCertList *chain, PatrolRC chain_result,
                   const char *host, size_t host_len,
                   const char *addr, size_t addr_len,
                   const char *proto, size_t proto_len,
                   uint16_t port)
{
    LOG_DEBUG(">> verify: %d, %s, %s, %s, %d",
              chain != NULL, host, addr, proto, port);

    PatrolRC ret = PATROL_ERROR;
    if (!chain)
        return ret;

    size_t ch_len = 0;
    CERTCertListNode *node;
    for (node = CERT_LIST_HEAD(chain); !CERT_LIST_END(node, chain);
         node = CERT_LIST_NEXT(node)) {
        ch_len++;
    }

    PatrolData *ch = malloc(ch_len * sizeof(PatrolData));
    int i = 0;
    for (node = CERT_LIST_HEAD(chain); !CERT_LIST_END(node, chain);
         node = CERT_LIST_NEXT(node), i++) {
        ch[i].data = node->cert->derCert.data;
        ch[i].size = node->cert->derCert.len;
    }

    ret = PATROL_verify(ch, ch_len, chain_result, PATROL_CERT_X509,
                        host, host_len, addr, addr_len, proto, proto_len,
                        port);

    free(ch);
    return ret;
}

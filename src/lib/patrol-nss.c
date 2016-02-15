#include "common.h"
#include "patrol.h"
#include "patrol-nss.h"

#include <nss.h>
#include <cert.h>

size_t
PATROL_NSS_convert_chain (const CERTCertList *chain, PatrolData **pchain)
{
    if (!chain)
        return 0;

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

    *pchain = ch;
    return ch_len;
}

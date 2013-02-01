#include "common.h"
#include "patrol.h"
#include "patrol-openssl.h"

#include <openssl/ssl.h>

size_t
PATROL_OPENSSL_convert_chain (const STACK_OF(X509) *chain, PatrolData **pchain)
{
    if (!chain)
        return 0;

    size_t ch_len = sk_X509_num(chain);
    PatrolData *ch = malloc(ch_len * sizeof(PatrolData));
    int i, r;

    for (i = 0; i < ch_len; i++) {
        ch[i].data = NULL;
        r = i2d_X509(sk_X509_value(chain, i), &(ch[i].data));
        ch[i].size = r >= 0 ? r : 0;
    }

    *pchain = ch;
    return ch_len;
}

void
PATROL_OPENSSL_free_chain (PatrolData *chain, size_t chain_len)
{
    if (!chain_len)
        return;

    size_t i;
    for (i = 0; i < chain_len; i++)
        OPENSSL_free(chain[i].data);

    free(chain);
}

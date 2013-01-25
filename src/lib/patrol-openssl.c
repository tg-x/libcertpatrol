#include "common.h"
#include "patrol.h"
#include "patrol-openssl.h"

#include <openssl/ssl.h>

PatrolRC
PATROL_OPENSSL_verify (const STACK_OF(X509) *chain,
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

    size_t ch_len = sk_X509_num(chain);
    PatrolData *ch = malloc(ch_len * sizeof(PatrolData));
    int i, r;

    for (i = 0; i < ch_len; i++) {
        ch[i].data = NULL;
        r = i2d_X509(sk_X509_value(chain, i), &(ch[i].data));
        ch[i].size = r >= 0 ? r : 0;
    }

    ret = PATROL_verify(ch, ch_len, host, host_len,
                        addr, addr_len, proto, proto_len, port);

    for (i = 0; i < ch_len; i++)
        OPENSSL_free(ch[i].data);
    free(ch);

    return ret;
}

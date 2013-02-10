#include "common.h"
#include "patrol.h"
#include "patrol-gnutls.h"

#if GNUTLS_CHECK_VERSION(3,0,0)

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

typedef struct crt_list crt_list;
struct crt_list {
    gnutls_x509_crt_t crt;
    crt_list *next;
};

typedef int (*GetIssuer) (const void *ca_list, gnutls_x509_crt_t cert,
                          gnutls_x509_crt_t *issuer, unsigned int flags);

PatrolRC
complete_chain (const gnutls_datum_t *chain, size_t chain_len,
                gnutls_certificate_type_t chain_type,
                GetIssuer get_issuer, const void *ca_list,
                gnutls_datum_t **ret_chain, size_t *ret_chain_len)
{
    if (!chain_len)
        return PATROL_ERROR;

    crt_list *ch = NULL, *cur, *prev = NULL;
    gnutls_x509_crt_t tail, crt, issuer;
    gnutls_datum_t *new_chain = (gnutls_datum_t *) chain;
    size_t i, new_len = chain_len;

    gnutls_x509_crt_init(&tail);
    int r = gnutls_x509_crt_import(tail, &chain[chain_len - 1],
                                   GNUTLS_X509_FMT_DER);
    if (r != GNUTLS_E_SUCCESS) {
        LOG_DEBUG(">>> error importing cert: %d", r);
        return PATROL_ERROR;
    }
    crt = tail;

    do {
        if (gnutls_x509_crt_check_issuer(crt, crt))
            break; // self-signed, end of chain

        issuer = NULL;
        get_issuer(ca_list, crt, &issuer, 0);
        if (!issuer)
            break;

        crt = issuer;
        new_len++;

        cur = gnutls_malloc(sizeof(crt_list));
        cur->crt = crt;
        cur->next = NULL;
        if (prev)
            prev->next = cur;
        else
            ch = cur;
        prev = cur;
    } while (1);

    gnutls_x509_crt_deinit(tail);

    if (new_len > chain_len) {
        new_chain = gnutls_malloc(new_len * sizeof(gnutls_datum_t));

        for (i = 0; i < chain_len; i++)
            new_chain[i] = chain[i];

        for (cur = ch; cur != NULL; cur = cur->next, i++) {
            gnutls_datum_t crt_der;
#if GNUTLS_CHECK_VERSION(3,1,0)
            r = gnutls_x509_crt_export2(cur->crt, GNUTLS_X509_FMT_DER, &crt_der);
#else
            crt_der.data = gnutls_malloc(new_chain[i].size);
            crt_der.size = new_chain[i].size;
            r = gnutls_x509_crt_export(cur->crt, GNUTLS_X509_FMT_DER,
                                       crt_der.data,
                                       (size_t *) &(crt_der.size));
#endif
            new_chain[i] = crt_der;
        }
        LOG_DEBUG(">>> added %zu CAs to chain", new_len - chain_len);
    }

    for (cur = ch, prev = NULL; cur != NULL; ) {
        prev = cur;
        cur = cur->next;
        gnutls_free(prev);
    }

    *ret_chain = new_chain;
    *ret_chain_len = new_len;
    return PATROL_OK;
}

void
PATROL_GNUTLS_free_completed_chain (gnutls_datum_t *new_chain, size_t new_len,
                                    size_t old_len)
{
    size_t i;

    if (new_len > old_len) {
        for (i = old_len; i < new_len; i++)
            gnutls_free(new_chain[i].data);
        gnutls_free(new_chain);
    }
}

PatrolRC
PATROL_GNUTLS_complete_chain_from_trust_list (const gnutls_datum_t *chain, size_t chain_len,
                                              gnutls_certificate_type_t chain_type,
                                              const gnutls_x509_trust_list_t trust_list,
                                              gnutls_datum_t **new_chain, size_t *new_chain_len)
{
    return complete_chain(chain, chain_len, chain_type,
                         (GetIssuer) gnutls_x509_trust_list_get_issuer,
                          trust_list, new_chain, new_chain_len);
}

PatrolRC
PATROL_GNUTLS_complete_chain_from_credentials (const gnutls_datum_t *chain, size_t chain_len,
                                               gnutls_certificate_type_t chain_type,
                                               const gnutls_certificate_credentials_t credentials,
                                               gnutls_datum_t **new_chain, size_t *new_chain_len)
{
    return complete_chain(chain, chain_len, chain_type,
                          (GetIssuer) gnutls_certificate_get_issuer,
                          credentials, new_chain, new_chain_len);
}

#endif

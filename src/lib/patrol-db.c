#include "common.h"
#include "patrol.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#define MAX(a, b) (a >= b ? a : b)
#define MIN(a, b) (a <= b ? a : b)

PatrolVerifyRC
PATROL_verify_chain (const PatrolData *chain, size_t chain_len,
                     PatrolCertType chain_type,
                     const char *host, const char *proto, uint16_t port)
{
    LOG_DEBUG(">> verify_chain: %zu, %d, %s, %s, %d", chain_len, chain_type, host, proto, port);

    gnutls_pubkey_t pk = { 0 };
    gnutls_x509_crt_t crt = { 0 };
    PatrolRecord *records = NULL, *rec = NULL;
    size_t i, records_len = 0;
    int r;

    PatrolVerifyRC ret = PATROL_VERIFY_NEW;

    switch (PATROL_get_certs(host, proto, port,
                             PATROL_STATUS_ACTIVE | PATROL_STATUS_REJECTED,
                             false, &records, &records_len)) {
    case PATROL_DONE: // no active certs found for peer
        LOG_DEBUG(">>> new cert");
        return ret;

    case PATROL_OK: // active cert(s) found for peer
        LOG_DEBUG(">>> cert found");

        // make a list of pubkeys present in the chain
        size_t pubkey_list_len = chain_len;
        PatrolData *pubkey_list
            = gnutls_malloc(pubkey_list_len * sizeof(PatrolData));

        for (i = 0; i < chain_len; i++) {
            gnutls_x509_crt_init(&crt);
            r = gnutls_x509_crt_import(crt, (gnutls_datum_t *) &chain[i],
                                       GNUTLS_X509_FMT_DER);
            if (r != GNUTLS_E_SUCCESS) {
                LOG_ERROR("verify_chain: error importing cert #%zd: %d", i, r);
                return PATROL_ERROR;
            }

            gnutls_pubkey_init(&pk);
            r = gnutls_pubkey_import_x509(pk, crt, 0);
            if (r != GNUTLS_E_SUCCESS) {
                LOG_ERROR("verify_chain: error importing pubkey #%zd: %d", i, r);
                return PATROL_ERROR;
            }

#if GNUTLS_CHECK_VERSION(3,1,3)
            r = gnutls_pubkey_export2(pk, GNUTLS_X509_FMT_DER,
                                      (gnutls_datum_t *) &pubkey_list[i]);
#else
            pubkey_list[i] = PATROL_DATA(malloc(chain[i].size),
                                         chain[i].size);
            r = gnutls_pubkey_export(pk, GNUTLS_X509_FMT_DER,
                                     pubkey_list[i].data,
                                     (size_t *) &(pubkey_list[i].size));
#endif
            if (r != GNUTLS_E_SUCCESS) {
                LOG_ERROR("verify_chain: error exporting pubkey #%zd: %d", i, r);
                return PATROL_ERROR;
            }

            gnutls_pubkey_deinit(pk);
            gnutls_x509_crt_deinit(crt);
        }

        // compare active pubkeys with pubkeys in the chain
        rec = records;
        do {
            if (rec->status == PATROL_STATUS_ACTIVE)
                ret = PATROL_VERIFY_CHANGE;
            for (i = 0; i < pubkey_list_len; i++) {
                if (pubkey_list[i].size == rec->pubkey.size
                    && 0 == memcmp(pubkey_list[i].data, rec->pubkey.data,
                                   pubkey_list[i].size)) {
                    ret = (rec->status == PATROL_STATUS_ACTIVE)
                        ? PATROL_VERIFY_OK
                        : PATROL_VERIFY_REJECT;
                    break;
                }
            }
        } while ((rec = rec->next) != NULL
                 && ret != PATROL_VERIFY_OK
                 && ret != PATROL_VERIFY_REJECT);

        for (i = 0; i < pubkey_list_len; i++)
            free(pubkey_list[i].data);
        free(pubkey_list);

        return ret;

    default:
        return PATROL_ERROR;
    }
}

int
PATROL_get_pin_level (const PatrolData *chain, size_t chain_len,
                      PatrolData pubkey)
{
    LOG_DEBUG(">> get_pin_level");

    gnutls_pubkey_t pk = NULL;
    gnutls_x509_crt_t crt = NULL;
    size_t i;
    int r;
    gnutls_global_init();

    for (i = 0; i < chain_len; i++) {
        gnutls_x509_crt_init(&crt);

        r = gnutls_x509_crt_import(crt, (gnutls_datum_t *) &chain[i],
                                   GNUTLS_X509_FMT_DER);
        if (r != GNUTLS_E_SUCCESS) {
            LOG_ERROR("get_pin_level: error importing cert #%zd: %d", i, r);
            return PATROL_ERROR;
        }

        gnutls_pubkey_init(&pk);
        r = gnutls_pubkey_import_x509(pk, crt, 0);
        gnutls_x509_crt_deinit(crt);

        if (r != GNUTLS_E_SUCCESS) {
            LOG_ERROR("get_pin_level: error importing pubkey #%zd: %d", i, r);
            gnutls_pubkey_deinit(pk);
            return PATROL_ERROR;
        }

        PatrolData pubkey_der;
#if GNUTLS_CHECK_VERSION(3,1,3)
        r = gnutls_pubkey_export2(pk, GNUTLS_X509_FMT_DER,
                                  (gnutls_datum_t *) &pubkey_der);
#else
        pubkey_der = PATROL_DATA(gnutls_malloc(chain[i].size),
                                 chain[i].size);
        r = gnutls_pubkey_export(pk, GNUTLS_X509_FMT_DER,
                                 pubkey_der.data,
                                 (size_t *) &(pubkey_der.size));
#endif
        gnutls_pubkey_deinit(pk);

        if (r != GNUTLS_E_SUCCESS) {
            LOG_ERROR("get_pin_level: error exporting pubkey #%zd: %d", i, r);
            gnutls_free(pubkey_der.data);
            return PATROL_ERROR;
        }

        r = memcmp(pubkey.data, pubkey_der.data, pubkey_der.size);
        gnutls_free(pubkey_der.data);
        if (r == 0)
            return i;
    }

    return PATROL_ERROR;
}

PatrolRC
PATROL_set_pubkey_from_chain (const char *host, const char *proto, uint16_t port,
                              PatrolID id, PatrolPinLevel pin_level,
                              const PatrolData *chain, size_t chain_len)
{
    LOG_DEBUG(">> set_pin_from_chain: %s, %s, %u, %d",
              host, proto, port, pin_level);

    PatrolRecord rec = { 0 };
    gnutls_pubkey_t pubkey = NULL;
    gnutls_x509_crt_t crt = NULL;
    size_t i;
    int r;

    if (!chain_len) {
        if (PATROL_OK != PATROL_get_cert(host, proto, port, id,
                                         PATROL_STATUS_ANY, &rec))
            return PATROL_ERROR;
        chain = rec.chain;
        chain_len = rec.chain_len;
    }

    for (i = 0; i < chain_len; i++) {
        if (!(i == MIN(pin_level, chain_len - 1)
              || i == MAX(chain_len + pin_level, 0)))
            continue;

        gnutls_x509_crt_init(&crt);

        r = gnutls_x509_crt_import(crt, (gnutls_datum_t *) &chain[i],
                                   GNUTLS_X509_FMT_DER);
        if (r != GNUTLS_E_SUCCESS) {
            LOG_ERROR("set_pin_from_chain: error importing cert #%zd: %d", i, r);
            return PATROL_ERROR;
        }

        gnutls_pubkey_init(&pubkey);
        r = gnutls_pubkey_import_x509(pubkey, crt, 0);
        gnutls_x509_crt_deinit(crt);

        if (r != GNUTLS_E_SUCCESS) {
            LOG_ERROR("set_pin_from_chain: error importing pubkey #%zd: %d", i, r);
            gnutls_pubkey_deinit(pubkey);
            return PATROL_ERROR;
        }

        PatrolData pubkey_der = { 0 };
#if GNUTLS_CHECK_VERSION(3,1,3)
        r = gnutls_pubkey_export2(pubkey, GNUTLS_X509_FMT_DER,
                                  (gnutls_datum_t *) &pubkey_der);
#else
        pubkey_der = PATROL_DATA(gnutls_malloc(chain[i].size),
                                 chain[i].size);
        r = gnutls_pubkey_export(pubkey, GNUTLS_X509_FMT_DER,
                                 pubkey_der.data,
                                 (size_t *) &(pubkey_der.size));
#endif
        gnutls_pubkey_deinit(pubkey);

        if (r != GNUTLS_E_SUCCESS) {
            LOG_ERROR("set_pin_from_chain: error exporting pubkey #%zd: %d", i, r);
            gnutls_free(pubkey_der.data);
            return PATROL_ERROR;
        }

        if (PATROL_OK != PATROL_set_pubkey(host, proto, port, id,
                                           pubkey_der.data, pubkey_der.size)) {
            LOG_ERROR("set_pin_from_chain: error pinning pubkey");

            gnutls_free(pubkey_der.data);
            return PATROL_ERROR;
        }

        gnutls_free(pubkey_der.data);
        return PATROL_OK;
   }

    return PATROL_ERROR;
}

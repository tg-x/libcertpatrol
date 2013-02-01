#include "common.h"
#include "patrol.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

/** Verify certificate chain against pin settings.
 */
PatrolVerifyRC
PATROL_verify_chain (const gnutls_datum_t *chain, size_t chain_len,
                     gnutls_certificate_type_t chain_type,
                     const char *host, size_t host_len,
                     const char *proto, size_t proto_len,
                     uint16_t port)
{
    LOG_DEBUG(">> verify_pin: %zu, %s, %s, %d", chain_len, host, proto, port);

    gnutls_pubkey_t pubkey = { 0 };
    gnutls_x509_crt_t crt = { 0 };
    PatrolRecord *records = NULL, *rec = NULL;
    size_t i, records_len = 0;
    int r;

    // TODO: check if rejected

    PatrolRC ret = PATROL_get_certs(host, host_len, proto, proto_len, port,
                                    PATROL_STATUS_ACTIVE, false,
                                    &records, &records_len);
    switch (ret) {
    case PATROL_DONE: // no active certs found for peer
        LOG_DEBUG(">>> new cert");
        return PATROL_VERIFY_NEW;

    case PATROL_OK: // active cert(s) found for peer
        LOG_DEBUG(">>> cert found");
        ret = PATROL_VERIFY_CHANGE;

        // make a list of pubkeys present in the chain
        size_t pubkey_list_len = chain_len;
        PatrolData *pubkey_list
            = gnutls_malloc(pubkey_list_len * sizeof(PatrolData));

        for (i = 0; i < chain_len; i++) {
            gnutls_x509_crt_init(&crt);
            r = gnutls_x509_crt_import(crt, (gnutls_datum_t *) &chain[i],
                                       GNUTLS_X509_FMT_DER);
            if (r != GNUTLS_E_SUCCESS) {
                LOG_DEBUG(">>> error importing cert #%zd: %d", i, r);
                return PATROL_ERROR;
            }

            gnutls_pubkey_init(&pubkey);
            r = gnutls_pubkey_import_x509(pubkey, crt, 0);
            if (r != GNUTLS_E_SUCCESS) {
                LOG_DEBUG(">>> error importing pubkey #%zd: %d", i, r);
                return PATROL_ERROR;
            }

#if GNUTLS_CHECK_VERSION(3,1,3)
            r = gnutls_pubkey_export2(pubkey, GNUTLS_X509_FMT_DER,
                                      (gnutls_datum_t *) &pubkey_list[i]);
#else
            pubkey_list[i] = PATROL_DATA(malloc(chain[i].size),
                                         chain[i].size);
            r = gnutls_pubkey_export(pubkey, GNUTLS_X509_FMT_DER,
                                     pubkey_list[i].data,
                                     (size_t *) &(pubkey_list[i].size));
#endif
            if (r != GNUTLS_E_SUCCESS) {
                LOG_DEBUG(">>> error exporting pubkey #%zd: %d", i, r);
                return PATROL_ERROR;
            }

            gnutls_pubkey_deinit(pubkey);
            gnutls_x509_crt_deinit(crt);
        }

        // compare active pubkeys with pubkeys in the chain
        rec = records;
        do {
            if (rec->status != PATROL_STATUS_ACTIVE)
                continue;

            for (i = 0; i < pubkey_list_len; i++) {
                if (pubkey_list[i].size == rec->pin_pubkey.size
                    && 0 == memcmp(pubkey_list[i].data, rec->pin_pubkey.data,
                                   pubkey_list[i].size)) {
                    ret = PATROL_VERIFY_OK;
                    break;
                }
            }
        } while ((rec = rec->next) != NULL && ret != PATROL_OK);

        for (i = 0; i < pubkey_list_len; i++)
            free(pubkey_list[i].data);
        free(pubkey_list);

        return ret;

    default:
        LOG_DEBUG(">>> get_certs error");
        return PATROL_ERROR;
    }
}

PatrolRC
PATROL_add_or_update_cert (const PatrolData *chain, size_t chain_len,
                           gnutls_certificate_type_t chain_type,
                           const char *host, size_t host_len,
                           const char *proto, size_t proto_len,
                           uint16_t port, PatrolPinLevel pin_level,
                           int64_t *cert_id)
{
    LOG_DEBUG(">> visit: %zu, %s, %s, %d", chain_len, host, proto, port);

    int r;
    gnutls_pubkey_t pubkey = { 0 };
    gnutls_x509_crt_t crt = { 0 };
    unsigned int i;

    PatrolRC ret = PATROL_add_cert(host, host_len, proto, proto_len, port,
                                   PATROL_STATUS_INACTIVE, chain, chain_len,
                                   NULL, 0, 0, cert_id);
    switch (ret) {
    case PATROL_OK: // cert is newly added, add pin on default level
        for (i = 0; i < chain_len; i++) {
            if (!(pin_level == i || pin_level == i - chain_len))
                continue;

            gnutls_x509_crt_init(&crt);
            r = gnutls_x509_crt_import(crt, (gnutls_datum_t *) &chain[i],
                                       GNUTLS_X509_FMT_DER);
            if (r != GNUTLS_E_SUCCESS) {
                LOG_DEBUG(">>> error importing cert #%d: %d", i, r);
                return PATROL_ERROR;
            }

            gnutls_pubkey_init(&pubkey);
            r = gnutls_pubkey_import_x509(pubkey, crt, 0);
            if (r != GNUTLS_E_SUCCESS) {
                LOG_DEBUG(">>> error importing pubkey #%d: %d", i, r);
                return PATROL_ERROR;
            }

            PatrolData pubkey_der;
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
            if (r != GNUTLS_E_SUCCESS) {
                LOG_DEBUG(">>> error exporting pubkey #%d: %d", i, r);
                return PATROL_ERROR;
            }

            time_t expiration = 0;
#if GNUTLS_CHECK_VERSION(3,1,6)
            time_t activation = 0;
            unsigned int critical;
            gnutls_x509_crt_get_private_key_usage_period(crt, &activation,
                                                         &expiration, &critical);
            LOG_DEBUG(">>> private key expiry: %ld", expiration);
#endif
            if (0 >= PATROL_set_pin_pubkey(host, host_len, proto, proto_len,
                                           port, *cert_id, pubkey_der.data,
                                           pubkey_der.size, expiration)) {
                LOG_DEBUG(">>> error pinning pubkey");
                return PATROL_ERROR;
            }

            gnutls_free(pubkey_der.data);
            gnutls_pubkey_deinit(pubkey);
            gnutls_x509_crt_deinit(crt);
            break;
        }
        return ret;

    case PATROL_DONE: // cert is already stored, mark it as seen
        PATROL_set_cert_seen(host, host_len, proto, proto_len, port,
                             *cert_id);
        return ret;

    default:
        LOG_DEBUG(">>> error adding cert");
        return PATROL_ERROR;
    }
}

int
PATROL_get_pin_level (PatrolData *chain, size_t chain_len, PatrolData pin_pubkey)
{
    LOG_DEBUG(">> PATROL_get_pin_level");

    gnutls_pubkey_t pubkey = NULL;
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

        gnutls_pubkey_init(&pubkey);
        r = gnutls_pubkey_import_x509(pubkey, crt, 0);
        gnutls_x509_crt_deinit(crt);

        if (r != GNUTLS_E_SUCCESS) {
            LOG_ERROR("get_pin_level: error importing pubkey #%zd: %d", i, r);
            gnutls_pubkey_deinit(pubkey);
            return PATROL_ERROR;
        }

        PatrolData pubkey_der;
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
            LOG_ERROR("get_pin_level: error exporting pubkey #%zd: %d", i, r);
            gnutls_free(pubkey_der.data);
            return PATROL_ERROR;
        }

        r = memcmp(pin_pubkey.data, pubkey_der.data, pubkey_der.size);
        gnutls_free(pubkey_der.data);
        if (r == 0)
            return i;
    }

    return PATROL_ERROR;
}

PatrolRC
PATROL_set_pin_from_chain (const char *host, size_t host_len,
                           const char *proto, size_t proto_len,
                           uint16_t port, int64_t cert_id,
                           PatrolPinLevel pin_level,
                           PatrolData *chain, size_t chain_len)
{
    LOG_DEBUG(">> PATROL_set_pin_level: %.*s, %.*s, %u, %" PRId64 ", %d",
              (int)host_len, host, (int)proto_len, proto, port, cert_id, pin_level);

    PatrolRecord rec = { 0 };
    gnutls_pubkey_t pubkey = NULL;
    gnutls_x509_crt_t crt = NULL;
    size_t i;
    int r;

    if (!chain_len) {
        if (PATROL_OK != PATROL_get_cert(host, host_len, proto, proto_len, port, cert_id, &rec))
            return PATROL_ERROR;
        chain = rec.chain;
        chain_len = rec.chain_len;
    }

    for (i = 0; i < chain_len; i++) {
        if (!(pin_level == i || pin_level == i - chain_len))
            continue;

        gnutls_x509_crt_init(&crt);

        r = gnutls_x509_crt_import(crt, (gnutls_datum_t *) &chain[i],
                                   GNUTLS_X509_FMT_DER);
        if (r != GNUTLS_E_SUCCESS) {
            LOG_ERROR("set_pin_level: error importing cert #%zd: %d", i, r);
            return PATROL_ERROR;
        }

        gnutls_pubkey_init(&pubkey);
        r = gnutls_pubkey_import_x509(pubkey, crt, 0);
        gnutls_x509_crt_deinit(crt);

        if (r != GNUTLS_E_SUCCESS) {
            LOG_ERROR("set_pin_level: error importing pubkey #%zd: %d", i, r);
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
            LOG_ERROR("set_pin_level: error exporting pubkey #%zd: %d", i, r);
            gnutls_free(pubkey_der.data);
            return PATROL_ERROR;
        }

        PATROL_set_pin_pubkey(host, host_len, proto, proto_len, port, cert_id,
                              pubkey_der.data, pubkey_der.size, 0);

        gnutls_free(pubkey_der.data);
        return PATROL_OK;
   }

    return PATROL_ERROR;
}

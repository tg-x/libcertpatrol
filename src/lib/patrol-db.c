#include "common.h"
#include "patrol.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

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
PATROL_set_pin_level (const char *host, size_t host_len,
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

        PATROL_set_pin(host, host_len, proto, proto_len, port, cert_id,
                       pubkey_der.data, pubkey_der.size, 0);

        gnutls_free(pubkey_der.data);
        return PATROL_OK;
   }

    return PATROL_ERROR;
}

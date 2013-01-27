#include "common.h"
#include "patrol.h"
#include "patrol-gnutls.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#ifdef HAVE_GNUTLS_DANE
# include <gnutls/dane.h>
#endif

#define GNUTLS_CHECK_VERSION(major, minor, patch)                       \
    (GNUTLS_VERSION_MAJOR > major                                       \
     || (GNUTLS_VERSION_MAJOR == major && GNUTLS_VERSION_MINOR > minor) \
     || (GNUTLS_VERSION_MAJOR == major && GNUTLS_VERSION_MINOR == minor \
         && GNUTLS_VERSION_PATCH >= patch))

/** Verify certificate chain of peer.
 */
PatrolRC
PATROL_GNUTLS_verify (const gnutls_datum_t *chain, size_t chain_len,
                      gnutls_certificate_type_t chain_type,
                      PatrolRC chain_result,
                      const char *host, size_t host_len,
                      const char *addr, size_t addr_len,
                      const char *proto, size_t proto_len,
                      uint16_t port)
{
    LOG_DEBUG(">> verify: %zu, %s, %s, %s, %d", chain_len, host, addr, proto, port);

    const char *name = host_len ? host : addr;
    size_t name_len = host_len ? host_len : addr_len;
    if (!chain_len || !name)
        return PATROL_ERROR;

    static int new_notify = -1, change_notify = -1;
    static const char *new_cmd = NULL, *change_cmd = NULL;
    static PatrolPinLevel pin_level = PATROL_PIN_END_ENTITY;
    char *buf;
    if (new_notify < 0) {
        buf = getenv("CERTPATROL_NEW_NOTIFY");
        new_notify = buf && buf[0] == '1' && buf[1] == '\0';
        new_cmd = getenv("CERTPATROL_NEW_CMD");
        if (new_cmd && new_cmd[0] == '\0')
            new_cmd = NULL;

        buf = getenv("CERTPATROL_CHANGE_NOTIFY");
        change_notify = buf && buf[0] == '1' && buf[1] == '\0';
        change_cmd = getenv("CERTPATROL_CHANGE_CMD");
        if (change_cmd && change_cmd[0] == '\0')
            change_cmd = NULL;

        buf = getenv("CERTPATROL_PIN_LEVEL");
        if (buf && buf[0] != '\0')
            pin_level = atoi(buf);
    }

#ifdef HAVE_GNUTLS_DANE
    static dane_state_t dstate = NULL;
    if (!dstate) {
        buf = getenv("CERTPATROL_IGNORE_LOCAL_RESOLVER");
        dane_state_init(&dstate,
                        (buf && buf[0] == '1' && buf[1] == '\0')
                        ? DANE_F_IGNORE_LOCAL_RESOLVER
                        : 0);
    }
    dane_verify_status_t dvstatus = 0;
    int dret = dane_verify_crt(dstate, chain, chain_len, chain_type,
                               host, proto, port, 0, 0, &dvstatus);
# ifdef DEBUG
    gnutls_datum_t dstr;
    dane_verification_status_print(dvstatus, &dstr, 0);
    LOG_DEBUG(">>> dane result: %d, %d - %.*s", dret, dvstatus, dstr.size, dstr.data);
    gnutls_free(dstr.data);
# endif
#else
    int dret = 0, dvstatus = 0;
#endif // HAVE_GNUTLS_DANE

    int r, notify;
    const char *cmd = NULL;
    PatrolRC ret = PATROL_ERROR;
    PatrolRecord *records = NULL, *rec = NULL;
    size_t records_len = 0;
    gnutls_pubkey_t pubkey;
    gnutls_x509_crt_t crt;
    int64_t cert_id = -1;
    unsigned int i;

    switch (PATROL_add_cert(name, name_len, proto, proto_len, port,
                            PATROL_STATUS_INACTIVE, chain, chain_len,
                            NULL, 0, 0, &cert_id)) {
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
            if (0 >= PATROL_set_pin(name, name_len, proto, proto_len,
                                    port, cert_id, pubkey_der.data,
                                    pubkey_der.size, expiration)) {
                LOG_DEBUG(">>> error pinning pubkey");
                return PATROL_ERROR;
            }

            gnutls_free(pubkey_der.data);
            gnutls_pubkey_deinit(pubkey);
            gnutls_x509_crt_deinit(crt);
            break;
        }
        break;

    case PATROL_DONE: // cert is already stored, mark it as seen
        PATROL_set_cert_seen(name, name_len, proto, proto_len, port,
                             cert_id);
        break;

    default:
        LOG_DEBUG(">>> error adding cert");
        return PATROL_ERROR;
    }

    switch (PATROL_get_certs(name, name_len, proto, proto_len, port,
                             PATROL_STATUS_ACTIVE, false,
                             &records, &records_len)) {
    case PATROL_DONE: // no active certs found for peer
        LOG_DEBUG(">>> new cert");

        cmd = new_cmd;
        notify = new_notify;
        break;

    case PATROL_OK: // active cert(s) found for peer
        LOG_DEBUG(">>> cert found");

        // make a list of pubkeys present in the chain
        size_t pubkey_list_len = chain_len;
        PatrolData *pubkey_list
            = malloc(pubkey_list_len * sizeof(PatrolData));

        for (i = 0; i < chain_len; i++) {
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
                LOG_DEBUG(">>> error exporting pubkey #%d: %d", i, r);
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
                LOG_DEBUG("%u vs %u", pubkey_list[i].size, rec->pin_pubkey.size);
                if (pubkey_list[i].size == rec->pin_pubkey.size
                    && 0 == memcmp(pubkey_list[i].data, rec->pin_pubkey.data,
                                   pubkey_list[i].size)) {
                    ret = PATROL_OK;
                    break;
                }
            }
        } while ((rec = rec->next) != NULL && ret != PATROL_OK);

        for (i = 0; i < pubkey_list_len; i++)
            free(pubkey_list[i].data);
        free(pubkey_list);

        cmd = change_cmd;
        notify = change_notify;
        break;

    default:
        LOG_DEBUG(">>> get_certs error");
        return PATROL_ERROR;
    }

    PatrolCmdRC cmd_ret = PATROL_CMD_ACCEPT;
    PatrolPinMode pin_mode = PATROL_PIN_EXCLUSIVE;

    if (ret != PATROL_OK && cmd != NULL) {
        cmd_ret = PATROL_exec_cmd(cmd, host, proto, port,
                                  cert_id, chain_result, dret, dvstatus, !notify);
    }

    switch (cmd_ret) {
    case PATROL_CMD_ACCEPT_ADD:
        pin_mode = PATROL_PIN_MULTIPLE;
        // fall thru
    case PATROL_CMD_ACCEPT:
        PATROL_set_cert_active(name, name_len, proto, proto_len, port,
                               cert_id, pin_mode);
        // fall thru
    case PATROL_CMD_CONTINUE:
        ret = PATROL_OK;
        break;
    case PATROL_CMD_REJECT:
        PATROL_set_cert_status(name, name_len, proto, proto_len, port,
                               cert_id, PATROL_STATUS_REJECTED);
        // fall thru
    default:
        ret = PATROL_ERROR;
    }

    return ret;
}

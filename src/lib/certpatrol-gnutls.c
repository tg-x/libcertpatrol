#include "common.h"
#include "certpatrol.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

#define GNUTLS_CHECK_VERSION(major, minor, patch)                       \
    (GNUTLS_VERSION_MAJOR > major                                       \
     || (GNUTLS_VERSION_MAJOR == major && GNUTLS_VERSION_MINOR > minor) \
     || (GNUTLS_VERSION_MAJOR == major && GNUTLS_VERSION_MINOR == minor \
         && GNUTLS_VERSION_PATCH >= patch))

/** Verify certificate chain of peer.
  */
CertPatrolRC
CertPatrol_GnuTLS_verify (const CertPatrolData *chain, unsigned int chain_len,
                          const char *host, size_t host_len,
                          const char *addr, size_t addr_len,
                          const char *proto, size_t proto_len, int port)
{
    LOG_DEBUG(">> verify: %u, %s, %s, %s, %d\n", chain_len, host, addr, proto, port);

    const char *name = host_len ? host : addr;
    size_t name_len = host_len ? host_len : addr_len;
    if (!chain_len || !name)
        return CERTPATROL_ERROR;

    static int new_notify = -1, change_notify = -1, pin_level = 0;
    static const char *new_cmd = NULL, *change_cmd = NULL;
    char *buf;
    if (new_notify < 0) {
        buf = getenv("CERTPATROL_NEW_NOTIFY");
        new_notify = buf ? (buf[0] == '1' && buf[1] == '\0') : 0;
        new_cmd = getenv("CERTPATROL_NEW_CMD");
        if (new_cmd && new_cmd[0] == '\0')
            new_cmd = NULL;

        buf = getenv("CERTPATROL_CHANGE_NOTIFY");
        change_notify = buf ? (buf[0] == '1' && buf[1] == '\0') : 0;
        change_cmd = getenv("CERTPATROL_CHANGE_CMD");
        if (change_cmd && change_cmd[0] == '\0')
            change_cmd = NULL;

        buf = getenv("CERTPATROL_PIN_LEVEL");
        if (buf && buf[0] != '\0')
            pin_level = atoi(buf);
    }

    int r;
    CertPatrolRC ret = CERTPATROL_ERROR;
    CertPatrolCmdRC cmd_ret = CERTPATROL_CMD_ACCEPT;
    CertPatrolRecord *records = NULL, *rec = NULL;
    size_t records_len = 0;
    gnutls_pubkey_t pubkey;
    gnutls_x509_crt_t crt;
    CertPatrolInt64 cert_id = -1;
    unsigned int i;

    switch (CertPatrol_add_cert(name, name_len, proto, proto_len, port,
                                CERTPATROL_STATUS_INACTIVE, chain, chain_len,
                                NULL, 0, 0, &cert_id)) {
    case CERTPATROL_OK: // cert is newly added, add pin on default level
        for (i = 0; i < chain_len; i++) {
            if (!(pin_level == i || pin_level == i - chain_len))
                continue;

            gnutls_x509_crt_init(&crt);

            r = gnutls_x509_crt_import(crt, (gnutls_datum_t *) &chain[i],
                                       GNUTLS_X509_FMT_DER);
            if (r != GNUTLS_E_SUCCESS) {
                LOG_DEBUG(">>> error importing cert #%d: %d\n", i, r);
                return CERTPATROL_ERROR;
            }

            gnutls_pubkey_init(&pubkey);
            r = gnutls_pubkey_import_x509(pubkey, crt, 0);
            if (r != GNUTLS_E_SUCCESS) {
                LOG_DEBUG(">>> error importing pubkey #%d: %d\n", i, r);
                return CERTPATROL_ERROR;
            }

            CertPatrolData pubkey_der;
#if GNUTLS_CHECK_VERSION(3, 1, 3)
            r = gnutls_pubkey_export2(pubkey, GNUTLS_X509_FMT_DER, &pubkey_der);
#else
            pubkey_der = CERTPATROL_DATA(gnutls_malloc(chain[i].size), chain[i].size);
            r = gnutls_pubkey_export(pubkey, GNUTLS_X509_FMT_DER,
                                     pubkey_der.data, (size_t *) &(pubkey_der.size));
#endif
            if (r != GNUTLS_E_SUCCESS) {
                LOG_DEBUG(">>> error exporting pubkey #%d: %d\n", i, r);
                return CERTPATROL_ERROR;
            }

            time_t expiration = 0;
            /* TODO
            time_t activation = 0;
            unsigned int critical;
            gnutls_x509_crt_get_private_key_usage_period(cert, &activation,
                                                         &expiration, &critical);
            */

            if (0 >= CertPatrol_set_pin(name, name_len, proto, proto_len,
                                        port, cert_id, pubkey_der.data,
                                        pubkey_der.size, expiration)) {
                LOG_DEBUG(">>> error pinning pubkey\n");
                return CERTPATROL_ERROR;
            }

            gnutls_free(pubkey_der.data);
            gnutls_pubkey_deinit(pubkey);
            gnutls_x509_crt_deinit(crt);
            break;
        }
        break;

    case CERTPATROL_DONE: // cert is already stored, mark it as seen
        CertPatrol_set_cert_seen(name, name_len, proto, proto_len, port,
                                 cert_id);
        break;

    default:
        LOG_DEBUG(">>> error adding cert\n");
        return CERTPATROL_ERROR;
    }

    switch (CertPatrol_get_certs(name, name_len, proto, proto_len, port,
                                 CERTPATROL_STATUS_ACTIVE, CERTPATROL_FALSE,
                                 &records, &records_len)) {
    case CERTPATROL_DONE: // no results found
        LOG_DEBUG(">>> new cert\n");

        if (new_cmd) {
            if (new_notify)
                CertPatrol_exec_cmd(new_cmd, "new", host, proto,
                                    port, cert_id, CERTPATROL_FALSE);
            else
                cmd_ret = CertPatrol_exec_cmd(new_cmd, "new", host, proto,
                                              port, cert_id, CERTPATROL_TRUE);
        }

        if (cmd_ret == CERTPATROL_CMD_ACCEPT) {
            CertPatrol_set_cert_active(name, name_len, proto, proto_len,
                                       port, cert_id, CERTPATROL_PIN_EXCLUSIVE);
            ret = CERTPATROL_OK;
        }
        break;

    case CERTPATROL_OK: // results found
        LOG_DEBUG(">>> cert found\n");

        // make a list of pubkeys present in the chain
        size_t pubkey_list_len = chain_len;
        CertPatrolData *pubkey_list
            = malloc(pubkey_list_len * sizeof(CertPatrolData));

        for (i = 0; i < chain_len; i++) {
            gnutls_x509_crt_init(&crt);
            r = gnutls_x509_crt_import(crt, (gnutls_datum_t *) &chain[i],
                                       GNUTLS_X509_FMT_DER);
            if (r != GNUTLS_E_SUCCESS) {
                LOG_DEBUG(">>> error importing cert #%d: %d\n", i, r);
                return CERTPATROL_ERROR;
            }

            gnutls_pubkey_init(&pubkey);
            r = gnutls_pubkey_import_x509(pubkey, crt, 0);
            if (r != GNUTLS_E_SUCCESS) {
                LOG_DEBUG(">>> error importing pubkey #%d: %d\n", i, r);
                return CERTPATROL_ERROR;
            }

#if GNUTLS_CHECK_VERSION(3, 1, 3)
            r = gnutls_pubkey_export2(pubkey, GNUTLS_X509_FMT_DER, &pubkey_list[i]);
#else
            pubkey_list[i] = CERTPATROL_DATA(malloc(chain[i].size), chain[i].size);
            r = gnutls_pubkey_export(pubkey, GNUTLS_X509_FMT_DER,
                                     pubkey_list[i].data, (size_t *) &(pubkey_list[i].size));
#endif
            if (r != GNUTLS_E_SUCCESS) {
                LOG_DEBUG(">>> error exporting pubkey #%d: %d\n", i, r);
                return CERTPATROL_ERROR;
            }

            gnutls_pubkey_deinit(pubkey);
            gnutls_x509_crt_deinit(crt);
        }

        // compare active pubkeys with pubkeys in the chain
        rec = records;
        do {
            if (rec->status != CERTPATROL_STATUS_ACTIVE)
                continue;

            for (i = 0; i < pubkey_list_len; i++) {
                LOG_DEBUG("%u vs %u\n", pubkey_list[i].size, rec->pin_pubkey.size);
                if (pubkey_list[i].size == rec->pin_pubkey.size
                    && 0 == memcmp(pubkey_list[i].data, rec->pin_pubkey.data,
                                   pubkey_list[i].size)) {
                    ret = CERTPATROL_OK;
                    break;
                }
            }
        } while ((rec = rec->next) != NULL && ret != CERTPATROL_OK);

        for (i = 0; i < pubkey_list_len; i++)
            free(pubkey_list[i].data);
        free(pubkey_list);

        if (ret != CERTPATROL_OK && change_cmd != NULL) {
            if (change_notify)
                CertPatrol_exec_cmd(change_cmd, "change", host, proto,
                                    port, cert_id, CERTPATROL_FALSE);
            else
                cmd_ret = CertPatrol_exec_cmd(change_cmd, "change", host, proto,
                                              port, cert_id, CERTPATROL_TRUE);
        }

        CertPatrolPinMode pin_mode = CERTPATROL_PIN_EXCLUSIVE;
        switch (cmd_ret) {
        case CERTPATROL_CMD_ACCEPT_ADD:
            pin_mode = CERTPATROL_PIN_MULTIPLE;
            // fall thru
        case CERTPATROL_CMD_ACCEPT:
            CertPatrol_set_cert_active(name, name_len, proto, proto_len, port,
                                       cert_id, pin_mode);
            // fall thru
        case CERTPATROL_CMD_CONTINUE:
            ret = CERTPATROL_OK;
            break;
        case CERTPATROL_CMD_REJECT:
            CertPatrol_set_cert_status(name, name_len, proto, proto_len, port,
                                       cert_id, CERTPATROL_STATUS_REJECTED);
            // fall thru
        default:
            ret = CERTPATROL_ERROR;
        }

        break;

    default:
        LOG_DEBUG(">>> get_certs error\n");
    }

    return ret;
}

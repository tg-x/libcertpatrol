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

/** Visit peer.
 *
 * Update seen count and last seen values,
 * or add a new inactive certificate if it's not stored yet.
 */
PatrolRC
PATROL_GNUTLS_visit (const PatrolData *chain, size_t chain_len,
                     gnutls_certificate_type_t chain_type,
                     const char *host, size_t host_len,
                     const char *proto, size_t proto_len,
                     uint16_t port, PatrolPinLevel pin_level, int64_t *cert_id)
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
            if (0 >= PATROL_set_pin(host, host_len, proto, proto_len,
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

/** Verify certificate chain against pin settings.
 */
PatrolVerifyRC
PATROL_GNUTLS_verify_pin (const PatrolData *chain, size_t chain_len,
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
                LOG_DEBUG("%u vs %u", pubkey_list[i].size, rec->pin_pubkey.size);
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

/** Verify certificate chain of peer using available pinning protocols.
 */
PatrolRC
PATROL_GNUTLS_verify (const gnutls_datum_t *chain, size_t chain_len,
                      gnutls_certificate_type_t chain_type,
                      int chain_result, //unsigned int chain_status,
                      const char *host, size_t host_len,
                      const char *addr, size_t addr_len,
                      const char *proto, size_t proto_len,
                      uint16_t port)
{
    LOG_DEBUG(">> verify: %zu, %s, %s, %s, %d", chain_len, host, addr, proto, port);

    gnutls_global_init(); // TODO deinit

    const char *name = host_len ? host : addr;
    size_t name_len = host_len ? host_len : addr_len;
    if (!chain_len || !name)
        return PATROL_ERROR;

    static int new_action = -1, change_action = -1;
    static const char *notify_cmd = NULL, *dialog_cmd = NULL;
    static PatrolPinLevel pin_level = PATROL_PIN_END_ENTITY;
    char *buf;
    if (new_action < 0) {
        buf = getenv("CERTPATROL_NEW_ACTION");
        if (buf && buf[0] != '\0')
            new_action = atoi(buf);

        buf = getenv("CERTPATROL_CHANGE_ACTION");
        if (buf && buf[0] != '\0')
            change_action = atoi(buf);

        buf = getenv("CERTPATROL_PIN_LEVEL");
        if (buf && buf[0] != '\0')
            pin_level = atoi(buf);

        notify_cmd = getenv("CERTPATROL_NOTIFY_CMD");
        if (notify_cmd && notify_cmd[0] == '\0')
            notify_cmd = NULL;

        dialog_cmd = getenv("CERTPATROL_DIALOG_CMD");
        if (dialog_cmd && dialog_cmd[0] == '\0')
            dialog_cmd = NULL;
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
    dane_verify_status_t dstatus = 0;
    int dret = dane_verify_crt(dstate, chain, chain_len, chain_type,
                               host, proto, port, 0, 0, &dstatus);
# ifdef DEBUG
    gnutls_datum_t dstr;
    dane_verification_status_print(dstatus, &dstr, 0);
    LOG_DEBUG(">>> dane result: %d, %d - %.*s", dret, dstatus, dstr.size, dstr.data);
    gnutls_free(dstr.data);
# endif
#else
    int dret = 0, dstatus = 0;
#endif // HAVE_GNUTLS_DANE

    PatrolRC ret = PATROL_ERROR;
    PatrolEvent event = PATROL_EVENT_NONE;
    PatrolAction action = PATROL_ACTION_NONE;
    int64_t cert_id = -1;

    if (0 > PATROL_GNUTLS_visit(chain, chain_len, chain_type, name, name_len,
                                proto, proto_len, port, pin_level, &cert_id)) {
        LOG_DEBUG(">>> error during visit()");
        return PATROL_ERROR;
    }

    switch (PATROL_GNUTLS_verify_pin(chain, chain_len, chain_type,
                                     name, name_len,
                                     proto, proto_len, port)) {
    case PATROL_VERIFY_OK:
        break;

    case PATROL_VERIFY_NEW:
        event = PATROL_EVENT_NEW;
        if (new_action || chain_result != PATROL_OK)
            action = new_action;
        break;

    case PATROL_VERIFY_CHANGE:
        event = PATROL_EVENT_CHANGE;
        action = change_action;
        break;

    default:
        LOG_DEBUG(">>> error during verify_pin()");
        return PATROL_ERROR;
    }

    const char *cmd = NULL;
    PatrolCmdRC cmd_ret = PATROL_CMD_ACCEPT;
    PatrolPinMode pin_mode = PATROL_PIN_EXCLUSIVE;

    if (action) {
        cmd = (action == PATROL_ACTION_NOTIFY) ? notify_cmd : dialog_cmd;
        if (cmd)
            cmd_ret = PATROL_exec_cmd(cmd,
                                      host, proto, port, cert_id, chain_result,
                                      dret, dstatus, NULL, event, action);
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
                int chain_result, //unsigned int chain_status,
                GetIssuer get_issuer, const void *ca_list,
                const char *host, size_t host_len,
                const char *addr, size_t addr_len,
                const char *proto, size_t proto_len,
                uint16_t port, gnutls_datum_t **ret_chain, size_t *ret_chain_len)
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
PATROL_GNUTLS_free_completed_chain (gnutls_datum_t *new_chain, size_t new_len, size_t old_len)
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
                                              int chain_result, //unsigned int chain_status,
                                              const gnutls_x509_trust_list_t trust_list,
                                              const char *host, size_t host_len,
                                              const char *addr, size_t addr_len,
                                              const char *proto, size_t proto_len,
                                              uint16_t port, gnutls_datum_t **new_chain,
                                              size_t *new_chain_len)
{
    return complete_chain(chain, chain_len, chain_type, chain_result,
                         (GetIssuer) gnutls_x509_trust_list_get_issuer, trust_list,
                          host, host_len, addr, addr_len,
                          proto, proto_len, port, new_chain, new_chain_len);
}

PatrolRC
PATROL_GNUTLS_complete_chain_from_credentials (const gnutls_datum_t *chain, size_t chain_len,
                                               gnutls_certificate_type_t chain_type,
                                               int chain_result, //unsigned int chain_status,
                                               const gnutls_certificate_credentials_t credentials,
                                               const char *host, size_t host_len,
                                               const char *addr, size_t addr_len,
                                               const char *proto, size_t proto_len,
                                               uint16_t port, gnutls_datum_t **new_chain,
                                              size_t *new_chain_len)
{
    return complete_chain(chain, chain_len, chain_type, chain_result,
                          (GetIssuer) gnutls_certificate_get_issuer, credentials,
                          host, host_len, addr, addr_len,
                          proto, proto_len, port, new_chain, new_chain_len);
}

PatrolRC
PATROL_GNUTLS_verify_trust_list (const gnutls_datum_t *chain, size_t chain_len,
                                 gnutls_certificate_type_t chain_type,
                                 int chain_result, //unsigned int chain_status,
                                 const gnutls_x509_trust_list_t trust_list,
                                 const char *host, size_t host_len,
                                 const char *addr, size_t addr_len,
                                 const char *proto, size_t proto_len,
                                 uint16_t port)
{
    gnutls_datum_t *new_chain = NULL;
    size_t new_chain_len = 0;

    if (PATROL_OK != complete_chain(chain, chain_len, chain_type, chain_result,
                                    (GetIssuer) gnutls_x509_trust_list_get_issuer, trust_list,
                                    host, host_len, addr, addr_len,
                                    proto, proto_len, port, &new_chain, &new_chain_len))
        return PATROL_ERROR;

    PatrolRC ret
        = PATROL_GNUTLS_verify(new_chain, new_chain_len,
                               chain_type, chain_result, host, host_len,
                               addr, addr_len,
                               proto, proto_len, port);

    PATROL_GNUTLS_free_completed_chain(new_chain, new_chain_len, chain_len);

    return ret;
}

PatrolRC
PATROL_GNUTLS_verify_credentials (const gnutls_datum_t *chain, size_t chain_len,
                                  gnutls_certificate_type_t chain_type,
                                  int chain_result, //unsigned int chain_status,
                                  const gnutls_certificate_credentials_t credentials,
                                  const char *host, size_t host_len,
                                  const char *addr, size_t addr_len,
                                  const char *proto, size_t proto_len,
                                  uint16_t port)
{
    gnutls_datum_t *new_chain = NULL;
    size_t new_chain_len = 0;

    if (PATROL_OK != complete_chain(chain, chain_len, chain_type, chain_result,
                                    (GetIssuer) gnutls_certificate_get_issuer, credentials,
                                    host, host_len, addr, addr_len,
                                    proto, proto_len, port, &new_chain, &new_chain_len))
        return PATROL_ERROR;

    PatrolRC ret
        = PATROL_GNUTLS_verify(new_chain, new_chain_len,
                               chain_type, chain_result, host, host_len,
                               addr, addr_len,
                               proto, proto_len, port);

    PATROL_GNUTLS_free_completed_chain(new_chain, new_chain_len, chain_len);

    return ret;
}

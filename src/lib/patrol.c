#include "common.h"
#include "patrol.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

#ifdef HAVE_GNUTLS_DANE
# include <gnutls/dane.h>
#endif

PatrolRC
PATROL_init ()
{
    gnutls_global_init();
    return PATROL_init_db();
}

PatrolRC
PATROL_deinit ()
{
    gnutls_global_deinit();
    return PATROL_deinit_db();
}

PatrolRC
PATROL_check (const PatrolConfig *cfg,
              const PatrolData *chain, size_t chain_len,
              PatrolCertType chain_type,
              int chain_result, //unsigned int chain_status,
              const char *host, const char *addr, const char *proto,
              uint16_t port)
{
    LOG_DEBUG(">> check: %zu, %d, %d, %s, %s, %s, %d",
              chain_len, chain_type, chain_result, host, addr, proto, port);

    const char *name = host ? host : addr;
    if (!chain_len || !name)
        return PATROL_ERROR;

    int dane_result = 0;
    unsigned int dane_status = 0;
#ifdef HAVE_GNUTLS_DANE
    static dane_state_t dane_state = NULL;

    if (cfg->check_flags & PATROL_CHECK_DANE) {
        if (!dane_state)
            dane_state_init(&dane_state, cfg->dane_flags);
        dane_result = dane_verify_crt(dane_state, chain, chain_len, chain_type,
                                      host, proto, port, 0, 0, &dane_status);
# ifdef DEBUG
        gnutls_datum_t dstr;
        dane_verification_status_print(dane_status, &dstr, 0);
        LOG_DEBUG(">>> dane result: %d, %d - %.*s",
                  dane_result, dane_status, dstr.size, dstr.data);
        gnutls_free(dstr.data);
# endif
    }
#endif // HAVE_GNUTLS_DANE

    PatrolID id = { 0 };
    switch (PATROL_add_cert(host, proto, port, PATROL_STATUS_INACTIVE,
                            chain, chain_len, chain_type, NULL, 0, &id)) {
    case PATROL_OK: // cert is newly added
        break;
    case PATROL_DONE: // cert is already stored
        if (cfg->flags & PATROL_CONFIG_UPDATE_SEEN)
            PATROL_set_cert_seen(host, proto, port, id);
        break;
    default:
        return PATROL_ERROR;
    }

    PatrolRC ret = PATROL_OK;
    PatrolAction action = PATROL_ACTION_NONE;

    if (chain_result != PATROL_OK
#ifdef HAVE_GNUTLS_DANE
        || dane_status & DANE_VERIFY_CERT_DIFFERS
        || dane_status & DANE_VERIFY_CA_CONSTRAINS_VIOLATED
#endif
        ) {

        ret = PATROL_ERROR;
        action = PATROL_ACTION_DIALOG;
    }

    PatrolVerifyRC result = PATROL_verify_chain(chain, chain_len, chain_type,
                                                name, proto, port);
    switch (result) {
    case PATROL_VERIFY_OK:
        LOG_DEBUG(">>> verify: OK");
        if (ret == PATROL_OK)
            return PATROL_OK;
        break;

    case PATROL_VERIFY_NEW:
        LOG_DEBUG(">>> verify: NEW");
        if (ret == PATROL_OK) {
            action = cfg->new_action;
            if (action < PATROL_ACTION_DIALOG)
                PATROL_set_pubkey_from_chain(host, proto, port, id,
                                             cfg->pin_level, chain, chain_len);

                PATROL_set_cert_active(host, proto, port, id, PATROL_PIN_MULTIPLE);
        }
        break;

    case PATROL_VERIFY_CHANGE:
        LOG_DEBUG(">>> verify: CHANGE");
        if (ret == PATROL_OK) {
            ret = PATROL_ERROR;
            action = cfg->change_action;
        }
        break;

    case PATROL_VERIFY_REJECT:
        LOG_DEBUG(">>> verify: REJECT");
        ret = PATROL_ERROR;
        action = cfg->reject_action;
        break;

    default:
        LOG_DEBUG(">>> error verifying chain");
        return PATROL_ERROR;
    }

    if (action) {
        const char *cmd
            = (action == PATROL_ACTION_DIALOG)
            ? cfg->dialog_cmd : cfg->notify_cmd;
        if (cmd) {
            PatrolCmdRC cmd_ret
                = PATROL_exec_cmd(cmd, host, proto, port, id, chain_result,
                                  dane_result < 0 ? dane_result : dane_status,
                                  NULL, result, action);
            switch (cmd_ret) {
            case PATROL_CMD_NONE:
                return ret;
            case PATROL_CMD_ACCEPT:
            case PATROL_CMD_CONTINUE:
                return PATROL_OK;
            case PATROL_CMD_REJECT:
            default:
                return PATROL_ERROR;
            }
        }
    }

    return ret;
}

PatrolCmdRC
PATROL_exec_cmd (const char *cmd, const char *host, const char *proto,
                 uint16_t port, PatrolID id, int chain_result,
                 int dane_result, const char *app_name,
                 PatrolVerifyRC result, PatrolAction action)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return PATROL_ERROR;
    }
    if (pid == 0) {
        char prt[6], res[7], cres[7], dres[7], id_str[PATROL_ID_STR_SIZE];
        snprintf(prt, 6, "%u", port);
        snprintf(res, 7, "%d", result);
        snprintf(cres, 7, "%d", chain_result);
        snprintf(dres, 7, "%d", dane_result);
        PATROL_get_id_str(id, id_str);

        char *app = (char *) app_name;
        if (!app_name) {
            char *cmd = malloc(64);
            snprintf(cmd, 64, "ps -o args= -p %lu", (unsigned long) getpid());
            FILE *pipe = popen(cmd, "r");
            if (pipe) {
                app = malloc(4096);
                fgets(app, 4096, pipe);
                pclose(pipe);
            }
            if (!app) {
                app = malloc(32);
                snprintf(app, 32, "PID %lu", (unsigned long) getpid());
            }
        }

        LOG_DEBUG(">> exec_cmd: %s --host %s --proto %s --port %s --id %s "
                  "--result %s --chain-result %s "
                  "--dane-result %s -- %s",
                  cmd, host, proto, prt, id_str, res, cres, dres, app);
        execlp(cmd, cmd, "--host", host, "--proto", proto, "--port", prt,
               "--id", id_str, "--result", res, "--chain-result", cres,
               "--dane-result", dres, "--", app, NULL);
        perror("exec");
        _exit(-1);
    }

    if (action != PATROL_ACTION_NOTIFY) {
        int status = 0;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            LOG_DEBUG(">>> cmd returned %d", WEXITSTATUS(status));
            return WEXITSTATUS(status);
        }
        return PATROL_ERROR;
    } else {
        return PATROL_CMD_NONE;
    }
}

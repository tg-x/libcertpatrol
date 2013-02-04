#include "common.h"
#include "patrol.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>

#ifdef HAVE_GNUTLS_DANE
# include <gnutls/dane.h>
#endif

static dane_state_t dstate = NULL;

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
              PatrolChainType chain_type,
              int chain_result, //unsigned int chain_status,
              const char *host, const char *addr, const char *proto,
              uint16_t port)
{
    LOG_DEBUG(">> check: %zu, %s, %s, %s, %d",
              chain_len, host, addr, proto, port);

    const char *name = host ? host : addr;
    if (!chain_len || !name)
        return PATROL_ERROR;

    int dret = 0;
    unsigned int dstatus = 0;
#ifdef HAVE_GNUTLS_DANE
    if (cfg->check_flags & PATROL_CHECK_DANE) {
        if (!dstate)
            dane_state_init(&dstate, cfg->dane_flags);
        dret = dane_verify_crt(dstate, chain, chain_len, chain_type,
                               host, proto, port, 0, 0, &dstatus);
# ifdef DEBUG
        gnutls_datum_t dstr;
        dane_verification_status_print(dstatus, &dstr, 0);
        LOG_DEBUG(">>> dane result: %d, %d - %.*s",
                  dret, dstatus, dstr.size, dstr.data);
        gnutls_free(dstr.data);
# endif
    }
#endif // HAVE_GNUTLS_DANE

    PatrolEvent event = PATROL_EVENT_NONE;
    PatrolAction action = PATROL_ACTION_NONE;
    PatrolID id = { 0 };

    if (0 > PATROL_add_or_update_cert(chain, chain_len, chain_type,
                                      name, proto, port,
                                      cfg->pin_level, &id)) {
        LOG_DEBUG(">>> error while storing chain");
        return PATROL_ERROR;
    }

    switch (PATROL_verify_chain(chain, chain_len, chain_type,
                                name, proto, port)) {
    case PATROL_VERIFY_OK:
        LOG_DEBUG(">>> verify: OK");
        break;

    case PATROL_VERIFY_NEW:
        LOG_DEBUG(">>> verify: NEW");
        event = PATROL_EVENT_NEW;
        if (cfg->new_action || chain_result != PATROL_OK)
            action = cfg->new_action;
        if (cfg->new_action < PATROL_ACTION_DIALOG)
            PATROL_set_cert_active(host, proto, port, id, PATROL_PIN_MULTIPLE);
        break;

    case PATROL_VERIFY_CHANGE:
        LOG_DEBUG(">>> verify: CHANGE");
        event = PATROL_EVENT_CHANGE;
        action = cfg->change_action;
        break;

    case PATROL_VERIFY_REJECT:
        LOG_DEBUG(">>> verify: REJECT");
        event = PATROL_EVENT_REJECT;
        action = cfg->reject_action;
        break;

    default:
        LOG_DEBUG(">>> error while verifying chain");
        return PATROL_ERROR;
    }

    const char *cmd = NULL;
    PatrolCmdRC cmd_ret = PATROL_CMD_ACCEPT;

    if (action) {
        cmd = (action == PATROL_ACTION_NOTIFY)
            ? cfg->notify_cmd : cfg->dialog_cmd;
        if (cmd)
            cmd_ret = PATROL_exec_cmd(cmd, host, proto, port, id, chain_result,
                                      dret, dstatus, NULL, event, action);
    }

    switch (event) {
    case PATROL_EVENT_NEW:
    case PATROL_EVENT_CHANGE:
        switch (cmd_ret) {
        case PATROL_CMD_ACCEPT:
        case PATROL_CMD_CONTINUE:
            return PATROL_OK;
        case PATROL_CMD_REJECT:
        default:
            return PATROL_ERROR;
        }
    case PATROL_EVENT_REJECT:
    default:
        return PATROL_ERROR;
    }
}

PatrolCmdRC
PATROL_exec_cmd (const char *cmd, const char *host, const char *proto,
                 uint16_t port, PatrolID id, int chain_result,
                 int dane_result, int dane_status, const char *app_name,
                 PatrolEvent event, PatrolAction action)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return PATROL_ERROR;
    }
    if (pid == 0) {
        char prt[6], cres[7], dres[7], dstatus[7], id_str[PATROL_ID_STR_SIZE];
        snprintf(prt, 6, "%u", port);
        snprintf(cres, 7, "%d", chain_result);
        snprintf(dres, 7, "%d", dane_result);
        snprintf(dstatus, 7, "%d", dane_status);
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

        const char *ev = NULL;
        switch (event) {
        case PATROL_EVENT_NEW:
            ev = "--new";
            break;
        case PATROL_EVENT_CHANGE:
            ev = "--change";
            break;
        case PATROL_EVENT_REJECT:
            ev = "--reject";
            break;
        default:
            break;
        }

        LOG_DEBUG(">> exec_cmd: %s --host %s --proto %s --port %s --id %s "
                  "--chain-result %s --dane-result %s --dane-status %s "
                  "%s -- %s",
                  cmd, host, proto, prt, id_str, cres, dres, dstatus,
                  ev, app);
        execlp(cmd, cmd, "--host", host, "--proto", proto, "--port", prt,
               "--id", id_str, "--chain-result", cres, "--dane-result", dres,
               "--dane-status", dstatus, ev, "--", app, NULL);
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
        return PATROL_CMD_ACCEPT;
    }
}

PatrolRC
PATROL_get_peer_addr (int fd, int *proto,
                      char *protoname, size_t protonamelen,
                      uint16_t *port, char *addrstr)
{
    socklen_t length = sizeof(int);

#if defined(SO_PROTOCOL) || defined(SO_PROTOTYPE)
# ifdef SO_PROTOCOL // Linux
    getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, proto, &length);
# else // Solaris
    getsockopt(fd, SOL_SOCKET, SO_PROTOTYPE, proto, &length);
# endif
    if (protoname != NULL) {
        struct protoent *ent = getprotobynumber(*proto);
        strncpy(protoname, ent->p_name, protonamelen);
    }
#else // BSD
    getsockopt(fd, SOL_SOCKET, SO_TYPE, proto, &length);

    switch (*proto) {
    case SOCK_STREAM:
        *proto = 6;
        strcpy(protoname, "tcp");
        break;
    case SOCK_DGRAM:
        *proto = 17;
        strcpy(protoname, "udp");
        break;
    }
#endif
    LOG_DEBUG(">> proto: %d, %s", *proto, protoname);

    struct sockaddr addr;
    socklen_t addrlen = sizeof(struct sockaddr);
    getpeername(fd, &addr, &addrlen);

    if (addr.sa_family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;
        *port = ntohs(addr6->sin6_port);
        if (addrstr != NULL)
            inet_ntop(addr.sa_family, &(addr6->sin6_addr), addrstr, INET6_ADDRSTRLEN);
    } else {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
        *port = ntohs(addr4->sin_port);
        if (addrstr != NULL)
            inet_ntop(addr.sa_family, &(addr4->sin_addr), addrstr, INET_ADDRSTRLEN);
    }

    return PATROL_OK;
}

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

void
PATROL_init ()
{
    gnutls_global_init();
}

void
PATROL_deinit ()
{
    gnutls_global_deinit();
}

PatrolRC
PATROL_get_config (PatrolConfig *c)
{
    LOG_DEBUG("PATROL_get_config");

    char *buf;
    buf = getenv("CERTPATROL_NEW_ACTION");
    if (buf && buf[0] != '\0')
        c->new_action = atoi(buf);
    else
        c->new_action = PATROL_ACTION_NOTIFY;

    buf = getenv("CERTPATROL_CHANGE_ACTION");
    if (buf && buf[0] != '\0')
        c->change_action = atoi(buf);
    else
        c->change_action = PATROL_ACTION_DIALOG;

    buf = getenv("CERTPATROL_REJECT_ACTION");
    if (buf && buf[0] != '\0')
        c->reject_action = atoi(buf);
    else
        c->reject_action = PATROL_ACTION_NOTIFY;

    buf = getenv("CERTPATROL_PIN_LEVEL");
    if (buf && buf[0] != '\0')
        c->pin_level = atoi(buf);
    else
        c->pin_level = PATROL_PIN_END_ENTITY;

    buf = getenv("CERTPATROL_IGNORE_LOCAL_RESOLVER");
    unsigned int dflags;
    if (buf && buf[0] == '1' && buf[1] == '\0')
        dflags = DANE_F_IGNORE_LOCAL_RESOLVER;
    else
        dflags = 0;

    if (c->dane_flags != dflags) {
        c->dane_flags = dflags;
        dstate = NULL;
    }

    c->notify_cmd = getenv("CERTPATROL_NOTIFY_CMD");
    if (c->notify_cmd && c->notify_cmd[0] == '\0')
        c->notify_cmd = NULL;

    c->dialog_cmd = getenv("CERTPATROL_DIALOG_CMD");
    if (c->dialog_cmd && c->dialog_cmd[0] == '\0')
        c->dialog_cmd = NULL;

    return PATROL_OK;
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
    size_t name_len = host ? strlen(host) : strlen(addr);
    size_t proto_len = strlen(proto);
    if (!chain_len || !name)
        return PATROL_ERROR;

    int dret = 0;
    unsigned int dstatus = 0;
#ifdef HAVE_GNUTLS_DANE
    if (cfg->check & PATROL_CHECK_DANE) {
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
    int64_t cert_id = -1;

    if (0 > PATROL_add_or_update_cert(chain, chain_len, chain_type,
                                      name, name_len, proto, proto_len, port,
                                      cfg->pin_level, &cert_id)) {
        LOG_DEBUG(">>> error while storing chain");
        return PATROL_ERROR;
    }

    switch (PATROL_verify_chain(chain, chain_len, chain_type,
                                name, name_len, proto, proto_len, port)) {
    case PATROL_VERIFY_OK:
        break;

    case PATROL_VERIFY_NEW:
        event = PATROL_EVENT_NEW;
        if (cfg->new_action || chain_result != PATROL_OK)
            action = cfg->new_action;
        break;

    case PATROL_VERIFY_CHANGE:
        event = PATROL_EVENT_CHANGE;
        action = cfg->change_action;
        break;

    default:
        LOG_DEBUG(">>> error while verifying chain");
        return PATROL_ERROR;
    }

    const char *cmd = NULL;
    PatrolCmdRC cmd_ret = PATROL_CMD_ACCEPT;

    if (action) {
        cmd = (action == PATROL_ACTION_NOTIFY) ? cfg->notify_cmd : cfg->dialog_cmd;
        if (cmd)
            cmd_ret = PATROL_exec_cmd(cmd,
                                      host, proto, port, cert_id, chain_result,
                                      dret, dstatus, NULL, event, action);
    }

    switch (cmd_ret) {
    case PATROL_CMD_CONTINUE:
    case PATROL_CMD_ACCEPT:
        return PATROL_OK;
    case PATROL_CMD_REJECT:
    default:
        return PATROL_ERROR;
    }
}

PatrolCmdRC
PATROL_exec_cmd (const char *cmd, const char *host, const char *proto,
                 uint16_t port, int64_t cert_id, int chain_result,
                 int dane_result, int dane_status, const char *app_name,
                 PatrolEvent event, PatrolAction action)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return PATROL_ERROR;
    }
    if (pid == 0) {
        char id[21], prt[6], cres[7], dres[7], dstatus[7];
        snprintf(prt, 6, "%u", port);
        snprintf(cres, 7, "%d", chain_result);
        snprintf(dres, 7, "%d", dane_result);
        snprintf(dstatus, 7, "%d", dane_status);
        snprintf(id, 21, "%" PRId64, cert_id);

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
                  "--chain-result %s --dane-result %s --dane-status %s "
                  "--%s -- %s",
                  cmd, host, proto, prt, id, cres, dres, dstatus,
                  event == PATROL_EVENT_NEW ? "new" : "change", app);
        execlp(cmd, cmd, "--host", host, "--proto", proto, "--port", prt,
               "--id", id, "--chain-result", cres, "--dane-result", dres,
               "--dane-status", dstatus,
               event == PATROL_EVENT_NEW ? "--new" : "--change",
               "--", app, NULL);
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

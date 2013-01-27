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

PatrolCmdRC
PATROL_exec_cmd (const char *cmd, const char *host, const char *proto,
                 uint16_t port, int64_t cert_id, int chain_result,
                 int dane_result, int dane_status, bool wait)
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
        LOG_DEBUG(">> exec_cmd: %s --host %s --proto %s --port %s --id %s "
                  "--chain-result %s --dane-result %s --dane-status %s",
                  cmd, host, proto, prt, id, cres, dres, dstatus);
        execlp(cmd, cmd, "--host", host, "--proto", proto, "--port", prt,
               "--id", id, "--chain-result", cres, "--dane-result", dres,
               "--dane-status", dstatus, NULL);
        perror("exec");
        _exit(-1);
    }

    if (wait) {
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

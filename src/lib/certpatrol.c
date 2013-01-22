#include "common.h"
#include "certpatrol.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>

CertPatrolRC
CertPatrol_get_peer_addr(int fd, int *proto,
                         char *protoname, size_t protonamelen,
                         int *port, char *addrstr) {
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
    LOG_DEBUG(">> proto: %d, %s\n", *proto, protoname);

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

    return CERTPATROL_OK;
}

CertPatrolCmdRC
CertPatrol_exec_cmd (const char *cmd, const char *host, const char *proto,
                     int port, CertPatrolInt64 cert_id, CertPatrolBool wait)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return CERTPATROL_ERROR;
    }
    if (pid == 0) {
        char id[21], prt[6];
        snprintf(prt, 6, "%d", port);
        snprintf(id, 21, "%lld", cert_id);
        LOG_DEBUG(">> exec_cmd: %s %s %s %s %s\n",
                  cmd, host, proto, prt, id);
        execlp(cmd, cmd, host, proto, prt, id, NULL);
        perror("exec");
        _exit(-1);
    }

    if (wait) {
        int ret;
        waitpid(pid, &ret, 0);
        LOG_DEBUG(">>> cmd returned %d\n", ret);
        return ret;
    } else {
        return CERTPATROL_CMD_ACCEPT;
    }
}

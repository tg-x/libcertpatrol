#ifndef PATROL_PRELOAD_H
# define PATROL_PRELOAD_H

#include <stdlib.h>
#include <dlfcn.h>

int
PATROL_get_peer_addr (int fd, int *proto,
                      char *protoname, size_t protonamelen,
                      uint16_t *port, char *addrstr);


/** Get pointer to function by name in lib */
static void *
getfunc (const char *name, const char *lib)
{
    void *handle = NULL;
#ifdef RTLD_NEXT
    handle = RTLD_NEXT;
#else
    handle = dlopen(lib, RTLD_LAZY);
    if (!handle) {
        //fputs(dlerror(), stderr);
        return NULL;
    }
#endif
    void *func = dlsym(handle, name);
    if (!func) {
        //fputs(dlerror(), stderr);
        return NULL;
    }
    return func;
}

#endif

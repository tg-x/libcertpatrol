#ifndef PATROL_COMMON_H
# define PATROL_COMMON_H

#include <stdio.h>
#include "config.h"

#define C2ARG(str)  str, sizeof(str)-1

#ifndef LOG_TARGET
# define LOG_TARGET "CertPatrol"
#endif

#define LOG_ERROR(fmt, ...) fprintf(stderr, "[" LOG_TARGET "] " fmt "\n", ##__VA_ARGS__)

#ifdef DEBUG
# define LOG_DEBUG LOG_ERROR
#else
# define LOG_DEBUG(...)
#endif

#define GNUTLS_CHECK_VERSION(major, minor, patch)                       \
    (GNUTLS_VERSION_MAJOR > major                                       \
     || (GNUTLS_VERSION_MAJOR == major && GNUTLS_VERSION_MINOR > minor) \
     || (GNUTLS_VERSION_MAJOR == major && GNUTLS_VERSION_MINOR == minor \
         && GNUTLS_VERSION_PATCH >= patch))

#endif

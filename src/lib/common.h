#ifndef DEBUG_H
# define DEBUG_H

#include <stdio.h>

#define C2ARG(str)  str, sizeof(str)-1

#define LOG_ERROR(fmt, ...) fprintf(stderr, "[CertPatrol] " fmt, ##__VA_ARGS__)

#ifdef DEBUG
# define LOG_DEBUG LOG_ERROR
#else
# define LOG_DEBUG(...)
#endif

#endif // DEBUG_H

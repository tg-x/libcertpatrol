#ifndef DEBUG_H
# define DEBUG_H

#include <stdio.h>

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

#endif // DEBUG_H

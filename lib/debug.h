#ifndef _ZZ_DEBUG_H
#define _ZZ_DEBUG_H

#include <stdio.h>

#define ZZ_DEBUG_PREFIX ">>> "

#define PRINT(string) \
    do if (zz->setup.verbose) \
           fprintf(stderr, ZZ_DEBUG_PREFIX "%s\n", string); while (0)

#define PRINTF(format, ...) \
    do if (zz->setup.verbose) \
           fprintf(stderr, ZZ_DEBUG_PREFIX format "\n", ##__VA_ARGS__); while (0)

#endif

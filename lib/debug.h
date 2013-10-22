#ifndef _ZIZZANIA_DEBUG_H
#define _ZIZZANIA_DEBUG_H

#include <stdio.h>

#define ZIZZANIA_DEBUG_PREFIX ">>> "

#define PRINT(string) \
    do if (z->setup.verbose) \
           fprintf(stderr, ZIZZANIA_DEBUG_PREFIX "%s\n", string); while (0)

#define PRINTF(format, ...) \
    do if (z->setup.verbose) \
           fprintf(stderr, ZIZZANIA_DEBUG_PREFIX format "\n", ##__VA_ARGS__); while (0)

#endif

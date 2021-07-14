#ifndef ZZ_TERMINAL_H
#define ZZ_TERMINAL_H

#include <stdio.h>

#include "handler.h"

#define ZZ_ANSI(codes, str) \
    (zz->setup.is_tty_output ? "\x1b[" codes "m" str "\x1b[0m" : str)

#define ZZ_OUT_PREFIX ZZ_ANSI("32", "[+]")
#define ZZ_ERR_PREFIX ZZ_ANSI("31", "[!]")
#define ZZ_LOG_PREFIX ZZ_ANSI("34", "[*]")

#define zz_print(type, condition, format, ...) \
    do { \
        if (condition) { \
            fprintf(stderr, "%s " format "\n", \
                    ZZ_##type##_PREFIX, \
                    ##__VA_ARGS__); \
        } \
    } while (0)

#define zz_out(format, ...) zz_print(OUT, 1, format, ##__VA_ARGS__)
#define zz_err(format, ...) zz_print(ERR, 1, format, ##__VA_ARGS__)
#define zz_log(format, ...) zz_print(LOG, zz->setup.is_verbose, format, ##__VA_ARGS__)

void zz_print_usage();
void zz_print_error(const zz_handler *zz);
void zz_print_stats(zz_handler *zz);

#endif

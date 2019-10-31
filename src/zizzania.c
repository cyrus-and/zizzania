#include <stdlib.h>

#include "options.h"
#include "terminal.h"

int main(int argc, char *argv[]) {
    zz_handler zz;

    if (!zz_initialize(&zz)) {
        zz_print_error(&zz);
        return EXIT_FAILURE;
    }

    if (!zz_parse_options(&zz, argc, argv)) {
        zz_print_usage();
        zz_print_error(&zz);
        return EXIT_FAILURE;
    }

    if (!zz_start(&zz)) {
        zz_print_error(&zz);
        return EXIT_FAILURE;
    }

    zz_print_stats(&zz);

    if (!zz_finalize(&zz)) {
        zz_print_error(&zz);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

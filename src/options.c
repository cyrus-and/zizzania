#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "handler.h"

static int parse_natural(const char *string, int *value) {
    long int tmp;
    char *chk = NULL;

    /* attempt conversion */
    errno = 0;
    tmp = strtol(string, &chk, 10);
    if (errno == ERANGE || tmp <= 0 || tmp > INT_MAX) {
        return 0;
    } else {
        *value = tmp;
        return 1;
    }
}

int zz_parse_options(zz_handler *zz, int argc, char *argv[]) {
    int opt;
    int n_inputs = 0;
    int n_outputs = 0;
    int max_handshake_2 = 0;
    int max_handshake_3 = 0;
    int n_deauths = 0;
    int killer_max_attempts = 0;
    int killer_interval = 0;
    zz_mac_addr mac_addr;
    zz_mac_addr mac_mask;
    char *mask_ptr;
    zz_members *members;

    opterr = 0;
    while (opt = getopt(argc, argv, ":i:c:nd:a:t:r:b:B:s:S:x:w:23gv"), opt != -1) {
        switch (opt) {

        case 'i':
        case 'r':
            zz->setup.input = optarg;
            zz->setup.is_live = (opt == 'i');
            n_inputs++;
            break;

        case 'c':
            if (!parse_natural(optarg, &zz->setup.channel)) {
                zz_error(zz, "Invalid channel '%s'", optarg);
                return 0;
            }
            break;

        case 'n':
            zz->setup.is_passive = 1;
            break;

        case 'd':
            n_deauths = 1;
            if (!parse_natural(optarg, &zz->setup.n_deauths)) {
                zz_error(zz, "Invalid deauthentication count '%s'", optarg);
                return 0;
            }
            break;

        case 'a':
            killer_max_attempts = 1;
            if (!parse_natural(optarg, &zz->setup.killer_max_attempts)) {
                zz_error(zz, "Invalid max deauthentication attempts '%s'", optarg);
                return 0;
            }
            break;

        case 't':
            killer_interval = 1;
            if (!parse_natural(optarg, &zz->setup.killer_interval)) {
                zz_error(zz, "Invalid deauthentication interval '%s'", optarg);
                return 0;
            }
            break;

        case 'b':
        case 'B':
        case 's':
        case 'S':
            if (!zz_mac_addr_sscan(&mac_addr, optarg, "/")) {
                zz_error(zz, "Invalid MAC address '%s'", optarg);
                return 0;
            }
            if (mask_ptr = strchr(optarg, '/'), mask_ptr) {
                if (!zz_mac_addr_sscan(&mac_mask, mask_ptr + 1, "")) {
                    zz_error(zz, "Invalid MAC address mask '%s'", mask_ptr + 1);
                    return 0;
                }
            } else {
                mac_mask = -1;  /* 0xff... */
            }
            switch (opt) {
            case 'b': members = &zz->setup.included_bssids; break;
            case 'B': members = &zz->setup.excluded_bssids; break;
            case 's': members = &zz->setup.included_stations; break;
            case 'S': members = &zz->setup.excluded_stations; break;
            default: __builtin_unreachable();
            }
            zz_members_put_mask(members, mac_addr, mac_mask);
            break;

        case 'x':
            if (strcmp(optarg, "b") == 0) {
                zz->setup.bssids_exclude_first = 1;
            } else if (strcmp(optarg, "s") == 0) {
                zz->setup.stations_exclude_first = 1;
            } else {
                zz_error(zz, "Invalid argument '%s' for option -%c", optarg, optopt);
                return 0;
            }
            break;

        case 'w':
            zz->setup.output = optarg;
            n_outputs++;
            break;

        case '2':
            zz->setup.max_handshake = 2;
            max_handshake_2 = 1;
            break;

        case '3':
            zz->setup.max_handshake = 3;
            max_handshake_3 = 1;
            break;

        case 'g':
            zz->setup.dump_group_traffic = 1;
            break;

        case 'v':
            zz->setup.is_verbose = 1;
            break;

        case '?':
            zz_error(zz, "Unknown option -%c", optopt);
            return 0;

        default:
            zz_error(zz, "Option -%c requires an argument", optopt);
            return 0;
        }
    }

    /* warn about no input */
    if (n_inputs == 0) {
        zz_error(zz, "No input specified, use either -r or -i");
        return 0;
    }

    /* warn about multiple input specified */
    if (n_inputs > 1) {
        zz_error(zz, "Multiple inputs specified");
        return 0;
    }

    /* warn about multiple output specified */
    if (n_outputs > 1) {
        zz_error(zz, "Multiple outputs specified");
        return 0;
    }

    /* warn about unparsed options */
    if (optind != argc) {
        zz_error(zz, "Unparsed option '%s'", argv[optind]);
        return 0;
    }

    /* warn about live-related options while offline */
    if (!zz->setup.is_live &&
        (zz->setup.channel > 0 || zz->setup.is_passive ||
         n_deauths || killer_max_attempts || killer_interval)) {
        zz_error(zz, "Incompatible options -c, -n, -d, -a, -t with offline mode");
        return 0;
    }

    /* warn about active-related options while passive */
    if (zz->setup.is_passive &&
        (n_deauths || killer_max_attempts || killer_interval)) {
        zz_error(zz, "Incompatible options -d, -a, -t with passive mode");
        return 0;
    }

    /* warn about dump-related options without output */
    if (zz->setup.dump_group_traffic && n_outputs == 0) {
        zz_error(zz, "Useless option -g without an output file");
        return 0;
    }

    /* warn about max handshake conflicts */
    if (max_handshake_2 && max_handshake_3) {
        zz_error(zz, "Incompatible options -2 and -3");
        return 0;
    }

    return 1;
}

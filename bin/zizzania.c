#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "zizzania.h"

#define DUMP_ERROR_AND_DIE(zz) { \
        fprintf(stderr, "# %s\n", zz.error_buffer); \
        return EXIT_FAILURE; \
    }

static int dump_to_stdout = 0;

static void print_usage() {
    fprintf(stderr,
            "Usage:\n"
            "\n"
            "    zizzania -i <device> | -r <file>\n"
            "             -b <bssid_1> -b <bssid_2> ... | -a\n"
            "             [-n] [-w <file>]\n"
            "\n"
            "    -i <device> : use <device> for both capture and injection\n"
            "    -r <file>   : read packets from <file> (- for stdin)\n"
            "    -b <bssid>  : handshakes of <bssid> clients only\n"
            "    -a          : auto discover BSSIDs\n"
            "    -n          : passively look for handshakes\n"
            "    -w          : dump captured packets to <file> (- for stdout)\n"
            "    -v          : print verbose messages\n"
            "\n");
}

static int parse_options(zz_t *zz, int argc, char *argv[]) {
    int opt;
    int n_target = 0;
    int n_input = 0;
    int n_output = 0;

    opterr = 0;
    while (opt = getopt(argc, argv, ":ab:i:r:w:nv"), opt != -1) {
        switch (opt) {
        case 'a':
            zz->setup.auto_add_targets = 1;
            break;

        case 'b': {
            uint8_t bssid[6];

            /* parse bssid address */
            if (!ieee80211_addr_sscan(bssid, optarg)) {
                zz_set_error_messagef(zz, "Invalid MAC address '%s'", optarg);
                return 0;
            }

            /* use this address as target */
            zz_add_target(zz, bssid);
            n_target++;
            break;
        }

        case 'i':
        case 'r':
            strncpy(zz->setup.input, optarg, ZZ_MAX_PATH);
            zz->setup.live = (opt == 'i');
            n_input++;
            break;

        case 'w':
            strncpy(zz->setup.output, optarg, ZZ_MAX_PATH);
            dump_to_stdout = (strcmp(zz->setup.output, "-") == 0);
            n_output++;
            break;

        case 'n':
            zz->setup.passive = 1;
            break;

        case 'v':
            zz->setup.verbose = 1;
            break;

        case ':':
            zz_set_error_messagef(zz, "Missing argument for option '%c'", optopt);
            return 0;

        default:
            zz_set_error_messagef(zz, "Unknown option '%c'", optopt);
            return 0;
        }
    }

    /* coherence checks */

    /* warn about no input */
    if (n_input == 0) {
        zz_set_error_messagef(zz, "No input specified, use either -r or -i");
        return 0;
    }

    /* warn about multiple input specified */
    if (n_input > 1) {
        zz_set_error_messagef(zz, "Multiple input specified");
        return 0;
    }

    /* warn about multiple output specified */
    if (n_output > 1) {
        zz_set_error_messagef(zz, "Multiple output specified");
        return 0;
    }

    /* warn about unparset options */
    if (optind != argc) {
        zz_set_error_messagef(zz, "Unparsed option '%s'", argv[optind]);
        return 0;
    }

    /* warn about nothing to do */
    if (!zz->setup.auto_add_targets && n_target == 0) {
        zz_set_error_messagef(zz, "Specify at least one target BSSID (-b)"
                             " or force auto mode (-a)");
        return 0;
    }

    /* warn about useless options */
    if (zz->setup.auto_add_targets && n_target > 0) {
        zz_set_error_messagef(zz, "Option -a includes every combination of -b");
        return 0;
    }

    /* warn about passive mode while offline */
    if (zz->setup.passive && !zz->setup.live) {
        zz_set_error_messagef
            (zz, "Offline sessions are always passive there's no need of -n");
        return 0;
    }

    return 1;
}

static void on_new_client(const ieee80211_addr_t bssid,
                          const ieee80211_addr_t client) {
    char bssid_str[18], client_str[18];

    ieee80211_addr_sprint(bssid, bssid_str);
    ieee80211_addr_sprint(client, client_str);

    fprintf(dump_to_stdout ? stderr : stdout, "N %s @ %s\n",
            client_str, bssid_str);
}

static void on_handshake(const ieee80211_addr_t bssid,
                         const ieee80211_addr_t client) {
    char bssid_str[18], client_str[18];

    ieee80211_addr_sprint(bssid, bssid_str);
    ieee80211_addr_sprint(client, client_str);

    fprintf(dump_to_stdout ? stderr : stdout, "H %s @ %s <<<\n",
            client_str, bssid_str);
}

int main(int argc, char *argv[]) {
    zz_t zz;

    if (!zz_initialize(&zz)) {
        DUMP_ERROR_AND_DIE(zz);
    }

    if (!parse_options(&zz, argc, argv)) {
        print_usage();
        DUMP_ERROR_AND_DIE(zz);
    }

    zz.setup.on_new_client = on_new_client;
    zz.setup.on_handshake = on_handshake;

    if (!zz_start(&zz)) {
        DUMP_ERROR_AND_DIE(zz);
    }

    zz_finalize(&zz);
    return EXIT_SUCCESS;
}

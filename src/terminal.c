#include <stdio.h>

#include "handler.h"
#include "release.h"
#include "terminal.h"

void zz_print_usage() {
    #define LN(x) x "\n"
    fprintf(stderr,
            LN("zizzania v" ZZ_VERSION " - Automated DeAuth attack")
            LN("Copyright (c) 2016 Andrea Cardaci <cyrus.and@gmail.com>")
            LN("")
            LN("Usage:")
            LN("")
            LN("    zizzania (-r <file> | -i <device> [-c <channel>]")
            LN("              (-n | [-d <count>] [-a <count>] [-t <seconds>]))")
            LN("             [-b <address>...] [-x <address>...] [-2 | -3]")
            LN("             [-w <file> [-g]] [-v]")
            LN("")
            LN("    -i <device>   Use <device> for both capture and injection")
            LN("    -c <channel>  Set <device> to RFMON mode on <channel>")
            LN("    -n            Passively wait for WPA handshakes")
            LN("    -d <count>    Send groups of <count> deauthentication frames")
            LN("    -a <count>    Perform <count> deauthentications before giving up")
            LN("    -t <seconds>  Time to wait between two deauthentication attempts")
            LN("    -r <file>     Read packets from <file> (- for stdin)")
            LN("    -b <address>  Limit the operations to the given BSS")
            LN("    -x <address>  Exclude the given station from the operations")
            LN("    -2            Settle for the first two handshake messages")
            LN("    -3            Settle for the first three handshake messages")
            LN("    -w <file>     Write packets to <file> (- for stdout)")
            LN("    -g            Also dump multicast and broadcast traffic")
            LN("    -v            Print verbose messages to stderr (toggle with SIGUSR1)")
            LN("")
            LN("Example:")
            LN("")
            LN("    zizzania -i wlan0 -c 1 -w out.pcap")
            LN(""));
    #undef LN
}

void zz_print_error(const zz_handler *zz) {
    zz_err("%s", zz->error_buffer);
}

void zz_print_stats(zz_handler *zz) {
    struct pcap_stat stats;
    zz_bss *tmp, *bss;
    int n_allowed_ssid;

    if (pcap_stats(zz->pcap, &stats) == 0) {
        zz_out("");
        zz_out("Packet statistics");
        zz_out("  - Received ....... %u", stats.ps_recv);
        zz_out("  - Dropped ........ %u", stats.ps_drop + stats.ps_ifdrop);
    }

    n_allowed_ssid = 0;
    HASH_ITER(hh, zz->bsss, bss, tmp) {
        char bssid_str[ZZ_MAC_ADDR_STRING_SIZE];
        char escaped_ssid[ZZ_BEACON_MAX_SSID_ESCAPE_LENGTH + 1] = {0};
        int is_escaped;

        if (!bss->is_allowed) {
            continue;
        }
        n_allowed_ssid++;

        /* prepare B/SSID */
        zz_ssid_escape_sprint(escaped_ssid, &is_escaped,
                              bss->ssid, bss->ssid_length);
        zz_mac_addr_sprint(bssid_str, bss->bssid);

        /* print stats */
        zz_out("");
        zz_out("SSID %s'%s' (%s)", is_escaped ? "$": "", escaped_ssid, bssid_str);
        zz_out("  - Handshakes ..... %ld", bss->n_handshakes);
        zz_out("  - Stations ....... %u", zz_members_count(&bss->stations));
        zz_out("  - Data packets ... %ld", bss->n_data_packets);
        if (bss->n_handshakes > 0 && (!zz->setup.is_live || zz->setup.output)) {
            const char *file;

            /* XXX file not shell-escaped */

            /* print hint */
            file = (zz->setup.output ? zz->setup.output : zz->setup.input);
            file = (strcmp(file, "-") == 0 ? "?" : file);
            zz_out("  Decrypt with airdecap-ng -e %s'%s' -b %s -p '?' '%s'",
                   is_escaped ? "$": "", escaped_ssid, bssid_str, file);
        }
    }

    if (n_allowed_ssid == 0) {
        zz_out("");
        zz_out("No BSS found");
        return;
    }
}

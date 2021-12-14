#include <stdio.h>
#include <string.h>

#include "handler.h"
#include "release.h"
#include "terminal.h"

void zz_print_usage() {
    #define LN(x) x "\n"
    fprintf(stderr,
            LN("zizzania v" ZZ_VERSION " - " ZZ_DESCRIPTION)
            LN("Copyright (c) " ZZ_YEAR " " ZZ_AUTHOR)
            LN("")
            LN("Usage:")
            LN("")
            LN("    zizzania (-r <file> | -i <device> [-M] [-c <channel>] [-q]")
            LN("              (-n | [-d <count>] [-a <count>] [-t <seconds>]))")
            LN("             [-b <match>...] [-B <match>...] [-x b]")
            LN("             [-s <match>...] [-S <match>...] [-x s]")
            LN("             [-2 | -3]")
            LN("             [-w <file> [-g]] [-v]")
            LN("")
            LN("    -r <file>     Read packets from <file> (- for stdin)")
            LN("    -i <device>   Use <device> for both capture and injection")
            LN("    -M            Do not set <devidce> in RFMON mode (useful for airmon-ng)")
            LN("    -c <channel>  Tune the <device> on <channel>")
            LN("    -q            Quit after capturing the first handshake")
            LN("    -n            Passively wait for WPA handshakes")
            LN("    -d <count>    Send groups of <count> deauthentication frames")
            LN("    -a <count>    Perform <count> deauthentications before giving up")
            LN("    -t <seconds>  Time to wait between two deauthentication attempts")
            LN("    -b <match>    Include the given BSSID (<address>[/<mask>])")
            LN("    -B <match>    Exclude the given BSSID (<address>[/<mask>])")
            LN("    -s <match>    Include the given station (<address>[/<mask>])")
            LN("    -S <match>    Exclude the given station (<address>[/<mask>])")
            LN("    -x b|s        First exclude then include BSSIDs (b) or stations (s)")
            LN("    -2            Settle for the first two handshake messages")
            LN("    -3            Settle for the first three handshake messages")
            LN("    -w <file>     Write packets to <file> (- for stdout)")
            LN("    -g            Also dump multicast and broadcast traffic")
            LN("    -v            Print verbose messages to stderr (toggle with SIGUSR1)")
            LN("")
            LN("Example:")
            LN("")
            LN("    zizzania -i wlan0 -c 1 -b ac:1d:1f:1e:dd:ad/ff:ff:ff:00:00:00 -w out.pcap")
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

        if (!bss->is_allowed) {
            continue;
        }
        n_allowed_ssid++;

        /* prepare BSSID */
        zz_mac_addr_sprint(bssid_str, bss->bssid);

        /* print stats */
        zz_out("");
        zz_out("SSID $'%s' (%s)", bss->ssid, bssid_str);
        zz_out("  - Handshakes ..... %ld", bss->n_handshakes);
        zz_out("  - Stations ....... %u", zz_members_count(&bss->stations));
        zz_out("  - Data packets ... %ld", bss->n_data_packets);
        if (bss->n_handshakes > 0 && (!zz->setup.is_live || zz->setup.output)) {
            const char *file;

            /* format file name (XXX file not shell-escaped) */
            file = (zz->setup.output ? zz->setup.output : zz->setup.input);
            file = (strcmp(file, "-") == 0 ? "CAPTURE" : file);

            /* print cracking hint */
            zz_out("  - Crack with ..... aircrack-ng -w 'WORDLIST' -b %s '%s'", bssid_str, file);

            /* print decryption hint */
            zz_out("  - Decrypt with ... airdecap-ng -e $'%s' -b %s -p 'PASSPHRASE' '%s'",
                   bss->ssid, bssid_str, file);
        }
    }

    if (n_allowed_ssid == 0) {
        zz_out("");
        zz_out("No BSS found");
        return;
    }
}

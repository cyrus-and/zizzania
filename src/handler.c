#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "dispatcher.h"
#include "dissector.h"
#include "handler.h"
#include "iface.h"
#include "terminal.h"
#include "util.h"

/* use smaller snaplen if not saving traffic */
#define MIN_SNAPLEN 256
#define MAX_SNAPLEN 65535

#define BPF "wlan[0] == " ZZ_STRING(ZZ_FCF_DATA) \
        " || wlan[0] == " ZZ_STRING(ZZ_FCF_QOS_DATA) \
        " || wlan[0] == " ZZ_STRING(ZZ_FCF_BEACON)

static int create_pcap(zz_handler *zz) {
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];

    /* get pcap handle live */
    if (zz->setup.is_live) {
        /* create but not activate */
        *pcap_error_buffer = '\0';
        zz->pcap = pcap_create(zz->setup.input, pcap_error_buffer);

        /* log pcap warning (not a failure) */
        if (zz->pcap && *pcap_error_buffer) {
            zz_log("WARNING: %s", pcap_error_buffer);
        }

        /* if success (failure is handled later) */
        if (zz->pcap) {
            int snaplen;

            /* set individual options and activate the handler */
            snaplen = zz->setup.output ? MAX_SNAPLEN : MIN_SNAPLEN;
            if (pcap_set_snaplen(zz->pcap, snaplen) != 0 ||
                pcap_set_promisc(zz->pcap, 1) != 0 ||
                pcap_set_rfmon(zz->pcap, 1) ||
                pcap_activate(zz->pcap)) {
                zz_error(zz, "libpcap: %s", pcap_geterr(zz->pcap));
                return 0;
            }

            /* switch to the desired channel */
            if (zz->setup.is_live && zz->setup.channel > 0) {
                zz_log("Setting '%s' to channel %d", zz->setup.input, zz->setup.channel);
                if (!zz_set_channel(zz)) {
                    zz_error(zz, "Cannot set '%s' to channel %d: %s",
                             zz->setup.input, zz->setup.channel, strerror(errno));
                    return 0;
                }
            }
        }
    }
    /* get pcap handler from file */
    else {
        zz->pcap = pcap_open_offline(zz->setup.input, pcap_error_buffer);
        zz->setup.is_passive = 1;
    }

    if (!zz->pcap) {
        zz_error(zz, "libpcap: %s", pcap_error_buffer);
        return 0;
    }

    return 1;
}

static int check_monitor(zz_handler *zz) {
    int dlt;

    if (!zz->setup.is_live) {
        return 1;
    }

    dlt = pcap_datalink(zz->pcap);
    zz_log("Datalink type '%s'", pcap_datalink_val_to_name(dlt));
    if (dlt != DLT_IEEE802_11_RADIO) {
        const char *expected_dlt;

        expected_dlt = pcap_datalink_val_to_name(DLT_IEEE802_11_RADIO);
        zz_error(zz, "Wrong device type/mode '%s'; '%s' expected",
                 pcap_datalink_val_to_name(dlt), expected_dlt);
        return 0;
    }

    return 1;
}

static int set_bpf(zz_handler *zz) {
    struct bpf_program fp;

    if (pcap_compile(zz->pcap, &fp, BPF, 1, -1) != 0) {
        zz_error(zz, "libpcap: %s", pcap_geterr(zz->pcap));
        return 0;
    }

    if (pcap_setfilter(zz->pcap, &fp) != 0) {
        zz_error(zz, "libpcap: %s", pcap_geterr(zz->pcap));
        return 0;
    }

    pcap_freecode(&fp);
    return 1;
}

static int open_dumper(zz_handler *zz) {
    if (zz->setup.output) {
        zz_log("Dumping packets to '%s'", zz->setup.output);

        zz->dumper = pcap_dump_open(zz->pcap, zz->setup.output);
        if (!zz->dumper) {
            zz_error(zz, "libpcap: %s", pcap_geterr(zz->pcap));
            return 0;
        }
    }

    return 1;
}

static int packet_loop(zz_handler *zz) {
    pthread_t dispatcher;
    int error;
    int dispatcher_return;

    /* start the dispatcher */
    if (!zz_dispatcher_start(zz, &dispatcher)) {
        return 0;
    }

    if (zz->setup.is_live) {
        zz_out("Waiting for traffic, press Ctrl-C to exit...");
    } else {
        zz_out("Parsing '%s'", zz->setup.input);
    }

    /* start capture loop */
    error = 0;
    switch (pcap_loop(zz->pcap, -1, zz_dissect_packet, (u_char *)zz)) {
    case 0: /* end of file */
        zz_log("EOF for '%s'", zz->setup.input);
        break;

    case -1: /* error */
        zz_error(zz, "libpcap: %s", pcap_geterr(zz->pcap));
        error = 1;
        break;

    case -2: /* user termination */
        break;
    }

    /* notify termination */
    zz_out("Terminating...");
    zz->is_done = 1;

    /* join dispatcher thread */
    if (pthread_join(dispatcher, (void *)&dispatcher_return) != 0) {
        zz_error(zz, "Cannot join the dispatcher");
        return 0;
    }

    return !error && dispatcher_return;
}

int zz_initialize(zz_handler *zz) {
    memset(zz, 0, sizeof(zz_handler));
    zz_members_new(&zz->setup.included_bssids);
    zz_members_new(&zz->setup.excluded_bssids);
    zz_members_new(&zz->setup.included_stations);
    zz_members_new(&zz->setup.excluded_stations);
    zz_bsss_new(&zz->bsss);
    zz_clients_new(&zz->clients);

    if (!zz->setup.is_passive) {
        zz_killer_new(&zz->killer);
    }

    /* inhibit ansi output if not tty */
    zz->setup.is_tty_output = isatty(2); /* stderr */

    /* default values */

    /* require full handler by default */
    zz->setup.max_handshake = 4;

    /* just one deauthentication frame at a time */
    zz->setup.n_deauths = 1;

    /* killer-related params */
    zz->setup.killer_max_attempts = 10;
    zz->setup.killer_interval = 5;
    return 1;
}

int zz_start(zz_handler *zz) {
    return create_pcap(zz) &&
           zz_drop_root(zz) &&
           check_monitor(zz) &&
           set_bpf(zz) &&
           open_dumper(zz) &&
           packet_loop(zz);
}

int zz_finalize(zz_handler *zz) {
    if (zz->dumper) {
        zz_log("Closing packet dump '%s'", zz->setup.output);
        pcap_dump_close(zz->dumper);
    }

    zz_members_free(&zz->setup.included_bssids);
    zz_members_free(&zz->setup.excluded_bssids);
    zz_members_free(&zz->setup.included_stations);
    zz_members_free(&zz->setup.excluded_stations);
    zz_bsss_free(&zz->bsss);
    zz_clients_free(&zz->clients);

    if (!zz->setup.is_passive) {
        zz_killer_free(&zz->killer);
    }

    pcap_close(zz->pcap);
    return 1;
}

int zz_error(zz_handler *zz, const char *format, ...) {
    int chk;
    va_list ap;

    va_start(ap, format);
    chk = vsnprintf(zz->error_buffer, ZZ_ERROR_BUFFER_SIZE, format, ap);
    va_end(ap);
    return chk > 0 && chk < ZZ_ERROR_BUFFER_SIZE;
}

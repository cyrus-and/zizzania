#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <endian.h>
#include <stdarg.h>
#include "debug.h"
#include "handshake.h"
#include "dispatcher.h"
#include "zizzania.h"

#define READ_TIMEOUT 500
#define BPF "wlan[0] == 0x08 || wlan[0] == 0x88" /* data, qos data */
#define MIN_SNAPLEN 128
#define MAX_SNAPLEN 65535

static void zz_drop_root(zz_t *zz) {
    /* nothing to do for non-root users */
    if (getuid() == 0) {
        const char *sudo_user;
        uid_t uid;
        gid_t gid;

        /* if from sudo restore credential */
        if (sudo_user = getenv("SUDO_USER"), sudo_user) {
            PRINTF("sudo detected, becoming %s", sudo_user);
            uid = atoi(getenv("SUDO_UID"));
            gid = atoi(getenv("SUDO_GID"));

        }
        /* otherwise become nobody */
        else {
            struct passwd *nobody;

            PRINT("becoming nobody");
            nobody = getpwnam("nobody");
            uid = nobody->pw_uid;
            gid = nobody->pw_gid;
        }

        /* set permissions */
        setgroups(0, NULL);
        setgid(gid);
        setuid(uid);
    }
}

int zz_initialize(zz_t *zz) {
    memset(zz, 0, sizeof(zz_t));

    /* bssids hashtable */
    zz->targets = g_hash_table_new_full(ieee80211_addr_hash,
                                        ieee80211_addr_equal,
                                        g_free,
                                        (GDestroyNotify)g_hash_table_destroy);
    /* kill list */
    zz->kill_list = g_hash_table_new_full(ieee80211_addr_hash,
                                          ieee80211_addr_equal,
                                          g_free, g_free);

    /* create non-blocking communication pipe */
    if (pipe(zz->comm) ||
        fcntl(zz->comm[0], F_SETFL, O_NONBLOCK) ||
        fcntl(zz->comm[1], F_SETFL, O_NONBLOCK)) {
        zz_set_error_messagef
            (zz, "cannot create the non-blocking communication pipe");
        return 0;
    }

    return 1;
}

int zz_set_error_messagef(zz_t *zz, const char *format, ...) {
    int chk;
    va_list ap;

    va_start(ap, format);
    chk = vsnprintf(zz->error_buffer, ZZ_ERROR_BUFFER_SIZE + 1, format, ap);
    va_end(ap);

    return chk != ZZ_ERROR_BUFFER_SIZE;
}

int zz_add_target(zz_t *zz, const ieee80211_addr_t target) {
    /* add a new bssid target */
    if (!g_hash_table_lookup(zz->targets, target)) {
        GHashTable *clients;

        /* prepare target's hashtable */
        clients = g_hash_table_new_full(ieee80211_addr_hash,
                                        ieee80211_addr_equal,
                                        g_free, g_free);

        g_hash_table_insert(zz->targets, g_memdup(target, 6), clients);
        return 1;
    }

    return 0;
}

int zz_start(zz_t *zz) {
    struct sigaction sa;
    sigset_t set;
    struct bpf_program fp;
    const uint8_t *packet;
    struct pcap_pkthdr *packet_header;
    int dlt;
    uint8_t retval;
    int error = 0;

    /* get pcap handle live */
    if (zz->setup.live) {
        int snaplen;

        *zz->error_buffer = '\0';
        snaplen = *(zz->setup.output) ? MAX_SNAPLEN : MIN_SNAPLEN;
        zz->handler = pcap_open_live(zz->setup.input, snaplen,
                                     1, READ_TIMEOUT, zz->error_buffer);

        /* warning */
        if (*zz->error_buffer) {
            PRINT(zz->error_buffer);
        }
    }
    /* from file */
    else {
        zz->handler = pcap_open_offline(zz->setup.input, zz->error_buffer);
        zz->setup.passive = 1;
    }

    if (!zz->handler) {
        return 0;
    }

    /* drop root privileges */
    zz_drop_root(zz);

    /* check datalink type */
    dlt = pcap_datalink(zz->handler);
    PRINTF("datalink type %s", pcap_datalink_val_to_name(dlt));

    if (dlt != DLT_IEEE802_11_RADIO) {
        const char *expected_dlt;

        expected_dlt = pcap_datalink_val_to_name(DLT_IEEE802_11_RADIO);
        zz_set_error_messagef(zz, "wrong device type/mode %s; %s expected",
                              pcap_datalink_val_to_name(dlt), expected_dlt);
        return 0;
    }

    /* set capture filter */
    pcap_compile(zz->handler, &fp, BPF, 1, -1);
    pcap_setfilter(zz->handler, &fp);
    pcap_freecode(&fp);

    /* open dumper */
    if (*(zz->setup.output)) {
        PRINTF("dumping packets to %s", zz->setup.output);

        zz->dumper = pcap_dump_open(zz->handler, zz->setup.output);
        if (!zz->dumper) {
            zz_set_error_messagef(zz, pcap_geterr(zz->handler));
            return 0;
        }
    }

    /* ignore signals */
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGINT, &sa, NULL) || sigaction(SIGTERM, &sa, NULL)) {
        zz_set_error_messagef(zz, "unable to set signal action");
        return 0;
    }

    /* mask all signals (so everything is sent to the dispatcher, blocked on the
       sigtimedwait) */
    sigfillset(&set);
    if (pthread_sigmask(SIG_SETMASK, &set, NULL)) {
        zz_set_error_messagef(zz, "unable to set signal mask");
        return 0;
    }

    /* start dispatcher */
    if (pthread_create(&zz->dispatcher, NULL, zz_dispatcher, zz)) {
        zz_set_error_messagef(zz, "unable to start dispatcher thread");
        return 0;
    }

    /* packet loop */
    while (!zz->stop) {
        switch (pcap_next_ex(zz->handler, &packet_header, &packet)) {
        case 0: /* timeout */
            break; /* recheck flag and eventually start over */

        case 1: /* no problem */
            error = !zz_process_packet(zz, packet_header, packet);
            break;

        case -1: /* error */
            PRINT(pcap_geterr(zz->handler));
            zz_set_error_messagef(zz, pcap_geterr(zz->handler));
            error = zz->stop = 1;
            break;

        case -2: /* end of file */
            PRINT("eof");
            zz->stop = 1;
            break;
        }
    }

    PRINT("shuting down the dispatcher");

    /* force dispatcher wakeup on errors on this thread */
    pthread_kill(zz->dispatcher, SIGTERM);

    /* join dispatcher thread */
    if (pthread_join(zz->dispatcher, (void *)&retval)) {
        PRINT("cannot join the dispatcher");
        return 0;
    }

    return !error && retval;
}

void zz_finalize(zz_t *zz) {
    if (zz->dumper) {
        pcap_dump_close(zz->dumper);
    }

    if (zz->setup.verbose) {
        struct pcap_stat stats;
        if (pcap_stats(zz->handler, &stats) == 0) {
            PRINTF("recv:   %d", stats.ps_recv);
            PRINTF("drop:   %d", stats.ps_drop);
            PRINTF("ifdrop: %d", stats.ps_ifdrop);
        }
    }

    pcap_close(zz->handler);
    close(zz->comm[0]);
    close(zz->comm[1]);
    g_hash_table_destroy(zz->targets);
    g_hash_table_destroy(zz->kill_list);
}

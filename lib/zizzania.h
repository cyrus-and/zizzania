#ifndef _ZZ_ZIZZANIA_H
#define _ZZ_ZIZZANIA_H

#include <pcap/pcap.h>
#include <glib.h>
#include <pthread.h>
#include "dissectors.h"

#define ZZ_ERROR_BUFFER_SIZE PCAP_ERRBUF_SIZE
#define ZZ_MAX_PATH 255

typedef void (* client_notify)(const ieee80211_addr_t bssid,
                               const ieee80211_addr_t client);

typedef struct {
    struct {
        char input[ZZ_MAX_PATH + 1];
        char output[ZZ_MAX_PATH + 1];
        int live;
        int auto_add_targets;
        int passive;
        client_notify on_new_client;
        client_notify on_handshake;
        int verbose;
    } setup;

    char error_buffer[ZZ_ERROR_BUFFER_SIZE + 1];

    pcap_t *handler;
    pcap_dumper_t *dumper;
    GHashTable *targets;
    pthread_t dispatcher;
    int stop;
    GHashTable *kill_list;
    int comm[2];
} zz_t;

int zz_initialize(zz_t *zz);
int zz_set_error_messagef(zz_t *zz, const char *format, ...);
int zz_add_target(zz_t *zz, const ieee80211_addr_t target);
int zz_start(zz_t *zz);
void zz_finalize(zz_t *zz);

#endif

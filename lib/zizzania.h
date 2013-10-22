#ifndef _ZIZZANIA_ZIZZANIA_H
#define _ZIZZANIA_ZIZZANIA_H

#include <pcap/pcap.h>
#include <glib.h>
#include <pthread.h>
#include "dissectors.h"

#define ZIZZANIA_ERROR_BUFFER_SIZE PCAP_ERRBUF_SIZE
#define ZIZZANIA_MAX_PATH 255

typedef void (* client_notify)(const ieee80211_addr_t bssid,
                               const ieee80211_addr_t client);

struct zizzania {
    struct {
        char input[ZIZZANIA_MAX_PATH + 1];
        char output[ZIZZANIA_MAX_PATH + 1];
        int live;
        int auto_add_targets;
        int passive;
        client_notify on_new_client;
        client_notify on_handshake;
        int verbose;
    } setup;

    char error_buffer[ZIZZANIA_ERROR_BUFFER_SIZE + 1];

    pcap_t *handler;
    pcap_dumper_t *dumper;
    GHashTable *targets;
    pthread_t dispatcher;
    int stop;
    GHashTable *kill_list;
    int comm[2];
};

int zizzania_initialize(struct zizzania *z);
int zizzania_set_error_messagef(struct zizzania *z, const char *format, ...);
int zizzania_add_target(struct zizzania *z, const ieee80211_addr_t target);
int zizzania_start(struct zizzania *z);
void zizzania_finalize(struct zizzania *z);

#endif

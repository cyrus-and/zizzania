#ifndef ZZ_HANDLER_H
#define ZZ_HANDLER_H

#include <pcap/pcap.h>

#include "clients.h"
#include "killer.h"
#include "members.h"
#include "bsss.h"

#define ZZ_ERROR_BUFFER_SIZE (1024 + PCAP_ERRBUF_SIZE)

typedef struct {
    struct {
        char *input;
        char *output;
        unsigned is_live:1;
        unsigned is_passive:1;
        unsigned is_verbose:1;
        unsigned is_tty_output:1;
        unsigned dump_group_traffic:1;
        int channel;
        int n_deauths;
        int killer_max_attempts;
        int killer_interval;
        int max_handshake;
        zz_members allowed_bssids;
        zz_members banned_stations;
    } setup;

    double epoch; /* first packet timestamp in seconds */

    pcap_t *pcap;
    pcap_dumper_t *dumper;

    zz_bsss bsss;
    zz_clients clients;
    zz_killer killer;

    unsigned is_done:1;

    char error_buffer[ZZ_ERROR_BUFFER_SIZE];
} zz_handler;

int zz_initialize(zz_handler *zz);
int zz_start(zz_handler *zz);
int zz_finalize(zz_handler *zz);

int zz_error(zz_handler *zz, const char *format, ...);

#endif

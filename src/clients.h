#ifndef ZZ_CLIENTS_H
#define ZZ_CLIENTS_H

#include <time.h>

#include <uthash.h>

#include "ieee802.h"

typedef struct {
    zz_mac_addr station;
    zz_mac_addr bssid;
    time_t last_data_ts;
    uint64_t last_handshake_ts; /* handshake reference timestamp */
    uint64_t replay_counter; /* only valid if handshake != 0 */
    unsigned handshake; /* handshake messages bitmask */
    struct ieee8021x_authentication_header headers[4];
    UT_hash_handle hh;
} zz_client;

typedef zz_client *zz_clients;

void zz_clients_new(zz_clients *clients);
int zz_clients_lookup(zz_clients *clients,
                      zz_mac_addr station, zz_mac_addr bssid,
                      zz_client **client);
void zz_clients_free(zz_clients *clients);

#endif

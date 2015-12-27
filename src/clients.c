#include <assert.h>
#include <stdlib.h>

#include "clients.h"

void zz_clients_new(zz_clients *clients) {
    *clients = NULL;
}

int zz_clients_lookup(zz_clients *clients,
                      zz_mac_addr station, zz_mac_addr bssid,
                      zz_client **client) {
    const zz_mac_addr key[] = {station, bssid};

    /* try find (addresses are tighly packed) */
    HASH_FIND(hh, *clients, key, sizeof(key), *client);
    if (*client) {
        return 0;
    }

    /* otherwise add an empty one */
    *client = calloc(1, sizeof(zz_client));
    assert(*client != NULL);
    (*client)->station = station;
    (*client)->bssid = bssid;
    HASH_ADD(hh, *clients, station, sizeof(key), *client);
    return 1;
}

void zz_clients_free(zz_clients *clients) {
    zz_client *tmp, *client;

    HASH_ITER(hh, *clients, client, tmp) {
        HASH_DEL(*clients, client);
        free(client);
    }
}

#ifndef ZZ_BSSS_H
#define ZZ_BSSS_H

#include <uthash.h>

#include "members.h"

#include "ieee802.h"

typedef struct {
    zz_mac_addr bssid;
    unsigned is_allowed:1;
    unsigned has_beacon:1;
    char ssid[ZZ_BEACON_MAX_SSID_ESCAPED_LENGTH + 1];
    zz_members stations; /* at least one handshake */
    long n_handshakes;
    long n_data_packets;
    UT_hash_handle hh;
} zz_bss;

typedef zz_bss *zz_bsss;

void zz_bsss_new(zz_bsss *bsss);
// return true if this is a new bss
int zz_bsss_lookup(zz_bsss *bsss, zz_mac_addr bssid, zz_bss **bss);
void zz_bsss_free(zz_bsss *bsss);

#endif

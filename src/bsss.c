#include <assert.h>
#include <stdlib.h>

#include "bsss.h"

void zz_bsss_new(zz_bsss *bsss) {
    *bsss = NULL;
}

int zz_bsss_lookup(zz_bsss *bsss, zz_mac_addr bssid, zz_bss **bss) {
    /* try find (addresses are tighly packed) */
    HASH_FIND(hh, *bsss, &bssid, sizeof(zz_mac_addr), *bss);
    if (*bss) {
        return 0;
    }

    /* otherwise add an empty one */
    *bss = calloc(1, sizeof(zz_bss));
    assert(*bss != NULL);
    (*bss)->bssid = bssid;
    zz_members_new(&(*bss)->stations);
    HASH_ADD(hh, *bsss, bssid, sizeof(zz_mac_addr), *bss);
    return 1;
}

void zz_bsss_free(zz_bsss *bsss) {
    zz_bss *tmp, *bss;

    HASH_ITER(hh, *bsss, bss, tmp) {
        HASH_DEL(*bsss, bss);
        zz_members_free(&bss->stations);
        free(bss);
    }
}

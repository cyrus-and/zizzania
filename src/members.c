#include <assert.h>
#include <stdlib.h>

#include <uthash.h>

#include "members.h"

struct zz_device {
    zz_mac_addr addr;
    UT_hash_handle hh;
};

void zz_members_new(zz_members *members) {
    *members = NULL;
}

int zz_members_add(zz_members *members, zz_mac_addr mac_addr) {
    struct zz_device *device;

    HASH_FIND(hh, *members, &mac_addr, sizeof(zz_mac_addr), device);
    if (device) {
        return 0;
    }

    device = malloc(sizeof(struct zz_device));
    assert(device != NULL);
    device->addr = mac_addr;
    HASH_ADD(hh, *members, addr, sizeof(zz_mac_addr), device);
    return 1;
}

int zz_members_get(const zz_members *members, zz_mac_addr mac_addr) {
    struct zz_device *device;

    HASH_FIND(hh, *members, &mac_addr, sizeof(zz_mac_addr), device);
    return !!device;
}

unsigned zz_members_count(const zz_members *members) {
    return HASH_COUNT(*members);
}

int zz_members_is_empty(const zz_members *members) {
    return HASH_COUNT(*members) == 0;
}

void zz_members_free(zz_members *members) {
    struct zz_device *tmp, *device;

    HASH_ITER(hh, *members, device, tmp) {
        HASH_DEL(*members, device);
        free(device);
    }
}

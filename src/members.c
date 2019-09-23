#include <assert.h>
#include <stdlib.h>

#include <uthash.h>

#include "members.h"

struct zz_device {
    zz_mac_addr addr;
    zz_mac_addr mask;
    UT_hash_handle hh;
};

void zz_members_new(zz_members *members) {
    *members = NULL;
}

int zz_members_put(zz_members *members, zz_mac_addr mac_addr) {
    return zz_members_put_mask(members, mac_addr, -1);
}

int zz_members_put_mask(zz_members *members, zz_mac_addr mac_addr, zz_mac_addr mac_mask) {
    struct zz_device *device;

    HASH_FIND(hh, *members, &mac_addr, sizeof(zz_mac_addr), device);
    if (device) {
        return 0;
    }

    device = malloc(sizeof(struct zz_device));
    assert(device != NULL);
    device->addr = mac_addr;
    device->mask = mac_mask;
    HASH_ADD(hh, *members, addr, sizeof(zz_mac_addr), device);
    return 1;
}

int zz_members_has(const zz_members *members, zz_mac_addr mac_addr) {
    struct zz_device *device;

    HASH_FIND(hh, *members, &mac_addr, sizeof(zz_mac_addr), device);
    return !!device;
}

int zz_members_match(const zz_members *members, zz_mac_addr mac_addr) {
    struct zz_device *tmp, *device;

    HASH_ITER(hh, *members, device, tmp) {
        if ((mac_addr & device->mask) == (device->addr & device->mask)) {
            return 1;
        }
    }

    return 0;
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

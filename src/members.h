#ifndef ZZ_MEMBERS_H
#define ZZ_MEMBERS_H

#include "ieee802.h"

struct zz_device;
typedef struct zz_device *zz_members;

void zz_members_new(zz_members *members);
int zz_members_add(zz_members *members, zz_mac_addr mac_addr);
int zz_members_get(const zz_members *members, zz_mac_addr mac_addr);
unsigned zz_members_count(const zz_members *members);
int zz_members_is_empty(const zz_members *members);
void zz_members_free(zz_members *members);

#endif

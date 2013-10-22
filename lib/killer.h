#ifndef _ZZ_KILLER_H
#define _ZZ_KILLER_H

#include <stdint.h>
#include "zizzania.h"

#define ZZ_NEW_CLIENT 0x00
#define ZZ_HANDSHAKE 0x01

struct zz_killer_message {
    uint8_t action;
    uint8_t client[6];
    uint8_t bssid[6];
};

int zz_start_killer(zz_t *zz);

#endif

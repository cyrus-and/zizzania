#ifndef _ZIZZANIA_KILLER_H
#define _ZIZZANIA_KILLER_H

#include <stdint.h>
#include "zizzania.h"

#define ZIZZANIA_NEW_CLIENT 0x00
#define ZIZZANIA_HANDSHAKE 0x01

struct zizzania_killer_message
{
    uint8_t action;
    uint8_t client[6];
    uint8_t bssid[6];
};

int zizzania_start_killer( struct zizzania *z );

#endif

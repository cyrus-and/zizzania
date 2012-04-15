#ifndef _ZIZZANIA_DISPATCHER_H
#define _ZIZZANIA_DISPATCHER_H

#define ZIZZANIA_NEW_CLIENT 0x00
#define ZIZZANIA_HANDSHAKE 0x01

#include <stdint.h>

struct zizzania_killer_message
{
    uint8_t action;
    uint8_t client[6];
    uint8_t bssid[6];
};

void * zizzania_dispatcher( void *arg );

#endif

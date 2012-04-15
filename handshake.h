#ifndef _ZIZZANIA_HANDSHAKE_H
#define _ZIZZANIA_HANDSHAKE_H

#include <stdint.h>
#include <glib.h>
#include "zizzania.h"

struct client
{
    uint8_t need_set;
    int64_t start_counter;
};

struct client_info
{
    uint64_t replay_counter;
    uint16_t flags;
};

void zizzania_update( struct zizzania *z , const ieee80211_addr_t target , const ieee80211_addr_t client_addr , struct client *client , const struct client_info *client_info );
void zizzania_process_packet( struct zizzania *z , const struct pcap_pkthdr *pkt_header , const uint8_t *pkt );

#endif

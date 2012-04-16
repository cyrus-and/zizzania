#ifndef _ZIZZANIA_HANDSHAKE_H
#define _ZIZZANIA_HANDSHAKE_H

#include <stdint.h>
#include <glib.h>
#include "zizzania.h"

void zizzania_process_packet( struct zizzania *z , const struct pcap_pkthdr *pkt_header , const uint8_t *pkt );

#endif

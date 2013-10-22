#ifndef _ZZ_HANDSHAKE_H
#define _ZZ_HANDSHAKE_H

#include <stdint.h>
#include <glib.h>
#include "zizzania.h"

int zz_process_packet(zz_t *zz, const struct pcap_pkthdr *pkt_header,
                      const uint8_t *pkt);

#endif

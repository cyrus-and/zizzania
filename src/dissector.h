#ifndef ZZ_DISSECT_H
#define ZZ_DISSECT_H

#include <pcap/pcap.h>

#include "handler.h"

void zz_dissect_packet(u_char *_zz, const struct pcap_pkthdr *packet_header,
                       const uint8_t *packet);

#endif

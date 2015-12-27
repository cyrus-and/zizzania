#ifndef ZZ_HANDSHAKE_H
#define ZZ_HANDSHAKE_H

#include "handler.h"

enum {
    ZZ_IGNORE_REASON_RETRANSMISSION,
    ZZ_IGNORE_REASON_INVALID_EAPOL,
    ZZ_IGNORE_REASON_INVALID_COUNTER
};

enum {
    ZZ_TRACK_REASON_ALIVE,
    ZZ_TRACK_REASON_FIRST_HANDSHAKE,
    ZZ_TRACK_REASON_EXPIRATION,
    ZZ_TRACK_REASON_INVALIDATION
};

typedef struct {
    unsigned new_client:1;
    unsigned ignore:1;
    unsigned ignore_reason:2;
    unsigned track_client:1;
    unsigned track_reason:2;
    unsigned grace_time:1;
    unsigned dump_packet:1;
    unsigned got_handshake:1;
    unsigned handshake_info:3;
} zz_packet_outcome;

zz_packet_outcome zz_process_packet(zz_handler *zz,
    zz_mac_addr station, zz_mac_addr bssid,
    const struct pcap_pkthdr *packet_header,
    const struct ieee8021x_authentication_header *auth);

void zz_killer_post_message(zz_killer *killer,
                            zz_mac_addr station, zz_mac_addr bssid,
                            zz_packet_outcome outcome); /* to avoid circular deps */
#endif

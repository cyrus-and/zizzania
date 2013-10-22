#ifndef _ZZ_DISSECTORS_H
#define _ZZ_DISSECTORS_H

#include <glib.h>
#include <stdint.h>

#define BROADCAST_MAC_ADDRESS "\xff\xff\xff\xff\xff\xff"
#define IPV4_MULTICAST_MAC_ADDRESS_PFX "\x01\x00\x5e"
#define IPV6_MULTICAST_MAC_ADDRESS_PFX "\x33\x33"
#define IPV4_MULTICAST_MAC_ADDRESS_PFX_LENGTH 3
#define IPV6_MULTICAST_MAC_ADDRESS_PFX_LENGTH 2

typedef uint8_t *ieee80211_addr_t;

guint ieee80211_addr_hash(gconstpointer key);
gboolean ieee80211_addr_equal(gconstpointer a, gconstpointer b);
void ieee80211_addr_sprint(const ieee80211_addr_t addr, char buffer[18]);
int ieee80211_addr_sscan(ieee80211_addr_t addr, const char buffer[18]);

struct ieee80211_radiotap_header {
    uint8_t version;
    uint8_t padding;
    uint16_t length;
    uint32_t present;
}
__attribute__((__packed__));

struct ieee80211_mac_header {
    /* frame control field (2byte) */
    int version:2;
    int type:2;
    int sub_type:4;
    int to_ds:1;
    int from_ds:1;
    int more_fragments:1;
    int retry:1;
    int power_management:1;
    int more_data:1;
    int wep:1;
    int order:1;

    uint16_t duration;
    uint8_t address_1[6];
    uint8_t address_2[6];
    uint8_t address_3[6];
    uint16_t sequence_control;
}
__attribute__((__packed__));

struct ieee8022_llc_snap_header {
    /* llc should be 0xaaaa03 for snap */
    uint8_t dsap;
    uint8_t ssap;
    uint8_t control;

    /* snap */
    uint8_t oui[3];
    uint16_t type; /* should be 0x888e for ieee8021x_authentication */
}
__attribute__((__packed__));

struct ieee8021x_authentication_header {
    uint8_t version;
    uint8_t type;
    uint16_t length;
    uint8_t descriptor_type;
    uint16_t flags;
    uint16_t key_length;
    uint64_t replay_counter;
}
__attribute__((__packed__));

#endif
